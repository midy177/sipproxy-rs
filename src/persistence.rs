use crate::cluster::{ClusterCommand, ContactBinding, ContactStateSnapshot};
use crate::config::HaPersistenceConfig;
use crate::config::SipTransport;
use crate::ha::HaStateSnapshot;
use crate::proxy::{AffinityBindingSnapshot, AffinityKey, AffinityStateSnapshot, AffinityTarget};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::task;
use tracing::{info, warn};

#[derive(Clone)]
pub struct HaPersistence {
    inner: Arc<HaPersistenceInner>,
}

struct HaPersistenceInner {
    conn: Arc<StdMutex<Connection>>,
    required: bool,
    event_retention_seconds: u64,
    event_appends_succeeded: AtomicU64,
    event_appends_failed: AtomicU64,
    sqlite_writes_failed: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum HaEventPayload {
    RegisterContact { binding: ContactBinding },
    UnregisterContact { aor: String },
    UpsertAffinity { binding: AffinityBindingSnapshot },
    RemoveAffinity { key: AffinityKey },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaEventRecord {
    pub seq: u64,
    pub payload: HaEventPayload,
    #[serde(with = "crate::serde_u128")]
    pub created_at_epoch_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaEventsResponse {
    pub base_seq: u64,
    pub latest_seq: u64,
    pub snapshot_required: bool,
    pub events: Vec<HaEventRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HaPersistenceStats {
    pub latest_event_seq: u64,
    pub last_applied_seq: u64,
    pub event_rows: u64,
    pub event_appends_succeeded: u64,
    pub event_appends_failed: u64,
    pub sqlite_writes_failed: u64,
}

impl HaPersistence {
    pub fn open(config: &HaPersistenceConfig) -> Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        if let Some(parent) = Path::new(&config.path).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create HA persistence dir {}", parent.display())
            })?;
        }
        let conn = Connection::open(&config.path)
            .with_context(|| format!("failed to open HA persistence database {}", config.path))?;
        configure_connection(&conn)?;
        migrate(&conn)?;
        info!(
            path = %config.path,
            required = config.required,
            "HA persistence database opened"
        );
        Ok(Some(Self {
            inner: Arc::new(HaPersistenceInner {
                conn: Arc::new(StdMutex::new(conn)),
                required: config.required,
                event_retention_seconds: config.event_retention_seconds,
                event_appends_succeeded: AtomicU64::new(0),
                event_appends_failed: AtomicU64::new(0),
                sqlite_writes_failed: AtomicU64::new(0),
            }),
        }))
    }

    pub fn required(&self) -> bool {
        self.inner.required
    }

    #[cfg(test)]
    pub fn set_query_only_for_tests(&self, enabled: bool) -> Result<()> {
        let conn = self
            .inner
            .conn
            .lock()
            .expect("HA persistence connection lock poisoned");
        conn.pragma_update(None, "query_only", enabled)?;
        Ok(())
    }

    pub async fn load_snapshot(&self) -> Result<HaStateSnapshot> {
        let conn = self.inner.conn.clone();
        task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .expect("HA persistence connection lock poisoned");
            Ok(HaStateSnapshot {
                last_seq: latest_event_seq(&conn)?,
                checksum: String::new(),
                contacts: load_contacts(&conn)?,
                affinity: load_affinity(&conn)?,
            })
            .map(HaStateSnapshot::with_checksum)
        })
        .await
        .context("HA persistence load task failed")?
    }

    pub async fn apply_cluster_command(&self, command: &ClusterCommand) -> Result<()> {
        let command = command.clone();
        let conn = self.inner.conn.clone();
        let result = task::spawn_blocking(move || {
            let mut conn = conn
                .lock()
                .expect("HA persistence connection lock poisoned");
            apply_cluster_command(&mut conn, &command, true).map(|_| ())
        })
        .await
        .context("HA persistence command task failed")?;
        self.record_write_result(&result, 1);
        result
    }

    pub async fn upsert_affinity_bindings(
        &self,
        bindings: Vec<AffinityBindingSnapshot>,
    ) -> Result<()> {
        if bindings.is_empty() {
            return Ok(());
        }
        let appended_events = bindings.len() as u64;
        let conn = self.inner.conn.clone();
        let result = task::spawn_blocking(move || {
            let mut conn = conn
                .lock()
                .expect("HA persistence connection lock poisoned");
            let tx = conn.transaction()?;
            for binding in bindings {
                let seq = append_event(
                    &tx,
                    &event_key_for_affinity(&binding),
                    &HaEventPayload::UpsertAffinity {
                        binding: binding.clone(),
                    },
                )?;
                upsert_affinity_binding(&tx, &binding, Some(seq))?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .context("HA persistence affinity task failed")?;
        self.record_write_result(&result, appended_events);
        result
    }

    pub async fn install_snapshot(&self, snapshot: &HaStateSnapshot) -> Result<()> {
        let snapshot = snapshot.clone();
        let conn = self.inner.conn.clone();
        let result = task::spawn_blocking(move || {
            let mut conn = conn
                .lock()
                .expect("HA persistence connection lock poisoned");
            let tx = conn.transaction()?;
            tx.execute("delete from contacts", [])?;
            tx.execute("delete from affinity", [])?;
            for binding in snapshot.contacts.contacts {
                if !binding.is_expired() {
                    upsert_contact(&tx, &binding, None)?;
                }
            }
            for binding in snapshot.affinity.bindings {
                if binding.expires_at_epoch_ms > now_epoch_ms() {
                    upsert_affinity_binding(&tx, &binding, None)?;
                }
            }
            set_meta_u64(&tx, "last_applied_seq", snapshot.last_seq)?;
            tx.commit()?;
            Ok(())
        })
        .await
        .context("HA persistence snapshot task failed")?;
        self.record_sqlite_write_result(&result);
        result
    }

    pub async fn cleanup_expired(&self) -> Result<()> {
        let conn = self.inner.conn.clone();
        let retention = self.inner.event_retention_seconds;
        let result = task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .expect("HA persistence connection lock poisoned");
            let now = now_epoch_ms().to_string();
            let retain_after = now_epoch_ms()
                .saturating_sub(u128::from(retention) * 1_000)
                .to_string();
            conn.execute(
                "delete from contacts where expires_at_epoch_ms <= ?1",
                [&now],
            )?;
            conn.execute(
                "delete from affinity where expires_at_epoch_ms <= ?1",
                [&now],
            )?;
            conn.execute(
                "delete from ha_events where created_at_epoch_ms <= ?1",
                [&retain_after],
            )?;
            Ok(())
        })
        .await
        .context("HA persistence cleanup task failed")?;
        self.record_sqlite_write_result(&result);
        result
    }

    pub async fn latest_event_seq(&self) -> Result<u64> {
        let conn = self.inner.conn.clone();
        task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .expect("HA persistence connection lock poisoned");
            latest_event_seq(&conn)
        })
        .await
        .context("HA persistence latest seq task failed")?
    }

    pub async fn last_applied_seq(&self) -> Result<u64> {
        let conn = self.inner.conn.clone();
        task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .expect("HA persistence connection lock poisoned");
            last_applied_seq(&conn).map(|seq| seq.unwrap_or(0))
        })
        .await
        .context("HA persistence last applied seq task failed")?
    }

    pub async fn events_after(&self, after: u64, limit: usize) -> Result<HaEventsResponse> {
        let conn = self.inner.conn.clone();
        task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .expect("HA persistence connection lock poisoned");
            events_after(&conn, after, limit)
        })
        .await
        .context("HA persistence events task failed")?
    }

    pub async fn apply_event(&self, event: &HaEventRecord) -> Result<()> {
        let event = event.clone();
        let conn = self.inner.conn.clone();
        let result = task::spawn_blocking(move || {
            let mut conn = conn
                .lock()
                .expect("HA persistence connection lock poisoned");
            apply_event_without_append(&mut conn, &event)
        })
        .await
        .context("HA persistence apply event task failed")?;
        self.record_sqlite_write_result(&result);
        result
    }

    pub async fn stats(&self) -> Result<HaPersistenceStats> {
        let conn = self.inner.conn.clone();
        let stats = task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .expect("HA persistence connection lock poisoned");
            persistence_stats(&conn)
        })
        .await
        .context("HA persistence stats task failed")??;
        Ok(HaPersistenceStats {
            event_appends_succeeded: self.inner.event_appends_succeeded.load(Ordering::Relaxed),
            event_appends_failed: self.inner.event_appends_failed.load(Ordering::Relaxed),
            sqlite_writes_failed: self.inner.sqlite_writes_failed.load(Ordering::Relaxed),
            ..stats
        })
    }

    pub async fn cleanup_loop(
        self,
        interval: std::time::Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(err) = self.cleanup_expired().await {
                        warn!(error = %format!("{err:#}"), "failed to cleanup expired HA persistence rows");
                    }
                }
            }
        }
        Ok(())
    }

    fn record_write_result(&self, result: &Result<()>, appended_events: u64) {
        self.record_sqlite_write_result(result);
        match result {
            Ok(()) => {
                self.inner
                    .event_appends_succeeded
                    .fetch_add(appended_events, Ordering::Relaxed);
            }
            Err(_) => {
                self.inner
                    .event_appends_failed
                    .fetch_add(appended_events, Ordering::Relaxed);
            }
        }
    }

    fn record_sqlite_write_result(&self, result: &Result<()>) {
        if result.is_err() {
            self.inner
                .sqlite_writes_failed
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn configure_connection(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "busy_timeout", 5_000_i64)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        create table if not exists contacts (
            aor text primary key,
            contact text not null,
            source text not null,
            expires_at_epoch_ms text not null,
            updated_seq integer
        );
        create table if not exists affinity (
            key text primary key,
            target_addr text not null,
            transport text not null,
            expires_at_epoch_ms text not null,
            updated_seq integer
        );
        create table if not exists ha_events (
            seq integer primary key autoincrement,
            kind text not null,
            key text not null,
            payload_json text not null,
            created_at_epoch_ms text not null
        );
        create table if not exists meta (
            key text primary key,
            value text not null
        );
        insert into meta(key, value)
        values('schema_version', '1')
        on conflict(key) do update set value = excluded.value;
        "#,
    )?;
    Ok(())
}

fn apply_cluster_command(
    conn: &mut Connection,
    command: &ClusterCommand,
    append: bool,
) -> Result<Option<u64>> {
    let tx = conn.transaction()?;
    let seq = if append {
        Some(match command {
            ClusterCommand::RegisterContact(binding) => append_event(
                &tx,
                &binding.aor,
                &HaEventPayload::RegisterContact {
                    binding: binding.clone(),
                },
            )?,
            ClusterCommand::UnregisterContact { aor } => append_event(
                &tx,
                aor,
                &HaEventPayload::UnregisterContact { aor: aor.clone() },
            )?,
        })
    } else {
        None
    };
    match command {
        ClusterCommand::RegisterContact(binding) => upsert_contact(&tx, binding, seq)?,
        ClusterCommand::UnregisterContact { aor } => {
            tx.execute("delete from contacts where aor = ?1", [aor])?;
        }
    }
    tx.commit()?;
    Ok(seq)
}

fn upsert_contact(
    conn: &Connection,
    binding: &ContactBinding,
    updated_seq: Option<u64>,
) -> Result<()> {
    conn.execute(
        r#"
        insert into contacts(aor, contact, source, expires_at_epoch_ms, updated_seq)
        values(?1, ?2, ?3, ?4, ?5)
        on conflict(aor) do update set
            contact = excluded.contact,
            source = excluded.source,
            expires_at_epoch_ms = excluded.expires_at_epoch_ms,
            updated_seq = excluded.updated_seq
        "#,
        params![
            binding.aor,
            binding.contact,
            binding.source,
            binding.expires_at_epoch_ms.to_string(),
            updated_seq
        ],
    )?;
    Ok(())
}

fn upsert_affinity_binding(
    conn: &Connection,
    binding: &AffinityBindingSnapshot,
    updated_seq: Option<u64>,
) -> Result<()> {
    conn.execute(
        r#"
        insert into affinity(key, target_addr, transport, expires_at_epoch_ms, updated_seq)
        values(?1, ?2, ?3, ?4, ?5)
        on conflict(key) do update set
            target_addr = excluded.target_addr,
            transport = excluded.transport,
            expires_at_epoch_ms = excluded.expires_at_epoch_ms,
            updated_seq = excluded.updated_seq
        "#,
        params![
            binding.key.as_str(),
            binding.target.addr.to_string(),
            binding.target.transport.as_str(),
            binding.expires_at_epoch_ms.to_string(),
            updated_seq
        ],
    )?;
    Ok(())
}

fn load_contacts(conn: &Connection) -> Result<ContactStateSnapshot> {
    let now = now_epoch_ms();
    let mut stmt =
        conn.prepare("select aor, contact, source, expires_at_epoch_ms from contacts")?;
    let contacts = stmt
        .query_map([], |row| {
            let expires: String = row.get(3)?;
            Ok(ContactBinding {
                aor: row.get(0)?,
                contact: row.get(1)?,
                source: row.get(2)?,
                expires_at_epoch_ms: expires.parse().unwrap_or_default(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|binding| binding.expires_at_epoch_ms > now)
        .collect();
    Ok(ContactStateSnapshot { contacts })
}

fn load_affinity(conn: &Connection) -> Result<AffinityStateSnapshot> {
    let now = now_epoch_ms();
    let mut stmt =
        conn.prepare("select key, target_addr, transport, expires_at_epoch_ms from affinity")?;
    let rows = stmt
        .query_map([], |row| {
            let key: String = row.get(0)?;
            let target_addr: String = row.get(1)?;
            let transport: String = row.get(2)?;
            let expires: String = row.get(3)?;
            Ok((key, target_addr, transport, expires))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut bindings = Vec::new();
    for (key, target_addr, transport, expires) in rows {
        let expires_at_epoch_ms = expires.parse::<u128>().unwrap_or_default();
        if expires_at_epoch_ms <= now {
            continue;
        }
        let transport = match transport.as_str() {
            "udp" => SipTransport::Udp,
            "tcp" => SipTransport::Tcp,
            other => bail!("invalid persisted affinity transport '{other}'"),
        };
        bindings.push(AffinityBindingSnapshot {
            key: AffinityKey::from_string(key),
            target: AffinityTarget {
                addr: target_addr.parse().with_context(|| {
                    format!("invalid persisted affinity target address '{target_addr}'")
                })?,
                transport,
            },
            expires_at_epoch_ms,
        });
    }
    Ok(AffinityStateSnapshot { bindings })
}

fn append_event(conn: &Connection, key: &str, payload: &HaEventPayload) -> Result<u64> {
    let created_at = now_epoch_ms();
    let kind = event_kind(payload);
    let payload_json = serde_json::to_string(payload)?;
    conn.execute(
        "insert into ha_events(kind, key, payload_json, created_at_epoch_ms) values(?1, ?2, ?3, ?4)",
        params![kind, key, payload_json, created_at.to_string()],
    )?;
    Ok(conn.last_insert_rowid() as u64)
}

fn event_kind(payload: &HaEventPayload) -> &'static str {
    match payload {
        HaEventPayload::RegisterContact { .. } => "register-contact",
        HaEventPayload::UnregisterContact { .. } => "unregister-contact",
        HaEventPayload::UpsertAffinity { .. } => "upsert-affinity",
        HaEventPayload::RemoveAffinity { .. } => "remove-affinity",
    }
}

fn event_key_for_affinity(binding: &AffinityBindingSnapshot) -> String {
    binding.key.as_str().to_string()
}

fn latest_event_seq(conn: &Connection) -> Result<u64> {
    let seq = conn.query_row("select coalesce(max(seq), 0) from ha_events", [], |row| {
        row.get::<_, u64>(0)
    })?;
    Ok(seq)
}

fn event_row_count(conn: &Connection) -> Result<u64> {
    let count = conn.query_row("select count(*) from ha_events", [], |row| {
        row.get::<_, u64>(0)
    })?;
    Ok(count)
}

fn persistence_stats(conn: &Connection) -> Result<HaPersistenceStats> {
    Ok(HaPersistenceStats {
        latest_event_seq: latest_event_seq(conn)?,
        last_applied_seq: last_applied_seq(conn)?.unwrap_or(0),
        event_rows: event_row_count(conn)?,
        event_appends_succeeded: 0,
        event_appends_failed: 0,
        sqlite_writes_failed: 0,
    })
}

fn first_event_seq(conn: &Connection) -> Result<Option<u64>> {
    Ok(conn.query_row("select min(seq) from ha_events", [], |row| {
        row.get::<_, Option<u64>>(0)
    })?)
}

fn events_after(conn: &Connection, after: u64, limit: usize) -> Result<HaEventsResponse> {
    let latest_seq = latest_event_seq(conn)?;
    let first_seq = first_event_seq(conn)?;
    let snapshot_required = first_seq.is_some_and(|first| after + 1 < first);
    if snapshot_required {
        return Ok(HaEventsResponse {
            base_seq: first_seq.unwrap_or(latest_seq + 1).saturating_sub(1),
            latest_seq,
            snapshot_required: true,
            events: Vec::new(),
        });
    }
    let limit = limit.clamp(1, 10_000) as i64;
    let mut stmt = conn.prepare(
        "select seq, payload_json, created_at_epoch_ms from ha_events where seq > ?1 order by seq asc limit ?2",
    )?;
    let events = stmt
        .query_map(params![after, limit], |row| {
            let payload_json: String = row.get(1)?;
            let created_at: String = row.get(2)?;
            let payload = serde_json::from_str::<HaEventPayload>(&payload_json).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            Ok(HaEventRecord {
                seq: row.get(0)?,
                payload,
                created_at_epoch_ms: created_at.parse().unwrap_or_default(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(HaEventsResponse {
        base_seq: after,
        latest_seq,
        snapshot_required: false,
        events,
    })
}

fn apply_event_without_append(conn: &mut Connection, event: &HaEventRecord) -> Result<()> {
    let tx = conn.transaction()?;
    match &event.payload {
        HaEventPayload::RegisterContact { binding } => {
            if !binding.is_expired() {
                upsert_contact(&tx, binding, Some(event.seq))?;
            }
        }
        HaEventPayload::UnregisterContact { aor } => {
            tx.execute("delete from contacts where aor = ?1", [aor])?;
        }
        HaEventPayload::UpsertAffinity { binding } => {
            if binding.expires_at_epoch_ms > now_epoch_ms() {
                upsert_affinity_binding(&tx, binding, Some(event.seq))?;
            }
        }
        HaEventPayload::RemoveAffinity { key } => {
            tx.execute("delete from affinity where key = ?1", [key.as_str()])?;
        }
    }
    set_meta_u64(&tx, "last_applied_seq", event.seq)?;
    tx.commit()?;
    Ok(())
}

fn set_meta_u64(conn: &Connection, key: &str, value: u64) -> Result<()> {
    conn.execute(
        r#"
        insert into meta(key, value)
        values(?1, ?2)
        on conflict(key) do update set value = excluded.value
        "#,
        params![key, value.to_string()],
    )?;
    Ok(())
}

fn now_epoch_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn last_applied_seq(conn: &Connection) -> Result<Option<u64>> {
    let value = conn
        .query_row(
            "select value from meta where key = 'last_applied_seq'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(value.and_then(|value| value.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::expires_at;
    use std::time::Duration;

    fn test_config(path: String) -> HaPersistenceConfig {
        HaPersistenceConfig {
            enabled: true,
            path,
            required: false,
            event_retention_seconds: 3600,
            cleanup_interval_ms: 60_000,
        }
    }

    #[tokio::test]
    async fn persistence_round_trips_contacts_and_affinity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db").to_string_lossy().to_string();
        let persistence = HaPersistence::open(&test_config(path.clone()))
            .unwrap()
            .unwrap();

        persistence
            .apply_cluster_command(&ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:100@example.com".to_string(),
                contact: "sip:100@127.0.0.1:5062".to_string(),
                source: "127.0.0.1:50000".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await
            .unwrap();
        persistence
            .upsert_affinity_bindings(vec![AffinityBindingSnapshot {
                key: AffinityKey::from_string("call-id:abc".to_string()),
                target: AffinityTarget {
                    addr: "127.0.0.1:5080".parse().unwrap(),
                    transport: SipTransport::Udp,
                },
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }])
            .await
            .unwrap();
        drop(persistence);

        let reopened = HaPersistence::open(&test_config(path)).unwrap().unwrap();
        let snapshot = reopened.load_snapshot().await.unwrap();
        assert_eq!(snapshot.contacts.contacts.len(), 1);
        assert_eq!(snapshot.contacts.contacts[0].aor, "sip:100@example.com");
        assert_eq!(snapshot.affinity.bindings.len(), 1);
        assert_eq!(snapshot.affinity.bindings[0].key.as_str(), "call-id:abc");
    }

    #[tokio::test]
    async fn persistence_does_not_restore_expired_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db").to_string_lossy().to_string();
        let persistence = HaPersistence::open(&test_config(path)).unwrap().unwrap();

        persistence
            .apply_cluster_command(&ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:expired@example.com".to_string(),
                contact: "sip:expired@127.0.0.1:5062".to_string(),
                source: "127.0.0.1:50000".to_string(),
                expires_at_epoch_ms: 0,
            }))
            .await
            .unwrap();
        persistence.cleanup_expired().await.unwrap();

        let snapshot = persistence.load_snapshot().await.unwrap();
        assert!(snapshot.contacts.contacts.is_empty());
        assert!(snapshot.affinity.bindings.is_empty());
    }

    #[tokio::test]
    async fn persistence_stats_reports_sequences_rows_and_write_counters() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db").to_string_lossy().to_string();
        let persistence = HaPersistence::open(&test_config(path)).unwrap().unwrap();

        persistence
            .apply_cluster_command(&ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:100@example.com".to_string(),
                contact: "sip:100@127.0.0.1:5062".to_string(),
                source: "127.0.0.1:50000".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await
            .unwrap();
        persistence
            .upsert_affinity_bindings(vec![AffinityBindingSnapshot {
                key: AffinityKey::from_string("call-id:abc".to_string()),
                target: AffinityTarget {
                    addr: "127.0.0.1:5080".parse().unwrap(),
                    transport: SipTransport::Udp,
                },
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }])
            .await
            .unwrap();

        let stats = persistence.stats().await.unwrap();
        assert_eq!(stats.latest_event_seq, 2);
        assert_eq!(stats.last_applied_seq, 0);
        assert_eq!(stats.event_rows, 2);
        assert_eq!(stats.event_appends_succeeded, 2);
        assert_eq!(stats.event_appends_failed, 0);
        assert_eq!(stats.sqlite_writes_failed, 0);
    }

    #[tokio::test]
    async fn event_log_replays_contacts_and_affinity_to_follower() {
        let source_dir = tempfile::tempdir().unwrap();
        let target_dir = tempfile::tempdir().unwrap();
        let source = HaPersistence::open(&test_config(
            source_dir
                .path()
                .join("state.db")
                .to_string_lossy()
                .to_string(),
        ))
        .unwrap()
        .unwrap();
        let target = HaPersistence::open(&test_config(
            target_dir
                .path()
                .join("state.db")
                .to_string_lossy()
                .to_string(),
        ))
        .unwrap()
        .unwrap();

        source
            .apply_cluster_command(&ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:100@example.com".to_string(),
                contact: "sip:100@127.0.0.1:5062".to_string(),
                source: "127.0.0.1:50000".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await
            .unwrap();
        source
            .upsert_affinity_bindings(vec![AffinityBindingSnapshot {
                key: AffinityKey::from_string("call-id:abc".to_string()),
                target: AffinityTarget {
                    addr: "127.0.0.1:5080".parse().unwrap(),
                    transport: SipTransport::Udp,
                },
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }])
            .await
            .unwrap();

        let response = source.events_after(0, 10).await.unwrap();
        assert!(!response.snapshot_required);
        assert_eq!(response.events.len(), 2);
        for event in &response.events {
            target.apply_event(event).await.unwrap();
        }
        assert_eq!(target.last_applied_seq().await.unwrap(), 2);

        let snapshot = target.load_snapshot().await.unwrap();
        assert_eq!(snapshot.contacts.contacts.len(), 1);
        assert_eq!(snapshot.affinity.bindings.len(), 1);
    }

    #[tokio::test]
    async fn event_log_reports_snapshot_required_when_after_is_behind_retained_events() {
        let dir = tempfile::tempdir().unwrap();
        let persistence = HaPersistence::open(&test_config(
            dir.path().join("state.db").to_string_lossy().to_string(),
        ))
        .unwrap()
        .unwrap();
        persistence
            .apply_cluster_command(&ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:100@example.com".to_string(),
                contact: "sip:100@127.0.0.1:5062".to_string(),
                source: "127.0.0.1:50000".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await
            .unwrap();

        {
            let conn = persistence.inner.conn.lock().unwrap();
            conn.execute("delete from ha_events where seq = 1", [])
                .unwrap();
            conn.execute(
                "insert into ha_events(seq, kind, key, payload_json, created_at_epoch_ms) values(2, 'noop', 'noop', '{}', '1')",
                [],
            )
            .unwrap();
        }

        let response = persistence.events_after(0, 10).await.unwrap();
        assert!(response.snapshot_required);
    }
}
