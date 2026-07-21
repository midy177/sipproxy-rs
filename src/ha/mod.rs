use crate::cluster::{ClusterApplyResult, ClusterCommand, ContactStateSnapshot};
use crate::cluster::{ClusterReplicator, ClusterRole, NodeId};
use crate::config::{
    HaActiveStandbyConfig, HaAddonConfig, HaInitialRole, HaReplicationConfig, NodeConfig,
};
use crate::persistence::{HaEventRecord, HaEventsResponse};
use crate::proxy::{AffinityStateSnapshot, ProxyServer};
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::{RwLock, watch};
use tokio::time::MissedTickBehavior;
use tokio::time::timeout;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct HaContext {
    pub node_id: NodeId,
    pub role: ClusterRole,
}

impl HaContext {
    pub fn from_node(node: &NodeConfig, role: ClusterRole) -> Self {
        Self {
            node_id: node.id,
            role,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaStateSnapshot {
    #[serde(default)]
    pub last_seq: u64,
    #[serde(default)]
    pub checksum: String,
    pub contacts: ContactStateSnapshot,
    pub affinity: AffinityStateSnapshot,
}

impl HaStateSnapshot {
    pub fn with_checksum(mut self) -> Self {
        self.checksum = self.compute_checksum();
        self
    }

    pub fn checksum_is_valid(&self) -> bool {
        self.checksum.is_empty() || self.checksum == self.compute_checksum()
    }

    pub fn compute_checksum(&self) -> String {
        let mut contacts = self.contacts.contacts.clone();
        contacts.sort_by(|a, b| {
            a.aor
                .cmp(&b.aor)
                .then_with(|| a.contact.cmp(&b.contact))
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.expires_at_epoch_ms.cmp(&b.expires_at_epoch_ms))
        });
        let mut affinity = self.affinity.bindings.clone();
        affinity.sort_by(|a, b| {
            a.key
                .as_str()
                .cmp(b.key.as_str())
                .then_with(|| a.target.addr.cmp(&b.target.addr))
                .then_with(|| a.target.transport.as_str().cmp(b.target.transport.as_str()))
                .then_with(|| a.expires_at_epoch_ms.cmp(&b.expires_at_epoch_ms))
        });

        let mut hash = FNV_OFFSET_BASIS;
        hash_u64(&mut hash, self.last_seq);
        for contact in contacts {
            hash_str(&mut hash, &contact.aor);
            hash_str(&mut hash, &contact.contact);
            hash_str(&mut hash, &contact.source);
            hash_u128(&mut hash, contact.expires_at_epoch_ms);
        }
        for binding in affinity {
            hash_str(&mut hash, binding.key.as_str());
            hash_str(&mut hash, &binding.target.addr.to_string());
            hash_str(&mut hash, binding.target.transport.as_str());
            hash_u128(&mut hash, binding.expires_at_epoch_ms);
        }
        format!("fnv1a64:{hash:016x}")
    }
}

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
    *hash ^= 0xff;
    *hash = hash.wrapping_mul(FNV_PRIME);
}

fn hash_str(hash: &mut u64, value: &str) {
    hash_bytes(hash, value.as_bytes());
}

fn hash_u64(hash: &mut u64, value: u64) {
    hash_bytes(hash, &value.to_be_bytes());
}

fn hash_u128(hash: &mut u64, value: u128) {
    hash_bytes(hash, &value.to_be_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaHeartbeat {
    pub node_id: NodeId,
    pub role: ClusterRole,
    pub epoch: u64,
}

#[derive(Debug)]
pub struct ActiveStandbyRuntime {
    node_id: NodeId,
    role: RwLock<ClusterRole>,
    epoch: AtomicU64,
}

impl ActiveStandbyRuntime {
    pub fn new(node_id: NodeId, initial_role: HaInitialRole) -> Arc<Self> {
        let role = match initial_role {
            HaInitialRole::Active => ClusterRole::Leader,
            HaInitialRole::Standby => ClusterRole::Follower,
        };
        Arc::new(Self {
            node_id,
            role: RwLock::new(role),
            epoch: AtomicU64::new(1),
        })
    }

    pub async fn role(&self) -> ClusterRole {
        *self.role.read().await
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }

    async fn heartbeat(&self) -> HaHeartbeat {
        HaHeartbeat {
            node_id: self.node_id,
            role: self.role().await,
            epoch: self.epoch(),
        }
    }

    async fn promote(&self) {
        let mut role = self.role.write().await;
        if !role.accepts_writes() {
            self.epoch.fetch_add(1, Ordering::Relaxed);
            *role = ClusterRole::Leader;
        }
    }

    async fn demote(&self) {
        *self.role.write().await = ClusterRole::Follower;
    }
}

pub struct ActiveStandbyReplicator {
    inner: Arc<dyn ClusterReplicator>,
    runtime: Arc<ActiveStandbyRuntime>,
}

impl ActiveStandbyReplicator {
    pub fn new(inner: Arc<dyn ClusterReplicator>, runtime: Arc<ActiveStandbyRuntime>) -> Arc<Self> {
        Arc::new(Self { inner, runtime })
    }
}

#[async_trait]
impl ClusterReplicator for ActiveStandbyReplicator {
    async fn submit(&self, command: ClusterCommand) -> Result<ClusterApplyResult> {
        if !self.role().await.accepts_writes() {
            bail!("active-standby node is standby and does not accept writes");
        }
        self.inner.submit(command).await
    }

    async fn role(&self) -> ClusterRole {
        self.runtime.role().await
    }

    async fn leader(&self) -> Option<NodeId> {
        if self.role().await.accepts_writes() {
            Some(self.runtime.node_id)
        } else {
            None
        }
    }

    async fn shutdown(&self) -> Result<()> {
        self.inner.shutdown().await
    }
}

#[async_trait]
pub trait HaAddon: Send + Sync {
    async fn on_become_leader(&self, _ctx: HaContext) -> Result<()> {
        Ok(())
    }

    async fn on_step_down(&self, _ctx: HaContext) -> Result<()> {
        Ok(())
    }

    async fn on_leader_changed(&self, _ctx: HaContext, _leader: Option<NodeId>) -> Result<()> {
        Ok(())
    }
}

pub type HaAddonRef = Arc<dyn HaAddon>;

pub fn build_addon(config: &HaAddonConfig) -> HaAddonRef {
    match config {
        HaAddonConfig::Noop => Arc::new(NoopHaAddon),
        HaAddonConfig::Command {
            on_become_leader,
            on_step_down,
            timeout_ms,
        } => Arc::new(CommandHaAddon {
            on_become_leader: on_become_leader.clone(),
            on_step_down: on_step_down.clone(),
            timeout: Duration::from_millis(*timeout_ms),
        }),
    }
}

pub async fn run_leader_monitor(
    node: NodeConfig,
    replicator: Arc<dyn ClusterReplicator>,
    addon: HaAddonRef,
    mut shutdown: watch::Receiver<bool>,
    interval: Duration,
) -> Result<()> {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut state = HaMonitorState::default();

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                let role = replicator.role().await;
                let leader = replicator.leader().await;
                observe_ha_state(&mut state, &node, &addon, role, leader).await;
            }
        }
    }

    Ok(())
}

pub async fn run_active_standby(
    config: HaActiveStandbyConfig,
    runtime: Arc<ActiveStandbyRuntime>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let bind_addr = config
        .heartbeat_bind
        .parse::<SocketAddr>()
        .context("ha.active_standby.heartbeat_bind must be a SocketAddr")?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind active-standby heartbeat listener {bind_addr}"))?;
    let app = Router::new()
        .route("/ha/heartbeat", get(ha_heartbeat))
        .with_state(runtime.clone());

    let monitor_task = tokio::spawn(run_active_standby_monitor(
        config,
        runtime,
        shutdown.clone(),
    ));
    let http = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = shutdown.changed().await;
    });
    http.await
        .context("active-standby heartbeat HTTP server failed")?;
    monitor_task.await??;
    Ok(())
}

async fn ha_heartbeat(State(runtime): State<Arc<ActiveStandbyRuntime>>) -> Json<HaHeartbeat> {
    Json(runtime.heartbeat().await)
}

async fn run_active_standby_monitor(
    config: HaActiveStandbyConfig,
    runtime: Arc<ActiveStandbyRuntime>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let Some(peer_addr) = config.peer_heartbeat_addr else {
        return wait_for_shutdown(shutdown).await;
    };

    let endpoint = heartbeat_endpoint(&peer_addr);
    let client = Client::new();
    let heartbeat_interval = Duration::from_millis(config.heartbeat_interval_ms);
    let failover_timeout = Duration::from_millis(config.failover_timeout_ms);
    let mut ticker = tokio::time::interval(heartbeat_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_seen = Some(Instant::now());

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                match timeout(heartbeat_interval, client.get(&endpoint).send()).await {
                    Ok(Ok(response)) if response.status().is_success() => {
                        match timeout(heartbeat_interval, response.json::<HaHeartbeat>()).await {
                            Ok(Ok(peer)) => {
                                last_seen = Some(Instant::now());
                                reconcile_active_standby(runtime.as_ref(), peer).await;
                            }
                            Ok(Err(err)) => warn!(peer = %peer_addr, error = %err, "failed to decode active-standby heartbeat"),
                            Err(_) => warn!(peer = %peer_addr, "timed out decoding active-standby heartbeat"),
                        }
                    }
                    Ok(Ok(response)) => warn!(
                        peer = %peer_addr,
                        status = %response.status(),
                        "active-standby peer returned non-success status"
                    ),
                    Ok(Err(err)) => warn!(peer = %peer_addr, error = %err, "failed to fetch active-standby heartbeat"),
                    Err(_) => warn!(peer = %peer_addr, "timed out fetching active-standby heartbeat"),
                }

                if !runtime.role().await.accepts_writes()
                    && last_seen.is_none_or(|seen| seen.elapsed() >= failover_timeout)
                {
                    info!(node_id = runtime.node_id, "active-standby peer timed out; promoting local node");
                    runtime.promote().await;
                }
            }
        }
    }
    Ok(())
}

async fn reconcile_active_standby(runtime: &ActiveStandbyRuntime, peer: HaHeartbeat) {
    let local = runtime.heartbeat().await;
    let local_active = local.role.accepts_writes();
    let peer_active = peer.role.accepts_writes();

    match (local_active, peer_active) {
        (true, true) if peer_should_win(&local, &peer) => {
            warn!(
                local_node_id = local.node_id,
                peer_node_id = peer.node_id,
                peer_epoch = peer.epoch,
                local_epoch = local.epoch,
                "active-standby detected two active nodes; demoting local node"
            );
            runtime.demote().await;
        }
        (false, false) if local.node_id < peer.node_id => {
            info!(
                local_node_id = local.node_id,
                peer_node_id = peer.node_id,
                "active-standby detected two standby nodes; promoting lower node id"
            );
            runtime.promote().await;
        }
        _ => {}
    }
}

fn heartbeat_endpoint(addr: &str) -> String {
    format!("http://{addr}/ha/heartbeat")
}

fn peer_should_win(local: &HaHeartbeat, peer: &HaHeartbeat) -> bool {
    peer.epoch > local.epoch || (peer.epoch == local.epoch && peer.node_id < local.node_id)
}

pub async fn run_state_replication(
    config: HaReplicationConfig,
    server: Arc<ProxyServer>,
    replicator: Arc<dyn ClusterReplicator>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let bind_addr = config
        .bind_addr
        .parse::<SocketAddr>()
        .context("ha.replication.bind_addr must be a SocketAddr")?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind HA replication listener {bind_addr}"))?;
    let app = Router::new()
        .route("/ha/snapshot", get(ha_snapshot))
        .route("/ha/events", get(ha_events))
        .with_state(server.clone());

    let pull_task = tokio::spawn(run_snapshot_pull(
        config.clone(),
        server,
        replicator,
        shutdown.clone(),
    ));

    let http = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = shutdown.changed().await;
    });
    http.await.context("HA replication HTTP server failed")?;
    pull_task.await??;
    Ok(())
}

async fn ha_snapshot(State(server): State<Arc<ProxyServer>>) -> Json<HaStateSnapshot> {
    Json(server.snapshot_state().await)
}

#[derive(Debug, Deserialize)]
struct HaEventsQuery {
    #[serde(default)]
    after: u64,
    #[serde(default = "default_ha_events_limit")]
    limit: usize,
}

fn default_ha_events_limit() -> usize {
    1_000
}

async fn ha_events(
    State(server): State<Arc<ProxyServer>>,
    Query(query): Query<HaEventsQuery>,
) -> Json<HaEventsResponse> {
    Json(server.ha_events_after(query.after, query.limit).await)
}

async fn run_snapshot_pull(
    config: HaReplicationConfig,
    server: Arc<ProxyServer>,
    replicator: Arc<dyn ClusterReplicator>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let Some(peer_addr) = config.peer_addr else {
        return wait_for_shutdown(shutdown).await;
    };
    let endpoint = format!("http://{peer_addr}/ha/snapshot");
    let events_endpoint = format!("http://{peer_addr}/ha/events");
    let client = Client::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(config.pull_interval_ms));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let request_timeout = Duration::from_millis(config.request_timeout_ms);

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                if replicator.role().await.accepts_writes() {
                    continue;
                }
                match pull_ha_events(&client, &events_endpoint, request_timeout, server.clone()).await {
                    Ok(HaEventPullOutcome::Applied) => {
                        server.record_ha_event_pull("applied");
                        debug!(peer = %peer_addr, "applied HA event batch from peer");
                        continue;
                    }
                    Ok(HaEventPullOutcome::Idle) => {
                        server.record_ha_event_pull("idle");
                        continue;
                    }
                    Ok(HaEventPullOutcome::SnapshotRequired) => {
                        server.record_ha_event_pull("snapshot-required");
                        server.record_ha_snapshot_fallback("event-log-unavailable");
                    }
                    Err(err) => {
                        server.record_ha_event_pull("error");
                        server.record_ha_snapshot_fallback("event-pull-error");
                        warn!(peer = %peer_addr, error = %format!("{err:#}"), "failed to pull HA events; falling back to snapshot");
                    }
                }
                match timeout(request_timeout, client.get(&endpoint).send()).await {
                    Ok(Ok(response)) if response.status().is_success() => {
                        match timeout(request_timeout, response.json::<HaStateSnapshot>()).await {
                            Ok(Ok(snapshot)) => {
                                if server.install_state_snapshot(snapshot).await {
                                    server.record_ha_snapshot_pull("installed");
                                    debug!(peer = %peer_addr, "installed HA state snapshot from peer");
                                } else {
                                    server.record_ha_snapshot_pull("rejected");
                                }
                            }
                            Ok(Err(err)) => {
                                server.record_ha_snapshot_pull("decode-error");
                                warn!(peer = %peer_addr, error = %err, "failed to decode HA snapshot");
                            }
                            Err(_) => {
                                server.record_ha_snapshot_pull("decode-timeout");
                                warn!(peer = %peer_addr, "timed out decoding HA snapshot");
                            }
                        }
                    }
                    Ok(Ok(response)) => {
                        server.record_ha_snapshot_pull("http-error");
                        warn!(
                            peer = %peer_addr,
                            status = %response.status(),
                            "HA snapshot peer returned non-success status"
                        );
                    }
                    Ok(Err(err)) => {
                        server.record_ha_snapshot_pull("request-error");
                        warn!(peer = %peer_addr, error = %err, "failed to pull HA snapshot");
                    }
                    Err(_) => {
                        server.record_ha_snapshot_pull("request-timeout");
                        warn!(peer = %peer_addr, "timed out pulling HA snapshot");
                    }
                }
            }
        }
    }
    Ok(())
}

enum HaEventPullOutcome {
    Applied,
    Idle,
    SnapshotRequired,
}

async fn pull_ha_events(
    client: &Client,
    endpoint: &str,
    request_timeout: Duration,
    server: Arc<ProxyServer>,
) -> Result<HaEventPullOutcome> {
    if !server.has_ha_persistence() {
        return Ok(HaEventPullOutcome::SnapshotRequired);
    }
    let after = server.last_applied_ha_event_seq().await;
    let url = format!("{endpoint}?after={after}&limit=1000");
    let response = timeout(request_timeout, client.get(url).send())
        .await
        .context("timed out fetching HA events")??;
    if !response.status().is_success() {
        bail!(
            "HA event peer returned non-success status {}",
            response.status()
        );
    }
    let events = timeout(request_timeout, response.json::<HaEventsResponse>())
        .await
        .context("timed out decoding HA events")??;
    if events.snapshot_required {
        return Ok(HaEventPullOutcome::SnapshotRequired);
    }
    if events.events.is_empty() {
        return Ok(HaEventPullOutcome::Idle);
    }
    apply_ha_events(server, events.events).await?;
    Ok(HaEventPullOutcome::Applied)
}

async fn apply_ha_events(server: Arc<ProxyServer>, events: Vec<HaEventRecord>) -> Result<()> {
    let mut expected = server.last_applied_ha_event_seq().await + 1;
    for event in events {
        if event.seq != expected {
            bail!(
                "HA event sequence gap: expected {}, got {}",
                expected,
                event.seq
            );
        }
        server.apply_ha_event(event).await?;
        expected += 1;
    }
    Ok(())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) -> Result<()> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        if shutdown.changed().await.is_err() {
            return Ok(());
        }
    }
}

#[derive(Debug, Default)]
struct HaMonitorState {
    initialized: bool,
    previous_role: Option<ClusterRole>,
    previous_leader: Option<NodeId>,
}

async fn observe_ha_state(
    state: &mut HaMonitorState,
    node: &NodeConfig,
    addon: &HaAddonRef,
    role: ClusterRole,
    leader: Option<NodeId>,
) {
    let ctx = HaContext::from_node(node, role);
    let was_active = state.previous_role.is_some_and(is_active_role);
    let is_active = is_active_role(role);

    if !state.initialized {
        if is_active {
            run_ha_hook(
                addon.on_become_leader(ctx.clone()).await,
                "on_become_leader",
            );
        }
    } else if was_active && !is_active {
        run_ha_hook(addon.on_step_down(ctx.clone()).await, "on_step_down");
    } else if !was_active && is_active {
        run_ha_hook(
            addon.on_become_leader(ctx.clone()).await,
            "on_become_leader",
        );
    }

    if !state.initialized || state.previous_leader != leader {
        run_ha_hook(
            addon.on_leader_changed(ctx, leader).await,
            "on_leader_changed",
        );
        debug!(?leader, "HA leader observation changed");
    }

    state.initialized = true;
    state.previous_role = Some(role);
    state.previous_leader = leader;
}

fn is_active_role(role: ClusterRole) -> bool {
    matches!(role, ClusterRole::Leader | ClusterRole::Standalone)
}

fn run_ha_hook(result: Result<()>, hook: &'static str) {
    if let Err(err) = result {
        warn!(hook, error = %err, "HA addon hook failed");
    }
}

struct NoopHaAddon;

#[async_trait]
impl HaAddon for NoopHaAddon {
    async fn on_become_leader(&self, ctx: HaContext) -> Result<()> {
        info!(
            node_id = ctx.node_id,
            "noop HA addon observed leader promotion"
        );
        Ok(())
    }
}

struct CommandHaAddon {
    on_become_leader: Option<String>,
    on_step_down: Option<String>,
    timeout: Duration,
}

#[async_trait]
impl HaAddon for CommandHaAddon {
    async fn on_become_leader(&self, ctx: HaContext) -> Result<()> {
        if let Some(command) = &self.on_become_leader {
            run_hook(command, &ctx, self.timeout).await?;
        }
        Ok(())
    }

    async fn on_step_down(&self, ctx: HaContext) -> Result<()> {
        if let Some(command) = &self.on_step_down {
            run_hook(command, &ctx, self.timeout).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::{
        ClusterApplyResult, ClusterCommand, ContactBinding, SharedState, expires_at,
    };
    use crate::config::{Config, HaPersistenceConfig};
    use crate::persistence::HaPersistence;
    use crate::proxy::ProxyServer;
    use std::sync::Mutex;
    use tokio::sync::watch;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        BecomeLeader(ClusterRole),
        StepDown(ClusterRole),
        LeaderChanged(Option<NodeId>),
    }

    #[derive(Default)]
    struct RecordingAddon {
        events: Mutex<Vec<Event>>,
    }

    impl RecordingAddon {
        fn events(&self) -> Vec<Event> {
            self.events.lock().unwrap().clone()
        }
    }

    struct FixedRoleReplicator {
        role: ClusterRole,
    }

    #[async_trait]
    impl ClusterReplicator for FixedRoleReplicator {
        async fn submit(&self, _command: ClusterCommand) -> Result<ClusterApplyResult> {
            Ok(ClusterApplyResult {
                applied: true,
                index: None,
            })
        }

        async fn role(&self) -> ClusterRole {
            self.role
        }

        async fn leader(&self) -> Option<NodeId> {
            None
        }
    }

    #[async_trait]
    impl HaAddon for RecordingAddon {
        async fn on_become_leader(&self, ctx: HaContext) -> Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(Event::BecomeLeader(ctx.role));
            Ok(())
        }

        async fn on_step_down(&self, ctx: HaContext) -> Result<()> {
            self.events.lock().unwrap().push(Event::StepDown(ctx.role));
            Ok(())
        }

        async fn on_leader_changed(&self, _ctx: HaContext, leader: Option<NodeId>) -> Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(Event::LeaderChanged(leader));
            Ok(())
        }
    }

    #[tokio::test]
    async fn observes_leader_promotion_and_step_down() {
        let node = NodeConfig { id: 1 };
        let addon = Arc::new(RecordingAddon::default());
        let addon_ref: HaAddonRef = addon.clone();
        let mut state = HaMonitorState::default();

        observe_ha_state(
            &mut state,
            &node,
            &addon_ref,
            ClusterRole::Follower,
            Some(2),
        )
        .await;
        observe_ha_state(&mut state, &node, &addon_ref, ClusterRole::Leader, Some(1)).await;
        observe_ha_state(
            &mut state,
            &node,
            &addon_ref,
            ClusterRole::Follower,
            Some(2),
        )
        .await;

        assert_eq!(
            addon.events(),
            vec![
                Event::LeaderChanged(Some(2)),
                Event::BecomeLeader(ClusterRole::Leader),
                Event::LeaderChanged(Some(1)),
                Event::StepDown(ClusterRole::Follower),
                Event::LeaderChanged(Some(2)),
            ]
        );
    }

    #[tokio::test]
    async fn standby_pulls_and_installs_peer_snapshot() {
        let snapshot = HaStateSnapshot {
            last_seq: 0,
            checksum: String::new(),
            contacts: ContactStateSnapshot {
                contacts: vec![ContactBinding {
                    aor: "sip:100@example.com".to_string(),
                    contact: "sip:100@127.0.0.1:5061".to_string(),
                    source: "127.0.0.1:5061".to_string(),
                    expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
                }],
            },
            affinity: AffinityStateSnapshot { bindings: vec![] },
        }
        .with_checksum();
        let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();
        let peer_app = Router::new().route(
            "/ha/snapshot",
            get({
                let snapshot = snapshot.clone();
                move || async move { Json(snapshot.clone()) }
            }),
        );
        let peer_task = tokio::spawn(async move {
            axum::serve(peer_listener, peer_app).await.unwrap();
        });

        let state = Arc::new(SharedState::default());
        let replicator: Arc<dyn ClusterReplicator> = Arc::new(FixedRoleReplicator {
            role: ClusterRole::Follower,
        });
        let server = Arc::new(
            ProxyServer::new(Config::default(), state.clone(), replicator.clone(), None).unwrap(),
        );
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let pull_task = tokio::spawn(run_snapshot_pull(
            HaReplicationConfig {
                enabled: true,
                bind_addr: "127.0.0.1:0".to_string(),
                peer_addr: Some(peer_addr.to_string()),
                pull_interval_ms: 10,
                request_timeout_ms: 500,
            },
            server,
            replicator,
            shutdown_rx,
        ));

        for _ in 0..50 {
            if state.lookup("sip:100@example.com").await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(state.lookup("sip:100@example.com").await.is_some());
        let _ = shutdown_tx.send(true);
        pull_task.await.unwrap().unwrap();
        peer_task.abort();
    }

    #[tokio::test]
    async fn standby_pulls_and_applies_peer_events() {
        let source_dir = tempfile::tempdir().unwrap();
        let target_dir = tempfile::tempdir().unwrap();
        let source_persistence = HaPersistence::open(&HaPersistenceConfig {
            enabled: true,
            path: source_dir
                .path()
                .join("source.db")
                .to_string_lossy()
                .to_string(),
            required: false,
            event_retention_seconds: 3600,
            cleanup_interval_ms: 60_000,
        })
        .unwrap()
        .unwrap();
        source_persistence
            .apply_cluster_command(&ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:200@example.com".to_string(),
                contact: "sip:200@127.0.0.1:5062".to_string(),
                source: "127.0.0.1:50000".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await
            .unwrap();

        let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();
        let peer_app = Router::new().route(
            "/ha/events",
            get({
                let source_persistence = source_persistence.clone();
                move |Query(query): Query<HaEventsQuery>| {
                    let source_persistence = source_persistence.clone();
                    async move {
                        Json(
                            source_persistence
                                .events_after(query.after, query.limit)
                                .await
                                .unwrap(),
                        )
                    }
                }
            }),
        );
        let peer_task = tokio::spawn(async move {
            axum::serve(peer_listener, peer_app).await.unwrap();
        });

        let target_persistence = HaPersistence::open(&HaPersistenceConfig {
            enabled: true,
            path: target_dir
                .path()
                .join("target.db")
                .to_string_lossy()
                .to_string(),
            required: false,
            event_retention_seconds: 3600,
            cleanup_interval_ms: 60_000,
        })
        .unwrap()
        .unwrap();
        let state = Arc::new(SharedState::default());
        let replicator: Arc<dyn ClusterReplicator> = Arc::new(FixedRoleReplicator {
            role: ClusterRole::Follower,
        });
        let server = Arc::new(
            ProxyServer::new(
                Config::default(),
                state.clone(),
                replicator,
                Some(target_persistence.clone()),
            )
            .unwrap(),
        );

        let outcome = pull_ha_events(
            &Client::new(),
            &format!("http://{peer_addr}/ha/events"),
            Duration::from_millis(500),
            server,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, HaEventPullOutcome::Applied));
        assert!(state.lookup("sip:200@example.com").await.is_some());
        assert_eq!(target_persistence.last_applied_seq().await.unwrap(), 1);
        peer_task.abort();
    }

    #[tokio::test]
    async fn active_standby_replicator_rejects_writes_until_promoted() {
        let runtime = ActiveStandbyRuntime::new(2, HaInitialRole::Standby);
        let inner: Arc<dyn ClusterReplicator> = Arc::new(FixedRoleReplicator {
            role: ClusterRole::Standalone,
        });
        let replicator = ActiveStandbyReplicator::new(inner, runtime.clone());
        let command = ClusterCommand::RegisterContact(ContactBinding {
            aor: "sip:100@example.com".to_string(),
            contact: "sip:100@127.0.0.1:5062".to_string(),
            source: "127.0.0.1:50000".to_string(),
            expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
        });

        assert!(replicator.submit(command.clone()).await.is_err());

        runtime.promote().await;
        let result = replicator.submit(command).await.unwrap();
        assert!(result.applied);
    }

    #[tokio::test]
    async fn active_standby_promotes_after_peer_timeout() {
        let runtime = ActiveStandbyRuntime::new(2, HaInitialRole::Standby);
        let unused_peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_addr = unused_peer.local_addr().unwrap();
        drop(unused_peer);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_active_standby(
            HaActiveStandbyConfig {
                enabled: true,
                initial_role: HaInitialRole::Standby,
                heartbeat_bind: "127.0.0.1:0".to_string(),
                peer_heartbeat_addr: Some(peer_addr.to_string()),
                heartbeat_interval_ms: 10,
                failover_timeout_ms: 40,
            },
            runtime.clone(),
            shutdown_rx,
        ));

        for _ in 0..50 {
            if runtime.role().await.accepts_writes() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(runtime.role().await, ClusterRole::Leader);
        let _ = shutdown_tx.send(true);
        task.await.unwrap().unwrap();
    }

    #[test]
    fn peer_should_win_prefers_higher_epoch_then_lower_node_id() {
        let local = HaHeartbeat {
            node_id: 2,
            role: ClusterRole::Leader,
            epoch: 2,
        };
        let higher_epoch = HaHeartbeat {
            node_id: 3,
            role: ClusterRole::Leader,
            epoch: 3,
        };
        let lower_node_same_epoch = HaHeartbeat {
            node_id: 1,
            role: ClusterRole::Leader,
            epoch: 2,
        };
        let higher_node_same_epoch = HaHeartbeat {
            node_id: 3,
            role: ClusterRole::Leader,
            epoch: 2,
        };

        assert!(peer_should_win(&local, &higher_epoch));
        assert!(peer_should_win(&local, &lower_node_same_epoch));
        assert!(!peer_should_win(&local, &higher_node_same_epoch));
    }
}

async fn run_hook(command: &str, ctx: &HaContext, limit: Duration) -> Result<()> {
    info!(command, node_id = ctx.node_id, "running HA command hook");
    let mut child = Command::new("sh");
    child
        .arg("-c")
        .arg(command)
        .env("SIGPROXY_NODE_ID", ctx.node_id.to_string())
        .env("SIGPROXY_ROLE", format!("{:?}", ctx.role));

    let output = timeout(limit, child.output())
        .await
        .context("HA command hook timed out")?
        .context("failed to execute HA command hook")?;

    if !output.status.success() {
        warn!(
            command,
            status = ?output.status,
            stderr = %String::from_utf8_lossy(&output.stderr),
            "HA command hook failed"
        );
        anyhow::bail!("HA command hook failed: {}", output.status);
    }
    Ok(())
}
