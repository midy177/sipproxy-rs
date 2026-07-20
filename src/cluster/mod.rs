use crate::persistence::HaPersistence;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::warn;

pub type NodeId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterRole {
    Leader,
    Follower,
    Candidate,
    Standalone,
}

impl ClusterRole {
    pub fn accepts_writes(self) -> bool {
        matches!(self, Self::Leader | Self::Standalone)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactBinding {
    pub aor: String,
    pub contact: String,
    pub source: String,
    #[serde(with = "crate::serde_u128")]
    pub expires_at_epoch_ms: u128,
}

impl ContactBinding {
    pub fn is_expired(&self) -> bool {
        now_epoch_ms() >= self.expires_at_epoch_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactStateSnapshot {
    pub contacts: Vec<ContactBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterCommand {
    RegisterContact(ContactBinding),
    UnregisterContact { aor: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterApplyResult {
    pub applied: bool,
    pub index: Option<u64>,
}

#[async_trait]
pub trait ClusterReplicator: Send + Sync {
    async fn submit(&self, command: ClusterCommand) -> Result<ClusterApplyResult>;
    async fn role(&self) -> ClusterRole;
    async fn leader(&self) -> Option<NodeId>;
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct SharedState {
    contacts: RwLock<HashMap<String, ContactBinding>>,
}

impl SharedState {
    pub async fn apply(&self, command: ClusterCommand) -> ClusterApplyResult {
        match command {
            ClusterCommand::RegisterContact(binding) => {
                self.contacts
                    .write()
                    .await
                    .insert(binding.aor.clone(), binding);
            }
            ClusterCommand::UnregisterContact { aor } => {
                self.contacts.write().await.remove(&aor);
            }
        }
        ClusterApplyResult {
            applied: true,
            index: None,
        }
    }

    pub async fn lookup(&self, aor: &str) -> Option<ContactBinding> {
        let binding = self.contacts.read().await.get(aor).cloned()?;
        if binding.is_expired() {
            self.contacts.write().await.remove(aor);
            None
        } else {
            Some(binding)
        }
    }

    pub async fn contact_count(&self) -> usize {
        let mut contacts = self.contacts.write().await;
        contacts.retain(|_, binding| !binding.is_expired());
        contacts.len()
    }

    pub async fn snapshot(&self) -> ContactStateSnapshot {
        let mut contacts = self.contacts.write().await;
        contacts.retain(|_, binding| !binding.is_expired());
        ContactStateSnapshot {
            contacts: contacts.values().cloned().collect(),
        }
    }

    pub async fn install_snapshot(&self, snapshot: ContactStateSnapshot) {
        let contacts = snapshot
            .contacts
            .into_iter()
            .filter(|binding| !binding.is_expired())
            .map(|binding| (binding.aor.clone(), binding))
            .collect();
        *self.contacts.write().await = contacts;
    }
}

pub struct StandaloneReplicator {
    state: Arc<SharedState>,
    persistence: Option<HaPersistence>,
}

impl StandaloneReplicator {
    pub fn new(state: Arc<SharedState>, persistence: Option<HaPersistence>) -> Self {
        Self { state, persistence }
    }
}

#[async_trait]
impl ClusterReplicator for StandaloneReplicator {
    async fn submit(&self, command: ClusterCommand) -> Result<ClusterApplyResult> {
        if let Some(persistence) = &self.persistence
            && persistence.required()
        {
            persistence.apply_cluster_command(&command).await?;
            return Ok(self.state.apply(command).await);
        }
        let result = self.state.apply(command.clone()).await;
        if let Some(persistence) = &self.persistence
            && let Err(err) = persistence.apply_cluster_command(&command).await
        {
            warn!(
                error = %format!("{err:#}"),
                "failed to persist cluster command; continuing with in-memory state"
            );
        }
        Ok(result)
    }

    async fn role(&self) -> ClusterRole {
        ClusterRole::Standalone
    }

    async fn leader(&self) -> Option<NodeId> {
        None
    }
}

pub async fn build_replicator(
    state: Arc<SharedState>,
    persistence: Option<HaPersistence>,
) -> Result<Arc<dyn ClusterReplicator>> {
    Ok(Arc::new(StandaloneReplicator::new(state, persistence)))
}

pub fn expires_at(ttl: Duration) -> u128 {
    now_epoch_ms() + ttl.as_millis()
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn standalone_replicator_applies_register_and_unregister() {
        let state = Arc::new(SharedState::default());
        let replicator = StandaloneReplicator::new(state.clone(), None);

        replicator
            .submit(ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:100@example.com".to_string(),
                contact: "sip:100@127.0.0.1:5062".to_string(),
                source: "127.0.0.1:50000".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await
            .unwrap();

        assert_eq!(state.contact_count().await, 1);
        assert_eq!(
            state.lookup("sip:100@example.com").await.unwrap().contact,
            "sip:100@127.0.0.1:5062"
        );

        replicator
            .submit(ClusterCommand::UnregisterContact {
                aor: "sip:100@example.com".to_string(),
            })
            .await
            .unwrap();

        assert!(state.lookup("sip:100@example.com").await.is_none());
    }

    #[tokio::test]
    async fn contact_snapshot_restores_unexpired_bindings() {
        let source = SharedState::default();
        let target = SharedState::default();
        source
            .apply(ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:100@example.com".to_string(),
                contact: "sip:100@127.0.0.1:5062".to_string(),
                source: "127.0.0.1:50000".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await;
        source
            .apply(ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:200@example.com".to_string(),
                contact: "sip:200@127.0.0.1:5063".to_string(),
                source: "127.0.0.1:50001".to_string(),
                expires_at_epoch_ms: 0,
            }))
            .await;

        target.install_snapshot(source.snapshot().await).await;

        assert!(target.lookup("sip:100@example.com").await.is_some());
        assert!(target.lookup("sip:200@example.com").await.is_none());
    }
}
