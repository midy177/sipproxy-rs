use super::{
    ClusterApplyResult, ClusterCommand, ClusterReplicator, ClusterRole, ContactBinding, SharedState,
};
use crate::config::ClusterConfig;
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use openraft::entry::RaftPayload;
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::storage::{RaftLogStorage, RaftStateMachine};
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, LogState, RaftLogReader, RaftSnapshotBuilder, Snapshot,
    SnapshotMeta, StorageError, StoredMembership, Vote, declare_raft_types,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::io::Cursor;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

declare_raft_types!(
    pub TypeConfig:
        D = ClusterCommand,
        R = ClusterApplyResult,
        NodeId = u64,
        Node = BasicNode,
        Entry = Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
        Responder = openraft::impls::OneshotResponder<TypeConfig>,
);

pub type SigRaft = openraft::Raft<TypeConfig>;

pub struct RaftReplicator {
    raft: SigRaft,
    shared: Arc<SharedState>,
    client: reqwest::Client,
    rpc_server: Mutex<Option<RpcServerHandle>>,
}

impl RaftReplicator {
    pub async fn new(
        node_id: u64,
        config: &ClusterConfig,
        shared: Arc<SharedState>,
    ) -> Result<Self> {
        let rpc_listener = bind_rpc_listener(&config.bind_addr).await?;
        let store = MemoryRaftStore::new(shared.clone());
        let raft_config = Arc::new(
            openraft::Config {
                cluster_name: "sigproxy".to_string(),
                ..openraft::Config::default()
            }
            .validate()
            .context("invalid openraft config")?,
        );
        let raft = openraft::Raft::new(
            node_id,
            raft_config,
            HttpNetworkFactory::new(),
            store.clone(),
            store,
        )
        .await
        .context("failed to create openraft node")?;

        if !raft.is_initialized().await? {
            raft.initialize(initial_members(node_id, config)).await?;
        }
        if config.peers.len() <= 1 {
            let _ = raft.trigger().elect().await;
            wait_for_leader(&raft, node_id).await;
        }

        let rpc_server = start_rpc_server(rpc_listener, raft.clone());

        Ok(Self {
            raft,
            shared,
            client: reqwest::Client::new(),
            rpc_server: Mutex::new(Some(rpc_server)),
        })
    }

    async fn forward_client_write(
        &self,
        leader: openraft::error::ForwardToLeader<u64, BasicNode>,
        command: ClusterCommand,
    ) -> Result<ClusterApplyResult> {
        let leader_id = leader
            .leader_id
            .context("raft follower does not know the current leader id")?;
        let leader_node = leader
            .leader_node
            .context("raft follower does not know the current leader address")?;
        let endpoint = format!("http://{}/raft/client-write", leader_node.addr);
        let response = self
            .client
            .post(&endpoint)
            .json(&command)
            .send()
            .await
            .with_context(|| {
                format!("failed to forward client write to raft leader {leader_id}")
            })?;

        if !response.status().is_success() {
            anyhow::bail!(
                "raft leader {leader_id} rejected forwarded client write with HTTP {}",
                response.status()
            );
        }

        let result = response
            .json::<std::result::Result<ClusterApplyResult, String>>()
            .await
            .with_context(|| {
                format!("failed to decode forwarded client write response from leader {leader_id}")
            })?;
        result.map_err(|err| anyhow!("raft leader {leader_id} rejected forwarded write: {err}"))
    }
}

#[async_trait]
impl ClusterReplicator for RaftReplicator {
    async fn submit(&self, command: ClusterCommand) -> Result<ClusterApplyResult> {
        let result = match write_to_local_raft(&self.raft, command.clone()).await {
            Ok(result) => result,
            Err(err) => {
                let err_text = err.to_string();
                let Some(forward) = err.into_forward_to_leader::<BasicNode>() else {
                    return Err(anyhow!("raft client write failed: {err_text}"));
                };
                self.forward_client_write(forward, command.clone()).await?
            }
        };
        // REGISTER/location commands are idempotent; applying locally after the
        // committed write gives the proxy immediate read-after-write behavior.
        self.shared.apply(command).await;
        Ok(result)
    }

    async fn role(&self) -> ClusterRole {
        match self.raft.metrics().borrow().state {
            openraft::ServerState::Leader => ClusterRole::Leader,
            openraft::ServerState::Candidate => ClusterRole::Candidate,
            openraft::ServerState::Follower | openraft::ServerState::Learner => {
                ClusterRole::Follower
            }
            openraft::ServerState::Shutdown => ClusterRole::Follower,
        }
    }

    async fn leader(&self) -> Option<u64> {
        self.raft.metrics().borrow().current_leader
    }

    async fn shutdown(&self) -> Result<()> {
        if let Some(server) = self.rpc_server.lock().await.take() {
            server.shutdown().await?;
        }
        self.raft
            .shutdown()
            .await
            .map_err(|err| anyhow!("failed to shutdown openraft node: {err:?}"))
    }
}

type ClientWriteRaftError =
    openraft::error::RaftError<u64, openraft::error::ClientWriteError<u64, BasicNode>>;

async fn write_to_local_raft(
    raft: &SigRaft,
    command: ClusterCommand,
) -> std::result::Result<ClusterApplyResult, ClientWriteRaftError> {
    raft.client_write(command)
        .await
        .map(|response| response.data)
}

fn initial_members(node_id: u64, config: &ClusterConfig) -> BTreeMap<u64, BasicNode> {
    if config.peers.is_empty() {
        return BTreeMap::from([(
            node_id,
            BasicNode {
                addr: config.bind_addr.clone(),
            },
        )]);
    }

    config
        .peers
        .iter()
        .map(|peer| {
            (
                peer.id,
                BasicNode {
                    addr: peer.raft_addr.clone(),
                },
            )
        })
        .collect()
}

async fn wait_for_leader(raft: &SigRaft, node_id: u64) {
    for _ in 0..20 {
        if raft.metrics().borrow().current_leader == Some(node_id) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[derive(Clone, Default)]
pub struct MemoryRaftStore {
    inner: Arc<Mutex<MemoryRaftStoreInner>>,
    shared: Arc<SharedState>,
}

#[derive(Default)]
struct MemoryRaftStoreInner {
    vote: Option<Vote<u64>>,
    committed: Option<LogId<u64>>,
    last_purged_log_id: Option<LogId<u64>>,
    logs: BTreeMap<u64, Entry<TypeConfig>>,
    last_applied_log_id: Option<LogId<u64>>,
    last_membership: StoredMembership<u64, BasicNode>,
    current_snapshot: Option<Snapshot<TypeConfig>>,
}

impl MemoryRaftStore {
    pub fn new(shared: Arc<SharedState>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemoryRaftStoreInner::default())),
            shared,
        }
    }
}

impl RaftLogReader<TypeConfig> for MemoryRaftStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>> {
        let inner = self.inner.lock().await;
        let start = match range.start_bound() {
            Bound::Included(index) => *index,
            Bound::Excluded(index) => index.saturating_add(1),
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(index) => index.saturating_add(1),
            Bound::Excluded(index) => *index,
            Bound::Unbounded => u64::MAX,
        };

        Ok(inner
            .logs
            .range(start..end)
            .map(|(_, entry)| entry.clone())
            .collect())
    }
}

impl RaftLogStorage<TypeConfig> for MemoryRaftStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<u64>> {
        let inner = self.inner.lock().await;
        Ok(LogState {
            last_purged_log_id: inner.last_purged_log_id,
            last_log_id: inner
                .logs
                .last_key_value()
                .map(|(_, entry)| entry.log_id)
                .or(inner.last_purged_log_id),
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        self.inner.lock().await.vote = Some(vote.clone());
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        Ok(self.inner.lock().await.vote.clone())
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<u64>>,
    ) -> Result<(), StorageError<u64>> {
        self.inner.lock().await.committed = committed;
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        Ok(self.inner.lock().await.committed)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: openraft::storage::LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut inner = self.inner.lock().await;
        for entry in entries {
            inner.logs.insert(entry.log_id.index, entry);
        }
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        self.inner.lock().await.logs.split_off(&log_id.index);
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let mut inner = self.inner.lock().await;
        inner.logs.retain(|index, _| *index > log_id.index);
        inner.last_purged_log_id = Some(log_id);
        Ok(())
    }
}

impl RaftStateMachine<TypeConfig> for MemoryRaftStore {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let inner = self.inner.lock().await;
        Ok((inner.last_applied_log_id, inner.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<ClusterApplyResult>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut results = Vec::new();
        for entry in entries {
            if let Some(membership) = entry.get_membership() {
                self.inner.lock().await.last_membership =
                    StoredMembership::new(Some(entry.log_id), membership.clone());
            }

            let result = match entry.payload {
                EntryPayload::Blank | EntryPayload::Membership(_) => ClusterApplyResult {
                    applied: true,
                    index: Some(entry.log_id.index),
                },
                EntryPayload::Normal(command) => {
                    let mut result = self.shared.apply(command).await;
                    result.index = Some(entry.log_id.index);
                    result
                }
            };

            self.inner.lock().await.last_applied_log_id = Some(entry.log_id);
            results.push(result);
        }
        Ok(results)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        let state: SnapshotState =
            serde_json::from_slice(snapshot.get_ref()).map_err(storage_read_snapshot)?;
        {
            let mut inner = self.inner.lock().await;
            inner.last_applied_log_id = meta.last_log_id;
            inner.last_membership = meta.last_membership.clone();
            inner.current_snapshot = Some(Snapshot {
                meta: meta.clone(),
                snapshot,
            });
        }
        self.install_snapshot_state(state).await;
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<u64>> {
        Ok(self.inner.lock().await.current_snapshot.clone())
    }
}

impl RaftSnapshotBuilder<TypeConfig> for MemoryRaftStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<u64>> {
        let inner = self.inner.lock().await;
        let state = SnapshotState {
            contacts: Vec::new(),
        };
        let bytes = serde_json::to_vec(&state).map_err(storage_write_snapshot)?;
        let meta = SnapshotMeta {
            last_log_id: inner.last_applied_log_id,
            last_membership: inner.last_membership.clone(),
            snapshot_id: format!(
                "snapshot-{}",
                inner
                    .last_applied_log_id
                    .map(|log_id| log_id.index)
                    .unwrap_or_default()
            ),
        };
        let snapshot = Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(bytes)),
        };
        Ok(snapshot)
    }
}

impl MemoryRaftStore {
    async fn install_snapshot_state(&self, _state: SnapshotState) {
        // Snapshot state installation will be expanded once SharedState exposes a bulk replace API.
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotState {
    contacts: Vec<ContactBinding>,
}

#[derive(Clone, Default)]
pub struct HttpNetworkFactory {
    client: reqwest::Client,
}

impl HttpNetworkFactory {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl RaftNetworkFactory<TypeConfig> for HttpNetworkFactory {
    type Network = HttpNetwork;

    async fn new_client(&mut self, target: u64, _node: &BasicNode) -> Self::Network {
        HttpNetwork {
            client: self.client.clone(),
            target,
            target_node: _node.clone(),
        }
    }
}

pub struct HttpNetwork {
    client: reqwest::Client,
    target: u64,
    target_node: BasicNode,
}

impl HttpNetwork {
    fn endpoint(&self, path: &str) -> String {
        format!("http://{}{}", self.target_node.addr, path)
    }

    async fn post_rpc<Req, Resp, E>(
        &self,
        path: &str,
        request: &Req,
    ) -> Result<Resp, openraft::error::RPCError<u64, BasicNode, openraft::error::RaftError<u64, E>>>
    where
        Req: Serialize + Sync,
        Resp: DeserializeOwned,
        E: std::error::Error + DeserializeOwned,
    {
        let endpoint = self.endpoint(path);
        let response = self
            .client
            .post(&endpoint)
            .json(request)
            .send()
            .await
            .map_err(|err| unreachable_error(self.target, err))?;

        if !response.status().is_success() {
            return Err(
                unreachable_error(self.target, format!("HTTP {}", response.status())).into(),
            );
        }

        let result = response
            .json::<Result<Resp, openraft::error::RaftError<u64, E>>>()
            .await
            .map_err(|err| unreachable_error(self.target, err))?;

        result.map_err(|err| {
            openraft::error::RemoteError::new_with_node(self.target, self.target_node.clone(), err)
                .into()
        })
    }
}

impl RaftNetwork<TypeConfig> for HttpNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<u64>,
        openraft::error::RPCError<u64, BasicNode, openraft::error::RaftError<u64>>,
    > {
        self.post_rpc("/raft/append", &rpc).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        openraft::error::RPCError<
            u64,
            BasicNode,
            openraft::error::RaftError<u64, openraft::error::InstallSnapshotError>,
        >,
    > {
        self.post_rpc("/raft/snapshot", &rpc).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<
        VoteResponse<u64>,
        openraft::error::RPCError<u64, BasicNode, openraft::error::RaftError<u64>>,
    > {
        self.post_rpc("/raft/vote", &rpc).await
    }
}

struct RpcServerHandle {
    shutdown_tx: oneshot::Sender<()>,
    task: JoinHandle<Result<(), std::io::Error>>,
}

impl RpcServerHandle {
    async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown_tx.send(());
        self.task
            .await
            .context("raft RPC server task join failed")?
            .context("raft RPC server failed")
    }
}

async fn bind_rpc_listener(bind_addr: &str) -> Result<TcpListener> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind raft RPC listener {bind_addr}"))?;
    Ok(listener)
}

fn start_rpc_server(listener: TcpListener, raft: SigRaft) -> RpcServerHandle {
    let app = Router::new()
        .route("/raft/append", post(rpc_append_entries))
        .route("/raft/vote", post(rpc_vote))
        .route("/raft/snapshot", post(rpc_install_snapshot))
        .route("/raft/client-write", post(rpc_client_write))
        .with_state(raft);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    RpcServerHandle { shutdown_tx, task }
}

async fn rpc_append_entries(
    State(raft): State<SigRaft>,
    Json(request): Json<AppendEntriesRequest<TypeConfig>>,
) -> Json<Result<AppendEntriesResponse<u64>, openraft::error::RaftError<u64>>> {
    Json(raft.append_entries(request).await)
}

async fn rpc_vote(
    State(raft): State<SigRaft>,
    Json(request): Json<VoteRequest<u64>>,
) -> Json<Result<VoteResponse<u64>, openraft::error::RaftError<u64>>> {
    Json(raft.vote(request).await)
}

async fn rpc_install_snapshot(
    State(raft): State<SigRaft>,
    Json(request): Json<InstallSnapshotRequest<TypeConfig>>,
) -> Json<
    Result<
        InstallSnapshotResponse<u64>,
        openraft::error::RaftError<u64, openraft::error::InstallSnapshotError>,
    >,
> {
    Json(raft.install_snapshot(request).await)
}

async fn rpc_client_write(
    State(raft): State<SigRaft>,
    Json(command): Json<ClusterCommand>,
) -> Json<std::result::Result<ClusterApplyResult, String>> {
    Json(
        write_to_local_raft(&raft, command)
            .await
            .map_err(|err| err.to_string()),
    )
}

fn unreachable_error(target: u64, err: impl Display) -> openraft::error::Unreachable {
    let err = std::io::Error::other(format!("raft RPC target {target} is unreachable: {err}"));
    openraft::error::Unreachable::new(&err)
}

fn storage_read_snapshot(err: serde_json::Error) -> StorageError<u64> {
    openraft::StorageIOError::read_snapshot(None, &err).into()
}

fn storage_write_snapshot(err: serde_json::Error) -> StorageError<u64> {
    openraft::StorageIOError::write_snapshot(None, &err).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::expires_at;
    use crate::config::{ClusterMode, ClusterPeer};
    use std::net::TcpListener as StdTcpListener;
    use std::time::Duration;

    #[tokio::test]
    async fn memory_store_applies_normal_entry_to_shared_state() {
        let shared = Arc::new(SharedState::default());
        let mut store = MemoryRaftStore::new(shared.clone());
        let entry = Entry::<TypeConfig> {
            log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
            payload: EntryPayload::Normal(ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:100@example.com".to_string(),
                contact: "sip:100@127.0.0.1:5061".to_string(),
                source: "127.0.0.1:50000".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            })),
        };

        let results = store.apply([entry]).await.unwrap();

        assert_eq!(results[0].index, Some(1));
        assert_eq!(
            shared.lookup("sip:100@example.com").await.unwrap().contact,
            "sip:100@127.0.0.1:5061"
        );
    }

    #[tokio::test]
    async fn single_node_raft_replicator_applies_client_write() {
        let shared = Arc::new(SharedState::default());
        let config = ClusterConfig {
            mode: crate::config::ClusterMode::Raft,
            bind_addr: "127.0.0.1:7000".to_string(),
            peers: Vec::new(),
            data_dir: "./data/test".to_string(),
        };
        let replicator = RaftReplicator::new(1, &config, shared.clone())
            .await
            .unwrap();

        let result = replicator
            .submit(ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:101@example.com".to_string(),
                contact: "sip:101@127.0.0.1:5061".to_string(),
                source: "127.0.0.1:50000".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await
            .unwrap();

        assert!(result.applied);
        assert_eq!(replicator.role().await, ClusterRole::Leader);
        for _ in 0..20 {
            if shared.lookup("sip:101@example.com").await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            shared.lookup("sip:101@example.com").await.unwrap().contact,
            "sip:101@127.0.0.1:5061"
        );
        replicator.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn two_node_raft_replicates_register_over_http_rpc() {
        let addr1 = free_addr();
        let addr2 = free_addr();
        let peers = vec![
            ClusterPeer {
                id: 1,
                raft_addr: addr1.clone(),
                sip_addr: "127.0.0.1:5060".to_string(),
            },
            ClusterPeer {
                id: 2,
                raft_addr: addr2.clone(),
                sip_addr: "127.0.0.1:5061".to_string(),
            },
        ];
        let config1 = ClusterConfig {
            mode: ClusterMode::Raft,
            bind_addr: addr1,
            peers: peers.clone(),
            data_dir: "./data/test-1".to_string(),
        };
        let config2 = ClusterConfig {
            mode: ClusterMode::Raft,
            bind_addr: addr2,
            peers,
            data_dir: "./data/test-2".to_string(),
        };
        let shared1 = Arc::new(SharedState::default());
        let shared2 = Arc::new(SharedState::default());

        let node1 = RaftReplicator::new(1, &config1, shared1.clone())
            .await
            .unwrap();
        let node2 = RaftReplicator::new(2, &config2, shared2.clone())
            .await
            .unwrap();

        let leader_id = wait_for_any_leader(&[&node1, &node2]).await.unwrap();
        let leader = if leader_id == 1 { &node1 } else { &node2 };
        let follower = if leader_id == 1 { &node2 } else { &node1 };

        leader
            .submit(ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:202@example.com".to_string(),
                contact: "sip:202@127.0.0.1:5062".to_string(),
                source: "127.0.0.1:50000".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await
            .unwrap();

        for _ in 0..80 {
            if shared1.lookup("sip:202@example.com").await.is_some()
                && shared2.lookup("sip:202@example.com").await.is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert_eq!(
            shared1.lookup("sip:202@example.com").await.unwrap().contact,
            "sip:202@127.0.0.1:5062"
        );
        assert_eq!(
            shared2.lookup("sip:202@example.com").await.unwrap().contact,
            "sip:202@127.0.0.1:5062"
        );

        follower
            .submit(ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:203@example.com".to_string(),
                contact: "sip:203@127.0.0.1:5063".to_string(),
                source: "127.0.0.1:50001".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await
            .unwrap();

        for _ in 0..80 {
            if shared1.lookup("sip:203@example.com").await.is_some()
                && shared2.lookup("sip:203@example.com").await.is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert_eq!(
            shared1.lookup("sip:203@example.com").await.unwrap().contact,
            "sip:203@127.0.0.1:5063"
        );
        assert_eq!(
            shared2.lookup("sip:203@example.com").await.unwrap().contact,
            "sip:203@127.0.0.1:5063"
        );

        node1.shutdown().await.unwrap();
        node2.shutdown().await.unwrap();
    }

    fn free_addr() -> String {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    }

    async fn wait_for_any_leader(nodes: &[&RaftReplicator]) -> Option<u64> {
        for _ in 0..80 {
            for node in nodes {
                if let Some(leader) = node.leader().await {
                    return Some(leader);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }
}
