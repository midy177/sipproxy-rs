use crate::cluster::{ClusterCommand, ClusterReplicator, ContactBinding, SharedState, expires_at};
use crate::config::{
    Config, EffectiveProxySecurityConfig, ProxyConfig, ProxyListenerConfig, ProxyMetricsConfig,
    ProxyRegisteredInviteSourceMatch, ProxySocketConfig, RegisterRoutingMode, SipTransport,
    UpstreamGroupConfig, UpstreamHealthCheckConfig, UpstreamHealthProbeConfig,
};
use crate::ha::HaStateSnapshot;
use crate::persistence::{HaEventPayload, HaEventRecord, HaEventsResponse, Persistence};
use crate::proxy::affinity::{AffinityKey, AffinityTable, AffinityTarget};
use crate::proxy::geo::{GeoDecision, GeoPolicy, GeoRuntime, evaluate_geo_policy};
use crate::proxy::metrics::{CounterHandle, ProxyMetrics};
use crate::proxy::registry::{
    extract_aor, extract_contact, extract_expires, extract_from_aor,
    extract_response_contact_expires, extract_to_aor,
};
use crate::proxy::routing::RouteTable;
use crate::proxy::threat::{ThreatDecision, ThreatPolicy, ThreatRuntime, evaluate_threat_policy};
use crate::proxy::xdp::XdpRuntime;
use crate::sip::{SipMessage, SipStartLine};
use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use axum::{Router, extract::State, routing::get};
use bytes::BytesMut;
use if_addrs::get_if_addrs;
use rsipstack::sip::prelude::HeadersExt;
use rsipstack::sip::{
    Transport as RsipTransport, Uri as RsipUri,
    typed::{Contact as RsipContact, Route as RsipRoute},
    uri::Param,
};
use rsipstack::transport::stream::{SipCodec, SipCodecType};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, HashMap, HashSet, hash_map::DefaultHasher};
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::time::timeout;
use tokio_util::codec::Decoder;
use tracing::{debug, error, info, warn};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const INVITE_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(300);
const UDP_BRANCH_TTL: Duration = Duration::from_secs(300);
const TCP_BRANCH_TTL: Duration = Duration::from_secs(300);
const PENDING_REGISTER_TTL: Duration = Duration::from_secs(300);
const INVITE_TRANSACTION_TTL: Duration = Duration::from_secs(300);
const LOCAL_INVITE_REJECTION_TTL: Duration = Duration::from_secs(300);
const SECURITY_PRUNE_INTERVAL: Duration = Duration::from_secs(60);
const SECURITY_BUCKET_IDLE_TTL: Duration = Duration::from_secs(600);
const HEALTH_CHECK_STANDBY_ROLE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const HEALTH_CHECK_FAILURE_LOG_INTERVAL: Duration = Duration::from_secs(60);
const SECURITY_MAP_SHARDS: usize = 64;
const ROUTE_MAP_SHARDS: usize = 64;
const METRIC_TRANSPORT_COUNT: usize = 2;
const METRIC_METHOD_COUNT: usize = 8;
const METRIC_TRANSPORTS: [&str; METRIC_TRANSPORT_COUNT] = ["udp", "tcp"];
const METRIC_METHODS: [&str; METRIC_METHOD_COUNT] = [
    "ACK", "BYE", "CANCEL", "INVITE", "MESSAGE", "OPTIONS", "REGISTER", "UNKNOWN",
];
const UPSTREAM_RESPONSE_LATENCY_MS_BUCKETS: [u64; 13] = [
    1, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000,
];
const PROXY_BRANCH_PREFIX: &str = "z9hG4bK-sigproxy-";
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub struct ProxyServer {
    config: Config,
    state: Arc<SharedState>,
    replicator: Arc<dyn ClusterReplicator>,
    persistence: Option<Persistence>,
    routes: ArcSwap<RouteTable>,
    upstreams: UpstreamGroups,
    affinity: AffinityTable,
    security: Arc<SecurityRuntime>,
    metrics: Arc<ProxyMetrics>,
    metric_handles: ProxyMetricHandles,
    udp_branches: ShardedStringMap<UdpBranchRoute>,
    udp_client_transactions: ShardedStringMap<UdpClientTransactionRoute>,
    pending_registers: Mutex<HashMap<String, PendingRegister>>,
    invite_transactions: ShardedStringMap<InviteTransactionRoute>,
    local_invite_rejections: Mutex<HashMap<String, Instant>>,
    tcp_upstreams: TcpUpstreamPool,
    advertised_addrs: Mutex<HashMap<String, String>>,
    local_ips: HashSet<IpAddr>,
}

struct UdpToTcpForward<'a> {
    socket: &'a UdpSocket,
    message: SipMessage,
    client_peer: SocketAddr,
    upstream: SocketAddr,
    branch: String,
    client_transaction_key: Option<String>,
    invite_transaction_key: Option<String>,
    method: &'a str,
}

struct UdpClientTransactionRef<'a> {
    branch: &'a str,
    key: Option<&'a str>,
    request_started_at: Instant,
}

struct ProxyMetricHandles {
    sip_requests: [[CounterHandle; METRIC_METHOD_COUNT]; METRIC_TRANSPORT_COUNT],
    forwarded_requests:
        [[[CounterHandle; METRIC_METHOD_COUNT]; METRIC_TRANSPORT_COUNT]; METRIC_TRANSPORT_COUNT],
}

impl ProxyMetricHandles {
    fn new(metrics: &ProxyMetrics) -> Self {
        Self {
            sip_requests: std::array::from_fn(|transport| {
                std::array::from_fn(|method| {
                    metrics.counter(
                        "sip_requests_total",
                        &[
                            ("transport", METRIC_TRANSPORTS[transport]),
                            ("method", METRIC_METHODS[method]),
                        ],
                    )
                })
            }),
            forwarded_requests: std::array::from_fn(|downstream| {
                std::array::from_fn(|upstream| {
                    std::array::from_fn(|method| {
                        metrics.counter(
                            "proxy_forwarded_requests_total",
                            &[
                                ("downstream_transport", METRIC_TRANSPORTS[downstream]),
                                ("upstream_transport", METRIC_TRANSPORTS[upstream]),
                                ("method", METRIC_METHODS[method]),
                            ],
                        )
                    })
                })
            }),
        }
    }
}

impl ProxyServer {
    pub fn new(
        config: Config,
        state: Arc<SharedState>,
        replicator: Arc<dyn ClusterReplicator>,
        persistence: Option<Persistence>,
    ) -> Result<Self> {
        let routes = RouteTable::new(&config.proxy).context("failed to build proxy route table")?;
        let upstreams = UpstreamGroups::new(&config.proxy.upstream_groups)
            .context("failed to build upstream groups")?;
        let max_message_bytes = config.sip.max_message_bytes;
        let affinity_config = config.proxy.affinity.clone();
        let security = Arc::new(SecurityRuntime::new(&config.proxy)?);
        let metrics = Arc::new(ProxyMetrics::default());
        let metric_handles = ProxyMetricHandles::new(&metrics);
        let local_ips = local_interface_ips();
        Ok(Self {
            config,
            state,
            replicator,
            persistence,
            routes: ArcSwap::from_pointee(routes),
            upstreams,
            affinity: AffinityTable::new(affinity_config),
            security,
            metrics,
            metric_handles,
            udp_branches: ShardedStringMap::new(ROUTE_MAP_SHARDS),
            udp_client_transactions: ShardedStringMap::new(ROUTE_MAP_SHARDS),
            pending_registers: Mutex::new(HashMap::new()),
            invite_transactions: ShardedStringMap::new(ROUTE_MAP_SHARDS),
            local_invite_rejections: Mutex::new(HashMap::new()),
            tcp_upstreams: TcpUpstreamPool::new(max_message_bytes),
            advertised_addrs: Mutex::new(HashMap::new()),
            local_ips,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn has_persistence(&self) -> bool {
        self.persistence.is_some()
    }

    pub async fn run(self: Arc<Self>, shutdown: watch::Receiver<bool>) -> Result<()> {
        let this = self;
        let mut tasks = Vec::new();
        this.restore_persistent_state().await?;

        if let Some(task) = this.security.spawn_geo_refresh(shutdown.clone()).await {
            tasks.push(task);
        }
        if let Some(task) = this.security.spawn_threat_refresh(shutdown.clone()).await {
            tasks.push(task);
        }
        tasks.push(tokio::spawn(
            this.security.clone().run_prune_loop(shutdown.clone()),
        ));

        for group in this.upstreams.groups.values() {
            if group.health_check.enabled {
                tasks.push(tokio::spawn(run_health_checks(
                    group.clone(),
                    this.replicator.clone(),
                    shutdown.clone(),
                )));
            }
        }

        if this.config.proxy.metrics.enabled {
            tasks.push(tokio::spawn(run_metrics_server(
                this.config.proxy.metrics.clone(),
                this.clone(),
                shutdown.clone(),
            )));
        }

        let workers_per_listener = this.config.proxy.socket.resolved_workers_per_listener();
        for configured_listener in &this.config.proxy.listeners {
            for listener in configured_listener.concrete_listeners() {
                this.log_listener_runtime_config(&listener).await;
                for worker in 0..workers_per_listener {
                    match listener.transport {
                        SipTransport::Udp => {
                            let socket = Arc::new(
                                bind_udp_socket(&listener, &this.config.proxy.socket).await?,
                            );
                            info!(
                                bind = %listener.bind,
                                upstream_group = %listener.upstream_group,
                                worker,
                                "SIP UDP listener started"
                            );
                            tasks.push(tokio::spawn(this.clone().run_udp(
                                socket,
                                listener.clone(),
                                shutdown.clone(),
                            )));
                        }
                        SipTransport::Tcp => {
                            let tcp_listener =
                                bind_tcp_listener(&listener, &this.config.proxy.socket).await?;
                            info!(
                                bind = %listener.bind,
                                upstream_group = %listener.upstream_group,
                                worker,
                                "SIP TCP listener started"
                            );
                            tasks.push(tokio::spawn(this.clone().run_tcp(
                                tcp_listener,
                                listener.clone(),
                                shutdown.clone(),
                            )));
                        }
                        SipTransport::TcpUdp => {
                            unreachable!("tcp_udp listeners are expanded before run")
                        }
                    }
                }
            }
        }

        for task in tasks {
            task.await??;
        }
        Ok(())
    }

    pub async fn snapshot_state(&self) -> HaStateSnapshot {
        let last_seq = match &self.persistence {
            Some(persistence) => match persistence.latest_event_seq().await {
                Ok(seq) => seq,
                Err(err) => {
                    warn!(
                        error = %format!("{err:#}"),
                        "failed to read persistence latest event sequence for snapshot"
                    );
                    0
                }
            },
            None => 0,
        };
        HaStateSnapshot {
            last_seq,
            checksum: String::new(),
            contacts: self.state.snapshot().await,
            affinity: self.affinity.snapshot().await,
        }
        .with_checksum()
    }

    pub async fn install_state_snapshot(&self, snapshot: HaStateSnapshot) -> bool {
        if !snapshot.checksum_is_valid() {
            warn!(
                last_seq = snapshot.last_seq,
                checksum = %snapshot.checksum,
                "refusing to install HA state snapshot with invalid checksum"
            );
            return false;
        }
        let persist_snapshot = snapshot.clone();
        self.state.install_snapshot(snapshot.contacts).await;
        self.affinity.install_snapshot(snapshot.affinity).await;
        if let Some(persistence) = &self.persistence
            && let Err(err) = persistence.install_snapshot(&persist_snapshot).await
        {
            warn!(
                error = %format!("{err:#}"),
                "failed to persist installed HA state snapshot"
            );
        }
        true
    }

    async fn restore_persistent_state(&self) -> Result<()> {
        let Some(persistence) = &self.persistence else {
            return Ok(());
        };
        let snapshot = persistence.load_snapshot().await?;
        let contact_count = snapshot.contacts.contacts.len();
        let affinity_count = snapshot.affinity.bindings.len();
        self.state.install_snapshot(snapshot.contacts).await;
        self.affinity.install_snapshot(snapshot.affinity).await;
        info!(
            contacts = contact_count,
            affinity_bindings = affinity_count,
            "restored proxy state from persistence"
        );
        Ok(())
    }

    pub async fn last_applied_ha_event_seq(&self) -> u64 {
        let Some(persistence) = &self.persistence else {
            return 0;
        };
        match persistence.last_applied_seq().await {
            Ok(seq) => seq,
            Err(err) => {
                warn!(
                    error = %format!("{err:#}"),
                    "failed to read persistence last applied sequence"
                );
                0
            }
        }
    }

    pub async fn ha_events_after(&self, after: u64, limit: usize) -> HaEventsResponse {
        let Some(persistence) = &self.persistence else {
            return HaEventsResponse {
                base_seq: 0,
                latest_seq: 0,
                snapshot_required: true,
                events: Vec::new(),
            };
        };
        match persistence.events_after(after, limit).await {
            Ok(response) => response,
            Err(err) => {
                warn!(
                    error = %format!("{err:#}"),
                    after,
                    limit,
                    "failed to read HA event log; requiring snapshot"
                );
                HaEventsResponse {
                    base_seq: after,
                    latest_seq: 0,
                    snapshot_required: true,
                    events: Vec::new(),
                }
            }
        }
    }

    pub async fn apply_ha_event(&self, event: HaEventRecord) -> Result<()> {
        match &event.payload {
            HaEventPayload::RegisterContact { binding } => {
                if !binding.is_expired() {
                    self.state
                        .apply(ClusterCommand::RegisterContact(binding.clone()))
                        .await;
                }
            }
            HaEventPayload::UnregisterContact { aor } => {
                self.state
                    .apply(ClusterCommand::UnregisterContact { aor: aor.clone() })
                    .await;
            }
            HaEventPayload::UpsertAffinity { binding } => {
                self.affinity
                    .upsert_snapshot_bindings(vec![binding.clone()])
                    .await;
            }
            HaEventPayload::RemoveAffinity { key } => {
                self.affinity.remove_key(key).await;
            }
        }
        if let Some(persistence) = &self.persistence {
            persistence.apply_event(&event).await?;
        }
        Ok(())
    }

    async fn render_metrics(&self) -> String {
        let mut output = self.metrics.render_prometheus();
        let udp_branch_routes = self.active_udp_branch_count().await;
        let udp_client_transactions = self.active_udp_client_transaction_count().await;
        let invite_transaction_routes = self.active_invite_transaction_count().await;
        let (tcp_upstream_connections, tcp_branch_routes) =
            self.tcp_upstreams.active_counts().await;
        let affinity_bindings = self.affinity.binding_len();
        let location_bindings = self.state.contact_count().await;
        let upstream_health = self.upstreams.health_snapshots();
        let security_stats = self.security.stats().await;
        let xdp_stats = self.security.xdp_stats();
        let persistence_stats = match &self.persistence {
            Some(persistence) => match persistence.stats().await {
                Ok(stats) => Some(stats),
                Err(err) => {
                    debug!(
                        error = %format!("{err:#}"),
                        "failed to collect persistence metrics"
                    );
                    None
                }
            },
            None => None,
        };

        append_gauge(
            &mut output,
            "proxy_udp_branch_routes",
            udp_branch_routes as u64,
        );
        append_gauge(
            &mut output,
            "proxy_udp_client_transactions",
            udp_client_transactions as u64,
        );
        append_gauge(
            &mut output,
            "proxy_invite_transaction_routes",
            invite_transaction_routes as u64,
        );
        append_gauge(
            &mut output,
            "proxy_tcp_upstream_connections",
            tcp_upstream_connections as u64,
        );
        append_gauge(
            &mut output,
            "proxy_tcp_branch_routes",
            tcp_branch_routes as u64,
        );
        append_gauge(
            &mut output,
            "proxy_affinity_bindings",
            affinity_bindings as u64,
        );
        append_gauge(
            &mut output,
            "proxy_location_bindings",
            location_bindings as u64,
        );
        append_gauge(
            &mut output,
            "proxy_security_active_blocks",
            security_stats.active_blocks_total,
        );
        append_gauge(
            &mut output,
            "proxy_security_token_buckets",
            security_stats.token_buckets_total,
        );
        for count in &security_stats.active_blocks {
            append_labeled_gauge(
                &mut output,
                "proxy_security_active_blocks_by_listener",
                &[
                    ("listener", count.listener.as_str()),
                    ("kind", count.kind.as_str()),
                ],
                count.count,
            );
        }
        for count in &security_stats.token_buckets {
            append_labeled_gauge(
                &mut output,
                "proxy_security_token_buckets_by_listener",
                &[
                    ("listener", count.listener.as_str()),
                    ("kind", count.kind.as_str()),
                ],
                count.count,
            );
        }
        if let Some(stats) = persistence_stats {
            let role = format!("{:?}", self.replicator.role().await).to_ascii_lowercase();
            let event_lag = stats
                .latest_event_seq
                .saturating_sub(stats.last_applied_seq);
            append_gauge(
                &mut output,
                "proxy_persistence_latest_event_seq",
                stats.latest_event_seq,
            );
            append_gauge(
                &mut output,
                "proxy_persistence_last_applied_seq",
                stats.last_applied_seq,
            );
            append_gauge(
                &mut output,
                "proxy_persistence_event_rows",
                stats.event_rows,
            );
            append_gauge(
                &mut output,
                "proxy_persistence_background_pending_events",
                stats.background_pending_events,
            );
            append_labeled_gauge(
                &mut output,
                "proxy_persistence_event_lag",
                &[("role", role.as_str())],
                event_lag,
            );
            append_labeled_counter(
                &mut output,
                "proxy_persistence_event_appends_total",
                &[("result", "success")],
                stats.event_appends_succeeded,
            );
            append_labeled_counter(
                &mut output,
                "proxy_persistence_event_appends_total",
                &[("result", "failure")],
                stats.event_appends_failed,
            );
            append_labeled_counter(
                &mut output,
                "proxy_persistence_sqlite_write_failures_total",
                &[],
                stats.sqlite_writes_failed,
            );
        }
        for health in upstream_health {
            let labels = [
                ("group", health.group.as_str()),
                ("server", health.server.as_str()),
            ];
            append_labeled_gauge(
                &mut output,
                "proxy_upstream_healthy",
                &labels,
                u64::from(health.healthy),
            );
            append_labeled_gauge(
                &mut output,
                "proxy_upstream_consecutive_successes",
                &labels,
                health.consecutive_successes as u64,
            );
            append_labeled_gauge(
                &mut output,
                "proxy_upstream_consecutive_failures",
                &labels,
                health.consecutive_failures as u64,
            );
        }
        for (action, value) in xdp_stats {
            append_labeled_counter(
                &mut output,
                "proxy_xdp_packets_total",
                &[("action", action)],
                value,
            );
        }
        output
    }

    async fn active_udp_branch_count(&self) -> usize {
        let now = Instant::now();
        self.udp_branches
            .len_after_retain(|_, route| now.duration_since(route.created_at) <= UDP_BRANCH_TTL)
            .await
    }

    async fn active_udp_client_transaction_count(&self) -> usize {
        let now = Instant::now();
        self.udp_client_transactions
            .len_after_retain(|_, route| now.duration_since(route.created_at) <= UDP_BRANCH_TTL)
            .await
    }

    async fn active_invite_transaction_count(&self) -> usize {
        let now = Instant::now();
        self.invite_transactions
            .len_after_retain(|_, route| {
                now.duration_since(route.created_at) <= INVITE_TRANSACTION_TTL
            })
            .await
    }

    async fn log_listener_runtime_config(&self, listener: &ProxyListenerConfig) {
        let target = self.first_upstream_for_listener(listener);
        let public = self
            .advertised_sip_addr(AdvertiseSide::Public, listener, target)
            .await;
        let internal = self
            .advertised_sip_addr(AdvertiseSide::Internal, listener, target)
            .await;
        info!(
            bind = %listener.bind,
            transport = %listener.transport.as_str(),
            public_addr = %public,
            internal_addr = %internal,
            upstream_group = %listener.upstream_group,
            record_route = self.config.proxy.record_route,
            register_routing = self.config.proxy.effective_register_routing().as_str(),
            rewrite_register_contact = self.config.proxy.rewrite_register_contact,
            affinity_enabled = self.config.proxy.affinity.enabled,
            affinity_key = ?self.config.proxy.affinity.key,
            affinity_ttl_seconds = self.config.proxy.affinity.ttl_seconds,
            reuse_port = self.config.proxy.socket.reuse_port,
            workers_per_listener = self.config.proxy.socket.resolved_workers_per_listener(),
            "SIP listener runtime config resolved"
        );
    }

    fn first_upstream_for_listener(&self, listener: &ProxyListenerConfig) -> SocketAddr {
        self.upstreams
            .groups
            .get(&listener.upstream_group)
            .and_then(|group| group.servers.first().copied())
            .unwrap_or_else(|| {
                listener
                    .bind
                    .parse()
                    .unwrap_or_else(|_| "127.0.0.1:5060".parse().unwrap())
            })
    }

    async fn run_udp(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        listener: ProxyListenerConfig,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut buf = vec![0; self.config.sip.max_message_bytes];
        let listener = Arc::new(listener);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                received = socket.recv_from(&mut buf) => {
                    let (len, peer) = match received {
                        Ok(received) => received,
                        Err(err) => {
                            warn!(error = %err, "failed to receive UDP SIP packet");
                            continue;
                        }
                    };
                    let packet = buf[..len].to_vec();
                    let this = self.clone();
                    let socket = socket.clone();
                    let listener = listener.clone();
                    tokio::spawn(async move {
                        if let Err(err) = this.handle_udp_packet(&socket, &packet, peer, &listener).await {
                            warn!(
                                %peer,
                                bytes = packet.len(),
                                preview = %packet_preview(&packet),
                                error = %err,
                                "failed to handle UDP SIP packet"
                            );
                        }
                    });
                }
            }
        }
        Ok(())
    }

    async fn remove_udp_branch(&self, branch: &str) {
        self.udp_branches.remove(branch).await;
    }

    async fn lookup_udp_client_transaction(&self, key: &str) -> Option<UdpClientTransactionRoute> {
        let now = Instant::now();
        let mut transactions = self.udp_client_transactions.shard_for_key(key).lock().await;
        prune_udp_client_transactions(&mut transactions, now);
        transactions.get(key).cloned()
    }

    async fn remember_udp_client_transaction(
        &self,
        key: String,
        target: UpstreamTarget,
        packet: Vec<u8>,
    ) {
        let mut transactions = self
            .udp_client_transactions
            .shard_for_key(&key)
            .lock()
            .await;
        prune_udp_client_transactions(&mut transactions, Instant::now());
        transactions.insert(
            key,
            UdpClientTransactionRoute {
                target,
                packet,
                final_response: None,
                created_at: Instant::now(),
            },
        );
        enforce_udp_client_transaction_shard_limit(
            &mut transactions,
            self.udp_client_transaction_shard_limit(),
        );
    }

    async fn remember_udp_client_transaction_final_response(&self, key: &str, response: Vec<u8>) {
        let now = Instant::now();
        let mut transactions = self.udp_client_transactions.shard_for_key(key).lock().await;
        prune_udp_client_transactions(&mut transactions, now);
        if let Some(route) = transactions.get_mut(key) {
            route.final_response = Some(response);
            route.created_at = now;
        }
    }

    async fn remove_udp_client_transaction(&self, key: &str) {
        self.udp_client_transactions.remove(key).await;
    }

    fn udp_client_transaction_shard_limit(&self) -> usize {
        self.config
            .proxy
            .udp_client_transaction_cache_entries
            .div_ceil(ROUTE_MAP_SHARDS)
            .max(1)
    }

    async fn remember_successful_forward(
        &self,
        message: &SipMessage,
        target: UpstreamTarget,
        branch: &str,
        invite_transaction_key: Option<String>,
        method: &str,
    ) {
        if should_record_forward_affinity(method) {
            match self
                .affinity
                .remember(
                    message,
                    AffinityTarget {
                        addr: target.addr,
                        transport: target.transport,
                    },
                )
                .await
            {
                Ok(bindings) => {
                    if let Some(persistence) = &self.persistence {
                        if persistence.required() {
                            if let Err(err) = persistence.upsert_affinity_bindings(bindings).await {
                                warn!(
                                    error = %format!("{err:#}"),
                                    "failed to persist SIP affinity bindings"
                                );
                            }
                        } else {
                            persistence.upsert_affinity_bindings_background(bindings);
                        }
                    }
                }
                Err(err) => {
                    warn!(error = %err, "failed to record SIP affinity for forwarded request");
                }
            }
        }

        if method == "INVITE" {
            self.remember_invite_transaction(invite_transaction_key, target, branch.to_string())
                .await;
        }
    }

    async fn submit_cluster_command(&self, command: ClusterCommand) {
        if let Err(err) = self.replicator.submit(command).await {
            warn!(
                error = %format!("{err:#}"),
                "failed to submit cluster state command"
            );
        }
    }

    fn upstream_response_timeout(method: &str) -> Duration {
        if method == "INVITE" {
            INVITE_UPSTREAM_TIMEOUT
        } else {
            UPSTREAM_TIMEOUT
        }
    }

    async fn recv_upstream_response(
        &self,
        responses: &mut mpsc::UnboundedReceiver<Vec<u8>>,
        upstream: SocketAddr,
        method: &str,
    ) -> Result<Vec<u8>> {
        match timeout(Self::upstream_response_timeout(method), responses.recv()).await {
            Ok(Some(response)) => Ok(response),
            Ok(None) => {
                self.upstreams.record_passive_result(upstream, false);
                bail!("upstream SIP TCP response channel closed");
            }
            Err(_) => {
                self.upstreams.record_passive_result(upstream, false);
                bail!("upstream SIP TCP response timed out");
            }
        }
    }

    async fn send_udp_to_tcp_responses(
        &self,
        socket: &UdpSocket,
        responses: &mut mpsc::UnboundedReceiver<Vec<u8>>,
        client_peer: SocketAddr,
        upstream: SocketAddr,
        transaction: UdpClientTransactionRef<'_>,
        method: &str,
    ) -> Result<()> {
        loop {
            let response = self
                .recv_upstream_response(responses, upstream, method)
                .await?;
            let mut response_message = SipMessage::parse(&response)?;
            let is_final = matches!(
                &response_message.start_line,
                SipStartLine::Response { code, .. } if *code >= 200
            );
            if let SipStartLine::Response { code, .. } = &response_message.start_line {
                self.record_upstream_response("tcp", *code);
                self.upstreams.record_passive_result(upstream, *code < 500);
                self.record_upstream_response_latency(
                    "udp",
                    SipTransport::Tcp,
                    method,
                    transaction.request_started_at.elapsed(),
                );
                self.apply_register_response(transaction.branch, &response_message, *code)
                    .await;
            }
            response_message.apply_top_via_received_rport(client_peer)?;
            let response = response_message.to_bytes();
            if is_final && let Some(key) = transaction.key {
                self.remember_udp_client_transaction_final_response(key, response.clone())
                    .await;
            }
            socket.send_to(&response, client_peer).await?;
            if is_final {
                break;
            }
        }
        Ok(())
    }

    async fn run_tcp(
        self: Arc<Self>,
        listener: TcpListener,
        proxy_listener: ProxyListenerConfig,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(err) => {
                            warn!(error = %err, "failed to accept TCP SIP connection");
                            continue;
                        }
                    };
                    if self.config.proxy.socket.tcp_nodelay
                        && let Err(err) = stream.set_nodelay(true)
                    {
                        warn!(%peer, error = %err, "failed to set TCP_NODELAY on SIP connection");
                        continue;
                    }
                    let this = self.clone();
                    let proxy_listener = proxy_listener.clone();
                    tokio::spawn(async move {
                        if let Err(err) = this.handle_tcp_client(stream, peer, proxy_listener).await {
                            warn!(%peer, error = %err, "failed to handle TCP SIP connection");
                        }
                    });
                }
            }
        }
        Ok(())
    }

    async fn handle_tcp_client(
        self: Arc<Self>,
        mut stream: TcpStream,
        peer: SocketAddr,
        listener: ProxyListenerConfig,
    ) -> Result<()> {
        let mut reader = TcpSipReader::new(self.config.sip.max_message_bytes);
        while let Some(packet) = reader.read_message(&mut stream).await? {
            self.handle_tcp_packet(&mut stream, &packet, peer, &listener)
                .await?;
        }
        Ok(())
    }

    async fn handle_tcp_packet(
        &self,
        stream: &mut TcpStream,
        packet: &[u8],
        peer: SocketAddr,
        listener: &ProxyListenerConfig,
    ) -> Result<()> {
        match self.security.check_packet(listener, peer, packet).await {
            SecurityDecision::Allow => {}
            SecurityDecision::Drop(reason) => {
                self.handle_security_drop(listener, peer, reason).await;
                return Ok(());
            }
        }

        let message = match SipMessage::parse(packet) {
            Ok(message) => message,
            Err(err) if self.security.enabled(listener) => {
                self.handle_parse_error(listener, peer, packet, err).await;
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        if message.is_response() {
            debug!(%peer, "ignoring SIP response received from downstream TCP client");
            return Ok(());
        }

        let Some(method) = message.method().map(str::to_string) else {
            return Ok(());
        };
        self.record_sip_request("tcp", method.as_str());

        let mut message = message;
        if method == "ACK" && self.consume_local_invite_ack(&message).await {
            debug!(%peer, listener = %listener.key(), "absorbed ACK for locally rejected INVITE");
            return Ok(());
        }
        if let Some(reason) = self
            .security
            .check_sip_request(listener, peer, &message, method.as_str())
            .await
        {
            self.record_security_drop(listener, reason);
            if let Some(reason) = self
                .security
                .record_dynamic_offense(listener, peer, Some(DynamicOffense::SipRateViolation))
                .await
            {
                self.record_security_drop(listener, reason);
            }
            let response = SipMessage::response_like(&message, 503, "Service Unavailable");
            self.remember_local_invite_rejection_if_needed(&message, method.as_str())
                .await;
            self.record_local_response("tcp", 503);
            stream.write_all(&response.to_bytes()).await?;
            return Ok(());
        }
        if let Some(reason) = self
            .check_sip_policy(listener, peer, &message, method.as_str())
            .await
        {
            self.record_security_drop(listener, reason);
            if let Some(reason) = self
                .security
                .record_dynamic_offense(listener, peer, Some(DynamicOffense::SipRateViolation))
                .await
            {
                self.record_security_drop(listener, reason);
            }
            let response = SipMessage::response_like(&message, 403, "Forbidden");
            self.remember_local_invite_rejection_if_needed(&message, method.as_str())
                .await;
            self.record_local_response("tcp", 403);
            stream.write_all(&response.to_bytes()).await?;
            return Ok(());
        }
        match decrement_max_forwards(&mut message) {
            Ok(true) => {}
            Ok(false) => {
                let response = SipMessage::response_like(&message, 483, "Too Many Hops");
                self.remember_local_invite_rejection_if_needed(&message, method.as_str())
                    .await;
                self.record_local_response("tcp", 483);
                stream.write_all(&response.to_bytes()).await?;
                return Ok(());
            }
            Err(err) => {
                warn!(%peer, error = %err, "invalid Max-Forwards header");
                let response = SipMessage::response_like(&message, 400, "Bad Request");
                self.remember_local_invite_rejection_if_needed(&message, method.as_str())
                    .await;
                self.record_local_response("tcp", 400);
                stream.write_all(&response.to_bytes()).await?;
                return Ok(());
            }
        }
        if let Err(err) = self
            .forward_tcp_stream(stream, message, peer, listener, method.as_str())
            .await
        {
            error!(error = %format!("{err:#}"), "failed to forward TCP SIP request");
            self.record_forward_error("tcp");
            let request = SipMessage::parse(packet)?;
            let response = SipMessage::response_like(&request, 503, "Service Unavailable");
            self.remember_local_invite_rejection_if_needed(&request, method.as_str())
                .await;
            self.record_local_response("tcp", 503);
            stream.write_all(&response.to_bytes()).await?;
        }
        Ok(())
    }

    async fn handle_udp_packet(
        &self,
        socket: &UdpSocket,
        packet: &[u8],
        peer: SocketAddr,
        listener: &ProxyListenerConfig,
    ) -> Result<()> {
        if is_crlf_keepalive(packet) {
            debug!(%peer, "ignoring UDP CRLF keepalive");
            return Ok(());
        }
        if let Some(response) = stun_binding_success_response(packet, peer) {
            socket.send_to(&response, peer).await?;
            debug!(%peer, "answered UDP STUN binding request");
            return Ok(());
        }
        if is_stun_packet(packet) {
            debug!(%peer, "ignoring non-binding UDP STUN packet");
            return Ok(());
        }

        match self.security.check_packet(listener, peer, packet).await {
            SecurityDecision::Allow => {}
            SecurityDecision::Drop(reason) => {
                self.handle_security_drop(listener, peer, reason).await;
                return Ok(());
            }
        }

        let message = match SipMessage::parse(packet) {
            Ok(message) => message,
            Err(err) if self.security.enabled(listener) => {
                self.handle_parse_error(listener, peer, packet, err).await;
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        if message.is_response() {
            return self.handle_udp_response(socket, message, peer).await;
        }

        let Some(method) = message.method().map(str::to_string) else {
            return Ok(());
        };
        self.record_sip_request("udp", method.as_str());

        let mut message = message;
        if method == "ACK" && self.consume_local_invite_ack(&message).await {
            debug!(%peer, listener = %listener.key(), "absorbed ACK for locally rejected INVITE");
            return Ok(());
        }
        if let Some(reason) = self
            .security
            .check_sip_request(listener, peer, &message, method.as_str())
            .await
        {
            self.record_security_drop(listener, reason);
            if let Some(reason) = self
                .security
                .record_dynamic_offense(listener, peer, Some(DynamicOffense::SipRateViolation))
                .await
            {
                self.record_security_drop(listener, reason);
            }
            let mut response = SipMessage::response_like(&message, 503, "Service Unavailable");
            response.apply_top_via_received_rport(peer)?;
            self.remember_local_invite_rejection_if_needed(&message, method.as_str())
                .await;
            self.record_local_response("udp", 503);
            socket.send_to(&response.to_bytes(), peer).await?;
            return Ok(());
        }
        if let Some(reason) = self
            .check_sip_policy(listener, peer, &message, method.as_str())
            .await
        {
            self.record_security_drop(listener, reason);
            if let Some(reason) = self
                .security
                .record_dynamic_offense(listener, peer, Some(DynamicOffense::SipRateViolation))
                .await
            {
                self.record_security_drop(listener, reason);
            }
            let mut response = SipMessage::response_like(&message, 403, "Forbidden");
            response.apply_top_via_received_rport(peer)?;
            self.remember_local_invite_rejection_if_needed(&message, method.as_str())
                .await;
            self.record_local_response("udp", 403);
            socket.send_to(&response.to_bytes(), peer).await?;
            return Ok(());
        }
        match decrement_max_forwards(&mut message) {
            Ok(true) => {}
            Ok(false) => {
                let mut response = SipMessage::response_like(&message, 483, "Too Many Hops");
                response.apply_top_via_received_rport(peer)?;
                self.remember_local_invite_rejection_if_needed(&message, method.as_str())
                    .await;
                self.record_local_response("udp", 483);
                socket.send_to(&response.to_bytes(), peer).await?;
                return Ok(());
            }
            Err(err) => {
                warn!(%peer, error = %err, "invalid Max-Forwards header");
                let mut response = SipMessage::response_like(&message, 400, "Bad Request");
                response.apply_top_via_received_rport(peer)?;
                self.remember_local_invite_rejection_if_needed(&message, method.as_str())
                    .await;
                self.record_local_response("udp", 400);
                socket.send_to(&response.to_bytes(), peer).await?;
                return Ok(());
            }
        }
        if let Err(err) = self
            .forward_udp(socket, message, peer, listener, method.as_str())
            .await
        {
            error!(error = %format!("{err:#}"), "failed to forward UDP SIP request");
            self.record_forward_error("udp");
            let request = SipMessage::parse(packet)?;
            let mut response = SipMessage::response_like(&request, 503, "Service Unavailable");
            response.apply_top_via_received_rport(peer)?;
            self.remember_local_invite_rejection_if_needed(&request, method.as_str())
                .await;
            self.record_local_response("udp", 503);
            socket.send_to(&response.to_bytes(), peer).await?;
        }
        Ok(())
    }

    async fn handle_udp_response(
        &self,
        socket: &UdpSocket,
        mut message: SipMessage,
        upstream_peer: SocketAddr,
    ) -> Result<()> {
        let branch = message
            .top_via_branch()?
            .context("upstream response is missing top Via branch")?;
        if !branch.starts_with(PROXY_BRANCH_PREFIX) {
            debug!(
                %upstream_peer,
                branch = %branch,
                "dropping UDP response whose top Via branch was not created by this proxy"
            );
            return Ok(());
        }

        let route = {
            let mut branches = self.udp_branches.shard_for_key(&branch).lock().await;
            prune_udp_branches(&mut branches, Instant::now());
            branches.get(&branch).cloned()
        };
        let Some(route) = route else {
            warn!(
                %upstream_peer,
                branch = %branch,
                "dropping UDP response without a matching client branch route"
            );
            return Ok(());
        };
        if route.upstream != upstream_peer {
            debug!(
                %upstream_peer,
                expected_upstream = %route.upstream,
                branch = %branch,
                "forwarding UDP response from unexpected upstream source"
            );
        }

        let is_final = matches!(
            &message.start_line,
            SipStartLine::Response { code, .. } if *code >= 200
        );
        if let SipStartLine::Response { code, .. } = &message.start_line {
            self.record_upstream_response("udp", *code);
            self.upstreams
                .record_passive_result(route.upstream, *code < 500);
            self.record_upstream_response_latency(
                "udp",
                SipTransport::Udp,
                route.method.as_str(),
                route.created_at.elapsed(),
            );
            self.apply_register_response(&branch, &message, *code).await;
        }
        message
            .pop_top_via()?
            .context("upstream response is missing Via")?;
        message.apply_top_via_received_rport(route.client_peer)?;
        let response = message.to_bytes();
        if is_final && let Some(key) = route.client_transaction_key.as_deref() {
            self.remember_udp_client_transaction_final_response(key, response.clone())
                .await;
        }
        let send_result = socket.send_to(&response, route.client_peer).await;
        if is_final && route.remove_on_final {
            self.remove_udp_branch(&branch).await;
        }
        send_result?;
        Ok(())
    }

    async fn check_sip_policy(
        &self,
        listener: &ProxyListenerConfig,
        peer: SocketAddr,
        message: &SipMessage,
        method: &str,
    ) -> Option<&'static str> {
        if method != "INVITE" {
            return None;
        }
        if self.upstreams.contains(peer) || self.security.is_trusted_peer(listener, peer.ip()) {
            return None;
        }
        let policy = self
            .config
            .proxy
            .effective_security_for_listener(listener)
            .sip_policy;
        if !policy.require_registered_invite_source {
            return None;
        }

        let from_aor = match extract_from_aor(message) {
            Ok(from_aor) => from_aor,
            Err(err) => {
                debug!(
                    %peer,
                    listener = %listener.key(),
                    error = %format!("{err:#}"),
                    "rejecting INVITE because From AoR could not be parsed"
                );
                return Some("sip-invalid-from");
            }
        };
        let Some(binding) = self.lookup_registration_binding(&from_aor).await else {
            debug!(
                %peer,
                listener = %listener.key(),
                from = %from_aor,
                "rejecting INVITE because From AoR has no active registration"
            );
            return Some("sip-unregistered-invite");
        };
        if registered_invite_source_matches(
            &binding.source,
            peer,
            policy.registered_invite_source_match,
        ) {
            return None;
        }
        debug!(
            %peer,
            listener = %listener.key(),
            from = %from_aor,
            registered_source = %binding.source,
            match_mode = ?policy.registered_invite_source_match,
            "rejecting INVITE because source does not match active registration"
        );
        Some("sip-unregistered-invite-source")
    }

    async fn forward_udp(
        &self,
        socket: &UdpSocket,
        message: SipMessage,
        peer: SocketAddr,
        listener: &ProxyListenerConfig,
        method: &str,
    ) -> Result<()> {
        let client_transaction_key = udp_client_transaction_key(&message, peer, method)?;
        if let Some(key) = client_transaction_key.as_deref()
            && let Some(route) = self.lookup_udp_client_transaction(key).await
        {
            debug!(
                %peer,
                target = %route.target.addr,
                transport = %route.target.transport.as_str(),
                method,
                "reusing upstream SIP request for UDP client retransmission"
            );
            if let Some(response) = route.final_response {
                socket
                    .send_to(&response, peer)
                    .await
                    .context("failed to retransmit cached SIP response to UDP client")?;
            } else if route.target.transport == SipTransport::Udp {
                socket
                    .send_to(&route.packet, route.target.addr)
                    .await
                    .context("failed to retransmit cached SIP request to upstream UDP socket")?;
            }
            return Ok(());
        }

        let (message, target, branch, invite_transaction_key) = self
            .prepare_forward(message, peer, listener, method)
            .await?;

        debug!(
            %peer,
            target = %target.addr,
            transport = %target.transport.as_str(),
            method,
            branch = %branch,
            "forwarding UDP SIP request"
        );
        match target.transport {
            SipTransport::Udp => {
                self.record_forwarded_request("udp", target.transport, Some(method));
                let packet = message.to_bytes();
                {
                    let mut branches = self.udp_branches.shard_for_key(&branch).lock().await;
                    prune_udp_branches(&mut branches, Instant::now());
                    branches.insert(
                        branch.clone(),
                        UdpBranchRoute {
                            client_peer: peer,
                            upstream: target.addr,
                            method: method.to_string(),
                            created_at: Instant::now(),
                            remove_on_final: method != "INVITE",
                            client_transaction_key: client_transaction_key.clone(),
                        },
                    );
                }
                if let Some(key) = client_transaction_key.clone() {
                    self.remember_udp_client_transaction(key, target, packet.clone())
                        .await;
                }
                if let Err(err) = socket.send_to(&packet, target.addr).await {
                    self.remove_udp_branch(&branch).await;
                    if let Some(key) = client_transaction_key.as_deref() {
                        self.remove_udp_client_transaction(key).await;
                    }
                    self.upstreams.record_passive_result(target.addr, false);
                    return Err(err).context("failed to send SIP request to upstream UDP socket");
                }
                self.remember_successful_forward(
                    &message,
                    target,
                    &branch,
                    invite_transaction_key,
                    method,
                )
                .await;
                Ok(())
            }
            SipTransport::Tcp => {
                self.record_forwarded_request("udp", target.transport, Some(method));
                self.forward_udp_to_tcp_upstream(UdpToTcpForward {
                    socket,
                    message,
                    client_peer: peer,
                    upstream: target.addr,
                    branch,
                    client_transaction_key,
                    invite_transaction_key,
                    method,
                })
                .await
            }
            SipTransport::TcpUdp => {
                bail!("tcp_udp upstream target must be expanded before forwarding")
            }
        }
    }

    async fn forward_udp_to_tcp_upstream(&self, request: UdpToTcpForward<'_>) -> Result<()> {
        let UdpToTcpForward {
            socket,
            message,
            client_peer,
            upstream,
            branch,
            client_transaction_key,
            invite_transaction_key,
            method,
        } = request;
        let packet = message.to_bytes();
        let request_started_at = Instant::now();
        let mut responses = match self
            .tcp_upstreams
            .send_request(upstream, &branch, &packet)
            .await
        {
            Ok(responses) => responses,
            Err(err) => {
                if let Some(key) = client_transaction_key.as_deref() {
                    self.remove_udp_client_transaction(key).await;
                }
                self.upstreams.record_passive_result(upstream, false);
                return Err(err);
            }
        };
        let target = UpstreamTarget {
            addr: upstream,
            transport: SipTransport::Tcp,
        };
        if let Some(key) = client_transaction_key.clone() {
            self.remember_udp_client_transaction(key, target, packet)
                .await;
        }
        self.remember_successful_forward(&message, target, &branch, invite_transaction_key, method)
            .await;

        self.send_udp_to_tcp_responses(
            socket,
            &mut responses,
            client_peer,
            upstream,
            UdpClientTransactionRef {
                branch: &branch,
                key: client_transaction_key.as_deref(),
                request_started_at,
            },
            method,
        )
        .await
    }

    async fn forward_tcp_stream(
        &self,
        client_stream: &mut TcpStream,
        message: SipMessage,
        peer: SocketAddr,
        listener: &ProxyListenerConfig,
        method: &str,
    ) -> Result<()> {
        let (message, target, branch, invite_transaction_key) = self
            .prepare_forward(message, peer, listener, method)
            .await?;
        self.record_forwarded_request("tcp", target.transport, Some(method));
        let packet = message.to_bytes();
        let request_started_at = Instant::now();
        let mut responses = match self
            .tcp_upstreams
            .send_request(target.addr, &branch, &packet)
            .await
        {
            Ok(responses) => responses,
            Err(err) => {
                self.upstreams.record_passive_result(target.addr, false);
                return Err(err);
            }
        };
        self.remember_successful_forward(&message, target, &branch, invite_transaction_key, method)
            .await;
        loop {
            let response = self
                .recv_upstream_response(&mut responses, target.addr, method)
                .await?;
            let response_message = SipMessage::parse(&response)?;
            let is_final = matches!(
                &response_message.start_line,
                SipStartLine::Response { code, .. } if *code >= 200
            );
            if let SipStartLine::Response { code, .. } = &response_message.start_line {
                self.record_upstream_response("tcp", *code);
                self.upstreams
                    .record_passive_result(target.addr, *code < 500);
                self.record_upstream_response_latency(
                    "tcp",
                    target.transport,
                    method,
                    request_started_at.elapsed(),
                );
                self.apply_register_response(&branch, &response_message, *code)
                    .await;
            }
            client_stream.write_all(&response).await?;
            if is_final {
                break;
            }
        }
        Ok(())
    }

    async fn prepare_forward(
        &self,
        mut message: SipMessage,
        _peer: SocketAddr,
        listener: &ProxyListenerConfig,
        method: &str,
    ) -> Result<(SipMessage, UpstreamTarget, String, Option<String>)> {
        let request_uri = message
            .request_uri()
            .context("request forwarding requires a request URI")?
            .to_string();
        let from_upstream = self.upstreams.contains(_peer);
        let from_trusted_peer = self.security.is_trusted_peer(listener, _peer.ip());
        let route_set_targets_this_proxy = self
            .top_route_targets_this_proxy(&message, listener, _peer)
            .await?;
        let request_uri_targets_this_proxy =
            self.request_uri_targets_this_proxy(&request_uri, listener);
        let direct_request_uri_target = if from_upstream || from_trusted_peer {
            self.direct_request_uri_target(&request_uri, listener)
        } else {
            None
        };
        let invite_transaction_key = invite_transaction_key(&message)?;
        let transaction_route =
            if method == "CANCEL" || (method == "ACK" && direct_request_uri_target.is_none()) {
                self.lookup_invite_transaction(invite_transaction_key.as_deref())
                    .await
            } else {
                None
            };
        let mut target = if method == "ACK"
            && let Some(target) = direct_request_uri_target
        {
            self.record_affinity_lookup("request-uri-target");
            target
        } else if let Some(route) = transaction_route.as_ref() {
            self.record_affinity_lookup("transaction-hit");
            route.target
        } else if from_upstream
            || request_uri_targets_this_proxy
            || (from_trusted_peer && route_set_targets_this_proxy)
        {
            if let Some(binding) = self
                .lookup_delivery_registration_binding(
                    &message,
                    &request_uri,
                    from_upstream || (from_trusted_peer && route_set_targets_this_proxy),
                )
                .await
            {
                self.record_affinity_lookup("location-hit");
                target_for_registration_binding(&binding, listener.transport)
                    .unwrap_or_else(|| self.select_upstream(&request_uri, listener))
            } else if (from_upstream || (from_trusted_peer && route_set_targets_this_proxy))
                && let Some(target) = self.direct_request_uri_target(&request_uri, listener)
            {
                self.record_affinity_lookup("request-uri-target");
                target
            } else if let Some(target) = self.affinity.lookup(&message).await? {
                let target = UpstreamTarget {
                    addr: target.addr,
                    transport: target.transport,
                };
                if self.is_healthy_upstream_target(target) {
                    self.record_affinity_lookup("hit");
                    target
                } else {
                    self.record_affinity_lookup("wrong-side");
                    self.select_upstream(&request_uri, listener)
                }
            } else {
                self.record_affinity_lookup("miss");
                self.select_upstream(&request_uri, listener)
            }
        } else if let Some(target) = direct_request_uri_target {
            self.record_affinity_lookup("request-uri-target");
            target
        } else if let Some(target) = self
            .lookup_registered_upstream_target(&message, &request_uri)
            .await
        {
            self.record_affinity_lookup("registered-upstream-hit");
            target
        } else if let Some(target) = self.affinity.lookup(&message).await? {
            let target = UpstreamTarget {
                addr: target.addr,
                transport: target.transport,
            };
            if self.is_healthy_upstream_target(target) {
                self.record_affinity_lookup("hit");
                target
            } else {
                self.record_affinity_lookup("wrong-side");
                self.select_upstream(&request_uri, listener)
            }
        } else {
            self.record_affinity_lookup("miss");
            self.select_upstream(&request_uri, listener)
        };
        if !self.upstreams.contains(target.addr)
            && self.is_advertised_or_listener_addr(target.addr, listener)
        {
            warn!(
                listener = %listener.key(),
                method,
                target = %target.addr,
                "selected proxy self address as SIP forward target; falling back to upstream group"
            );
            target = self.select_upstream(&request_uri, listener);
        }

        self.pop_own_route_headers(&mut message, listener, target.addr)
            .await?;

        let branch = transaction_route
            .map(|route| route.branch)
            .unwrap_or_else(|| format!("{PROXY_BRANCH_PREFIX}{}", unique_id()));
        let target_side = if self.upstreams.contains(target.addr) {
            AdvertiseSide::Internal
        } else {
            AdvertiseSide::Public
        };
        let via_host = self
            .advertised_sip_addr(target_side, listener, target.addr)
            .await;
        message.prepend_via(
            rsip_transport_from_sip(target.transport),
            &via_host,
            branch.clone(),
        )?;

        if self.config.proxy.record_route && should_record_route(method) {
            for addr in self
                .record_route_addrs(_peer, target.addr, listener)
                .await
                .into_iter()
                .rev()
            {
                message.prepend_record_route(&addr)?;
            }
        }
        if method == "REGISTER" {
            let pending_register = match self.config.proxy.effective_register_routing() {
                RegisterRoutingMode::ContactRewrite => self.rewrite_register_contact_and_pending(
                    &mut message,
                    &via_host,
                    _peer,
                    target,
                )?,
                RegisterRoutingMode::Path => {
                    let pending =
                        self.register_contact_routes_pending(&message, &via_host, _peer, target)?;
                    message.prepend_path(&via_host)?;
                    pending
                }
            };
            self.remember_pending_register(branch.clone(), pending_register)
                .await;
        }

        Ok((message, target, branch, invite_transaction_key))
    }

    async fn top_route_targets_this_proxy(
        &self,
        message: &SipMessage,
        listener: &ProxyListenerConfig,
        peer: SocketAddr,
    ) -> Result<bool> {
        let Some(route) = message.top_header_value("Route")? else {
            return Ok(false);
        };
        Ok(self.route_targets_this_proxy(&route, listener, peer).await)
    }

    fn direct_request_uri_target(
        &self,
        request_uri: &str,
        listener: &ProxyListenerConfig,
    ) -> Option<UpstreamTarget> {
        parse_contact_target(request_uri, listener.transport)
            .filter(|target| !self.upstreams.contains(target.addr))
            .filter(|target| !self.is_advertised_or_listener_addr(target.addr, listener))
    }

    fn request_uri_targets_this_proxy(
        &self,
        request_uri: &str,
        listener: &ProxyListenerConfig,
    ) -> bool {
        parse_contact_target(request_uri, listener.transport)
            .is_some_and(|target| self.is_advertised_or_listener_addr(target.addr, listener))
    }

    async fn pop_own_route_headers(
        &self,
        message: &mut SipMessage,
        listener: &ProxyListenerConfig,
        target: SocketAddr,
    ) -> Result<()> {
        while let Some(route) = message.top_header_value("Route")? {
            if !self
                .route_targets_this_proxy(&route, listener, target)
                .await
            {
                break;
            }
            message.pop_top_header_value("Route")?;
        }
        Ok(())
    }

    async fn route_targets_this_proxy(
        &self,
        route: &str,
        listener: &ProxyListenerConfig,
        target: SocketAddr,
    ) -> bool {
        let Some(route_target) = parse_route_target(route, listener.transport) else {
            return false;
        };
        self.is_advertised_or_listener_addr(route_target.addr, listener)
            || self
                .resolved_advertised_addr_matches(
                    AdvertiseSide::Public,
                    listener,
                    target,
                    route_target.addr,
                )
                .await
            || self
                .resolved_advertised_addr_matches(
                    AdvertiseSide::Internal,
                    listener,
                    target,
                    route_target.addr,
                )
                .await
    }

    async fn resolved_advertised_addr_matches(
        &self,
        side: AdvertiseSide,
        listener: &ProxyListenerConfig,
        target: SocketAddr,
        route_target: SocketAddr,
    ) -> bool {
        self.advertised_sip_addr(side, listener, target)
            .await
            .parse::<SocketAddr>()
            .is_ok_and(|addr| addr == route_target)
    }

    fn is_advertised_or_listener_addr(
        &self,
        addr: SocketAddr,
        listener: &ProxyListenerConfig,
    ) -> bool {
        [
            self.config.sip.external_addr.as_deref(),
            self.config.sip.public_addr.as_deref(),
            self.config.sip.internal_addr.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|configured| {
            parse_socket_addr_with_default_port(configured, listener_port(listener))
                .is_some_and(|external| external == addr)
        }) || self.listener_bind_matches_addr(addr, listener)
    }

    fn listener_bind_matches_addr(&self, addr: SocketAddr, listener: &ProxyListenerConfig) -> bool {
        let Ok(bind) = listener.bind.parse::<SocketAddr>() else {
            return false;
        };
        if bind.port() != addr.port() {
            return false;
        }
        if bind.ip().is_unspecified() {
            return self.local_ips.contains(&addr.ip());
        }
        bind == addr
    }

    async fn advertised_sip_addr(
        &self,
        side: AdvertiseSide,
        listener: &ProxyListenerConfig,
        target: SocketAddr,
    ) -> String {
        let cache_key = format!("{}|{}|{}", side.as_str(), listener.key(), target);
        if let Some(addr) = self.advertised_addrs.lock().await.get(&cache_key).cloned() {
            return addr;
        }

        let addr = self
            .resolve_advertised_sip_addr(side, listener, target)
            .await;
        self.advertised_addrs
            .lock()
            .await
            .insert(cache_key, addr.clone());
        addr
    }

    async fn resolve_advertised_sip_addr(
        &self,
        side: AdvertiseSide,
        listener: &ProxyListenerConfig,
        target: SocketAddr,
    ) -> String {
        let configured = self.configured_addr_for_side(side);
        let port = listener_port(listener);
        if let Some(configured) = configured
            && !advertised_addr_needs_auto(configured)
            && let Some(addr) = render_advertised_addr(configured, port)
        {
            return addr;
        }

        match side {
            AdvertiseSide::Public => {
                if let Some(server) = non_empty(self.config.sip.public_stun_server.as_deref()) {
                    match discover_public_ip(server).await {
                        Ok(ip) => return render_host_port(&ip.to_string(), port),
                        Err(err) => {
                            warn!(
                                stun_server = %server,
                                error = %err,
                                "failed to detect public SIP address with STUN"
                            );
                        }
                    }
                } else {
                    warn!(
                        bind = %listener.bind,
                        "sip.public_addr is empty and sip.public_stun_server is not set; falling back to local address detection"
                    );
                }
            }
            AdvertiseSide::Internal => {
                if let Some(probe) = non_empty(Some(self.config.sip.internal_probe_addr.as_str())) {
                    match resolve_probe_addr(probe) {
                        Ok(probe_addr) => match outbound_local_addr(probe_addr, port).await {
                            Ok(addr) => return addr.to_string(),
                            Err(err) => {
                                warn!(
                                    probe_addr = %probe,
                                    error = %err,
                                    "failed to detect internal SIP address"
                                );
                            }
                        },
                        Err(err) => {
                            warn!(
                                probe_addr = %probe,
                                error = %err,
                                "failed to resolve internal SIP address probe target"
                            );
                        }
                    }
                }
            }
        }

        advertised_sip_addr(configured, listener, target).await
    }

    async fn record_route_addrs(
        &self,
        peer: SocketAddr,
        target: SocketAddr,
        listener: &ProxyListenerConfig,
    ) -> Vec<String> {
        let from_upstream = self.upstreams.contains(peer);
        let to_upstream = self.upstreams.contains(target);
        if from_upstream == to_upstream {
            let side = if to_upstream {
                AdvertiseSide::Internal
            } else {
                AdvertiseSide::Public
            };
            return vec![self.advertised_sip_addr(side, listener, target).await];
        }

        let public = self
            .advertised_sip_addr(AdvertiseSide::Public, listener, target)
            .await;
        let internal = self
            .advertised_sip_addr(AdvertiseSide::Internal, listener, target)
            .await;
        match to_upstream {
            true => vec![internal, public],
            false => vec![public, internal],
        }
    }

    fn configured_addr_for_side(&self, side: AdvertiseSide) -> Option<&str> {
        match side {
            AdvertiseSide::Public => non_empty(
                self.config
                    .sip
                    .public_addr
                    .as_deref()
                    .or(self.config.sip.external_addr.as_deref()),
            ),
            AdvertiseSide::Internal => non_empty(
                self.config.sip.internal_addr.as_deref().or(self
                    .config
                    .sip
                    .external_addr
                    .as_deref()),
            ),
        }
    }

    async fn lookup_registration_binding(&self, request_uri: &str) -> Option<ContactBinding> {
        for key in registration_route_keys(request_uri) {
            if let Some(binding) = self.state.lookup(&key).await {
                return Some(binding);
            }
        }
        None
    }

    async fn lookup_delivery_registration_binding(
        &self,
        message: &SipMessage,
        request_uri: &str,
        allow_to_aor_fallback: bool,
    ) -> Option<ContactBinding> {
        if let Some(binding) = self.lookup_registration_binding(request_uri).await {
            return Some(binding);
        }
        if !allow_to_aor_fallback {
            return None;
        }
        let Ok(to_aor) = extract_to_aor(message) else {
            return None;
        };
        self.lookup_registration_binding(&to_aor).await
    }

    async fn lookup_registered_upstream_target(
        &self,
        message: &SipMessage,
        request_uri: &str,
    ) -> Option<UpstreamTarget> {
        if message.method()? != "INVITE" || !is_initial_invite_request(message) {
            return None;
        }
        for route in registered_upstream_lookup_keys(message, request_uri) {
            let key = registration_upstream_affinity_key(&route);
            let Some(target) = self.affinity.lookup_key(&key).await else {
                continue;
            };
            let target = UpstreamTarget {
                addr: target.addr,
                transport: target.transport,
            };
            if self.is_healthy_upstream_target(target) {
                return Some(target);
            }
            self.record_affinity_lookup("registered-upstream-unhealthy");
            return None;
        }
        None
    }

    fn rewrite_register_contact_and_pending(
        &self,
        message: &mut SipMessage,
        via_host: &str,
        peer: SocketAddr,
        target: UpstreamTarget,
    ) -> Result<Option<PendingRegister>> {
        let aor = extract_aor(message).ok();
        let original_contact = extract_contact(message).ok().flatten();
        let expires = extract_expires(message);
        let mut bindings = Vec::new();
        let rewritten_contacts = message.rewrite_contact_host_with_user(
            via_host,
            |original_contact, original_user| {
                rewritten_register_contact_user(
                    aor.as_deref(),
                    original_contact,
                    peer,
                    original_user,
                )
            },
        )?;
        for (original, rewritten) in rewritten_contacts {
            collect_contact_route_bindings(&mut bindings, &rewritten, &original, peer);
        }
        if let (Some(aor), Some(contact)) = (aor, original_contact) {
            push_pending_register_binding(
                &mut bindings,
                PendingRegisterBinding {
                    aor,
                    contact,
                    source: peer.to_string(),
                },
            );
        }
        Ok(pending_register(bindings, expires, target))
    }

    fn register_contact_routes_pending(
        &self,
        message: &SipMessage,
        via_host: &str,
        peer: SocketAddr,
        target: UpstreamTarget,
    ) -> Result<Option<PendingRegister>> {
        let expires = extract_expires(message);
        let mut first_contact = None;
        let mut bindings = Vec::new();
        let mut rewritten = message.clone();
        for (original, proxy_contact) in rewritten.rewrite_contact_host(via_host)? {
            if first_contact.is_none() {
                first_contact = Some(original.clone());
            }
            collect_contact_route_bindings(&mut bindings, &proxy_contact, &original, peer);
        }
        if let (Ok(aor), Some(contact)) = (extract_aor(message), first_contact) {
            push_pending_register_binding(
                &mut bindings,
                PendingRegisterBinding {
                    aor,
                    contact,
                    source: peer.to_string(),
                },
            );
        }
        Ok(pending_register(bindings, expires, target))
    }

    fn record_sip_request(&self, transport: &str, method: &str) {
        if let (Some(transport), Some(method)) = (
            metric_transport_index(transport),
            metric_method_index(method),
        ) {
            self.metric_handles.sip_requests[transport][method].incr();
            return;
        }

        self.metrics.incr(
            "sip_requests_total",
            &[("transport", transport), ("method", method)],
        );
    }

    fn record_forwarded_request(
        &self,
        downstream_transport: &str,
        upstream_transport: SipTransport,
        method: Option<&str>,
    ) {
        let method = method.unwrap_or("UNKNOWN");
        if let (Some(downstream), Some(method)) = (
            metric_transport_index(downstream_transport),
            metric_method_index(method),
        ) {
            let upstream = sip_transport_metric_index(upstream_transport);
            self.metric_handles.forwarded_requests[downstream][upstream][method].incr();
            return;
        }

        self.metrics.incr(
            "proxy_forwarded_requests_total",
            &[
                ("downstream_transport", downstream_transport),
                ("upstream_transport", upstream_transport.as_str()),
                ("method", method),
            ],
        );
    }

    fn record_forward_error(&self, downstream_transport: &str) {
        self.metrics.incr(
            "proxy_forward_errors_total",
            &[("downstream_transport", downstream_transport)],
        );
    }

    fn record_local_response(&self, transport: &str, code: u16) {
        let code = code.to_string();
        self.metrics.incr(
            "sip_local_responses_total",
            &[("transport", transport), ("code", code.as_str())],
        );
    }

    fn record_upstream_response(&self, transport: &str, code: u16) {
        let class = status_class(code);
        self.metrics.incr(
            "sip_upstream_responses_total",
            &[("transport", transport), ("class", class)],
        );
    }

    fn record_upstream_response_latency(
        &self,
        downstream_transport: &'static str,
        upstream_transport: SipTransport,
        method: &str,
        elapsed: Duration,
    ) {
        let elapsed_ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
        let upstream_transport = upstream_transport.as_str();
        for bucket in UPSTREAM_RESPONSE_LATENCY_MS_BUCKETS {
            if elapsed_ms <= bucket {
                let le = latency_bucket_label(bucket);
                self.metrics.incr(
                    "proxy_upstream_response_latency_ms_bucket",
                    &[
                        ("downstream_transport", downstream_transport),
                        ("upstream_transport", upstream_transport),
                        ("method", method),
                        ("le", le),
                    ],
                );
            }
        }
        self.metrics.incr(
            "proxy_upstream_response_latency_ms_bucket",
            &[
                ("downstream_transport", downstream_transport),
                ("upstream_transport", upstream_transport),
                ("method", method),
                ("le", "+Inf"),
            ],
        );
        self.metrics.incr(
            "proxy_upstream_response_latency_ms_count",
            &[
                ("downstream_transport", downstream_transport),
                ("upstream_transport", upstream_transport),
                ("method", method),
            ],
        );
        self.metrics.incr_by(
            "proxy_upstream_response_latency_ms_sum",
            &[
                ("downstream_transport", downstream_transport),
                ("upstream_transport", upstream_transport),
                ("method", method),
            ],
            elapsed_ms,
        );
    }

    fn record_affinity_lookup(&self, result: &str) {
        self.metrics
            .incr("proxy_affinity_lookup_total", &[("result", result)]);
    }

    async fn handle_security_drop(
        &self,
        listener: &ProxyListenerConfig,
        peer: SocketAddr,
        reason: &'static str,
    ) {
        self.record_security_drop(listener, reason);
        if let Some(reason) = self
            .security
            .record_dynamic_offense(listener, peer, dynamic_offense_for_reason(reason))
            .await
        {
            self.record_security_drop(listener, reason);
        }
    }

    async fn handle_parse_error(
        &self,
        listener: &ProxyListenerConfig,
        peer: SocketAddr,
        packet: &[u8],
        err: anyhow::Error,
    ) {
        let decision = self.security.record_parse_error(listener, peer).await;
        self.record_security_drop(
            listener,
            match decision {
                SecurityDecision::Allow => "parse-error",
                SecurityDecision::Drop(reason) => reason,
            },
        );
        if let Some(reason) = self
            .security
            .record_dynamic_offense(listener, peer, Some(DynamicOffense::ParseError))
            .await
        {
            self.record_security_drop(listener, reason);
        }
        if self
            .security
            .should_log_invalid_packet(listener, peer)
            .await
        {
            debug!(
                %peer,
                listener = %listener.key(),
                bytes = packet.len(),
                preview = %packet_preview(packet),
                error = %err,
                "dropped invalid SIP packet"
            );
        }
    }

    fn record_security_drop(&self, listener: &ProxyListenerConfig, reason: &str) {
        let listener_key = listener.key();
        self.metrics.incr(
            "proxy_security_dropped_packets_total",
            &[("listener", listener_key.as_str()), ("reason", reason)],
        );
    }

    pub(crate) fn record_ha_event_pull(&self, result: &str) {
        self.metrics
            .incr("proxy_ha_event_pulls_total", &[("result", result)]);
    }

    pub(crate) fn record_ha_snapshot_pull(&self, result: &str) {
        self.metrics
            .incr("proxy_ha_snapshot_pulls_total", &[("result", result)]);
    }

    pub(crate) fn record_ha_snapshot_fallback(&self, reason: &str) {
        self.metrics
            .incr("proxy_ha_snapshot_fallbacks_total", &[("reason", reason)]);
    }

    async fn lookup_invite_transaction(&self, key: Option<&str>) -> Option<InviteTransactionRoute> {
        let key = key?;
        let mut transactions = self.invite_transactions.shard_for_key(key).lock().await;
        prune_invite_transactions(&mut transactions, Instant::now());
        transactions.get(key).cloned()
    }

    async fn remember_invite_transaction(
        &self,
        key: Option<String>,
        target: UpstreamTarget,
        branch: String,
    ) {
        let Some(key) = key else {
            return;
        };
        let mut transactions = self.invite_transactions.shard_for_key(&key).lock().await;
        prune_invite_transactions(&mut transactions, Instant::now());
        transactions.insert(
            key,
            InviteTransactionRoute {
                target,
                branch,
                created_at: Instant::now(),
            },
        );
    }

    async fn remember_local_invite_rejection_if_needed(&self, message: &SipMessage, method: &str) {
        if method != "INVITE" {
            return;
        }
        let key = match invite_transaction_key(message) {
            Ok(Some(key)) => key,
            Ok(None) => return,
            Err(err) => {
                debug!(
                    error = %format!("{err:#}"),
                    "failed to build local INVITE rejection key"
                );
                return;
            }
        };
        let mut rejections = self.local_invite_rejections.lock().await;
        prune_local_invite_rejections(&mut rejections, Instant::now());
        rejections.insert(key, Instant::now());
    }

    async fn consume_local_invite_ack(&self, message: &SipMessage) -> bool {
        let key = match invite_transaction_key(message) {
            Ok(Some(key)) => key,
            _ => return false,
        };
        let mut rejections = self.local_invite_rejections.lock().await;
        prune_local_invite_rejections(&mut rejections, Instant::now());
        rejections.remove(&key).is_some()
    }

    async fn remember_pending_register(&self, branch: String, pending: Option<PendingRegister>) {
        let Some(pending) = pending else {
            return;
        };
        let mut registers = self.pending_registers.lock().await;
        prune_pending_registers(&mut registers, Instant::now());
        registers.insert(branch, pending);
    }

    async fn apply_register_response(&self, branch: &str, response: &SipMessage, code: u16) {
        if code < 200 {
            return;
        }
        let pending = {
            let mut registers = self.pending_registers.lock().await;
            prune_pending_registers(&mut registers, Instant::now());
            registers.remove(branch)
        };
        let Some(pending) = pending else {
            return;
        };
        if !(200..300).contains(&code) {
            debug!(
                branch,
                code, "discarding pending REGISTER state after non-2xx response"
            );
            return;
        }

        let expires = extract_response_contact_expires(response).unwrap_or(pending.request_expires);
        let mut upstream_affinity_bindings = Vec::new();
        for binding in pending.bindings {
            if expires.is_zero() {
                self.submit_cluster_command(ClusterCommand::UnregisterContact { aor: binding.aor })
                    .await;
            } else {
                let key = registration_upstream_affinity_key(&binding.aor);
                upstream_affinity_bindings.extend(
                    self.affinity
                        .remember_key(
                            key,
                            AffinityTarget {
                                addr: pending.target.addr,
                                transport: pending.target.transport,
                            },
                            expires,
                        )
                        .await,
                );
                self.submit_cluster_command(ClusterCommand::RegisterContact(ContactBinding {
                    aor: binding.aor,
                    contact: binding.contact,
                    source: binding.source,
                    expires_at_epoch_ms: expires_at(expires),
                }))
                .await;
            }
        }
        if let Some(persistence) = &self.persistence {
            if persistence.required() {
                if let Err(err) = persistence
                    .upsert_affinity_bindings(upstream_affinity_bindings)
                    .await
                {
                    warn!(
                        error = %format!("{err:#}"),
                        "failed to persist REGISTER upstream affinity bindings"
                    );
                }
            } else {
                persistence.upsert_affinity_bindings_background(upstream_affinity_bindings);
            }
        }
    }

    fn select_upstream(&self, uri: &str, listener: &ProxyListenerConfig) -> UpstreamTarget {
        let group = self
            .routes
            .load()
            .select(&listener.key(), uri)
            .map(|route| route.upstream_group)
            .unwrap_or_else(|| listener.upstream_group.clone());
        let addr = self
            .upstreams
            .select(&group)
            .expect("configuration should validate upstream group references");
        UpstreamTarget {
            addr,
            transport: listener.transport,
        }
    }

    fn is_healthy_upstream_target(&self, target: UpstreamTarget) -> bool {
        self.upstreams.contains(target.addr) && self.upstreams.is_healthy(target.addr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpstreamTarget {
    addr: SocketAddr,
    transport: SipTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdvertiseSide {
    Public,
    Internal,
}

impl AdvertiseSide {
    fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
        }
    }
}

async fn bind_udp_socket(
    listener: &ProxyListenerConfig,
    config: &ProxySocketConfig,
) -> Result<UdpSocket> {
    let addr = listener
        .bind
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid UDP bind address {}", listener.bind))?;
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    configure_socket(&socket, config)?;
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into()).context("failed to create Tokio UDP socket")
}

async fn bind_tcp_listener(
    listener: &ProxyListenerConfig,
    config: &ProxySocketConfig,
) -> Result<TcpListener> {
    let addr = listener
        .bind
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid TCP bind address {}", listener.bind))?;
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    configure_socket(&socket, config)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into()).context("failed to create Tokio TCP listener")
}

async fn run_metrics_server(
    config: ProxyMetricsConfig,
    server: Arc<ProxyServer>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let bind_addr = config
        .bind_addr
        .parse::<SocketAddr>()
        .context("proxy.metrics.bind_addr must be a SocketAddr")?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind proxy metrics listener {bind_addr}"))?;
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(server);
    info!(bind = %bind_addr, "proxy metrics listener started");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
        .context("proxy metrics HTTP server failed")
}

async fn metrics_handler(State(server): State<Arc<ProxyServer>>) -> String {
    server.render_metrics().await
}

fn append_gauge(output: &mut String, name: &str, value: u64) {
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    output.push_str("# TYPE ");
    output.push_str(name);
    output.push_str(" gauge\n");
    output.push_str(name);
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

fn append_labeled_gauge(output: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    append_labeled_metric(output, name, "gauge", labels, value);
}

fn append_labeled_counter(output: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    append_labeled_metric(output, name, "counter", labels, value);
}

fn append_labeled_metric(
    output: &mut String,
    name: &str,
    metric_type: &str,
    labels: &[(&str, &str)],
    value: u64,
) {
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    let type_line = format!("# TYPE {name} {metric_type}\n");
    if !output.contains(&type_line) {
        output.push_str(&type_line);
    }
    output.push_str(name);
    if !labels.is_empty() {
        output.push('{');
        for (index, (key, value)) in labels.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push_str(key);
            output.push_str("=\"");
            output.push_str(&escape_metric_label(value));
            output.push('"');
        }
        output.push('}');
    }
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

fn escape_metric_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn configure_socket(socket: &Socket, config: &ProxySocketConfig) -> Result<()> {
    socket.set_reuse_address(true)?;
    set_reuse_port(socket, config.reuse_port)?;
    if let Some(size) = config.recv_buffer_bytes {
        socket.set_recv_buffer_size(size)?;
    }
    if let Some(size) = config.send_buffer_bytes {
        socket.set_send_buffer_size(size)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_reuse_port(socket: &Socket, enabled: bool) -> io::Result<()> {
    socket.set_reuse_port(enabled)
}

#[cfg(not(unix))]
fn set_reuse_port(_socket: &Socket, enabled: bool) -> io::Result<()> {
    if enabled {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_REUSEPORT is not supported on this platform",
        ))
    } else {
        Ok(())
    }
}

struct UpstreamGroups {
    groups: HashMap<String, Arc<UpstreamGroupRuntime>>,
    servers_by_addr: HashMap<SocketAddr, Vec<UpstreamServerRef>>,
}

#[derive(Clone)]
struct UpstreamServerRef {
    group: Arc<UpstreamGroupRuntime>,
    index: usize,
}

#[derive(Debug, Clone)]
struct UdpBranchRoute {
    client_peer: SocketAddr,
    upstream: SocketAddr,
    method: String,
    created_at: Instant,
    remove_on_final: bool,
    client_transaction_key: Option<String>,
}

#[derive(Debug, Clone)]
struct UdpClientTransactionRoute {
    target: UpstreamTarget,
    packet: Vec<u8>,
    final_response: Option<Vec<u8>>,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct InviteTransactionRoute {
    target: UpstreamTarget,
    branch: String,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct PendingRegister {
    bindings: Vec<PendingRegisterBinding>,
    request_expires: Duration,
    target: UpstreamTarget,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct PendingRegisterBinding {
    aor: String,
    contact: String,
    source: String,
}

enum SecurityDecision {
    Allow,
    Drop(&'static str),
}

#[derive(Debug, Clone, Copy)]
enum DynamicOffense {
    InvalidPacket,
    ParseError,
    SipRateViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityBanAction {
    Installed,
    Extended,
    Retained,
}

struct SecurityRuntime {
    listeners: ArcSwap<HashMap<String, Arc<ListenerSecurityRuntime>>>,
    geo: Option<Arc<GeoRuntime>>,
    threat: Option<Arc<ThreatRuntime>>,
    xdp: XdpRuntime,
    buckets: ShardedSecurityMap<TokenBucket>,
    blocks: ShardedSecurityMap<Instant>,
}

#[derive(Debug, Default)]
struct SecurityRuntimeStats {
    active_blocks_total: u64,
    token_buckets_total: u64,
    active_blocks: Vec<SecurityRuntimeCount>,
    token_buckets: Vec<SecurityRuntimeCount>,
}

#[derive(Debug)]
struct SecurityRuntimeCount {
    listener: String,
    kind: String,
    count: u64,
}

impl SecurityRuntime {
    fn new(config: &ProxyConfig) -> Result<Self> {
        let mut listeners = HashMap::new();
        let mut effective_configs = Vec::new();
        for configured_listener in &config.listeners {
            for listener in configured_listener.concrete_listeners() {
                let effective = config.effective_security_for_listener(&listener);
                effective_configs.push(effective.clone());
                listeners.insert(
                    listener.key(),
                    Arc::new(ListenerSecurityRuntime::new(effective)?),
                );
            }
        }
        let geo = GeoRuntime::new(&effective_configs)?;
        let threat = ThreatRuntime::new(&effective_configs)?;
        let xdp = XdpRuntime::new(config, geo.as_ref(), threat.as_ref())?;
        Ok(Self {
            listeners: ArcSwap::from_pointee(listeners),
            geo,
            threat,
            xdp,
            buckets: ShardedSecurityMap::new(SECURITY_MAP_SHARDS),
            blocks: ShardedSecurityMap::new(SECURITY_MAP_SHARDS),
        })
    }

    async fn spawn_geo_refresh(
        &self,
        shutdown: watch::Receiver<bool>,
    ) -> Option<tokio::task::JoinHandle<Result<()>>> {
        self.geo.as_ref()?.spawn_refresh_task(shutdown).await
    }

    async fn spawn_threat_refresh(
        &self,
        shutdown: watch::Receiver<bool>,
    ) -> Option<tokio::task::JoinHandle<Result<()>>> {
        self.threat.as_ref()?.spawn_refresh_task(shutdown).await
    }

    fn xdp_stats(&self) -> Vec<(&'static str, u64)> {
        self.xdp.stats()
    }

    async fn stats(&self) -> SecurityRuntimeStats {
        let now = Instant::now();
        let block_counts = self
            .blocks
            .counts_by(|key, until| (*until > now).then(|| security_metric_key(key)))
            .await;
        let bucket_counts = self
            .buckets
            .counts_by(|key, _| Some(security_metric_key(key)))
            .await;
        SecurityRuntimeStats {
            active_blocks_total: block_counts.values().copied().sum(),
            token_buckets_total: bucket_counts.values().copied().sum(),
            active_blocks: security_metric_counts(block_counts),
            token_buckets: security_metric_counts(bucket_counts),
        }
    }

    async fn run_prune_loop(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tokio::time::sleep(SECURITY_PRUNE_INTERVAL) => {
                    self.prune_expired().await;
                    self.xdp.sync_static_policy(self.geo.as_ref(), self.threat.as_ref());
                }
            }
        }
        Ok(())
    }

    fn enabled(&self, listener: &ProxyListenerConfig) -> bool {
        self.listener(listener)
            .is_some_and(|runtime| runtime.config.enabled())
    }

    fn is_trusted_peer(&self, listener: &ProxyListenerConfig, ip: IpAddr) -> bool {
        self.listener(listener)
            .is_some_and(|runtime| runtime.is_trusted(ip))
    }

    async fn check_packet(
        &self,
        listener: &ProxyListenerConfig,
        peer: SocketAddr,
        packet: &[u8],
    ) -> SecurityDecision {
        let listener_key = listener.key();
        let Some(runtime) = self.listener_by_key(&listener_key) else {
            return SecurityDecision::Allow;
        };
        if !runtime.config.enabled() {
            return SecurityDecision::Allow;
        }
        if runtime.is_denied(peer.ip()) {
            return SecurityDecision::Drop("denied-cidr");
        }
        if !runtime.is_allowed(peer.ip()) {
            return SecurityDecision::Drop("not-allowed-cidr");
        }
        if runtime.is_trusted(peer.ip()) {
            return SecurityDecision::Allow;
        }

        let block_key = ip_security_key("block", listener_key.as_str(), peer.ip());
        if self.is_blocked(&block_key).await {
            return SecurityDecision::Drop("ip-blocked");
        }

        match evaluate_geo_policy(&runtime.geo_policy, self.geo.as_ref(), peer.ip()) {
            GeoDecision::Allow => {}
            GeoDecision::Drop(reason) => return SecurityDecision::Drop(reason),
        }

        match evaluate_threat_policy(&runtime.threat_policy, self.threat.as_ref(), peer.ip()) {
            ThreatDecision::Allow => {}
            ThreatDecision::Drop(reason) => return SecurityDecision::Drop(reason),
        }

        let flood = &runtime.config.flood;
        if flood.enabled {
            let (rate, burst, reason) = match listener.transport {
                SipTransport::Udp => (
                    flood.udp_packets_per_second,
                    flood.udp_burst,
                    "udp-flood-rate-limit",
                ),
                SipTransport::Tcp => (
                    flood.tcp_packets_per_second,
                    flood.tcp_burst,
                    "tcp-flood-rate-limit",
                ),
                SipTransport::TcpUdp => (
                    flood
                        .udp_packets_per_second
                        .max(flood.tcp_packets_per_second),
                    flood.udp_burst.max(flood.tcp_burst),
                    "tcp-udp-flood-rate-limit",
                ),
            };
            if rate > 0 && burst > 0 {
                let bucket_key = ip_security_key("flood-packets", listener_key.as_str(), peer.ip());
                if !self
                    .allow_bucket(bucket_key, rate as f64, burst as f64)
                    .await
                {
                    if flood.block_seconds > 0 {
                        let subject = peer.ip().to_string();
                        self.block_for(
                            &block_key,
                            flood.block_seconds,
                            listener_key.as_str(),
                            "ip",
                            subject.as_str(),
                            reason,
                        )
                        .await;
                    }
                    return SecurityDecision::Drop(reason);
                }
            }
        }

        let ip_rate = &runtime.config.ip_rate_limit;
        if ip_rate.enabled && ip_rate.packets_per_second > 0 && ip_rate.burst > 0 {
            let bucket_key = ip_security_key("packets", listener_key.as_str(), peer.ip());
            if !self
                .allow_bucket(
                    bucket_key,
                    ip_rate.packets_per_second as f64,
                    ip_rate.burst as f64,
                )
                .await
            {
                let subject = peer.ip().to_string();
                self.block_for(
                    &block_key,
                    ip_rate.block_seconds,
                    listener_key.as_str(),
                    "ip",
                    subject.as_str(),
                    "ip-rate-limit",
                )
                .await;
                return SecurityDecision::Drop("ip-rate-limit");
            }
        }

        let prefilter = &runtime.config.prefilter;
        if prefilter.enabled
            && prefilter.drop_invalid_start_line
            && !is_probable_sip_start_line(packet, prefilter.drop_non_sip_methods)
        {
            return SecurityDecision::Drop("invalid-start-line");
        }

        SecurityDecision::Allow
    }

    async fn record_parse_error(
        &self,
        listener: &ProxyListenerConfig,
        peer: SocketAddr,
    ) -> SecurityDecision {
        let listener_key = listener.key();
        let Some(runtime) = self.listener_by_key(&listener_key) else {
            return SecurityDecision::Allow;
        };
        if !runtime.config.enabled() || runtime.is_trusted(peer.ip()) {
            return SecurityDecision::Allow;
        }

        let ip_rate = &runtime.config.ip_rate_limit;
        if !ip_rate.enabled || ip_rate.parse_errors_per_minute == 0 {
            return SecurityDecision::Allow;
        }

        let bucket_key = ip_security_key("parse-errors", listener_key.as_str(), peer.ip());
        if self
            .allow_bucket(
                bucket_key,
                ip_rate.parse_errors_per_minute as f64 / 60.0,
                ip_rate.parse_errors_per_minute as f64,
            )
            .await
        {
            return SecurityDecision::Allow;
        }

        let block_key = ip_security_key("block", listener_key.as_str(), peer.ip());
        let subject = peer.ip().to_string();
        self.block_for(
            &block_key,
            ip_rate.block_seconds,
            listener_key.as_str(),
            "ip",
            subject.as_str(),
            "parse-error-rate-limit",
        )
        .await;
        SecurityDecision::Drop("parse-error-rate-limit")
    }

    async fn record_dynamic_offense(
        &self,
        listener: &ProxyListenerConfig,
        peer: SocketAddr,
        offense: Option<DynamicOffense>,
    ) -> Option<&'static str> {
        let offense = offense?;
        let listener_key = listener.key();
        let runtime = self.listener_by_key(&listener_key)?;
        if !runtime.config.dynamic_ban.enabled || runtime.is_trusted(peer.ip()) {
            return None;
        }
        let dynamic_ban = &runtime.config.dynamic_ban;
        let per_minute = match offense {
            DynamicOffense::InvalidPacket => dynamic_ban.invalid_packets_per_minute,
            DynamicOffense::ParseError => dynamic_ban.parse_errors_per_minute,
            DynamicOffense::SipRateViolation => dynamic_ban.sip_rate_violations_per_minute,
        };
        if per_minute == 0 {
            return None;
        }
        let bucket_key = format!(
            "dynamic-ban|{}|{}|{}",
            dynamic_offense_key(offense),
            listener_key,
            peer.ip()
        );
        if self
            .allow_bucket(bucket_key, per_minute as f64 / 60.0, per_minute as f64)
            .await
        {
            return None;
        }
        let block_key = ip_security_key("block", listener_key.as_str(), peer.ip());
        let subject = peer.ip().to_string();
        self.block_for(
            &block_key,
            dynamic_ban.ban_seconds,
            listener_key.as_str(),
            "ip",
            subject.as_str(),
            "dynamic-ban",
        )
        .await;
        Some("dynamic-ban")
    }

    async fn should_log_invalid_packet(
        &self,
        listener: &ProxyListenerConfig,
        peer: SocketAddr,
    ) -> bool {
        let listener_key = listener.key();
        let Some(runtime) = self.listener_by_key(&listener_key) else {
            return false;
        };
        let prefilter = &runtime.config.prefilter;
        if !prefilter.enabled || !prefilter.log_invalid_packets {
            return false;
        }
        let per_minute = prefilter.invalid_log_sample_per_minute;
        if per_minute == 0 {
            return false;
        }
        self.allow_bucket(
            ip_security_key("invalid-log", listener_key.as_str(), peer.ip()),
            per_minute as f64 / 60.0,
            per_minute as f64,
        )
        .await
    }

    async fn check_sip_request(
        &self,
        listener: &ProxyListenerConfig,
        peer: SocketAddr,
        message: &SipMessage,
        method: &str,
    ) -> Option<&'static str> {
        if matches!(method, "ACK" | "CANCEL") {
            return None;
        }
        let listener_key = listener.key();
        let runtime = self.listener_by_key(&listener_key)?;
        if !runtime.config.enabled() || runtime.is_trusted(peer.ip()) {
            return None;
        }
        let sip_rate = &runtime.config.sip_rate_limit;
        if !sip_rate.enabled {
            return None;
        }

        let (per_minute, reason) = match method {
            "REGISTER" if sip_rate.register_per_minute_per_aor > 0 => (
                sip_rate.register_per_minute_per_aor,
                "sip-register-rate-limit",
            ),
            "INVITE" if sip_rate.invite_per_minute_per_aor > 0 => {
                (sip_rate.invite_per_minute_per_aor, "sip-invite-rate-limit")
            }
            _ => return None,
        };

        let identity = sip_rate_identity(message, method, peer);
        let block_key = format!("sip-block|{listener_key}|{method}|{identity}");
        if self.is_blocked(&block_key).await {
            return Some("sip-blocked");
        }
        let bucket_key = format!("sip-rate|{listener_key}|{method}|{identity}");
        if self
            .allow_bucket(bucket_key, per_minute as f64 / 60.0, per_minute as f64)
            .await
        {
            return None;
        }

        self.block_for(
            &block_key,
            sip_rate.block_seconds,
            listener_key.as_str(),
            method,
            identity.as_str(),
            reason,
        )
        .await;
        Some(reason)
    }

    fn listener(&self, listener: &ProxyListenerConfig) -> Option<Arc<ListenerSecurityRuntime>> {
        self.listener_by_key(&listener.key())
    }

    fn listener_by_key(&self, listener_key: &str) -> Option<Arc<ListenerSecurityRuntime>> {
        self.listeners.load().get(listener_key).cloned()
    }

    async fn allow_bucket(&self, key: String, rate_per_second: f64, burst: f64) -> bool {
        if rate_per_second <= 0.0 || burst <= 0.0 {
            return true;
        }
        let now = Instant::now();
        let mut buckets = self.buckets.shard_for_key(&key).lock().await;
        let bucket = buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(rate_per_second, burst, now));
        bucket.allow(now, rate_per_second, burst)
    }

    async fn is_blocked(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut blocks = self.blocks.shard_for_key(key).lock().await;
        match blocks.get(key).copied() {
            Some(until) if until > now => true,
            Some(_) => {
                blocks.remove(key);
                false
            }
            None => false,
        }
    }

    async fn block_for(
        &self,
        key: &str,
        seconds: u64,
        listener_key: &str,
        subject_kind: &str,
        subject: &str,
        reason: &str,
    ) {
        if seconds == 0 {
            return;
        }
        let now = Instant::now();
        let Some(until) = now.checked_add(Duration::from_secs(seconds)) else {
            warn!(
                listener = %listener_key,
                subject_kind,
                subject,
                reason,
                ban_seconds = seconds,
                "security ban duration overflow; skipping ban"
            );
            return;
        };
        let action = {
            let mut blocks = self.blocks.shard_for_key(key).lock().await;
            match blocks.get(key).copied() {
                Some(existing) if existing > now && existing >= until => {
                    SecurityBanAction::Retained
                }
                Some(existing) if existing > now => {
                    blocks.insert(key.to_string(), until);
                    SecurityBanAction::Extended
                }
                _ => {
                    blocks.insert(key.to_string(), until);
                    SecurityBanAction::Installed
                }
            }
        };
        match action {
            SecurityBanAction::Installed => info!(
                listener = %listener_key,
                subject_kind,
                subject,
                reason,
                ban_seconds = seconds,
                "security ban installed"
            ),
            SecurityBanAction::Extended => info!(
                listener = %listener_key,
                subject_kind,
                subject,
                reason,
                ban_seconds = seconds,
                "security ban extended"
            ),
            SecurityBanAction::Retained => debug!(
                listener = %listener_key,
                subject_kind,
                subject,
                reason,
                ban_seconds = seconds,
                "security ban retained"
            ),
        }
        if matches!(
            action,
            SecurityBanAction::Installed | SecurityBanAction::Extended
        ) && subject_kind == "ip"
            && let Ok(ip) = subject.parse::<IpAddr>()
        {
            self.xdp
                .sync_ip_block(listener_key, ip, until, reason)
                .await;
        }
    }

    async fn prune_expired(&self) {
        let now = Instant::now();
        self.blocks.retain(|_, until| *until > now).await;
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.updated_at) <= SECURITY_BUCKET_IDLE_TTL)
            .await;
        self.xdp.prune_expired().await;
    }
}

struct ShardedStringMap<V> {
    shards: Vec<Mutex<HashMap<String, V>>>,
}

type ShardedSecurityMap<V> = ShardedStringMap<V>;

impl<V> ShardedStringMap<V> {
    fn new(shards: usize) -> Self {
        let shard_count = shards.max(1);
        Self {
            shards: (0..shard_count)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
        }
    }

    fn shard_for_key(&self, key: &str) -> &Mutex<HashMap<String, V>> {
        &self.shards[string_shard_index(key, self.shards.len())]
    }

    async fn retain<F>(&self, mut f: F)
    where
        F: FnMut(&String, &mut V) -> bool,
    {
        for shard in &self.shards {
            shard.lock().await.retain(|key, value| f(key, value));
        }
    }

    async fn remove(&self, key: &str) -> Option<V> {
        self.shard_for_key(key).lock().await.remove(key)
    }

    async fn len_after_retain<F>(&self, mut f: F) -> usize
    where
        F: FnMut(&String, &mut V) -> bool,
    {
        let mut len = 0;
        for shard in &self.shards {
            let mut entries = shard.lock().await;
            entries.retain(|key, value| f(key, value));
            len += entries.len();
        }
        len
    }

    async fn counts_by<F>(&self, mut f: F) -> BTreeMap<(String, String), u64>
    where
        F: FnMut(&String, &V) -> Option<(String, String)>,
    {
        let mut counts = BTreeMap::new();
        for shard in &self.shards {
            let entries = shard.lock().await;
            for (key, value) in entries.iter() {
                if let Some(metric_key) = f(key, value) {
                    *counts.entry(metric_key).or_insert(0) += 1;
                }
            }
        }
        counts
    }

    #[cfg(test)]
    async fn is_empty(&self) -> bool {
        for shard in &self.shards {
            if !shard.lock().await.is_empty() {
                return false;
            }
        }
        true
    }
}

fn string_shard_index(key: &str, shards: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % shards
}

fn security_metric_key(key: &str) -> (String, String) {
    let mut parts = key.split('|');
    match parts.next().unwrap_or("unknown") {
        "dynamic-ban" => {
            let _offense = parts.next();
            (
                parts.next().unwrap_or("unknown").to_string(),
                "dynamic-ban".to_string(),
            )
        }
        "sip-block" | "sip-rate" => {
            let kind = key.split('|').next().unwrap_or("unknown").to_string();
            let listener = key.split('|').nth(1).unwrap_or("unknown").to_string();
            (listener, kind)
        }
        kind => {
            let listener = parts.next().unwrap_or("unknown").to_string();
            (listener, kind.to_string())
        }
    }
}

fn security_metric_counts(counts: BTreeMap<(String, String), u64>) -> Vec<SecurityRuntimeCount> {
    counts
        .into_iter()
        .map(|((listener, kind), count)| SecurityRuntimeCount {
            listener,
            kind,
            count,
        })
        .collect()
}

struct ListenerSecurityRuntime {
    config: EffectiveProxySecurityConfig,
    geo_policy: GeoPolicy,
    threat_policy: ThreatPolicy,
    trusted_cidrs: Vec<Cidr>,
    allow_cidrs: Vec<Cidr>,
    deny_cidrs: Vec<Cidr>,
}

impl ListenerSecurityRuntime {
    fn new(config: EffectiveProxySecurityConfig) -> Result<Self> {
        Ok(Self {
            geo_policy: GeoPolicy::from_config(&config.geo),
            threat_policy: ThreatPolicy::from_config(&config.threat_intel),
            trusted_cidrs: parse_cidrs(&config.trusted_cidrs)?,
            allow_cidrs: parse_cidrs(&config.allow_cidrs)?,
            deny_cidrs: parse_cidrs(&config.deny_cidrs)?,
            config,
        })
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    fn is_allowed(&self, ip: IpAddr) -> bool {
        self.allow_cidrs.is_empty() || self.allow_cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    fn is_denied(&self, ip: IpAddr) -> bool {
        self.deny_cidrs.iter().any(|cidr| cidr.contains(ip))
    }
}

#[derive(Debug, Clone, Copy)]
struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        let (addr, prefix) = if let Some((addr, prefix)) = value.split_once('/') {
            (
                addr.parse::<IpAddr>()
                    .with_context(|| format!("invalid CIDR address '{value}'"))?,
                Some(
                    prefix
                        .parse::<u8>()
                        .with_context(|| format!("invalid CIDR prefix '{value}'"))?,
                ),
            )
        } else {
            (
                value
                    .parse::<IpAddr>()
                    .with_context(|| format!("invalid CIDR address '{value}'"))?,
                None,
            )
        };
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = prefix.unwrap_or(max_prefix);
        if prefix > max_prefix {
            bail!("CIDR prefix in '{value}' must be at most {max_prefix}");
        }
        Ok(Self { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix);
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix);
                (u128::from(network) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

fn parse_cidrs(values: &[String]) -> Result<Vec<Cidr>> {
    values.iter().map(|value| Cidr::parse(value)).collect()
}

#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    updated_at: Instant,
}

impl TokenBucket {
    fn new(_rate_per_second: f64, burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            updated_at: now,
        }
    }

    fn allow(&mut self, now: Instant, rate_per_second: f64, burst: f64) -> bool {
        let elapsed = now.duration_since(self.updated_at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate_per_second).min(burst);
        self.updated_at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn ip_security_key(kind: &str, listener_key: &str, ip: IpAddr) -> String {
    format!("{kind}|{listener_key}|{ip}")
}

fn dynamic_offense_for_reason(reason: &str) -> Option<DynamicOffense> {
    match reason {
        "invalid-start-line" => Some(DynamicOffense::InvalidPacket),
        "parse-error" | "parse-error-rate-limit" => Some(DynamicOffense::ParseError),
        "sip-register-rate-limit"
        | "sip-invite-rate-limit"
        | "sip-blocked"
        | "sip-invalid-from"
        | "sip-unregistered-invite"
        | "sip-unregistered-invite-source" => Some(DynamicOffense::SipRateViolation),
        _ => None,
    }
}

fn dynamic_offense_key(offense: DynamicOffense) -> &'static str {
    match offense {
        DynamicOffense::InvalidPacket => "invalid-packet",
        DynamicOffense::ParseError => "parse-error",
        DynamicOffense::SipRateViolation => "sip-rate-violation",
    }
}

fn is_probable_sip_start_line(packet: &[u8], require_known_method: bool) -> bool {
    let end = packet
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        .unwrap_or(packet.len());
    let Ok(line) = std::str::from_utf8(&packet[..end]) else {
        return false;
    };
    let line = line.trim();
    if line.starts_with("SIP/2.0 ") {
        return true;
    }
    if !line.contains(" SIP/2.0") {
        return false;
    }
    let Some(method) = line.split_ascii_whitespace().next() else {
        return false;
    };
    !require_known_method || is_known_sip_method(method)
}

fn is_known_sip_method(method: &str) -> bool {
    matches!(
        method,
        "INVITE"
            | "ACK"
            | "BYE"
            | "CANCEL"
            | "OPTIONS"
            | "REGISTER"
            | "MESSAGE"
            | "INFO"
            | "UPDATE"
            | "REFER"
            | "NOTIFY"
            | "PUBLISH"
            | "SUBSCRIBE"
            | "PRACK"
    )
}

fn sip_rate_identity(message: &SipMessage, method: &str, peer: SocketAddr) -> String {
    if method == "REGISTER"
        && let Ok(aor) = extract_aor(message)
    {
        return aor;
    }
    message
        .top_header_value("From")
        .ok()
        .flatten()
        .unwrap_or_else(|| peer.ip().to_string())
}

struct TcpUpstreamPool {
    connections: Mutex<HashMap<SocketAddr, Arc<TcpUpstreamConnection>>>,
    max_message_bytes: usize,
}

impl TcpUpstreamPool {
    fn new(max_message_bytes: usize) -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
            max_message_bytes,
        }
    }

    async fn send_request(
        &self,
        target: SocketAddr,
        branch: &str,
        packet: &[u8],
    ) -> Result<mpsc::UnboundedReceiver<Vec<u8>>> {
        let mut last_error = None;
        for _ in 0..2 {
            let connection = self.get_or_connect(target).await?;
            match connection.send_request(branch, packet).await {
                Ok(responses) => return Ok(responses),
                Err(err) => {
                    last_error = Some(err);
                    self.remove_if_same(target, &connection).await;
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("failed to send TCP upstream request")))
    }

    async fn get_or_connect(&self, target: SocketAddr) -> Result<Arc<TcpUpstreamConnection>> {
        if let Some(connection) = self.connections.lock().await.get(&target).cloned()
            && connection.is_alive()
        {
            return Ok(connection);
        }

        let connection = TcpUpstreamConnection::connect(target, self.max_message_bytes).await?;
        self.connections
            .lock()
            .await
            .insert(target, connection.clone());
        Ok(connection)
    }

    async fn remove_if_same(&self, target: SocketAddr, connection: &Arc<TcpUpstreamConnection>) {
        let mut connections = self.connections.lock().await;
        if let Some(existing) = connections.get(&target)
            && Arc::ptr_eq(existing, connection)
        {
            connections.remove(&target);
        }
    }

    async fn active_counts(&self) -> (usize, usize) {
        let connections = self
            .connections
            .lock()
            .await
            .values()
            .filter(|connection| connection.is_alive())
            .cloned()
            .collect::<Vec<_>>();
        let mut branch_count = 0;
        for connection in &connections {
            let mut branches = connection.branches.lock().await;
            prune_tcp_branches(&mut branches, Instant::now());
            branch_count += branches.len();
        }
        (connections.len(), branch_count)
    }
}

struct TcpUpstreamConnection {
    target: SocketAddr,
    writer: Mutex<OwnedWriteHalf>,
    branches: Mutex<HashMap<String, TcpBranchRoute>>,
    alive: AtomicBool,
}

struct TcpBranchRoute {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    created_at: Instant,
}

impl TcpUpstreamConnection {
    async fn connect(target: SocketAddr, max_message_bytes: usize) -> Result<Arc<Self>> {
        let stream = timeout(UPSTREAM_TIMEOUT, TcpStream::connect(target))
            .await
            .context("upstream SIP TCP connect timed out")??;
        let (read_half, write_half) = stream.into_split();
        let connection = Arc::new(Self {
            target,
            writer: Mutex::new(write_half),
            branches: Mutex::new(HashMap::new()),
            alive: AtomicBool::new(true),
        });
        tokio::spawn(run_tcp_upstream_reader(
            connection.clone(),
            read_half,
            max_message_bytes,
        ));
        Ok(connection)
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    async fn send_request(
        &self,
        branch: &str,
        packet: &[u8],
    ) -> Result<mpsc::UnboundedReceiver<Vec<u8>>> {
        if !self.is_alive() {
            bail!("upstream SIP TCP connection {} is closed", self.target);
        }

        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut branches = self.branches.lock().await;
            prune_tcp_branches(&mut branches, Instant::now());
            branches.insert(
                branch.to_string(),
                TcpBranchRoute {
                    tx,
                    created_at: Instant::now(),
                },
            );
        }

        let write_result = timeout(UPSTREAM_TIMEOUT, self.writer.lock().await.write_all(packet))
            .await
            .context("upstream SIP TCP write timed out")?;
        if let Err(err) = write_result {
            self.branches.lock().await.remove(branch);
            self.alive.store(false, Ordering::Relaxed);
            return Err(err).context("failed to write SIP request to upstream TCP connection");
        }
        Ok(rx)
    }
}

async fn run_tcp_upstream_reader(
    connection: Arc<TcpUpstreamConnection>,
    mut read_half: OwnedReadHalf,
    max_message_bytes: usize,
) {
    let mut reader = TcpSipReader::new(max_message_bytes);
    loop {
        let packet = match reader.read_message(&mut read_half).await {
            Ok(Some(packet)) => packet,
            Ok(None) => break,
            Err(err) => {
                warn!(
                    target = %connection.target,
                    error = %err,
                    "upstream SIP TCP reader failed"
                );
                break;
            }
        };

        if let Err(err) = dispatch_tcp_upstream_response(&connection, packet).await {
            warn!(
                target = %connection.target,
                error = %err,
                "failed to dispatch upstream SIP TCP response"
            );
        }
    }
    connection.alive.store(false, Ordering::Relaxed);
    connection.branches.lock().await.clear();
    debug!(target = %connection.target, "upstream SIP TCP connection closed");
}

async fn dispatch_tcp_upstream_response(
    connection: &TcpUpstreamConnection,
    packet: Vec<u8>,
) -> Result<()> {
    let mut message = SipMessage::parse(&packet)?;
    let branch = message
        .top_via_branch()?
        .context("upstream TCP response is missing top Via branch")?;
    if !branch.starts_with(PROXY_BRANCH_PREFIX) {
        debug!(
            target = %connection.target,
            branch = %branch,
            "dropping TCP response whose top Via branch was not created by this proxy"
        );
        return Ok(());
    }

    let is_final = matches!(
        &message.start_line,
        SipStartLine::Response { code, .. } if *code >= 200
    );
    message
        .pop_top_via()?
        .context("upstream TCP response is missing Via")?;
    let response = message.to_bytes();

    let route = {
        let mut branches = connection.branches.lock().await;
        prune_tcp_branches(&mut branches, Instant::now());
        let Some(route) = branches.get(&branch) else {
            warn!(
                target = %connection.target,
                branch = %branch,
                "dropping TCP response without a matching client branch route"
            );
            return Ok(());
        };
        let tx = route.tx.clone();
        if is_final {
            branches.remove(&branch);
        }
        tx
    };

    let _ = route.send(response);
    Ok(())
}

fn prune_tcp_branches(branches: &mut HashMap<String, TcpBranchRoute>, now: Instant) {
    branches.retain(|_, route| now.duration_since(route.created_at) <= TCP_BRANCH_TTL);
}

impl UpstreamGroups {
    fn new(configs: &[UpstreamGroupConfig]) -> Result<Self> {
        let groups = configs
            .iter()
            .map(|config| {
                Ok((
                    config.name.clone(),
                    Arc::new(UpstreamGroupRuntime::new(config)?),
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        let mut servers_by_addr: HashMap<SocketAddr, Vec<UpstreamServerRef>> = HashMap::new();
        for group in groups.values() {
            let mut seen_in_group = HashSet::new();
            for (index, server) in group.servers.iter().copied().enumerate() {
                if seen_in_group.insert(server) {
                    servers_by_addr
                        .entry(server)
                        .or_default()
                        .push(UpstreamServerRef {
                            group: group.clone(),
                            index,
                        });
                }
            }
        }
        Ok(Self {
            groups,
            servers_by_addr,
        })
    }

    fn select(&self, name: &str) -> Result<SocketAddr> {
        let Some(group) = self.groups.get(name) else {
            bail!("unknown upstream group '{name}'");
        };
        group.select()
    }

    fn record_passive_result(&self, server: SocketAddr, healthy: bool) {
        if let Some(servers) = self.servers_by_addr.get(&server) {
            for server in servers {
                server.group.record_passive_result_at(server.index, healthy);
            }
        }
    }

    fn is_healthy(&self, server: SocketAddr) -> bool {
        self.servers_by_addr
            .get(&server)
            .map(|servers| {
                servers
                    .iter()
                    .any(|server| server.group.is_healthy_at(server.index))
            })
            .unwrap_or(true)
    }

    fn contains(&self, server: SocketAddr) -> bool {
        self.servers_by_addr.contains_key(&server)
    }

    fn health_snapshots(&self) -> Vec<UpstreamHealthSnapshot> {
        self.groups
            .values()
            .flat_map(|group| group.health_snapshots())
            .collect()
    }
}

struct UpstreamHealthSnapshot {
    group: String,
    server: String,
    healthy: bool,
    consecutive_successes: usize,
    consecutive_failures: usize,
}

struct HealthRecordUpdate {
    was_healthy: bool,
    is_healthy: bool,
    consecutive_successes: usize,
    consecutive_failures: usize,
}

struct UpstreamGroupRuntime {
    name: String,
    servers: Vec<SocketAddr>,
    health: Vec<AtomicBool>,
    consecutive_successes: Vec<AtomicUsize>,
    consecutive_failures: Vec<AtomicUsize>,
    next: AtomicUsize,
    health_check: UpstreamHealthCheckConfig,
}

impl UpstreamGroupRuntime {
    fn new(config: &UpstreamGroupConfig) -> Result<Self> {
        let servers = config
            .servers
            .iter()
            .map(|server| resolve_upstream_server(&config.name, server))
            .collect::<Result<Vec<_>>>()?;
        let health = servers.iter().map(|_| AtomicBool::new(true)).collect();
        let consecutive_successes = servers.iter().map(|_| AtomicUsize::new(0)).collect();
        let consecutive_failures = servers.iter().map(|_| AtomicUsize::new(0)).collect();
        Ok(Self {
            name: config.name.clone(),
            servers,
            health,
            consecutive_successes,
            consecutive_failures,
            next: AtomicUsize::new(0),
            health_check: config.health_check.clone(),
        })
    }

    fn select(&self) -> Result<SocketAddr> {
        if self.servers.is_empty() {
            bail!("upstream group '{}' has no servers", self.name);
        }

        for _ in 0..self.servers.len() {
            let index = self.next.fetch_add(1, Ordering::Relaxed) % self.servers.len();
            if self.health[index].load(Ordering::Relaxed) {
                return Ok(self.servers[index]);
            }
        }

        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.servers.len();
        Ok(self.servers[index])
    }

    #[cfg(test)]
    fn set_health(&self, index: usize, healthy: bool) {
        self.health[index].store(healthy, Ordering::Relaxed);
        self.consecutive_successes[index].store(0, Ordering::Relaxed);
        self.consecutive_failures[index].store(0, Ordering::Relaxed);
    }

    fn record_health_result(&self, index: usize, healthy: bool) -> HealthRecordUpdate {
        let was_healthy = self.health[index].load(Ordering::Relaxed);
        if healthy {
            self.consecutive_failures[index].store(0, Ordering::Relaxed);
            let successes = self.consecutive_successes[index].fetch_add(1, Ordering::Relaxed) + 1;
            if successes >= self.health_check.success_threshold {
                self.health[index].store(true, Ordering::Relaxed);
            }
        } else {
            self.consecutive_successes[index].store(0, Ordering::Relaxed);
            let failures = self.consecutive_failures[index].fetch_add(1, Ordering::Relaxed) + 1;
            if failures >= self.health_check.failure_threshold {
                self.health[index].store(false, Ordering::Relaxed);
            }
        }
        HealthRecordUpdate {
            was_healthy,
            is_healthy: self.health[index].load(Ordering::Relaxed),
            consecutive_successes: self.consecutive_successes[index].load(Ordering::Relaxed),
            consecutive_failures: self.consecutive_failures[index].load(Ordering::Relaxed),
        }
    }

    fn record_passive_result_at(&self, index: usize, healthy: bool) {
        if !self.health_check.enabled {
            return;
        }
        if index < self.servers.len() {
            self.record_health_result(index, healthy);
        }
    }

    fn is_healthy_at(&self, index: usize) -> bool {
        self.health[index].load(Ordering::Relaxed)
    }

    fn health_snapshots(&self) -> Vec<UpstreamHealthSnapshot> {
        self.servers
            .iter()
            .enumerate()
            .map(|(index, server)| UpstreamHealthSnapshot {
                group: self.name.clone(),
                server: server.to_string(),
                healthy: self.health[index].load(Ordering::Relaxed),
                consecutive_successes: self.consecutive_successes[index].load(Ordering::Relaxed),
                consecutive_failures: self.consecutive_failures[index].load(Ordering::Relaxed),
            })
            .collect()
    }
}

fn resolve_upstream_server(group: &str, server: &str) -> Result<SocketAddr> {
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = server
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve upstream '{server}' in group '{group}'"))?;
    addrs.next().with_context(|| {
        format!("upstream '{server}' in group '{group}' did not resolve to any address")
    })
}

async fn run_health_checks(
    group: Arc<UpstreamGroupRuntime>,
    role_provider: Arc<dyn ClusterReplicator>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let probes = HealthCheckRuntime::new(&group).await?;
    let interval = Duration::from_millis(group.health_check.interval_ms);
    loop {
        if *shutdown.borrow() {
            break;
        }
        let role = role_provider.role().await;
        let sleep_interval = if role.accepts_writes() {
            run_health_check_round(group.clone(), &probes).await;
            interval
        } else {
            debug!(
                group = %group.name,
                role = ?role,
                "skipping backend health check while node is not active"
            );
            HEALTH_CHECK_STANDBY_ROLE_POLL_INTERVAL
        };
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(sleep_interval) => {}
        }
    }
    Ok(())
}

struct HealthCheckRuntime {
    udp_sockets: Vec<Option<Arc<UdpSocket>>>,
    tcp_streams: Vec<Option<Arc<Mutex<Option<TcpStream>>>>>,
    failure_logs: Vec<Mutex<HealthCheckFailureLog>>,
}

impl HealthCheckRuntime {
    async fn new(group: &UpstreamGroupRuntime) -> Result<Self> {
        let probe_transport = match group.health_check.probe {
            UpstreamHealthProbeConfig::Options { transport, .. } => Some(transport),
            UpstreamHealthProbeConfig::TcpConnect => None,
        };
        let mut udp_sockets = Vec::with_capacity(group.servers.len());
        let mut tcp_streams = Vec::with_capacity(group.servers.len());
        for server in group.servers.iter().copied() {
            if probe_transport == Some(SipTransport::Udp) {
                let socket = bind_health_probe_udp_socket(server)
                    .await
                    .with_context(|| {
                        format!("failed to bind UDP health-check socket for {server}")
                    })?;
                udp_sockets.push(Some(Arc::new(socket)));
            } else {
                udp_sockets.push(None);
            }
            if probe_transport == Some(SipTransport::Tcp) {
                tcp_streams.push(Some(Arc::new(Mutex::new(None))));
            } else {
                tcp_streams.push(None);
            }
        }
        Ok(Self {
            udp_sockets,
            tcp_streams,
            failure_logs: group
                .servers
                .iter()
                .map(|_| Mutex::new(HealthCheckFailureLog::default()))
                .collect(),
        })
    }

    fn udp_socket(&self, index: usize) -> Option<Arc<UdpSocket>> {
        self.udp_sockets.get(index).cloned().flatten()
    }

    fn tcp_stream(&self, index: usize) -> Option<Arc<Mutex<Option<TcpStream>>>> {
        self.tcp_streams.get(index).cloned().flatten()
    }

    async fn failure_warning_due(&self, index: usize, now: Instant) -> Option<Option<u64>> {
        let log = self.failure_logs.get(index)?;
        Some(log.lock().await.warn_if_due(now))
    }

    async fn recover_failure_log(&self, index: usize) -> Option<u64> {
        let log = self.failure_logs.get(index)?;
        log.lock().await.recovered()
    }
}

#[derive(Debug, Default)]
struct HealthCheckFailureLog {
    last_warning: Option<Instant>,
    suppressed: u64,
}

impl HealthCheckFailureLog {
    fn warn_if_due(&mut self, now: Instant) -> Option<u64> {
        if self
            .last_warning
            .is_some_and(|last| now.duration_since(last) < HEALTH_CHECK_FAILURE_LOG_INTERVAL)
        {
            self.suppressed += 1;
            return None;
        }

        let suppressed = self.suppressed;
        self.suppressed = 0;
        self.last_warning = Some(now);
        Some(suppressed)
    }

    fn recovered(&mut self) -> Option<u64> {
        self.last_warning?;
        let suppressed = self.suppressed;
        self.last_warning = None;
        self.suppressed = 0;
        Some(suppressed)
    }
}

async fn run_health_check_round(group: Arc<UpstreamGroupRuntime>, probes: &HealthCheckRuntime) {
    let mut checks = tokio::task::JoinSet::new();
    for (index, server) in group.servers.iter().copied().enumerate() {
        let config = group.health_check.clone();
        let udp_socket = probes.udp_socket(index);
        let tcp_stream = probes.tcp_stream(index);
        checks.spawn(async move {
            let result = probe_upstream_health(server, &config, udp_socket, tcp_stream).await;
            (index, server, result)
        });
    }

    while let Some(result) = checks.join_next().await {
        let Ok((index, server, result)) = result else {
            warn!("backend health check task failed");
            continue;
        };
        let update = group.record_health_result(index, result.healthy);
        let mode = health_probe_mode(&group.health_check.probe);
        if !result.healthy {
            let reason = result
                .reason
                .as_deref()
                .unwrap_or("probe returned unhealthy");
            match probes.failure_warning_due(index, Instant::now()).await {
                Some(Some(suppressed)) => {
                    warn!(
                        group = %group.name,
                        %server,
                        mode,
                        reason,
                        consecutive_failures = update.consecutive_failures,
                        failure_threshold = group.health_check.failure_threshold,
                        currently_healthy = update.is_healthy,
                        suppressed_health_check_failures = suppressed,
                        "backend health check failed"
                    );
                }
                Some(None) => {
                    debug!(
                        group = %group.name,
                        %server,
                        mode,
                        reason,
                        consecutive_failures = update.consecutive_failures,
                        failure_threshold = group.health_check.failure_threshold,
                        currently_healthy = update.is_healthy,
                        "backend health check failed"
                    );
                }
                None => {
                    warn!(
                        group = %group.name,
                        %server,
                        mode,
                        reason,
                        consecutive_failures = update.consecutive_failures,
                        failure_threshold = group.health_check.failure_threshold,
                        currently_healthy = update.is_healthy,
                        "backend health check failed"
                    );
                }
            }
        } else {
            let _ = probes.recover_failure_log(index).await;
        }
        if update.was_healthy && !update.is_healthy {
            warn!(
                group = %group.name,
                %server,
                mode,
                consecutive_failures = update.consecutive_failures,
                "backend marked unhealthy"
            );
        } else if !update.was_healthy && update.is_healthy {
            info!(
                group = %group.name,
                %server,
                mode,
                consecutive_successes = update.consecutive_successes,
                "backend marked healthy"
            );
        }
        debug!(
            group = %group.name,
            %server,
            healthy = result.healthy,
            mode,
            "backend health check completed"
        );
    }
}

struct HealthProbeResult {
    healthy: bool,
    reason: Option<String>,
}

impl HealthProbeResult {
    fn healthy() -> Self {
        Self {
            healthy: true,
            reason: None,
        }
    }

    fn failed(reason: impl Into<String>) -> Self {
        Self {
            healthy: false,
            reason: Some(reason.into()),
        }
    }
}

async fn probe_upstream_health(
    server: SocketAddr,
    config: &UpstreamHealthCheckConfig,
    udp_socket: Option<Arc<UdpSocket>>,
    tcp_stream: Option<Arc<Mutex<Option<TcpStream>>>>,
) -> HealthProbeResult {
    let limit = Duration::from_millis(config.timeout_ms);
    match &config.probe {
        UpstreamHealthProbeConfig::Options {
            transport,
            uri,
            success_codes,
            vary_call_id,
        } => {
            probe_sip_options(
                SipOptionsProbe {
                    server,
                    transport: *transport,
                    uri,
                    vary_call_id: *vary_call_id,
                    limit,
                    success_codes,
                },
                udp_socket,
                tcp_stream,
            )
            .await
        }
        UpstreamHealthProbeConfig::TcpConnect => probe_tcp_connect(server, limit).await,
    }
}

fn health_probe_mode(probe: &UpstreamHealthProbeConfig) -> &'static str {
    match probe {
        UpstreamHealthProbeConfig::Options { .. } => "options",
        UpstreamHealthProbeConfig::TcpConnect => "tcp-connect",
    }
}

struct SipOptionsProbe<'a> {
    server: SocketAddr,
    transport: SipTransport,
    uri: &'a str,
    vary_call_id: bool,
    limit: Duration,
    success_codes: &'a [u16],
}

async fn probe_sip_options(
    probe: SipOptionsProbe<'_>,
    udp_socket: Option<Arc<UdpSocket>>,
    tcp_stream: Option<Arc<Mutex<Option<TcpStream>>>>,
) -> HealthProbeResult {
    let future = async {
        match probe.transport {
            SipTransport::Udp => {
                let socket = udp_socket.context("missing UDP health-check socket")?;
                probe_sip_options_udp(probe.server, probe.uri, probe.vary_call_id, socket).await
            }
            SipTransport::Tcp => {
                let stream = tcp_stream.context("missing TCP health-check stream")?;
                probe_sip_options_tcp(probe.server, probe.uri, probe.vary_call_id, stream).await
            }
            SipTransport::TcpUdp => bail!("SIP OPTIONS health-check transport must be udp or tcp"),
        }
    };
    let Ok(response) = timeout(probe.limit, future).await else {
        return HealthProbeResult::failed(format!("SIP OPTIONS timed out after {:?}", probe.limit));
    };
    let response = match response {
        Ok(response) => response,
        Err(err) => {
            return HealthProbeResult::failed(format!("SIP OPTIONS probe failed: {err:#}"));
        }
    };
    let message = match SipMessage::parse(&response) {
        Ok(message) => message,
        Err(err) => {
            return HealthProbeResult::failed(format!(
                "SIP OPTIONS returned invalid SIP response: {err:#}"
            ));
        }
    };
    match message.start_line {
        SipStartLine::Response { code, .. } => {
            let accepted = if probe.success_codes.is_empty() {
                code < 500
            } else {
                probe.success_codes.contains(&code)
            };
            if accepted {
                HealthProbeResult::healthy()
            } else {
                HealthProbeResult::failed(format!(
                    "SIP OPTIONS returned status {code}, expected one of {:?}",
                    probe.success_codes
                ))
            }
        }
        SipStartLine::Request { .. } => {
            HealthProbeResult::failed("SIP OPTIONS probe received a request instead of a response")
        }
    }
}

struct HealthOptionsRequest {
    packet: Vec<u8>,
    branch: String,
}

fn build_health_options_request(
    server: SocketAddr,
    uri: &str,
    transport: SipTransport,
    sent_by: SocketAddr,
    vary_call_id: bool,
) -> Result<HealthOptionsRequest> {
    let id = unique_id();
    let branch = format!("z9hG4bK-health-{id}");
    let cseq = cseq_from_id(id);
    let call_id = health_options_call_id(server, transport, uri, vary_call_id.then_some(id));
    let packet = SipMessage::options_request(
        uri,
        rsip_transport_from_sip(transport),
        sent_by,
        branch.clone(),
        format!("health-{id}"),
        call_id,
        cseq,
    )?
    .to_bytes();
    Ok(HealthOptionsRequest { packet, branch })
}

fn cseq_from_id(id: u64) -> u32 {
    ((id.saturating_sub(1) % u64::from(u32::MAX)) + 1) as u32
}

fn health_options_call_id(
    server: SocketAddr,
    transport: SipTransport,
    uri: &str,
    request_id: Option<u64>,
) -> String {
    let key = if let Some(request_id) = request_id {
        format!(
            "health|{}|{}|{}|{}|{}",
            std::process::id(),
            transport.as_str(),
            server,
            uri,
            request_id
        )
    } else {
        format!(
            "health|{}|{}|{}|{}",
            std::process::id(),
            transport.as_str(),
            server,
            uri
        )
    };
    format!("{}@sipproxy-rs", uuid_like_id(&key))
}

fn uuid_like_id(key: &str) -> String {
    let mut hash = 0x6a09_e667_f3bc_c908_bb67_ae85_84ca_a73b_u128;
    for byte in key.bytes() {
        hash ^= u128::from(byte);
        hash = hash.wrapping_mul(0x0000_0000_0100_0000_0000_0000_0000_013b_u128);
        hash ^= hash >> 64;
    }

    let mut bytes = hash.to_be_bytes();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{}-{}-{}-{}-{}",
        hex_bytes(&bytes[0..4]),
        hex_bytes(&bytes[4..6]),
        hex_bytes(&bytes[6..8]),
        hex_bytes(&bytes[8..10]),
        hex_bytes(&bytes[10..16])
    )
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

async fn bind_health_probe_udp_socket(server: SocketAddr) -> Result<UdpSocket> {
    let bind_addr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(server).await?;
    Ok(socket)
}

async fn probe_sip_options_udp(
    server: SocketAddr,
    uri: &str,
    vary_call_id: bool,
    socket: Arc<UdpSocket>,
) -> Result<Vec<u8>> {
    let request = build_health_options_request(
        server,
        uri,
        SipTransport::Udp,
        socket.local_addr()?,
        vary_call_id,
    )?;
    socket.send(&request.packet).await?;
    let mut buf = vec![0; 65_535];
    loop {
        let len = socket.recv(&mut buf).await?;
        let response = buf[..len].to_vec();
        if health_options_response_matches_branch(&response, &request.branch)? {
            return Ok(response);
        }
    }
}

fn health_options_response_matches_branch(response: &[u8], branch: &str) -> Result<bool> {
    let message = SipMessage::parse(response)?;
    if !matches!(message.start_line, SipStartLine::Response { .. }) {
        return Ok(true);
    }
    if message.header("Via").is_none() {
        return Ok(true);
    }
    Ok(message
        .top_via_branch()?
        .is_none_or(|response_branch| response_branch == branch))
}

async fn probe_sip_options_tcp(
    server: SocketAddr,
    uri: &str,
    vary_call_id: bool,
    stream_slot: Arc<Mutex<Option<TcpStream>>>,
) -> Result<Vec<u8>> {
    let mut stream_guard = stream_slot.lock().await;
    if stream_guard.is_none() {
        *stream_guard = Some(TcpStream::connect(server).await?);
    }

    let stream = stream_guard.as_mut().expect("stream initialized above");
    let request = build_health_options_request(
        server,
        uri,
        SipTransport::Tcp,
        stream.local_addr()?,
        vary_call_id,
    )?;
    if let Err(err) = stream.write_all(&request.packet).await {
        *stream_guard = None;
        return Err(err).context("failed to write SIP OPTIONS to upstream TCP connection");
    }

    let mut reader = TcpSipReader::new(65_535);
    loop {
        let response = match reader.read_message(stream).await {
            Ok(Some(response)) => response,
            Ok(None) => {
                *stream_guard = None;
                bail!("upstream SIP TCP connection closed without health-check response");
            }
            Err(err) => {
                *stream_guard = None;
                return Err(err);
            }
        };
        if health_options_response_matches_branch(&response, &request.branch)? {
            return Ok(response);
        }
    }
}

async fn probe_tcp_connect(server: SocketAddr, limit: Duration) -> HealthProbeResult {
    match timeout(limit, TcpStream::connect(server)).await {
        Ok(Ok(_)) => HealthProbeResult::healthy(),
        Ok(Err(err)) => HealthProbeResult::failed(format!("TCP connect failed: {err:#}")),
        Err(_) => HealthProbeResult::failed(format!("TCP connect timed out after {:?}", limit)),
    }
}

fn prune_udp_branches(branches: &mut HashMap<String, UdpBranchRoute>, now: Instant) {
    branches.retain(|_, route| now.duration_since(route.created_at) <= UDP_BRANCH_TTL);
}

fn prune_udp_client_transactions(
    transactions: &mut HashMap<String, UdpClientTransactionRoute>,
    now: Instant,
) {
    transactions.retain(|_, route| now.duration_since(route.created_at) <= UDP_BRANCH_TTL);
}

fn enforce_udp_client_transaction_shard_limit(
    transactions: &mut HashMap<String, UdpClientTransactionRoute>,
    limit: usize,
) {
    while transactions.len() > limit {
        let Some(oldest_key) = transactions
            .iter()
            .min_by_key(|(_, route)| route.created_at)
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        transactions.remove(&oldest_key);
    }
}

fn prune_pending_registers(registers: &mut HashMap<String, PendingRegister>, now: Instant) {
    registers.retain(|_, pending| now.duration_since(pending.created_at) <= PENDING_REGISTER_TTL);
}

fn prune_local_invite_rejections(rejections: &mut HashMap<String, Instant>, now: Instant) {
    rejections
        .retain(|_, created_at| now.duration_since(*created_at) <= LOCAL_INVITE_REJECTION_TTL);
}

fn should_record_forward_affinity(method: &str) -> bool {
    !method.eq_ignore_ascii_case("OPTIONS")
}

fn metric_transport_index(transport: &str) -> Option<usize> {
    match transport {
        "udp" => Some(0),
        "tcp" => Some(1),
        _ => None,
    }
}

fn sip_transport_metric_index(transport: SipTransport) -> usize {
    match transport {
        SipTransport::Udp => 0,
        SipTransport::Tcp => 1,
        SipTransport::TcpUdp => unreachable!("tcp_udp metrics transport must be expanded"),
    }
}

fn metric_method_index(method: &str) -> Option<usize> {
    match method {
        "ACK" => Some(0),
        "BYE" => Some(1),
        "CANCEL" => Some(2),
        "INVITE" => Some(3),
        "MESSAGE" => Some(4),
        "OPTIONS" => Some(5),
        "REGISTER" => Some(6),
        "UNKNOWN" => Some(7),
        _ => None,
    }
}

fn is_crlf_keepalive(packet: &[u8]) -> bool {
    packet.is_empty() || packet.iter().all(|byte| matches!(byte, b'\r' | b'\n'))
}

fn is_stun_packet(packet: &[u8]) -> bool {
    packet.len() >= 20
        && packet[0] & 0b1100_0000 == 0
        && u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) == STUN_MAGIC_COOKIE
        && 20 + u16::from_be_bytes([packet[2], packet[3]]) as usize <= packet.len()
}

async fn discover_public_ip(server: &str) -> Result<IpAddr> {
    let server = resolve_probe_addr(server)?;
    let bind_addr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(server).await?;
    let request = stun_binding_request();
    socket.send(&request).await?;

    let mut buf = [0_u8; 1500];
    let len = timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .context("STUN request timed out")??;
    parse_stun_mapped_addr(&buf[..len])
        .map(|addr| addr.ip())
        .context("STUN response did not contain a mapped address")
}

fn resolve_probe_addr(addr: &str) -> Result<SocketAddr> {
    if let Ok(addr) = addr.parse::<SocketAddr>() {
        return Ok(addr);
    }
    addr.to_socket_addrs()?
        .next()
        .with_context(|| format!("probe target '{addr}' did not resolve to any address"))
}

fn stun_binding_request() -> Vec<u8> {
    let id = unique_id();
    let mut transaction_id = [0_u8; 12];
    transaction_id[4..12].copy_from_slice(&id.to_be_bytes());

    let mut request = Vec::with_capacity(20);
    request.extend_from_slice(&0x0001_u16.to_be_bytes());
    request.extend_from_slice(&0_u16.to_be_bytes());
    request.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request.extend_from_slice(&transaction_id);
    request
}

fn parse_stun_mapped_addr(packet: &[u8]) -> Option<SocketAddr> {
    if !is_stun_packet(packet) || u16::from_be_bytes([packet[0], packet[1]]) != 0x0101 {
        return None;
    }
    let transaction_id = &packet[8..20];
    let mut offset = 20;
    while offset + 4 <= packet.len() {
        let attr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let attr_len = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + attr_len;
        if value_end > packet.len() {
            return None;
        }
        let value = &packet[value_start..value_end];
        let mapped = match attr_type {
            0x0020 => parse_stun_xor_mapped_addr(value, transaction_id),
            0x0001 => parse_stun_plain_mapped_addr(value),
            _ => None,
        };
        if mapped.is_some() {
            return mapped;
        }
        offset = value_end + ((4 - (attr_len % 4)) % 4);
    }
    None
}

fn parse_stun_xor_mapped_addr(value: &[u8], transaction_id: &[u8]) -> Option<SocketAddr> {
    if value.len() < 8 || transaction_id.len() != 12 {
        return None;
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]) ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    match family {
        0x01 if value.len() >= 8 => {
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            let octets = [
                value[4] ^ cookie[0],
                value[5] ^ cookie[1],
                value[6] ^ cookie[2],
                value[7] ^ cookie[3],
            ];
            Some(SocketAddr::new(IpAddr::from(octets), port))
        }
        0x02 if value.len() >= 20 => {
            let mut mask = [0_u8; 16];
            mask[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(transaction_id);
            let mut octets = [0_u8; 16];
            for index in 0..16 {
                octets[index] = value[4 + index] ^ mask[index];
            }
            Some(SocketAddr::new(IpAddr::from(octets), port))
        }
        _ => None,
    }
}

fn parse_stun_plain_mapped_addr(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 8 {
        return None;
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);
    match family {
        0x01 if value.len() >= 8 => Some(SocketAddr::new(
            IpAddr::from([value[4], value[5], value[6], value[7]]),
            port,
        )),
        0x02 if value.len() >= 20 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&value[4..20]);
            Some(SocketAddr::new(IpAddr::from(octets), port))
        }
        _ => None,
    }
}

fn stun_binding_success_response(packet: &[u8], peer: SocketAddr) -> Option<Vec<u8>> {
    if !is_stun_packet(packet) || u16::from_be_bytes([packet[0], packet[1]]) != 0x0001 {
        return None;
    }

    let transaction_id = &packet[8..20];
    let attr = stun_xor_mapped_address_attr(peer, transaction_id);
    let mut response = Vec::with_capacity(20 + attr.len());
    response.extend_from_slice(&0x0101_u16.to_be_bytes());
    response.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    response.extend_from_slice(transaction_id);
    response.extend_from_slice(&attr);
    Some(response)
}

fn stun_xor_mapped_address_attr(peer: SocketAddr, transaction_id: &[u8]) -> Vec<u8> {
    let xor_port = peer.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let mut value = Vec::new();
    value.push(0);
    match peer.ip() {
        IpAddr::V4(ip) => {
            value.push(0x01);
            value.extend_from_slice(&xor_port.to_be_bytes());
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            for (byte, mask) in ip.octets().iter().zip(cookie.iter()) {
                value.push(byte ^ mask);
            }
        }
        IpAddr::V6(ip) => {
            value.push(0x02);
            value.extend_from_slice(&xor_port.to_be_bytes());
            let mut mask = [0_u8; 16];
            mask[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(transaction_id);
            for (byte, mask) in ip.octets().iter().zip(mask.iter()) {
                value.push(byte ^ mask);
            }
        }
    }

    let mut attr = Vec::with_capacity(4 + value.len());
    attr.extend_from_slice(&0x0020_u16.to_be_bytes());
    attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attr.extend_from_slice(&value);
    attr
}

fn packet_preview(packet: &[u8]) -> String {
    let mut output = String::new();
    for byte in packet.iter().take(48) {
        match byte {
            b'\r' => output.push_str("\\r"),
            b'\n' => output.push_str("\\n"),
            0x20..=0x7e => output.push(*byte as char),
            _ => {
                let _ = write!(output, "\\x{byte:02x}");
            }
        }
    }
    if packet.len() > 48 {
        output.push_str("...");
    }
    output
}

fn prune_invite_transactions(
    transactions: &mut HashMap<String, InviteTransactionRoute>,
    now: Instant,
) {
    transactions.retain(|_, route| now.duration_since(route.created_at) <= INVITE_TRANSACTION_TTL);
}

fn decrement_max_forwards(message: &mut SipMessage) -> Result<bool> {
    let Some(hops) = message.max_forwards()? else {
        message.set_max_forwards(70);
        return Ok(true);
    };
    if hops == 0 {
        return Ok(false);
    }
    message.set_max_forwards(hops - 1);
    Ok(true)
}

fn invite_transaction_key(message: &SipMessage) -> Result<Option<String>> {
    let Some(branch) = message.top_via_branch()? else {
        return Ok(None);
    };
    let Some(request) = message.as_request() else {
        return Ok(None);
    };
    let call_id = request
        .call_id_header()
        .context("failed to read Call-ID header")?
        .value();
    let cseq_number = request
        .cseq_header()
        .context("failed to read CSeq header")?
        .seq()
        .context("failed to parse CSeq sequence number")?;
    Ok(Some(format!(
        "{}:{}:{}",
        branch.trim(),
        call_id.trim(),
        cseq_number
    )))
}

fn udp_client_transaction_key(
    message: &SipMessage,
    peer: SocketAddr,
    method: &str,
) -> Result<Option<String>> {
    let Some(branch) = message.top_via_branch()? else {
        return Ok(None);
    };
    let Some(request) = message.as_request() else {
        return Ok(None);
    };
    let call_id = request
        .call_id_header()
        .context("failed to read Call-ID header")?
        .value();
    let cseq_number = request
        .cseq_header()
        .context("failed to read CSeq header")?
        .seq()
        .context("failed to parse CSeq sequence number")?;
    Ok(Some(format!(
        "{}:{}:{}:{}:{}",
        peer,
        branch.trim(),
        call_id.trim(),
        cseq_number,
        method
    )))
}

fn should_record_route(method: &str) -> bool {
    matches!(method, "INVITE" | "SUBSCRIBE" | "REFER")
}

fn status_class(code: u16) -> &'static str {
    match code {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        600..=699 => "6xx",
        _ => "unknown",
    }
}

fn latency_bucket_label(bucket: u64) -> &'static str {
    match bucket {
        1 => "1",
        5 => "5",
        10 => "10",
        25 => "25",
        50 => "50",
        100 => "100",
        250 => "250",
        500 => "500",
        1_000 => "1000",
        2_500 => "2500",
        5_000 => "5000",
        10_000 => "10000",
        30_000 => "30000",
        _ => "+Inf",
    }
}

#[cfg(test)]
async fn forward_tcp(target: SocketAddr, packet: Vec<u8>) -> Result<Vec<u8>> {
    let mut stream = timeout(UPSTREAM_TIMEOUT, TcpStream::connect(target))
        .await
        .context("upstream SIP TCP connect timed out")??;
    timeout(UPSTREAM_TIMEOUT, stream.write_all(&packet))
        .await
        .context("upstream SIP TCP write timed out")??;
    timeout(
        UPSTREAM_TIMEOUT,
        TcpSipReader::new(65_535).read_message(&mut stream),
    )
    .await
    .context("upstream SIP TCP response timed out")??
    .context("upstream SIP TCP connection closed without response")
}

struct TcpSipReader {
    codec: SipCodec,
    buf: BytesMut,
    read_buf: BytesMut,
    max_bytes: usize,
}

impl TcpSipReader {
    fn new(max_bytes: usize) -> Self {
        let mut read_buf = BytesMut::with_capacity(max_bytes.min(65_535));
        read_buf.resize(max_bytes.min(65_535), 0);
        Self {
            codec: SipCodec::new(),
            buf: BytesMut::new(),
            read_buf,
            max_bytes,
        }
    }

    async fn read_message<R>(&mut self, stream: &mut R) -> Result<Option<Vec<u8>>>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            while let Some(frame) = self
                .codec
                .decode(&mut self.buf)
                .map_err(|err| anyhow::anyhow!(err.to_string()))?
            {
                match frame {
                    SipCodecType::Message(message) => {
                        let bytes = message.to_bytes();
                        if bytes.len() > self.max_bytes {
                            bail!("SIP TCP message exceeded max_message_bytes");
                        }
                        return Ok(Some(bytes));
                    }
                    SipCodecType::KeepaliveRequest | SipCodecType::KeepaliveResponse => {
                        continue;
                    }
                }
            }

            let len = stream.read(&mut self.read_buf).await?;
            if len == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    bail!("SIP TCP connection closed before a complete message was received")
                };
            }
            self.buf.extend_from_slice(&self.read_buf[..len]);
            if self.buf.len() > self.max_bytes {
                bail!("SIP TCP message exceeded max_message_bytes");
            }
        }
    }
}

fn parse_contact_target(contact: &str, default_transport: SipTransport) -> Option<UpstreamTarget> {
    let contact = RsipContact::parse(contact).ok()?;
    let addr = SocketAddr::try_from(contact.uri.host_with_port).ok()?;
    let transport = contact
        .uri
        .params
        .iter()
        .chain(contact.params.iter())
        .find_map(|param| match param {
            Param::Transport(transport) => sip_transport_from_rsip(*transport),
            _ => None,
        })
        .unwrap_or(default_transport);
    Some(UpstreamTarget { addr, transport })
}

fn parse_route_target(route: &str, default_transport: SipTransport) -> Option<UpstreamTarget> {
    let route = RsipRoute::parse(route).ok()?;
    let addr = SocketAddr::try_from(route.uri.host_with_port).ok()?;
    let transport = route
        .uri
        .params
        .iter()
        .chain(route.params.iter())
        .find_map(|param| match param {
            Param::Transport(transport) => sip_transport_from_rsip(*transport),
            _ => None,
        })
        .unwrap_or(default_transport);
    Some(UpstreamTarget { addr, transport })
}

fn target_for_registration_binding(
    binding: &ContactBinding,
    default_transport: SipTransport,
) -> Option<UpstreamTarget> {
    let contact_target = parse_contact_target(&binding.contact, default_transport);
    let contact_transport = contact_target
        .map(|target| target.transport)
        .unwrap_or(default_transport);

    if contact_transport == SipTransport::Udp
        && let Ok(addr) = binding.source.parse::<SocketAddr>()
    {
        return Some(UpstreamTarget {
            addr,
            transport: SipTransport::Udp,
        });
    }

    contact_target
}

fn registered_invite_source_matches(
    registered_source: &str,
    peer: SocketAddr,
    mode: ProxyRegisteredInviteSourceMatch,
) -> bool {
    let Ok(registered) = registered_source.parse::<SocketAddr>() else {
        return false;
    };
    match mode {
        ProxyRegisteredInviteSourceMatch::Ip => registered.ip() == peer.ip(),
        ProxyRegisteredInviteSourceMatch::IpPort => registered == peer,
    }
}

fn registration_upstream_affinity_key(route: &str) -> AffinityKey {
    AffinityKey::from_string(format!("registration-upstream:{route}"))
}

fn registered_upstream_lookup_keys(message: &SipMessage, request_uri: &str) -> Vec<String> {
    let mut keys = Vec::new();
    if let Ok(to_aor) = extract_to_aor(message) {
        for key in registration_route_keys(&to_aor) {
            push_unique_key(&mut keys, key);
        }
    }
    for key in registration_route_keys(request_uri) {
        push_unique_key(&mut keys, key);
    }
    keys
}

fn is_initial_invite_request(message: &SipMessage) -> bool {
    let Some(request) = message.as_request() else {
        return false;
    };
    let Ok(to_header) = request.to_header() else {
        return false;
    };
    match rsipstack::sip::typed::To::parse(to_header.value()) {
        Ok(to) => to.tag().is_none(),
        Err(_) => false,
    }
}

fn registration_route_keys(route: &str) -> Vec<String> {
    let mut keys = Vec::new();
    push_unique_key(&mut keys, route.trim().to_string());

    if let Some(normalized) = normalized_sip_uri_without_params(route) {
        push_unique_key(&mut keys, normalized);
    }

    keys
}

fn collect_contact_route_bindings(
    bindings: &mut Vec<PendingRegisterBinding>,
    route: &str,
    contact: &str,
    peer: SocketAddr,
) {
    for aor in registration_route_keys(route) {
        push_pending_register_binding(
            bindings,
            PendingRegisterBinding {
                aor,
                contact: contact.to_string(),
                source: peer.to_string(),
            },
        );
    }
}

fn pending_register(
    bindings: Vec<PendingRegisterBinding>,
    request_expires: Duration,
    target: UpstreamTarget,
) -> Option<PendingRegister> {
    (!bindings.is_empty()).then_some(PendingRegister {
        bindings,
        request_expires,
        target,
        created_at: Instant::now(),
    })
}

fn push_pending_register_binding(
    bindings: &mut Vec<PendingRegisterBinding>,
    binding: PendingRegisterBinding,
) {
    if bindings.iter().any(|existing| existing.aor == binding.aor) {
        return;
    }
    bindings.push(binding);
}

fn rewritten_register_contact_user(
    aor: Option<&str>,
    original_contact: &str,
    _peer: SocketAddr,
    original_user: &str,
) -> String {
    let key = format!(
        "register-contact|{}|{}",
        aor.unwrap_or_default(),
        original_contact
    );
    let token = compact_uuid_token(&uuid_like_id(&key), 32);
    let user = if original_user.is_empty() {
        "contact"
    } else {
        original_user
    };
    format!("{user}~{token}")
}

fn compact_uuid_token(value: &str, len: usize) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .take(len)
        .collect()
}

fn normalized_sip_uri_without_params(value: &str) -> Option<String> {
    let mut uri = RsipContact::parse(value)
        .map(|contact| contact.uri)
        .or_else(|_| value.parse::<RsipUri>())
        .ok()?;
    uri.params.clear();
    uri.headers.clear();
    Some(uri.to_string())
}

fn push_unique_key(keys: &mut Vec<String>, key: String) {
    if !key.is_empty() && !keys.iter().any(|existing| existing == &key) {
        keys.push(key);
    }
}

fn parse_socket_addr_with_default_port(value: &str, default_port: u16) -> Option<SocketAddr> {
    render_advertised_addr(value, default_port)?.parse().ok()
}

fn local_interface_ips() -> HashSet<IpAddr> {
    match get_if_addrs() {
        Ok(addrs) => addrs.into_iter().map(|addr| addr.ip()).collect(),
        Err(err) => {
            warn!(
                error = %err,
                "failed to enumerate local interface addresses; wildcard listener self-detection is limited"
            );
            HashSet::new()
        }
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then_some(value)
    })
}

fn sip_transport_from_rsip(transport: RsipTransport) -> Option<SipTransport> {
    match transport.protocol() {
        RsipTransport::Udp => Some(SipTransport::Udp),
        RsipTransport::Tcp => Some(SipTransport::Tcp),
        _ => None,
    }
}

fn rsip_transport_from_sip(transport: SipTransport) -> RsipTransport {
    match transport {
        SipTransport::Udp => RsipTransport::Udp,
        SipTransport::Tcp => RsipTransport::Tcp,
        SipTransport::TcpUdp => unreachable!("tcp_udp SIP transport must be expanded"),
    }
}

async fn advertised_sip_addr(
    configured: Option<&str>,
    listener: &ProxyListenerConfig,
    upstream: SocketAddr,
) -> String {
    let fallback_port = listener_port(listener);
    let port = configured
        .and_then(advertised_addr_port)
        .or_else(|| {
            listener
                .bind
                .parse::<SocketAddr>()
                .ok()
                .map(|addr| addr.port())
        })
        .unwrap_or(upstream.port());

    if let Some(configured) = configured
        && !advertised_addr_needs_auto(configured)
    {
        return render_advertised_addr(configured, fallback_port)
            .unwrap_or_else(|| configured.to_string());
    }

    if let Ok(addr) = outbound_local_addr(upstream, port).await {
        return addr.to_string();
    }

    listener.bind.clone()
}

fn advertised_addr_needs_auto(value: &str) -> bool {
    let Some(host) = advertised_addr_host(value) else {
        return false;
    };
    let host = host.trim_matches(['[', ']']);
    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
    ip.is_loopback() || ip.is_unspecified()
}

fn render_advertised_addr(value: &str, default_port: u16) -> Option<String> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr.to_string());
    }
    let (host, port) = match split_advertised_host_port(value) {
        Some((host, port)) => (host, port.parse::<u16>().ok()?),
        None => (value, default_port),
    };
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    Some(render_host_port(host, port))
}

fn advertised_addr_host(value: &str) -> Option<&str> {
    split_advertised_host_port(value)
        .map(|(host, _)| host)
        .or(Some(value))
}

fn advertised_addr_port(value: &str) -> Option<u16> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr.port());
    }
    split_advertised_host_port(value).and_then(|(_, port)| port.parse().ok())
}

fn split_advertised_host_port(value: &str) -> Option<(&str, &str)> {
    if value.starts_with('[') {
        let end = value.find(']')?;
        return value[end + 1..]
            .strip_prefix(':')
            .map(|port| (&value[..=end], port));
    }
    if value.matches(':').count() == 1 {
        value.rsplit_once(':')
    } else {
        None
    }
}

fn render_host_port(host: &str, port: u16) -> String {
    let host = host.trim();
    if host.starts_with('[') && host.ends_with(']') {
        format!("{host}:{port}")
    } else if host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn listener_port(listener: &ProxyListenerConfig) -> u16 {
    listener
        .bind
        .parse::<SocketAddr>()
        .map(|addr| addr.port())
        .unwrap_or(5060)
}

async fn outbound_local_addr(upstream: SocketAddr, port: u16) -> Result<SocketAddr> {
    let bind_addr = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(upstream).await?;
    let local_ip = socket.local_addr()?.ip();
    Ok(SocketAddr::new(local_ip, port))
}

fn unique_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::{
        ClusterApplyResult, ClusterCommand, ClusterRole, ContactBinding, NodeId,
        StandaloneReplicator, expires_at,
    };
    use crate::config::PersistenceConfig;
    use crate::config::{
        Config, ProxyAffinityConfig, ProxyAffinityKey, ProxyConfig, ProxyDynamicBanConfig,
        ProxyGeoCountryListConfig, ProxyGeoSecurityConfig, ProxyGeoStartupRefresh,
        ProxyListenerConfig, ProxyRegisteredInviteSourceMatch, ProxySecurityConfig,
        ProxySecurityPrefilterConfig, ProxySecurityPreset, ProxySipPolicyConfig,
        ProxySipRateLimitConfig, ProxySocketConfig, ProxyXdpSecurityConfig, RouteConfig, SipConfig,
        SipTransport, UpstreamGroupConfig, UpstreamHealthCheckConfig, UpstreamMode,
    };
    use crate::proxy::geo::test_cache_bytes;
    use tokio::net::UdpSocket;

    struct MutableRoleReplicator {
        role: tokio::sync::RwLock<ClusterRole>,
    }

    impl MutableRoleReplicator {
        fn new(role: ClusterRole) -> Self {
            Self {
                role: tokio::sync::RwLock::new(role),
            }
        }

        async fn set_role(&self, role: ClusterRole) {
            *self.role.write().await = role;
        }
    }

    #[async_trait::async_trait]
    impl ClusterReplicator for MutableRoleReplicator {
        async fn submit(&self, _command: ClusterCommand) -> Result<ClusterApplyResult> {
            Ok(ClusterApplyResult {
                applied: false,
                index: None,
            })
        }

        async fn role(&self) -> ClusterRole {
            *self.role.read().await
        }

        async fn leader(&self) -> Option<NodeId> {
            None
        }
    }

    fn test_listener() -> ProxyListenerConfig {
        ProxyListenerConfig {
            bind: "127.0.0.1:5060".to_string(),
            transport: SipTransport::Udp,
            upstream_group: "default".to_string(),
            security: None,
        }
    }

    fn test_wildcard_listener() -> ProxyListenerConfig {
        ProxyListenerConfig {
            bind: "0.0.0.0:5060".to_string(),
            transport: SipTransport::Udp,
            upstream_group: "default".to_string(),
            security: None,
        }
    }

    fn test_tcp_listener() -> ProxyListenerConfig {
        ProxyListenerConfig {
            bind: "127.0.0.1:5060".to_string(),
            transport: SipTransport::Tcp,
            upstream_group: "default".to_string(),
            security: None,
        }
    }

    fn test_server_with_upstream(upstream: SocketAddr) -> ProxyServer {
        test_server_with_upstream_config(upstream, false)
    }

    fn test_server_with_upstream_config(
        upstream: SocketAddr,
        rewrite_register_contact: bool,
    ) -> ProxyServer {
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone(), None));
        ProxyServer::new(
            Config {
                sip: SipConfig {
                    external_addr: Some("127.0.0.1:5060".to_string()),
                    internal_probe_addr: upstream.to_string(),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
                    register_routing: None,
                    rewrite_register_contact,
                    udp_client_transaction_cache_entries: 65_536,
                    socket: ProxySocketConfig::default(),
                    metrics: Default::default(),
                    affinity: Default::default(),
                    security: Default::default(),
                    listeners: vec![test_listener()],
                    upstream_groups: vec![UpstreamGroupConfig {
                        name: "default".to_string(),
                        mode: UpstreamMode::RoundRobin,
                        health_check: UpstreamHealthCheckConfig::default(),
                        servers: vec![upstream.to_string()],
                    }],
                    routes: vec![RouteConfig {
                        name: "tenant-a".to_string(),
                        listener: Some("udp/127.0.0.1:5060".to_string()),
                        domain: Some("tenant-a.example.com".to_string()),
                        prefix: Some("sip:1".to_string()),
                        upstream_group: "default".to_string(),
                    }],
                },
                ..Config::default()
            },
            state,
            replicator,
            None,
        )
        .unwrap()
    }

    fn test_server_with_dual_advertise(upstream: SocketAddr) -> ProxyServer {
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone(), None));
        ProxyServer::new(
            Config {
                sip: SipConfig {
                    public_addr: Some("95.40.96.117".to_string()),
                    internal_addr: Some("172.30.0.101".to_string()),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
                    register_routing: None,
                    rewrite_register_contact: false,
                    udp_client_transaction_cache_entries: 65_536,
                    socket: ProxySocketConfig::default(),
                    metrics: Default::default(),
                    affinity: Default::default(),
                    security: Default::default(),
                    listeners: vec![test_listener()],
                    upstream_groups: vec![UpstreamGroupConfig {
                        name: "default".to_string(),
                        mode: UpstreamMode::RoundRobin,
                        health_check: UpstreamHealthCheckConfig::default(),
                        servers: vec![upstream.to_string()],
                    }],
                    routes: vec![],
                },
                ..Config::default()
            },
            state,
            replicator,
            None,
        )
        .unwrap()
    }

    fn test_server_with_wildcard_listener_and_trusted_peer(upstream: SocketAddr) -> ProxyServer {
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone(), None));
        ProxyServer::new(
            Config {
                proxy: ProxyConfig {
                    record_route: true,
                    register_routing: None,
                    rewrite_register_contact: false,
                    udp_client_transaction_cache_entries: 65_536,
                    socket: ProxySocketConfig::default(),
                    metrics: Default::default(),
                    affinity: Default::default(),
                    security: ProxySecurityConfig {
                        trusted_cidrs: Some(vec!["127.0.0.0/8".to_string()]),
                        ..ProxySecurityConfig::default()
                    },
                    listeners: vec![test_wildcard_listener()],
                    upstream_groups: vec![UpstreamGroupConfig {
                        name: "default".to_string(),
                        mode: UpstreamMode::RoundRobin,
                        health_check: UpstreamHealthCheckConfig::default(),
                        servers: vec![upstream.to_string()],
                    }],
                    routes: vec![],
                },
                ..Config::default()
            },
            state,
            replicator,
            None,
        )
        .unwrap()
    }

    fn test_server_with_upstreams(upstreams: Vec<SocketAddr>) -> ProxyServer {
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone(), None));
        ProxyServer::new(
            Config {
                sip: SipConfig {
                    external_addr: Some("127.0.0.1:5060".to_string()),
                    internal_probe_addr: upstreams
                        .first()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "127.0.0.1:5080".to_string()),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
                    register_routing: None,
                    rewrite_register_contact: false,
                    udp_client_transaction_cache_entries: 65_536,
                    socket: ProxySocketConfig::default(),
                    metrics: Default::default(),
                    affinity: Default::default(),
                    security: Default::default(),
                    listeners: vec![test_listener()],
                    upstream_groups: vec![UpstreamGroupConfig {
                        name: "default".to_string(),
                        mode: UpstreamMode::RoundRobin,
                        health_check: UpstreamHealthCheckConfig::default(),
                        servers: upstreams.iter().map(ToString::to_string).collect(),
                    }],
                    routes: vec![],
                },
                ..Config::default()
            },
            state,
            replicator,
            None,
        )
        .unwrap()
    }

    fn test_server_with_upstreams_and_affinity(
        upstreams: Vec<SocketAddr>,
        affinity: ProxyAffinityConfig,
    ) -> ProxyServer {
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone(), None));
        ProxyServer::new(
            Config {
                sip: SipConfig {
                    external_addr: Some("127.0.0.1:5060".to_string()),
                    internal_probe_addr: upstreams
                        .first()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "127.0.0.1:5080".to_string()),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
                    register_routing: None,
                    rewrite_register_contact: false,
                    udp_client_transaction_cache_entries: 65_536,
                    socket: ProxySocketConfig::default(),
                    metrics: Default::default(),
                    affinity,
                    security: Default::default(),
                    listeners: vec![test_listener()],
                    upstream_groups: vec![UpstreamGroupConfig {
                        name: "default".to_string(),
                        mode: UpstreamMode::RoundRobin,
                        health_check: UpstreamHealthCheckConfig::default(),
                        servers: upstreams.iter().map(ToString::to_string).collect(),
                    }],
                    routes: vec![],
                },
                ..Config::default()
            },
            state,
            replicator,
            None,
        )
        .unwrap()
    }

    fn test_server_with_security(
        upstream: SocketAddr,
        security: ProxySecurityConfig,
    ) -> ProxyServer {
        test_server_with_listener_and_security(upstream, test_listener(), security)
    }

    fn test_server_with_listener_and_security(
        upstream: SocketAddr,
        listener: ProxyListenerConfig,
        security: ProxySecurityConfig,
    ) -> ProxyServer {
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone(), None));
        ProxyServer::new(
            Config {
                sip: SipConfig {
                    external_addr: Some("127.0.0.1:5060".to_string()),
                    internal_probe_addr: upstream.to_string(),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
                    register_routing: None,
                    rewrite_register_contact: false,
                    udp_client_transaction_cache_entries: 65_536,
                    socket: ProxySocketConfig::default(),
                    metrics: Default::default(),
                    affinity: Default::default(),
                    security,
                    listeners: vec![listener],
                    upstream_groups: vec![UpstreamGroupConfig {
                        name: "default".to_string(),
                        mode: UpstreamMode::RoundRobin,
                        health_check: UpstreamHealthCheckConfig::default(),
                        servers: vec![upstream.to_string()],
                    }],
                    routes: vec![],
                },
                ..Config::default()
            },
            state,
            replicator,
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn options_is_forwarded_to_upstream() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        server
            .handle_udp_packet(
                &proxy_socket,
                b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK1\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:example.com>\r\n\
Call-ID: c1\r\n\
CSeq: 1 OPTIONS\r\n\r\n",
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with("OPTIONS sip:example.com SIP/2.0"));
        assert!(forwarded.contains("Call-ID: c1"));
    }

    #[tokio::test]
    async fn udp_security_prefilter_drops_invalid_start_line() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_security(
            upstream_socket.local_addr().unwrap(),
            ProxySecurityConfig {
                preset: Some(ProxySecurityPreset::Public),
                ..ProxySecurityConfig::default()
            },
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                b"GET / HTTP/1.0\r\n\r\n",
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn udp_security_invite_rate_limit_returns_503() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let server = test_server_with_security(
            upstream_socket.local_addr().unwrap(),
            ProxySecurityConfig {
                preset: Some(ProxySecurityPreset::Public),
                sip_rate_limit: ProxySipRateLimitConfig {
                    invite_per_minute_per_aor: Some(1),
                    ..ProxySipRateLimitConfig::default()
                },
                ..ProxySecurityConfig::default()
            },
        );

        for branch in ["z9hG4bK-security-invite-a", "z9hG4bK-security-invite-b"] {
            let invite = format!(
                "INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {client_addr};branch={branch};rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: {branch}\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n"
            );
            server
                .handle_udp_packet(
                    &proxy_socket,
                    invite.as_bytes(),
                    client_addr,
                    &test_listener(),
                )
                .await
                .unwrap();
        }

        let mut upstream_buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut upstream_buf).await.unwrap();
        let forwarded = String::from_utf8(upstream_buf[..len].to_vec()).unwrap();
        assert!(forwarded.contains("z9hG4bK-security-invite-a"));
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut upstream_buf)
            )
            .await
            .is_err()
        );

        let mut client_buf = [0_u8; 4096];
        let (len, _) = client_socket.recv_from(&mut client_buf).await.unwrap();
        let response = String::from_utf8(client_buf[..len].to_vec()).unwrap();
        assert!(response.starts_with("SIP/2.0 503 Service Unavailable"));
        assert!(response.contains(&format!("rport={}", client_addr.port())));
    }

    #[tokio::test]
    async fn udp_sip_policy_rejects_unregistered_invite_source() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let server = test_server_with_security(
            upstream_socket.local_addr().unwrap(),
            ProxySecurityConfig {
                sip_policy: ProxySipPolicyConfig {
                    require_registered_invite_source: Some(true),
                    ..ProxySipPolicyConfig::default()
                },
                ..ProxySecurityConfig::default()
            },
        );

        let invite = format!(
            "INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {client_addr};branch=z9hG4bK-unregistered-invite;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: unregistered-invite\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n"
        );
        server
            .handle_udp_packet(
                &proxy_socket,
                invite.as_bytes(),
                client_addr,
                &test_listener(),
            )
            .await
            .unwrap();

        let mut upstream_buf = [0_u8; 4096];
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut upstream_buf)
            )
            .await
            .is_err()
        );

        let mut client_buf = [0_u8; 4096];
        let (len, _) = client_socket.recv_from(&mut client_buf).await.unwrap();
        let response = String::from_utf8(client_buf[..len].to_vec()).unwrap();
        assert!(response.starts_with("SIP/2.0 403 Forbidden"));
        assert!(response.contains(&format!("rport={}", client_addr.port())));

        let ack = format!(
            "ACK sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {client_addr};branch=z9hG4bK-unregistered-invite;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: unregistered-invite\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\r\n"
        );
        server
            .handle_udp_packet(&proxy_socket, ack.as_bytes(), client_addr, &test_listener())
            .await
            .unwrap();
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut upstream_buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn udp_sip_policy_allows_registered_invite_source_ip_with_port_drift() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let registered_client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let invite_client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let registered_client_addr = registered_client_socket.local_addr().unwrap();
        let invite_client_addr = invite_client_socket.local_addr().unwrap();
        assert_eq!(registered_client_addr.ip(), invite_client_addr.ip());
        assert_ne!(registered_client_addr.port(), invite_client_addr.port());
        let server = test_server_with_security(
            upstream_socket.local_addr().unwrap(),
            ProxySecurityConfig {
                sip_policy: ProxySipPolicyConfig {
                    require_registered_invite_source: Some(true),
                    registered_invite_source_match: Some(ProxyRegisteredInviteSourceMatch::Ip),
                },
                ..ProxySecurityConfig::default()
            },
        );

        let register = format!(
            "REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {registered_client_addr};branch=z9hG4bK-register-policy;rport\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:100@example.com>\r\n\
Contact: <sip:100@{registered_client_addr}>;expires=60\r\n\
Call-ID: register-policy\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
        );
        server
            .handle_udp_packet(
                &proxy_socket,
                register.as_bytes(),
                registered_client_addr,
                &test_listener(),
            )
            .await
            .unwrap();
        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded_register = String::from_utf8(buf[..len].to_vec()).unwrap();
        complete_register_ok(
            &server,
            &proxy_socket,
            upstream_socket.local_addr().unwrap(),
            &forwarded_register,
            &format!("sip:100@{registered_client_addr}"),
            60,
        )
        .await;
        let mut registered_client_buf = [0_u8; 4096];
        let _ = registered_client_socket
            .recv_from(&mut registered_client_buf)
            .await
            .unwrap();

        let invite = format!(
            "INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {invite_client_addr};branch=z9hG4bK-registered-invite;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: registered-invite\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n"
        );
        server
            .handle_udp_packet(
                &proxy_socket,
                invite.as_bytes(),
                invite_client_addr,
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with("INVITE sip:200@example.com SIP/2.0"));
        assert!(forwarded.contains("From: <sip:100@example.com>;tag=a"));
    }

    #[tokio::test]
    async fn register_success_response_controls_invite_policy_after_mixed_contact_expires() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let server = test_server_with_security(
            upstream_socket.local_addr().unwrap(),
            ProxySecurityConfig {
                sip_policy: ProxySipPolicyConfig {
                    require_registered_invite_source: Some(true),
                    registered_invite_source_match: Some(ProxyRegisteredInviteSourceMatch::Ip),
                },
                ..ProxySecurityConfig::default()
            },
        );

        let register = format!(
            "REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {client_addr};branch=z9hG4bK-register-mixed-expires;rport\r\n\
From: <sip:3001@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Contact: <sip:3001@{client_addr};ob>\r\n\
Contact: <sip:3001@{client_addr};ob>;expires=0\r\n\
Expires: 300\r\n\
Call-ID: register-mixed-expires\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
        );
        server
            .handle_udp_packet(
                &proxy_socket,
                register.as_bytes(),
                client_addr,
                &test_listener(),
            )
            .await
            .unwrap();
        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded_register = String::from_utf8(buf[..len].to_vec()).unwrap();
        complete_register_ok(
            &server,
            &proxy_socket,
            upstream_socket.local_addr().unwrap(),
            &forwarded_register,
            &format!("sip:3001@{client_addr};ob"),
            300,
        )
        .await;
        let _ = client_socket.recv_from(&mut buf).await.unwrap();

        let invite = format!(
            "INVITE sip:3000@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {client_addr};branch=z9hG4bK-invite-after-mixed-register;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:3001@example.com>;tag=a\r\n\
To: <sip:3000@example.com>\r\n\
Call-ID: invite-after-mixed-register\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n"
        );
        server
            .handle_udp_packet(
                &proxy_socket,
                invite.as_bytes(),
                client_addr,
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded_invite = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded_invite.starts_with("INVITE sip:3000@example.com SIP/2.0"));
    }

    #[tokio::test]
    async fn udp_geo_deny_country_drops_before_forwarding() {
        let cache_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            cache_dir.path().join("geo.sgeo"),
            test_cache_bytes("US", "127.0.0.0/8\n"),
        )
        .unwrap();
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_security(
            upstream_socket.local_addr().unwrap(),
            ProxySecurityConfig {
                geo: ProxyGeoSecurityConfig {
                    enabled: Some(true),
                    cache_dir: Some(cache_dir.path().to_string_lossy().to_string()),
                    startup_refresh: Some(ProxyGeoStartupRefresh::Disabled),
                    deny: ProxyGeoCountryListConfig {
                        countries: Some(vec!["US".to_string()]),
                    },
                    ..ProxyGeoSecurityConfig::default()
                },
                ..ProxySecurityConfig::default()
            },
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-geo-drop\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:example.com>\r\n\
Call-ID: geo-drop\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n",
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn udp_dynamic_ban_blocks_ip_after_invalid_packets() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_security(
            upstream_socket.local_addr().unwrap(),
            ProxySecurityConfig {
                prefilter: ProxySecurityPrefilterConfig {
                    enabled: Some(true),
                    drop_invalid_start_line: Some(true),
                    drop_non_sip_methods: Some(true),
                    ..ProxySecurityPrefilterConfig::default()
                },
                dynamic_ban: ProxyDynamicBanConfig {
                    enabled: Some(true),
                    ban_seconds: Some(60),
                    invalid_packets_per_minute: Some(1),
                    ..ProxyDynamicBanConfig::default()
                },
                ..ProxySecurityConfig::default()
            },
        );
        let peer = "127.0.0.1:5061".parse().unwrap();

        for _ in 0..2 {
            server
                .handle_udp_packet(
                    &proxy_socket,
                    b"GET / HTTP/1.0\r\n\r\n",
                    peer,
                    &test_listener(),
                )
                .await
                .unwrap();
        }
        server
            .handle_udp_packet(
                &proxy_socket,
                b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-dynamic-block\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:example.com>\r\n\
Call-ID: dynamic-block\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n",
                peer,
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn tcp_security_prefilter_drops_invalid_start_line() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(tcp_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server_stream, peer) = tcp_listener.accept().await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = test_tcp_listener();
        let server = test_server_with_listener_and_security(
            upstream_socket.local_addr().unwrap(),
            listener.clone(),
            ProxySecurityConfig {
                prefilter: ProxySecurityPrefilterConfig {
                    enabled: Some(true),
                    drop_invalid_start_line: Some(true),
                    drop_non_sip_methods: Some(true),
                    ..ProxySecurityPrefilterConfig::default()
                },
                ..ProxySecurityConfig::default()
            },
        );

        server
            .handle_tcp_packet(
                &mut server_stream,
                b"GET / HTTP/1.0\r\n\r\n",
                peer,
                &listener,
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 128];
        assert!(
            timeout(Duration::from_millis(100), client.read(&mut buf))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn tcp_security_sip_rate_limit_returns_503() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(tcp_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server_stream, peer) = tcp_listener.accept().await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = test_tcp_listener();
        let server = test_server_with_listener_and_security(
            upstream_socket.local_addr().unwrap(),
            listener.clone(),
            ProxySecurityConfig {
                preset: Some(ProxySecurityPreset::Public),
                sip_rate_limit: ProxySipRateLimitConfig {
                    invite_per_minute_per_aor: Some(1),
                    ..ProxySipRateLimitConfig::default()
                },
                ..ProxySecurityConfig::default()
            },
        );
        server
            .security
            .allow_bucket(
                "sip-rate|tcp/127.0.0.1:5060|INVITE|<sip:100@example.com>;tag=a".to_string(),
                1.0 / 60.0,
                1.0,
            )
            .await;

        server
            .handle_tcp_packet(
                &mut server_stream,
                b"INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1:5061;branch=z9hG4bK-tcp-security\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: tcp-security\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                peer,
                &listener,
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let len = timeout(Duration::from_millis(500), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(response.starts_with("SIP/2.0 503 Service Unavailable"));
    }

    #[tokio::test]
    async fn security_prune_removes_expired_blocks_and_idle_buckets() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_security(
            upstream_socket.local_addr().unwrap(),
            ProxySecurityConfig::default(),
        );
        server
            .security
            .blocks
            .shard_for_key("expired")
            .lock()
            .await
            .insert(
                "expired".to_string(),
                Instant::now() - Duration::from_secs(1),
            );
        server
            .security
            .buckets
            .shard_for_key("idle")
            .lock()
            .await
            .insert(
                "idle".to_string(),
                TokenBucket {
                    tokens: 1.0,
                    updated_at: Instant::now() - SECURITY_BUCKET_IDLE_TTL - Duration::from_secs(1),
                },
            );

        server.security.prune_expired().await;

        assert!(server.security.blocks.is_empty().await);
        assert!(server.security.buckets.is_empty().await);
    }

    #[test]
    fn rejects_inconsistent_geo_source_config_across_listeners() {
        let cache_a = tempfile::tempdir().unwrap();
        let cache_b = tempfile::tempdir().unwrap();
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone(), None));
        let config = Config {
            proxy: ProxyConfig {
                listeners: vec![
                    ProxyListenerConfig {
                        bind: "127.0.0.1:5060".to_string(),
                        transport: SipTransport::Udp,
                        upstream_group: "default".to_string(),
                        security: Some(ProxySecurityConfig {
                            geo: ProxyGeoSecurityConfig {
                                enabled: Some(true),
                                cache_dir: Some(cache_a.path().to_string_lossy().to_string()),
                                ..ProxyGeoSecurityConfig::default()
                            },
                            ..ProxySecurityConfig::default()
                        }),
                    },
                    ProxyListenerConfig {
                        bind: "127.0.0.1:5061".to_string(),
                        transport: SipTransport::Udp,
                        upstream_group: "default".to_string(),
                        security: Some(ProxySecurityConfig {
                            geo: ProxyGeoSecurityConfig {
                                enabled: Some(true),
                                cache_dir: Some(cache_b.path().to_string_lossy().to_string()),
                                ..ProxyGeoSecurityConfig::default()
                            },
                            ..ProxySecurityConfig::default()
                        }),
                    },
                ],
                upstream_groups: vec![UpstreamGroupConfig {
                    name: "default".to_string(),
                    mode: UpstreamMode::RoundRobin,
                    health_check: UpstreamHealthCheckConfig::default(),
                    servers: vec!["127.0.0.1:5080".to_string()],
                }],
                ..ProxyConfig::default()
            },
            ..Config::default()
        };

        assert!(ProxyServer::new(config, state, replicator, None).is_err());
    }

    #[test]
    fn rejects_xdp_fail_closed_when_backend_unavailable() {
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone(), None));
        let config = Config {
            proxy: ProxyConfig {
                security: ProxySecurityConfig {
                    xdp: ProxyXdpSecurityConfig {
                        enabled: Some(true),
                        interfaces: Some(vec!["eth0".to_string()]),
                        fail_open: Some(false),
                        ..ProxyXdpSecurityConfig::default()
                    },
                    ..ProxySecurityConfig::default()
                },
                listeners: vec![test_listener()],
                upstream_groups: vec![UpstreamGroupConfig {
                    name: "default".to_string(),
                    mode: UpstreamMode::RoundRobin,
                    health_check: UpstreamHealthCheckConfig::default(),
                    servers: vec!["127.0.0.1:5080".to_string()],
                }],
                ..ProxyConfig::default()
            },
            ..Config::default()
        };

        assert!(ProxyServer::new(config, state, replicator, None).is_err());
    }

    #[tokio::test]
    async fn register_is_forwarded_to_upstream() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());

        server
            .handle_udp_packet(
                &proxy_socket,
                b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-register-forward\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:100@example.com>\r\n\
Contact: <sip:100@127.0.0.1:5061>;expires=60\r\n\
Call-ID: register-forward\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n",
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with("REGISTER sip:example.com SIP/2.0"));
        assert!(forwarded.contains("Path: <sip:127.0.0.1:5060;lr>"));
        assert!(forwarded.contains("Contact: <sip:100@127.0.0.1:5061>;expires=60"));
        assert!(forwarded.contains("Call-ID: register-forward"));
        complete_register_ok(
            &server,
            &proxy_socket,
            upstream_socket.local_addr().unwrap(),
            &forwarded,
            "sip:100@127.0.0.1:5061",
            60,
        )
        .await;
        assert_eq!(
            server
                .state
                .lookup("sip:100@example.com")
                .await
                .unwrap()
                .contact,
            "sip:100@127.0.0.1:5061"
        );
        assert_eq!(
            server
                .state
                .lookup("sip:100@127.0.0.1:5060")
                .await
                .unwrap()
                .contact,
            "sip:100@127.0.0.1:5061"
        );
    }

    #[tokio::test]
    async fn udp_register_retransmission_reuses_proxy_branch() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let request = b"REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:9500;rport;branch=z9hG4bK-register-retry\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:100@example.com>\r\n\
Contact: <sip:100@127.0.0.1:9500;transport=UDP>\r\n\
Call-ID: register-retry\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n";
        let peer = "127.0.0.1:9500".parse().unwrap();

        server
            .handle_udp_packet(&proxy_socket, request, peer, &test_listener())
            .await
            .unwrap();
        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let first = String::from_utf8(buf[..len].to_vec()).unwrap();

        server
            .handle_udp_packet(&proxy_socket, request, peer, &test_listener())
            .await
            .unwrap();
        let (len, _) = timeout(Duration::from_secs(1), upstream_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let second = String::from_utf8(buf[..len].to_vec()).unwrap();

        assert_eq!(
            SipMessage::parse(first.as_bytes())
                .unwrap()
                .top_via_branch()
                .unwrap(),
            SipMessage::parse(second.as_bytes())
                .unwrap()
                .top_via_branch()
                .unwrap()
        );
        assert_eq!(server.active_udp_branch_count().await, 1);
    }

    #[tokio::test]
    async fn udp_register_retransmission_after_final_response_is_answered_locally() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let listener = test_listener();
        let client_addr = client_socket.local_addr().unwrap();
        let request = format!(
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP {client_addr};rport;branch=z9hG4bK-register-final-retry\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:100@example.com>\r\n\
Contact: <sip:100@{client_addr};transport=UDP>\r\n\
Call-ID: register-final-retry\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(&proxy_socket, request.as_bytes(), client_addr, &listener)
            .await
            .unwrap();
        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        let response = format!(
            "SIP/2.0 401 Unauthorized\r\n\
{proxy_via}\r\n\
Via: SIP/2.0/UDP {client_addr};rport;branch=z9hG4bK-register-final-retry\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:100@example.com>;tag=b\r\n\
Call-ID: register-final-retry\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n",
            proxy_via = top_via_line(&forwarded),
        );
        server
            .handle_udp_packet(
                &proxy_socket,
                response.as_bytes(),
                upstream_socket.local_addr().unwrap(),
                &listener,
            )
            .await
            .unwrap();

        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let first_response = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(first_response.starts_with("SIP/2.0 401 Unauthorized"));
        assert!(!first_response.contains(PROXY_BRANCH_PREFIX));

        server
            .handle_udp_packet(&proxy_socket, request.as_bytes(), client_addr, &listener)
            .await
            .unwrap();
        let (len, _) = timeout(Duration::from_secs(1), client_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let retransmitted_response = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert_eq!(retransmitted_response, first_response);
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn udp_client_transaction_shard_limit_evicts_oldest() {
        let mut transactions = HashMap::new();
        let target = UpstreamTarget {
            addr: "127.0.0.1:5080".parse().unwrap(),
            transport: SipTransport::Udp,
        };
        let now = Instant::now();
        for index in 0_u64..3 {
            transactions.insert(
                format!("tx-{index}"),
                UdpClientTransactionRoute {
                    target,
                    packet: vec![index as u8],
                    final_response: None,
                    created_at: now + Duration::from_millis(index),
                },
            );
        }

        enforce_udp_client_transaction_shard_limit(&mut transactions, 2);

        assert_eq!(transactions.len(), 2);
        assert!(!transactions.contains_key("tx-0"));
        assert!(transactions.contains_key("tx-1"));
        assert!(transactions.contains_key("tx-2"));
    }

    #[tokio::test]
    async fn wildcard_listener_treats_local_request_uri_as_proxy_address() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_wildcard_listener_and_trusted_peer(
            upstream_socket.local_addr().unwrap(),
        );
        let listener = test_wildcard_listener();
        let message = SipMessage::parse(
            b"REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:9400;rport;branch=z9hG4bK-local-uri\r\n\
From: <sip:11199@example.com>;tag=a\r\n\
To: <sip:11199@example.com>\r\n\
Contact: <sip:11199@127.0.0.1:9400;transport=UDP>\r\n\
Call-ID: local-uri-register\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();

        assert!(server.request_uri_targets_this_proxy("sip:127.0.0.1:5060", &listener));
        let (_message, target, _branch, _invite_transaction_key) = server
            .prepare_forward(
                message,
                "127.0.0.1:9400".parse().unwrap(),
                &listener,
                "REGISTER",
            )
            .await
            .unwrap();

        assert_eq!(target.addr, upstream_socket.local_addr().unwrap());
    }

    #[tokio::test]
    async fn dual_advertise_uses_internal_address_toward_upstream() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_dual_advertise(upstream_socket.local_addr().unwrap());

        server
            .handle_udp_packet(
                &proxy_socket,
                b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-dual-register\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:100@example.com>\r\n\
Contact: <sip:100@127.0.0.1:5061>;expires=60\r\n\
Call-ID: dual-register\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n",
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let register = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(top_via_line(&register).contains("172.30.0.101:5060"));
        assert!(register.contains("Path: <sip:172.30.0.101:5060;lr>"));

        server
            .handle_udp_packet(
                &proxy_socket,
                b"INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-dual-invite\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: dual-invite\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let invite = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(top_via_line(&invite).contains("172.30.0.101:5060"));
        assert_eq!(
            header_lines(&invite, "Record-Route"),
            vec![
                "Record-Route: <sip:172.30.0.101:5060;lr>",
                "Record-Route: <sip:95.40.96.117:5060;lr>",
            ]
        );
    }

    #[tokio::test]
    async fn dual_advertise_uses_public_address_toward_client() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_dual_advertise(upstream_socket.local_addr().unwrap());
        let client_addr = client_socket.local_addr().unwrap();
        let packet = format!(
            "INVITE sip:6805@{client_addr} SIP/2.0\r\n\
Route: <sip:172.30.0.101:5060;lr>\r\n\
Via: SIP/2.0/UDP 172.30.0.60:5060;branch=z9hG4bK-dual-inbound\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:6805@example.com>\r\n\
Call-ID: dual-inbound\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:100@example.com>\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                packet.as_bytes(),
                upstream_socket.local_addr().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let invite = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(top_via_line(&invite).contains("95.40.96.117:5060"));
        assert_eq!(
            header_lines(&invite, "Record-Route"),
            vec![
                "Record-Route: <sip:95.40.96.117:5060;lr>",
                "Record-Route: <sip:172.30.0.101:5060;lr>",
            ]
        );
        assert!(!invite.lines().any(|line| line.starts_with("Route:")));
    }

    #[tokio::test]
    async fn register_contact_can_be_rewritten_to_proxy_address() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream_config(upstream_socket.local_addr().unwrap(), true);

        server
            .handle_udp_packet(
                &proxy_socket,
                b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-register-rewrite\r\n\
From: \"wuly\" <sip:6805@example.com>;tag=a\r\n\
To: \"wuly\" <sip:6805@example.com>\r\n\
Contact: \"wuly\" <sip:6805@10.0.0.10:53109;ob>;expires=60\r\n\
Call-ID: register-rewrite\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n",
                "127.0.0.1:53109".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        let rewritten_contact = contact_uri_from_message(&forwarded);
        assert!(rewritten_contact.starts_with("sip:6805~"));
        assert!(rewritten_contact.ends_with("@127.0.0.1:5060"));
        assert!(!rewritten_contact.contains(";ob"));
        assert!(!forwarded.contains("Path:"));

        complete_register_ok(
            &server,
            &proxy_socket,
            upstream_socket.local_addr().unwrap(),
            &forwarded,
            "sip:6805@10.0.0.10:53109;ob",
            60,
        )
        .await;

        let binding = server.state.lookup(&rewritten_contact).await.unwrap();
        assert_eq!(binding.contact, "sip:6805@10.0.0.10:53109;ob");
        let binding = server.state.lookup("sip:6805@example.com").await.unwrap();
        assert_eq!(binding.contact, "sip:6805@10.0.0.10:53109;ob");
    }

    #[tokio::test]
    async fn rewritten_register_contacts_are_unique_per_device() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream_config(upstream_socket.local_addr().unwrap(), true);

        for (branch, client_contact, peer) in [
            (
                "z9hG4bK-register-device-a",
                "sip:3001@10.0.0.10:53109;ob",
                "127.0.0.1:53109",
            ),
            (
                "z9hG4bK-register-device-b",
                "sip:3001@10.0.0.11:53110;ob",
                "127.0.0.1:53110",
            ),
        ] {
            let register = format!(
                "REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch={branch}\r\n\
From: <sip:3001@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Contact: <{client_contact}>;expires=60\r\n\
Call-ID: {branch}\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
            );
            server
                .handle_udp_packet(
                    &proxy_socket,
                    register.as_bytes(),
                    peer.parse().unwrap(),
                    &test_listener(),
                )
                .await
                .unwrap();
        }

        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let first = String::from_utf8(buf[..len].to_vec()).unwrap();
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let second = String::from_utf8(buf[..len].to_vec()).unwrap();
        let first_contact = contact_uri_from_message(&first);
        let second_contact = contact_uri_from_message(&second);

        assert_ne!(first_contact, second_contact);
        assert!(first_contact.starts_with("sip:3001~"));
        assert!(second_contact.starts_with("sip:3001~"));
        assert!(first_contact.ends_with("@127.0.0.1:5060"));
        assert!(second_contact.ends_with("@127.0.0.1:5060"));

        complete_register_ok(
            &server,
            &proxy_socket,
            upstream_socket.local_addr().unwrap(),
            &first,
            "sip:3001@10.0.0.10:53109;ob",
            60,
        )
        .await;
        complete_register_ok(
            &server,
            &proxy_socket,
            upstream_socket.local_addr().unwrap(),
            &second,
            "sip:3001@10.0.0.11:53110;ob",
            60,
        )
        .await;

        let first_binding = server.state.lookup(&first_contact).await.unwrap();
        let second_binding = server.state.lookup(&second_contact).await.unwrap();
        assert_eq!(first_binding.contact, "sip:3001@10.0.0.10:53109;ob");
        assert_eq!(second_binding.contact, "sip:3001@10.0.0.11:53110;ob");
    }

    #[tokio::test]
    async fn rewritten_register_contact_is_stable_when_nat_source_port_changes() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream_config(upstream_socket.local_addr().unwrap(), true);
        let client_contact = "sip:3001@10.0.0.10:53109;ob";

        for (branch, peer) in [
            ("z9hG4bK-register-nat-a", "127.0.0.1:53109"),
            ("z9hG4bK-register-nat-b", "127.0.0.1:62000"),
        ] {
            let register = format!(
                "REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch={branch}\r\n\
From: <sip:3001@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Contact: <{client_contact}>;expires=60\r\n\
Call-ID: {branch}\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
            );
            server
                .handle_udp_packet(
                    &proxy_socket,
                    register.as_bytes(),
                    peer.parse().unwrap(),
                    &test_listener(),
                )
                .await
                .unwrap();
        }

        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let first = String::from_utf8(buf[..len].to_vec()).unwrap();
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let second = String::from_utf8(buf[..len].to_vec()).unwrap();

        assert_eq!(
            contact_uri_from_message(&first),
            contact_uri_from_message(&second)
        );
    }

    #[tokio::test]
    async fn register_path_mode_routes_proxy_contact_to_original_contact() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let client_addr = client_socket.local_addr().unwrap();
        let register = format!(
            "REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {client_addr};branch=z9hG4bK-register-path\r\n\
From: <sip:3000@example.com>;tag=a\r\n\
To: <sip:3000@example.com>\r\n\
Contact: <sip:3000@{client_addr};ob>;expires=60\r\n\
Call-ID: register-path\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                register.as_bytes(),
                client_addr,
                &test_listener(),
            )
            .await
            .unwrap();
        let mut upstream_buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut upstream_buf).await.unwrap();
        let forwarded_register = String::from_utf8(upstream_buf[..len].to_vec()).unwrap();
        complete_register_ok(
            &server,
            &proxy_socket,
            upstream_socket.local_addr().unwrap(),
            &forwarded_register,
            &format!("sip:3000@{client_addr};ob"),
            60,
        )
        .await;
        let mut client_buf = [0_u8; 4096];
        let _ = client_socket.recv_from(&mut client_buf).await.unwrap();

        let invite = b"INVITE sip:3000@127.0.0.1:5060;ob SIP/2.0\r\n\
Route: <sip:127.0.0.1:5060;lr>\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5080;branch=z9hG4bK-upstream-invite\r\n\
From: <sip:3001@example.com>;tag=a\r\n\
To: <sip:3000@example.com>\r\n\
Call-ID: inbound-through-proxy-contact\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:3001@example.com>\r\n\
Content-Length: 0\r\n\r\n";

        server
            .handle_udp_packet(
                &proxy_socket,
                invite,
                upstream_socket.local_addr().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = client_socket.recv_from(&mut client_buf).await.unwrap();
        let forwarded = String::from_utf8(client_buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with("INVITE sip:3000@127.0.0.1:5060;ob SIP/2.0"));
        assert!(forwarded.contains(PROXY_BRANCH_PREFIX));
        assert!(!forwarded.lines().any(|line| line.starts_with("Route:")));

        let invite_without_ob = b"INVITE sip:3000@127.0.0.1:5060 SIP/2.0\r\n\
Route: <sip:127.0.0.1:5060;lr>\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5080;branch=z9hG4bK-upstream-invite-no-ob\r\n\
From: <sip:3001@example.com>;tag=a\r\n\
To: <sip:3000@example.com>\r\n\
Call-ID: inbound-through-proxy-contact-no-ob\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:3001@example.com>\r\n\
Content-Length: 0\r\n\r\n";

        server
            .handle_udp_packet(
                &proxy_socket,
                invite_without_ob,
                upstream_socket.local_addr().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = client_socket.recv_from(&mut client_buf).await.unwrap();
        let forwarded = String::from_utf8(client_buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with("INVITE sip:3000@127.0.0.1:5060 SIP/2.0"));
        assert!(forwarded.contains(PROXY_BRANCH_PREFIX));
        assert!(!forwarded.lines().any(|line| line.starts_with("Route:")));
    }

    #[tokio::test]
    async fn downstream_invite_ignores_registered_location_and_uses_upstream() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let registered_client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let caller_peer: SocketAddr = "127.0.0.1:5061".parse().unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let registered_client_addr = registered_client_socket.local_addr().unwrap();
        let register = format!(
            "REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {registered_client_addr};branch=z9hG4bK-register-3001\r\n\
From: <sip:3001@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Contact: <sip:3001@{registered_client_addr}>;expires=60\r\n\
Call-ID: register-3001\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                register.as_bytes(),
                registered_client_addr,
                &test_listener(),
            )
            .await
            .unwrap();
        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded_register = String::from_utf8(buf[..len].to_vec()).unwrap();
        complete_register_ok(
            &server,
            &proxy_socket,
            upstream_socket.local_addr().unwrap(),
            &forwarded_register,
            &format!("sip:3001@{registered_client_addr}"),
            60,
        )
        .await;
        let _ = registered_client_socket.recv_from(&mut buf).await.unwrap();

        server
            .handle_udp_packet(
                &proxy_socket,
                b"INVITE sip:3001@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-downstream-invite\r\n\
Max-Forwards: 70\r\n\
From: <sip:3000@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Call-ID: downstream-invite-uses-upstream\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                caller_peer,
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with("INVITE sip:3001@example.com SIP/2.0"));
        assert!(
            timeout(
                Duration::from_millis(100),
                registered_client_socket.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn downstream_invite_routes_to_upstream_that_registered_callee() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let registered_client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstreams(vec![
            first_upstream.local_addr().unwrap(),
            second_upstream.local_addr().unwrap(),
        ]);
        let registered_client_addr = registered_client_socket.local_addr().unwrap();
        let register = format!(
            "REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {registered_client_addr};branch=z9hG4bK-register-3001-upstream\r\n\
From: <sip:3001@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Contact: <sip:3001@{registered_client_addr}>;expires=60\r\n\
Call-ID: register-3001-upstream\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                register.as_bytes(),
                registered_client_addr,
                &test_listener(),
            )
            .await
            .unwrap();
        let mut buf = [0_u8; 4096];
        let (len, _) = first_upstream.recv_from(&mut buf).await.unwrap();
        let forwarded_register = String::from_utf8(buf[..len].to_vec()).unwrap();
        complete_register_ok(
            &server,
            &proxy_socket,
            first_upstream.local_addr().unwrap(),
            &forwarded_register,
            &format!("sip:3001@{registered_client_addr}"),
            60,
        )
        .await;
        let _ = registered_client_socket.recv_from(&mut buf).await.unwrap();

        server
            .handle_udp_packet(
                &proxy_socket,
                b"INVITE sip:3001@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-downstream-invite-callee-upstream\r\n\
Max-Forwards: 70\r\n\
From: <sip:3000@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Call-ID: downstream-invite-callee-upstream\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = first_upstream.recv_from(&mut buf).await.unwrap();
        let forwarded_invite = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded_invite.starts_with("INVITE sip:3001@example.com SIP/2.0"));
        assert!(
            timeout(
                Duration::from_millis(100),
                second_upstream.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn proxy_address_request_uri_from_pbx_alias_routes_to_registered_location() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let registered_client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pbx_alias_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let registered_client_addr = registered_client_socket.local_addr().unwrap();
        let pbx_alias_addr = pbx_alias_socket.local_addr().unwrap();
        let register = format!(
            "REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {registered_client_addr};branch=z9hG4bK-register-3001\r\n\
From: <sip:3001@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Contact: <sip:3001@{registered_client_addr}>;expires=60\r\n\
Call-ID: register-3001-for-pbx-alias\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                register.as_bytes(),
                registered_client_addr,
                &test_listener(),
            )
            .await
            .unwrap();
        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded_register = String::from_utf8(buf[..len].to_vec()).unwrap();
        complete_register_ok(
            &server,
            &proxy_socket,
            upstream_socket.local_addr().unwrap(),
            &forwarded_register,
            &format!("sip:3001@{registered_client_addr}"),
            60,
        )
        .await;
        let _ = registered_client_socket.recv_from(&mut buf).await.unwrap();

        let invite = format!(
            "INVITE sip:3001@127.0.0.1:5060 SIP/2.0\r\n\
Route: <sip:127.0.0.1:5060;lr>\r\n\
Via: SIP/2.0/UDP {pbx_alias_addr};branch=z9hG4bK-pbx-alias\r\n\
Max-Forwards: 70\r\n\
From: <sip:3000@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Call-ID: pbx-alias-invite\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:3000@example.com>\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                invite.as_bytes(),
                pbx_alias_addr,
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = registered_client_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with("INVITE sip:3001@127.0.0.1:5060 SIP/2.0"));
        assert!(forwarded.contains(PROXY_BRANCH_PREFIX));
        assert!(!forwarded.lines().any(|line| line.starts_with("Route:")));
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn udp_registration_location_routes_to_observed_source_flow() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let registered_source_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let contact_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pbx_alias_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let registered_source_addr = registered_source_socket.local_addr().unwrap();
        let contact_addr = contact_socket.local_addr().unwrap();
        let pbx_alias_addr = pbx_alias_socket.local_addr().unwrap();
        let register = format!(
            "REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {contact_addr};branch=z9hG4bK-register-3001-flow;rport\r\n\
From: <sip:3001@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Contact: <sip:3001@{contact_addr}>;expires=60\r\n\
Call-ID: register-3001-flow\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                register.as_bytes(),
                registered_source_addr,
                &test_listener(),
            )
            .await
            .unwrap();
        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded_register = String::from_utf8(buf[..len].to_vec()).unwrap();
        complete_register_ok(
            &server,
            &proxy_socket,
            upstream_socket.local_addr().unwrap(),
            &forwarded_register,
            &format!("sip:3001@{contact_addr}"),
            60,
        )
        .await;
        let _ = registered_source_socket.recv_from(&mut buf).await.unwrap();

        let invite = format!(
            "INVITE sip:3001@127.0.0.1:5060 SIP/2.0\r\n\
Route: <sip:127.0.0.1:5060;lr>\r\n\
Via: SIP/2.0/UDP {pbx_alias_addr};branch=z9hG4bK-pbx-alias-flow\r\n\
Max-Forwards: 70\r\n\
From: <sip:3000@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Call-ID: pbx-alias-invite-flow\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:3000@example.com>\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                invite.as_bytes(),
                pbx_alias_addr,
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = registered_source_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with("INVITE sip:3001@127.0.0.1:5060 SIP/2.0"));
        assert!(
            timeout(
                Duration::from_millis(100),
                contact_socket.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn upstream_route_set_uses_to_aor_when_request_uri_contact_is_not_registered() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let registered_source_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stale_contact_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let registered_source_addr = registered_source_socket.local_addr().unwrap();
        let stale_contact_addr = stale_contact_socket.local_addr().unwrap();
        let register = format!(
            "REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP {registered_source_addr};branch=z9hG4bK-register-3001-to-aor;rport\r\n\
From: <sip:3001@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Contact: <sip:3001@{registered_source_addr}>;expires=60\r\n\
Call-ID: register-3001-to-aor\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                register.as_bytes(),
                registered_source_addr,
                &test_listener(),
            )
            .await
            .unwrap();
        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded_register = String::from_utf8(buf[..len].to_vec()).unwrap();
        complete_register_ok(
            &server,
            &proxy_socket,
            upstream_socket.local_addr().unwrap(),
            &forwarded_register,
            &format!("sip:3001@{registered_source_addr}"),
            60,
        )
        .await;
        let _ = registered_source_socket.recv_from(&mut buf).await.unwrap();

        let invite = format!(
            "INVITE sip:3001@{stale_contact_addr};ob SIP/2.0\r\n\
Route: <sip:127.0.0.1:5060;lr>\r\n\
Via: SIP/2.0/UDP {upstream};branch=z9hG4bK-upstream-to-aor\r\n\
Max-Forwards: 70\r\n\
From: <sip:3000@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Call-ID: upstream-to-aor-invite\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:3000@example.com>\r\n\
Content-Length: 0\r\n\r\n",
            upstream = upstream_socket.local_addr().unwrap()
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                invite.as_bytes(),
                upstream_socket.local_addr().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = registered_source_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with(&format!("INVITE sip:3001@{stale_contact_addr};ob SIP/2.0")));
        assert!(
            timeout(
                Duration::from_millis(100),
                stale_contact_socket.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn upstream_request_uri_contact_routes_directly_to_client() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let client_addr = client_socket.local_addr().unwrap();
        let packet = format!(
            "INVITE sip:6805@{client_addr} SIP/2.0\r\n\
Route: <sip:127.0.0.1:5060;lr>\r\n\
Via: SIP/2.0/UDP 18.162.106.21:5060;branch=z9hG4bK-upstream\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:6805@example.com>\r\n\
Call-ID: upstream-invite\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:100@example.com>\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                packet.as_bytes(),
                upstream_socket.local_addr().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with(&format!("INVITE sip:6805@{client_addr} SIP/2.0")));
        assert!(forwarded.contains(PROXY_BRANCH_PREFIX));
        assert!(!forwarded.lines().any(|line| line.starts_with("Route:")));
    }

    #[tokio::test]
    async fn trusted_route_set_request_uri_contact_routes_directly_to_client() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let trusted_peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone(), None));
        let server = ProxyServer::new(
            Config {
                sip: SipConfig {
                    external_addr: Some("127.0.0.1:5060".to_string()),
                    internal_probe_addr: upstream_socket.local_addr().unwrap().to_string(),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
                    security: ProxySecurityConfig {
                        trusted_cidrs: Some(vec!["127.0.0.0/8".to_string()]),
                        ..ProxySecurityConfig::default()
                    },
                    listeners: vec![test_listener()],
                    upstream_groups: vec![UpstreamGroupConfig {
                        name: "default".to_string(),
                        mode: UpstreamMode::RoundRobin,
                        health_check: UpstreamHealthCheckConfig::default(),
                        servers: vec![upstream_socket.local_addr().unwrap().to_string()],
                    }],
                    ..ProxyConfig::default()
                },
                ..Config::default()
            },
            state,
            replicator,
            None,
        )
        .unwrap();
        let packet = format!(
            "INVITE sip:3001@{client_addr};ob SIP/2.0\r\n\
Route: <sip:127.0.0.1:5060;lr>\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5088;branch=z9hG4bK-trusted-route-set\r\n\
From: <sip:3000@example.com>;tag=a\r\n\
To: <sip:3001@example.com>\r\n\
Call-ID: trusted-route-set-invite\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:3000@example.com>\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                packet.as_bytes(),
                trusted_peer_socket.local_addr().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with(&format!("INVITE sip:3001@{client_addr};ob SIP/2.0")));
        assert!(forwarded.contains(PROXY_BRANCH_PREFIX));
        assert!(!forwarded.lines().any(|line| line.starts_with("Route:")));
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn trusted_ack_without_route_set_routes_request_uri_contact_directly_to_client() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let trusted_peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone(), None));
        let server = ProxyServer::new(
            Config {
                sip: SipConfig {
                    external_addr: Some("127.0.0.1:5060".to_string()),
                    internal_probe_addr: upstream_socket.local_addr().unwrap().to_string(),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
                    security: ProxySecurityConfig {
                        trusted_cidrs: Some(vec!["127.0.0.0/8".to_string()]),
                        ..ProxySecurityConfig::default()
                    },
                    listeners: vec![test_listener()],
                    upstream_groups: vec![UpstreamGroupConfig {
                        name: "default".to_string(),
                        mode: UpstreamMode::RoundRobin,
                        health_check: UpstreamHealthCheckConfig::default(),
                        servers: vec![upstream_socket.local_addr().unwrap().to_string()],
                    }],
                    ..ProxyConfig::default()
                },
                ..Config::default()
            },
            state,
            replicator,
            None,
        )
        .unwrap();
        let packet = format!(
            "ACK sip:1002@{client_addr};ob SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5088;branch=z9hG4bK-trusted-ack-no-route\r\n\
Max-Forwards: 70\r\n\
From: <sip:1000@example.com>;tag=a\r\n\
To: <sip:1002@example.com>;tag=b\r\n\
Call-ID: trusted-ack-no-route\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                packet.as_bytes(),
                trusted_peer_socket.local_addr().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with(&format!("ACK sip:1002@{client_addr};ob SIP/2.0")));
        assert!(forwarded.contains(PROXY_BRANCH_PREFIX));
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn trusted_ack_contact_target_wins_over_stale_invite_transaction_route() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let trusted_peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone(), None));
        let server = ProxyServer::new(
            Config {
                sip: SipConfig {
                    external_addr: Some("127.0.0.1:5060".to_string()),
                    internal_probe_addr: upstream_socket.local_addr().unwrap().to_string(),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    security: ProxySecurityConfig {
                        trusted_cidrs: Some(vec!["127.0.0.0/8".to_string()]),
                        ..ProxySecurityConfig::default()
                    },
                    listeners: vec![test_listener()],
                    upstream_groups: vec![UpstreamGroupConfig {
                        name: "default".to_string(),
                        mode: UpstreamMode::RoundRobin,
                        health_check: UpstreamHealthCheckConfig::default(),
                        servers: vec![upstream_socket.local_addr().unwrap().to_string()],
                    }],
                    ..ProxyConfig::default()
                },
                ..Config::default()
            },
            state,
            replicator,
            None,
        )
        .unwrap();

        server
            .handle_udp_packet(
                &proxy_socket,
                b"INVITE sip:1002@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-reused-ack-branch\r\n\
Max-Forwards: 70\r\n\
From: <sip:1000@example.com>;tag=a\r\n\
To: <sip:1002@example.com>\r\n\
Call-ID: reused-ack-branch\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded_invite = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded_invite.contains("CSeq: 1 INVITE"));

        let ack = format!(
            "ACK sip:1002@{client_addr};ob SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5088;branch=z9hG4bK-reused-ack-branch\r\n\
Max-Forwards: 70\r\n\
From: <sip:1000@example.com>;tag=a\r\n\
To: <sip:1002@example.com>;tag=b\r\n\
Call-ID: reused-ack-branch\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\r\n"
        );
        server
            .handle_udp_packet(
                &proxy_socket,
                ack.as_bytes(),
                trusted_peer_socket.local_addr().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let forwarded_ack = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded_ack.starts_with(&format!("ACK sip:1002@{client_addr};ob SIP/2.0")));
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn own_route_set_is_removed_before_forwarding_to_client() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_dual_advertise(upstream_socket.local_addr().unwrap());
        let client_addr = client_socket.local_addr().unwrap();
        let packet = format!(
            "ACK sip:6805@{client_addr} SIP/2.0\r\n\
Route: <sip:172.30.0.101:5060;lr>,<sip:95.40.96.117:5060;lr>\r\n\
Via: SIP/2.0/UDP 172.30.0.60:5060;branch=z9hG4bK-upstream-ack\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:6805@example.com>;tag=b\r\n\
Call-ID: upstream-ack\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\r\n"
        );

        server
            .handle_udp_packet(
                &proxy_socket,
                packet.as_bytes(),
                upstream_socket.local_addr().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with(&format!("ACK sip:6805@{client_addr} SIP/2.0")));
        assert!(!forwarded.lines().any(|line| line.starts_with("Route:")));
    }

    #[tokio::test]
    async fn own_route_set_is_removed_before_forwarding_to_upstream() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_dual_advertise(upstream_socket.local_addr().unwrap());
        let packet = b"ACK sip:3000@example.com SIP/2.0\r\n\
Route: <sip:95.40.96.117:5060;lr>,<sip:172.30.0.101:5060;lr>\r\n\
Via: SIP/2.0/UDP 10.10.16.41:57362;branch=z9hG4bK-client-ack\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:3000@example.com>;tag=b\r\n\
Call-ID: client-ack\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\r\n";

        server
            .handle_udp_packet(
                &proxy_socket,
                packet,
                "10.10.16.41:57362".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(forwarded.starts_with("ACK sip:3000@example.com SIP/2.0"));
        assert!(!forwarded.lines().any(|line| line.starts_with("Route:")));
    }

    #[tokio::test]
    async fn metrics_records_forwarded_udp_requests() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let listener = test_listener();
        let client_peer = client_socket.local_addr().unwrap();

        server
            .handle_udp_packet(
                &proxy_socket,
                b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-metrics-options\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:example.com>\r\n\
Call-ID: metrics-options\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n",
                client_peer,
                &listener,
            )
            .await
            .unwrap();

        server
            .handle_udp_packet(
                &proxy_socket,
                b"MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-metrics-message\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: metrics-message\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
                client_peer,
                &listener,
            )
            .await
            .unwrap();

        let mut upstream_buf = [0_u8; 4096];
        let _ = upstream_socket.recv_from(&mut upstream_buf).await.unwrap();
        let _ = upstream_socket.recv_from(&mut upstream_buf).await.unwrap();

        let metrics = server.render_metrics().await;
        assert!(metrics.contains("sip_requests_total{transport=\"udp\",method=\"OPTIONS\"} 1"));
        assert!(metrics.contains("sip_requests_total{transport=\"udp\",method=\"MESSAGE\"} 1"));
        assert!(metrics.contains(
            "proxy_forwarded_requests_total{downstream_transport=\"udp\",upstream_transport=\"udp\",method=\"OPTIONS\"} 1"
        ));
        assert!(metrics.contains(
            "proxy_forwarded_requests_total{downstream_transport=\"udp\",upstream_transport=\"udp\",method=\"MESSAGE\"} 1"
        ));
        assert!(metrics.contains("proxy_affinity_lookup_total{result=\"miss\"} 2"));
        assert!(metrics.contains("# TYPE proxy_udp_branch_routes gauge"));
        assert!(metrics.contains("proxy_udp_branch_routes 2"));
        assert!(metrics.contains("# TYPE proxy_udp_client_transactions gauge"));
        assert!(metrics.contains("proxy_udp_client_transactions 2"));
        assert!(metrics.contains("proxy_invite_transaction_routes 0"));
        assert!(metrics.contains("proxy_affinity_bindings 1"));
        assert!(metrics.contains("proxy_location_bindings 0"));
        assert!(metrics.contains(&format!(
            "proxy_upstream_healthy{{group=\"default\",server=\"{}\"}} 1",
            upstream_socket.local_addr().unwrap()
        )));
    }

    #[tokio::test]
    async fn metrics_reports_persistence_and_ha_replication_counters() {
        let dir = tempfile::tempdir().unwrap();
        let persistence = Persistence::open(&PersistenceConfig {
            enabled: true,
            path: dir.path().join("state.db").to_string_lossy().to_string(),
            required: false,
            event_retention_seconds: 3600,
            cleanup_interval_ms: 60_000,
        })
        .unwrap()
        .unwrap();
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(
            state.clone(),
            Some(persistence.clone()),
        ));
        let server = ProxyServer::new(
            Config {
                proxy: ProxyConfig {
                    listeners: vec![test_listener()],
                    upstream_groups: vec![UpstreamGroupConfig {
                        name: "default".to_string(),
                        mode: UpstreamMode::RoundRobin,
                        health_check: UpstreamHealthCheckConfig::default(),
                        servers: vec!["127.0.0.1:5080".to_string()],
                    }],
                    ..ProxyConfig::default()
                },
                ..Config::default()
            },
            state,
            replicator,
            Some(persistence.clone()),
        )
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
        server.record_ha_event_pull("applied");
        server.record_ha_snapshot_pull("installed");
        server.record_ha_snapshot_fallback("event-pull-error");

        let metrics = server.render_metrics().await;
        assert!(metrics.contains("proxy_persistence_latest_event_seq 1"));
        assert!(metrics.contains("proxy_persistence_last_applied_seq 0"));
        assert!(metrics.contains("proxy_persistence_event_rows 1"));
        assert!(metrics.contains("proxy_persistence_background_pending_events 0"));
        assert!(metrics.contains("proxy_persistence_event_lag{role=\"standalone\"} 1"));
        assert!(metrics.contains("proxy_persistence_event_appends_total{result=\"success\"} 1"));
        assert!(metrics.contains("proxy_persistence_sqlite_write_failures_total 0"));
        assert!(metrics.contains("proxy_ha_event_pulls_total{result=\"applied\"} 1"));
        assert!(metrics.contains("proxy_ha_snapshot_pulls_total{result=\"installed\"} 1"));
        assert!(
            metrics.contains("proxy_ha_snapshot_fallbacks_total{reason=\"event-pull-error\"} 1")
        );
    }

    #[tokio::test]
    async fn metrics_reports_security_runtime_gauges() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_security(
            upstream_socket.local_addr().unwrap(),
            ProxySecurityConfig::default(),
        );
        let listener_key = test_listener().key();
        let now = Instant::now();
        let ip_block_key = "block|udp/127.0.0.1:5060|203.0.113.10";
        let sip_block_key = "sip-block|udp/127.0.0.1:5060|INVITE|sip:100@example.com";
        let expired_block_key = "block|udp/127.0.0.1:5060|198.51.100.10";
        let packet_bucket_key = "packets|udp/127.0.0.1:5060|203.0.113.10";
        let dynamic_bucket_key = "dynamic-ban|parse-error|udp/127.0.0.1:5060|203.0.113.10";

        server
            .security
            .blocks
            .shard_for_key(ip_block_key)
            .lock()
            .await
            .insert(ip_block_key.to_string(), now + Duration::from_secs(60));
        server
            .security
            .blocks
            .shard_for_key(sip_block_key)
            .lock()
            .await
            .insert(sip_block_key.to_string(), now + Duration::from_secs(60));
        server
            .security
            .blocks
            .shard_for_key(expired_block_key)
            .lock()
            .await
            .insert(expired_block_key.to_string(), now - Duration::from_secs(1));
        server
            .security
            .buckets
            .shard_for_key(packet_bucket_key)
            .lock()
            .await
            .insert(
                packet_bucket_key.to_string(),
                TokenBucket {
                    tokens: 1.0,
                    updated_at: now,
                },
            );
        server
            .security
            .buckets
            .shard_for_key(dynamic_bucket_key)
            .lock()
            .await
            .insert(
                dynamic_bucket_key.to_string(),
                TokenBucket {
                    tokens: 1.0,
                    updated_at: now,
                },
            );

        let metrics = server.render_metrics().await;
        assert!(metrics.contains("proxy_security_active_blocks 2"));
        assert!(metrics.contains("proxy_security_token_buckets 2"));
        assert!(metrics.contains(&format!(
            "proxy_security_active_blocks_by_listener{{listener=\"{listener_key}\",kind=\"block\"}} 1"
        )));
        assert!(metrics.contains(&format!(
            "proxy_security_active_blocks_by_listener{{listener=\"{listener_key}\",kind=\"sip-block\"}} 1"
        )));
        assert!(metrics.contains(&format!(
            "proxy_security_token_buckets_by_listener{{listener=\"{listener_key}\",kind=\"dynamic-ban\"}} 1"
        )));
        assert!(metrics.contains(&format!(
            "proxy_security_token_buckets_by_listener{{listener=\"{listener_key}\",kind=\"packets\"}} 1"
        )));
        assert!(!metrics.contains("203.0.113.10"));
    }

    #[tokio::test]
    async fn udp_response_path_removes_proxy_via_and_allows_multiple_responses() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let listener = test_listener();
        let client_addr = client_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0_u8; 4096];
            let (len, proxy_addr) = upstream_socket.recv_from(&mut buf).await.unwrap();
            let request = String::from_utf8(buf[..len].to_vec()).unwrap();
            let vias = request
                .lines()
                .filter(|line| line.starts_with("Via:"))
                .map(str::to_string)
                .collect::<Vec<_>>();
            assert_eq!(vias.len(), 2);
            assert!(vias[0].contains(PROXY_BRANCH_PREFIX));
            assert!(vias[1].contains("z9hG4bK-client"));

            for code in ["100 Trying", "180 Ringing", "200 OK", "200 OK"] {
                let response = format!(
                    "SIP/2.0 {code}\r\n\
{proxy_via}\r\n\
{client_via}\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>;tag=b\r\n\
Call-ID: call-1\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                    proxy_via = vias[0],
                    client_via = vias[1],
                );
                upstream_socket
                    .send_to(response.as_bytes(), proxy_addr)
                    .await
                    .unwrap();
            }
        });

        server
            .handle_udp_packet(
                &proxy_socket,
                b"INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-client\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: call-1\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                client_addr,
                &listener,
            )
            .await
            .unwrap();

        for code in ["100 Trying", "180 Ringing", "200 OK", "200 OK"] {
            let mut proxy_buf = [0_u8; 4096];
            let (len, upstream_peer) = proxy_socket.recv_from(&mut proxy_buf).await.unwrap();
            server
                .handle_udp_packet(&proxy_socket, &proxy_buf[..len], upstream_peer, &listener)
                .await
                .unwrap();

            let mut client_buf = [0_u8; 4096];
            let (len, _) = client_socket.recv_from(&mut client_buf).await.unwrap();
            let response = String::from_utf8(client_buf[..len].to_vec()).unwrap();
            assert!(response.starts_with(&format!("SIP/2.0 {code}")));
            assert!(!response.contains(PROXY_BRANCH_PREFIX));
            assert!(response.contains("z9hG4bK-client"));
        }

        assert_eq!(server.active_udp_branch_count().await, 1);
    }

    #[tokio::test]
    async fn udp_non_invite_final_response_removes_branch_route() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let listener = test_listener();
        let client_addr = client_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0_u8; 4096];
            let (len, proxy_addr) = upstream_socket.recv_from(&mut buf).await.unwrap();
            let request = String::from_utf8(buf[..len].to_vec()).unwrap();
            let vias = request
                .lines()
                .filter(|line| line.starts_with("Via:"))
                .map(str::to_string)
                .collect::<Vec<_>>();
            assert_eq!(vias.len(), 2);
            assert!(vias[0].contains(PROXY_BRANCH_PREFIX));
            let response = format!(
                "SIP/2.0 200 OK\r\n\
{proxy_via}\r\n\
{client_via}\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:example.com>;tag=b\r\n\
Call-ID: options-branch-cleanup\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n",
                proxy_via = vias[0],
                client_via = vias[1],
            );
            upstream_socket
                .send_to(response.as_bytes(), proxy_addr)
                .await
                .unwrap();
        });

        server
            .handle_udp_packet(
                &proxy_socket,
                b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-client-options\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:example.com>\r\n\
Call-ID: options-branch-cleanup\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n",
                client_addr,
                &listener,
            )
            .await
            .unwrap();

        let mut proxy_buf = [0_u8; 4096];
        let (len, upstream_peer) = proxy_socket.recv_from(&mut proxy_buf).await.unwrap();
        server
            .handle_udp_packet(&proxy_socket, &proxy_buf[..len], upstream_peer, &listener)
            .await
            .unwrap();

        let mut client_buf = [0_u8; 4096];
        let (len, _) = client_socket.recv_from(&mut client_buf).await.unwrap();
        let response = String::from_utf8(client_buf[..len].to_vec()).unwrap();
        assert!(response.starts_with("SIP/2.0 200 OK"));
        assert!(!response.contains(PROXY_BRANCH_PREFIX));
        assert!(response.contains("z9hG4bK-client-options"));
        assert_eq!(server.active_udp_branch_count().await, 0);
        assert_eq!(server.affinity.active_len().await, 0);

        let metrics = server.render_metrics().await;
        assert!(metrics.contains(
            "proxy_upstream_response_latency_ms_bucket{downstream_transport=\"udp\",upstream_transport=\"udp\",method=\"OPTIONS\",le=\"+Inf\"} 1"
        ));
        assert!(metrics.contains(
            "proxy_upstream_response_latency_ms_count{downstream_transport=\"udp\",upstream_transport=\"udp\",method=\"OPTIONS\"} 1"
        ));
    }

    #[tokio::test]
    async fn udp_to_tcp_upstream_streams_multiple_invite_responses() {
        let tcp_client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_client_addr = tcp_client_listener.local_addr().unwrap();
        let proxy_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let pbx_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pbx_addr = pbx_socket.local_addr().unwrap();
        let server = Arc::new(test_server_with_upstream(pbx_addr));
        let listener = test_listener();

        server
            .state
            .apply(ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:200@example.com".to_string(),
                contact: format!("<sip:200@{tcp_client_addr};transport=tcp>"),
                source: "127.0.0.1:5061".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await;

        tokio::spawn(async move {
            let (mut stream, _) = tcp_client_listener.accept().await.unwrap();
            let mut reader = TcpSipReader::new(4096);
            let request = reader.read_message(&mut stream).await.unwrap().unwrap();
            let request = String::from_utf8(request).unwrap();
            let vias = request
                .lines()
                .filter(|line| line.starts_with("Via:"))
                .map(str::to_string)
                .collect::<Vec<_>>();
            assert_eq!(vias.len(), 2);
            assert!(vias[0].contains(PROXY_BRANCH_PREFIX));
            assert!(vias[0].contains("SIP/2.0/TCP"));
            assert!(vias[1].contains("z9hG4bK-client"));

            for code in ["100 Trying", "180 Ringing", "200 OK"] {
                let response = format!(
                    "SIP/2.0 {code}\r\n\
{proxy_via}\r\n\
{client_via}\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>;tag=b\r\n\
Call-ID: udp-tcp-call\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                    proxy_via = vias[0],
                    client_via = vias[1],
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let proxy_task = {
            let server = server.clone();
            let proxy_socket = proxy_socket.clone();
            tokio::spawn(async move {
                server
                    .handle_udp_packet(
                        proxy_socket.as_ref(),
                        b"INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-client\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: udp-tcp-call\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                        pbx_addr,
                        &listener,
                    )
                    .await
                    .unwrap();
            })
        };

        for code in ["100 Trying", "180 Ringing", "200 OK"] {
            let mut client_buf = [0_u8; 4096];
            let (len, _) = pbx_socket.recv_from(&mut client_buf).await.unwrap();
            let response = String::from_utf8(client_buf[..len].to_vec()).unwrap();
            assert!(response.starts_with(&format!("SIP/2.0 {code}")));
            assert!(!response.contains(PROXY_BRANCH_PREFIX));
            assert!(response.contains("z9hG4bK-client"));
        }

        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn affinity_routes_same_call_id_to_same_upstream() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstreams(vec![
            first_upstream.local_addr().unwrap(),
            second_upstream.local_addr().unwrap(),
        ]);
        let listener = test_listener();
        let client_peer: SocketAddr = "127.0.0.1:5061".parse().unwrap();

        for cseq in [1, 2] {
            let request = format!(
                "MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-client-{cseq}\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: stable-call\r\n\
CSeq: {cseq} MESSAGE\r\n\
Content-Length: 0\r\n\r\n"
            );
            server
                .handle_udp_packet(&proxy_socket, request.as_bytes(), client_peer, &listener)
                .await
                .unwrap();

            let mut buf = [0_u8; 4096];
            let (len, _) = timeout(
                Duration::from_millis(500),
                first_upstream.recv_from(&mut buf),
            )
            .await
            .unwrap()
            .unwrap();
            let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
            assert!(forwarded.contains("Call-ID: stable-call"));
        }

        let mut buf = [0_u8; 4096];
        assert!(
            timeout(
                Duration::from_millis(100),
                second_upstream.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn unhealthy_affinity_target_falls_back_to_healthy_upstream() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first_upstream.local_addr().unwrap();
        let second_addr = second_upstream.local_addr().unwrap();
        let server = test_server_with_upstreams_and_affinity(
            vec![first_addr, second_addr],
            ProxyAffinityConfig {
                enabled: true,
                key: ProxyAffinityKey::CallId,
                ttl_seconds: 3600,
            },
        );
        server
            .upstreams
            .groups
            .get("default")
            .unwrap()
            .set_health(0, false);
        let request = SipMessage::parse(
            b"MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-affinity-unhealthy\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: stale-affinity\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();
        server
            .affinity
            .remember(
                &request,
                AffinityTarget {
                    addr: first_addr,
                    transport: SipTransport::Udp,
                },
            )
            .await
            .unwrap();

        server
            .handle_udp_packet(
                &proxy_socket,
                &request.to_bytes(),
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        timeout(
            Duration::from_millis(500),
            second_upstream.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            timeout(
                Duration::from_millis(100),
                first_upstream.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn proxy_alias_request_ignores_unhealthy_affinity_target() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first_upstream.local_addr().unwrap();
        let second_addr = second_upstream.local_addr().unwrap();
        let server = test_server_with_upstreams_and_affinity(
            vec![first_addr, second_addr],
            ProxyAffinityConfig {
                enabled: true,
                key: ProxyAffinityKey::CallId,
                ttl_seconds: 3600,
            },
        );
        server
            .upstreams
            .groups
            .get("default")
            .unwrap()
            .set_health(0, false);
        let request = SipMessage::parse(
            b"MESSAGE sip:127.0.0.1:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-affinity-proxy-alias\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: stale-affinity-proxy-alias\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();
        server
            .affinity
            .remember(
                &request,
                AffinityTarget {
                    addr: first_addr,
                    transport: SipTransport::Udp,
                },
            )
            .await
            .unwrap();

        server
            .handle_udp_packet(
                &proxy_socket,
                &request.to_bytes(),
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        timeout(
            Duration::from_millis(500),
            second_upstream.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            timeout(
                Duration::from_millis(100),
                first_upstream.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn max_forwards_zero_returns_483_without_forwarding() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());

        server
            .handle_udp_packet(
                &proxy_socket,
                b"MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-mf0\r\n\
Max-Forwards: 0\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: mf0\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
                client_socket.local_addr().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut client_buf = [0_u8; 4096];
        let (len, _) = client_socket.recv_from(&mut client_buf).await.unwrap();
        let response = String::from_utf8(client_buf[..len].to_vec()).unwrap();
        assert!(response.starts_with("SIP/2.0 483 Too Many Hops"));

        let mut upstream_buf = [0_u8; 4096];
        assert!(
            timeout(
                Duration::from_millis(100),
                upstream_socket.recv_from(&mut upstream_buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn max_forwards_is_decremented_before_forwarding() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());

        server
            .handle_udp_packet(
                &proxy_socket,
                b"MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-mf1\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: mf1\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut upstream_buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut upstream_buf).await.unwrap();
        let request = String::from_utf8(upstream_buf[..len].to_vec()).unwrap();
        assert!(request.contains("Max-Forwards: 69"));
    }

    #[tokio::test]
    async fn missing_max_forwards_is_added_before_forwarding() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());

        server
            .handle_udp_packet(
                &proxy_socket,
                b"MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-mf-missing\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: mf-missing\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut upstream_buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut upstream_buf).await.unwrap();
        let request = String::from_utf8(upstream_buf[..len].to_vec()).unwrap();
        assert!(request.contains("Max-Forwards: 70"));
    }

    #[tokio::test]
    async fn cancel_routes_to_original_invite_upstream_without_affinity() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstreams_and_affinity(
            vec![
                first_upstream.local_addr().unwrap(),
                second_upstream.local_addr().unwrap(),
            ],
            ProxyAffinityConfig {
                enabled: false,
                ..ProxyAffinityConfig::default()
            },
        );
        let client_peer: SocketAddr = "127.0.0.1:5061".parse().unwrap();

        server
            .handle_udp_packet(
                &proxy_socket,
                b"INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-invite\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: cancel-same-target\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                client_peer,
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = first_upstream.recv_from(&mut buf).await.unwrap();
        let invite = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(invite.contains("CSeq: 1 INVITE"));
        let invite_via = top_via_line(&invite);

        server
            .handle_udp_packet(
                &proxy_socket,
                b"CANCEL sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-invite\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: cancel-same-target\r\n\
CSeq: 1 CANCEL\r\n\
Content-Length: 0\r\n\r\n",
                client_peer,
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = first_upstream.recv_from(&mut buf).await.unwrap();
        let cancel = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(cancel.contains("CSeq: 1 CANCEL"));
        assert_eq!(top_via_line(&cancel), invite_via);

        assert!(
            timeout(
                Duration::from_millis(100),
                second_upstream.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn ack_routes_to_original_invite_upstream_without_affinity() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstreams_and_affinity(
            vec![
                first_upstream.local_addr().unwrap(),
                second_upstream.local_addr().unwrap(),
            ],
            ProxyAffinityConfig {
                enabled: false,
                ..ProxyAffinityConfig::default()
            },
        );
        let client_peer: SocketAddr = "127.0.0.1:5061".parse().unwrap();

        server
            .handle_udp_packet(
                &proxy_socket,
                b"INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-ack-invite\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: ack-same-target\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                client_peer,
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = first_upstream.recv_from(&mut buf).await.unwrap();
        let invite = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(invite.contains("CSeq: 1 INVITE"));
        let invite_via = top_via_line(&invite);

        server
            .handle_udp_packet(
                &proxy_socket,
                b"ACK sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-ack-invite\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>;tag=b\r\n\
Call-ID: ack-same-target\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\r\n",
                client_peer,
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = first_upstream.recv_from(&mut buf).await.unwrap();
        let ack = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(ack.contains("CSeq: 1 ACK"));
        assert_eq!(top_via_line(&ack), invite_via);

        assert!(
            timeout(
                Duration::from_millis(100),
                second_upstream.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn in_dialog_methods_use_call_id_fallback_after_initial_invite() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstreams(vec![
            first_upstream.local_addr().unwrap(),
            second_upstream.local_addr().unwrap(),
        ]);
        let client_peer: SocketAddr = "127.0.0.1:5061".parse().unwrap();

        let invite = "INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-dialog-invite\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: dialog-fallback\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        server
            .handle_udp_packet(
                &proxy_socket,
                invite.as_bytes(),
                client_peer,
                &test_listener(),
            )
            .await
            .unwrap();
        let mut buf = [0_u8; 4096];
        let (len, _) = first_upstream.recv_from(&mut buf).await.unwrap();
        assert!(
            String::from_utf8(buf[..len].to_vec())
                .unwrap()
                .contains("CSeq: 1 INVITE")
        );

        for (method, cseq) in [("BYE", 2), ("INVITE", 3), ("UPDATE", 4)] {
            let request = format!(
                "{method} sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-dialog-{cseq}\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>;tag=b\r\n\
Call-ID: dialog-fallback\r\n\
CSeq: {cseq} {method}\r\n\
Content-Length: 0\r\n\r\n"
            );
            server
                .handle_udp_packet(
                    &proxy_socket,
                    request.as_bytes(),
                    client_peer,
                    &test_listener(),
                )
                .await
                .unwrap();

            let (len, _) = first_upstream.recv_from(&mut buf).await.unwrap();
            let forwarded = String::from_utf8(buf[..len].to_vec()).unwrap();
            assert!(forwarded.contains(&format!("CSeq: {cseq} {method}")));
        }

        assert!(
            timeout(
                Duration::from_millis(100),
                second_upstream.recv_from(&mut buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn record_route_is_only_added_to_dialog_forming_requests() {
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = test_server_with_upstream(upstream_socket.local_addr().unwrap());
        let client_peer: SocketAddr = "127.0.0.1:5061".parse().unwrap();

        server
            .handle_udp_packet(
                &proxy_socket,
                b"MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-rr-message\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: rr-message\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
                client_peer,
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let message = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(!message.contains("Record-Route:"));

        server
            .handle_udp_packet(
                &proxy_socket,
                b"INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-rr-invite\r\n\
Max-Forwards: 70\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: rr-invite\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                client_peer,
                &test_listener(),
            )
            .await
            .unwrap();

        let (len, _) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let invite = String::from_utf8(buf[..len].to_vec()).unwrap();
        assert!(invite.contains("Record-Route:"));
    }

    #[tokio::test]
    async fn proxy_state_snapshot_restores_contacts_and_affinity() {
        let source = test_server_with_upstream("127.0.0.1:5080".parse().unwrap());
        let target = test_server_with_upstream("127.0.0.1:5080".parse().unwrap());
        source
            .state
            .apply(ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:100@example.com".to_string(),
                contact: "<sip:100@127.0.0.1:5061>;expires=60".to_string(),
                source: "127.0.0.1:5061".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await;

        let request = SipMessage::parse(
            b"MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK2\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: stable-call\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();
        let affinity_target = AffinityTarget {
            addr: "127.0.0.1:5080".parse().unwrap(),
            transport: SipTransport::Udp,
        };
        source
            .affinity
            .remember(&request, affinity_target)
            .await
            .unwrap();

        target
            .install_state_snapshot(source.snapshot_state().await)
            .await;

        assert!(target.state.lookup("sip:100@example.com").await.is_some());
        assert_eq!(
            target.affinity.lookup(&request).await.unwrap(),
            Some(affinity_target)
        );
    }

    #[tokio::test]
    async fn proxy_state_snapshot_rejects_invalid_checksum() {
        let source = test_server_with_upstream("127.0.0.1:5080".parse().unwrap());
        let target = test_server_with_upstream("127.0.0.1:5080".parse().unwrap());
        source
            .state
            .apply(ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:checksum@example.com".to_string(),
                contact: "<sip:checksum@127.0.0.1:5061>;expires=60".to_string(),
                source: "127.0.0.1:5061".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await;

        let mut snapshot = source.snapshot_state().await;
        snapshot.checksum = "bad-checksum".to_string();
        target.install_state_snapshot(snapshot).await;

        assert!(
            target
                .state
                .lookup("sip:checksum@example.com")
                .await
                .is_none()
        );
    }

    #[test]
    fn upstream_group_skips_unhealthy_servers_when_possible() {
        let group = UpstreamGroupRuntime::new(&UpstreamGroupConfig {
            name: "default".to_string(),
            mode: UpstreamMode::RoundRobin,
            health_check: UpstreamHealthCheckConfig::default(),
            servers: vec!["127.0.0.1:5080".to_string(), "127.0.0.1:5081".to_string()],
        })
        .unwrap();

        group.set_health(0, false);
        assert_eq!(group.select().unwrap(), "127.0.0.1:5081".parse().unwrap());
    }

    #[test]
    fn upstream_group_applies_health_thresholds() {
        let group = UpstreamGroupRuntime::new(&UpstreamGroupConfig {
            name: "default".to_string(),
            mode: UpstreamMode::RoundRobin,
            health_check: UpstreamHealthCheckConfig {
                enabled: true,
                failure_threshold: 2,
                success_threshold: 2,
                ..UpstreamHealthCheckConfig::default()
            },
            servers: vec!["127.0.0.1:5080".to_string(), "127.0.0.1:5081".to_string()],
        })
        .unwrap();

        group.record_health_result(0, false);
        assert_eq!(group.select().unwrap(), "127.0.0.1:5080".parse().unwrap());
        group.record_health_result(0, false);
        assert_eq!(group.select().unwrap(), "127.0.0.1:5081".parse().unwrap());

        group.record_health_result(0, true);
        assert_eq!(group.select().unwrap(), "127.0.0.1:5081".parse().unwrap());
        group.record_health_result(0, true);
        assert_eq!(group.select().unwrap(), "127.0.0.1:5080".parse().unwrap());
    }

    #[test]
    fn passive_health_feedback_is_ignored_when_health_check_disabled() {
        let group = UpstreamGroupRuntime::new(&UpstreamGroupConfig {
            name: "default".to_string(),
            mode: UpstreamMode::RoundRobin,
            health_check: UpstreamHealthCheckConfig {
                enabled: false,
                failure_threshold: 1,
                ..UpstreamHealthCheckConfig::default()
            },
            servers: vec!["127.0.0.1:5080".to_string(), "127.0.0.1:5081".to_string()],
        })
        .unwrap();

        group.record_passive_result_at(0, false);

        assert_eq!(group.select().unwrap(), "127.0.0.1:5080".parse().unwrap());
    }

    #[test]
    fn upstream_groups_index_updates_shared_server_in_each_group() {
        let shared = "127.0.0.1:5080".parse().unwrap();
        let groups = UpstreamGroups::new(&[
            UpstreamGroupConfig {
                name: "first".to_string(),
                mode: UpstreamMode::RoundRobin,
                health_check: UpstreamHealthCheckConfig {
                    enabled: true,
                    failure_threshold: 1,
                    ..UpstreamHealthCheckConfig::default()
                },
                servers: vec!["127.0.0.1:5080".to_string(), "127.0.0.1:5081".to_string()],
            },
            UpstreamGroupConfig {
                name: "second".to_string(),
                mode: UpstreamMode::RoundRobin,
                health_check: UpstreamHealthCheckConfig {
                    enabled: true,
                    failure_threshold: 1,
                    ..UpstreamHealthCheckConfig::default()
                },
                servers: vec!["127.0.0.1:5080".to_string(), "127.0.0.1:5082".to_string()],
            },
        ])
        .unwrap();

        assert!(groups.contains(shared));
        assert!(groups.is_healthy(shared));
        assert!(groups.is_healthy("127.0.0.1:5999".parse().unwrap()));

        groups.record_passive_result(shared, false);

        assert!(!groups.groups["first"].is_healthy_at(0));
        assert!(!groups.groups["second"].is_healthy_at(0));
        assert!(!groups.is_healthy(shared));
    }

    #[test]
    fn health_options_reuses_call_id_per_backend() {
        let server = "127.0.0.1:5080".parse().unwrap();
        let sent_by = "127.0.0.1:5099".parse().unwrap();
        let first_request = build_health_options_request(
            server,
            "sip:healthcheck@example.com",
            SipTransport::Udp,
            sent_by,
            false,
        )
        .unwrap();
        let second_request = build_health_options_request(
            server,
            "sip:healthcheck@example.com",
            SipTransport::Udp,
            sent_by,
            false,
        )
        .unwrap();
        let first = SipMessage::parse(&first_request.packet).unwrap();
        let second = SipMessage::parse(&second_request.packet).unwrap();

        assert_eq!(first.header("call-id"), second.header("call-id"));
        let call_id = first.header("call-id").unwrap();
        assert!(call_id.ends_with("@sipproxy-rs"));
        assert_uuid_like(&call_id[..call_id.len() - "@sipproxy-rs".len()]);
        assert_ne!(first.header("cseq"), second.header("cseq"));
        assert_ne!(
            first.top_via_branch().unwrap(),
            second.top_via_branch().unwrap()
        );
    }

    #[test]
    fn health_options_can_vary_call_id_per_probe() {
        let server = "127.0.0.1:5080".parse().unwrap();
        let sent_by = "127.0.0.1:5099".parse().unwrap();
        let first_request = build_health_options_request(
            server,
            "sip:healthcheck@example.com",
            SipTransport::Udp,
            sent_by,
            true,
        )
        .unwrap();
        let second_request = build_health_options_request(
            server,
            "sip:healthcheck@example.com",
            SipTransport::Udp,
            sent_by,
            true,
        )
        .unwrap();
        let first = SipMessage::parse(&first_request.packet).unwrap();
        let second = SipMessage::parse(&second_request.packet).unwrap();

        assert_ne!(first.header("call-id"), second.header("call-id"));
        assert_ne!(first.header("cseq"), second.header("cseq"));
        assert_ne!(
            first.top_via_branch().unwrap(),
            second.top_via_branch().unwrap()
        );
    }

    #[test]
    fn health_options_response_branch_matching_uses_typed_via() {
        assert!(
            health_options_response_matches_branch(
                b"SIP/2.0 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n",
                "z9hG4bK-health-1",
            )
            .unwrap()
        );
        assert!(
            health_options_response_matches_branch(
                b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-health-1;rport=5060\r\n\
Content-Length: 0\r\n\r\n",
                "z9hG4bK-health-1",
            )
            .unwrap()
        );
        assert!(
            !health_options_response_matches_branch(
                b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-other;rport=5060\r\n\
Content-Length: 0\r\n\r\n",
                "z9hG4bK-health-1",
            )
            .unwrap()
        );
    }

    fn assert_uuid_like(value: &str) {
        assert_eq!(value.len(), 36);
        for index in [8, 13, 18, 23] {
            assert_eq!(value.as_bytes()[index], b'-');
        }
        assert!(
            value
                .chars()
                .enumerate()
                .all(|(index, ch)| [8, 13, 18, 23].contains(&index) || ch.is_ascii_hexdigit())
        );
    }

    fn top_via_line(message: &str) -> &str {
        message
            .lines()
            .find(|line| line.starts_with("Via:"))
            .unwrap()
    }

    fn header_lines<'a>(message: &'a str, name: &str) -> Vec<&'a str> {
        let prefix = format!("{name}:");
        message
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .collect()
    }

    fn contact_uri_from_message(message: &str) -> String {
        let value = header_lines(message, "Contact")
            .first()
            .unwrap()
            .trim_start_matches("Contact:")
            .trim();
        RsipContact::parse(value).unwrap().uri.to_string()
    }

    async fn complete_register_ok(
        server: &ProxyServer,
        proxy_socket: &UdpSocket,
        upstream: SocketAddr,
        forwarded_register: &str,
        contact: &str,
        expires: u64,
    ) {
        let branch = SipMessage::parse(forwarded_register.as_bytes())
            .unwrap()
            .top_via_branch()
            .unwrap()
            .unwrap();
        let response = format!(
            "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5060;branch={branch};rport=5060\r\n\
Contact: <{contact}>;expires={expires}\r\n\
Call-ID: register-ok\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
        );
        server
            .handle_udp_packet(
                proxy_socket,
                response.as_bytes(),
                upstream,
                &test_listener(),
            )
            .await
            .unwrap();
    }

    #[test]
    fn advertised_addr_auto_detection_only_replaces_local_bindings() {
        assert!(advertised_addr_needs_auto("127.0.0.1:5060"));
        assert!(advertised_addr_needs_auto("0.0.0.0:5060"));
        assert!(advertised_addr_needs_auto("[::]:5060"));
        assert!(!advertised_addr_needs_auto("198.51.100.10:5060"));
        assert!(!advertised_addr_needs_auto("sip.example.com:5060"));
    }

    #[test]
    fn udp_keepalive_and_stun_packets_are_classified() {
        assert!(is_crlf_keepalive(b""));
        assert!(is_crlf_keepalive(b"\r\n\r\n"));
        assert!(!is_crlf_keepalive(b"REGISTER sip:example.com SIP/2.0\r\n"));

        let mut request = Vec::new();
        request.extend_from_slice(&0x0001_u16.to_be_bytes());
        request.extend_from_slice(&0_u16.to_be_bytes());
        request.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        request.extend_from_slice(b"abcdefghijkl");

        let peer = "127.0.0.1:62607".parse().unwrap();
        let response = stun_binding_success_response(&request, peer).unwrap();
        assert_eq!(&response[0..2], &0x0101_u16.to_be_bytes());
        assert_eq!(&response[2..4], &12_u16.to_be_bytes());
        assert_eq!(&response[4..8], &STUN_MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&response[8..20], b"abcdefghijkl");
        assert_eq!(&response[20..22], &0x0020_u16.to_be_bytes());
    }

    #[tokio::test]
    async fn public_addr_can_be_discovered_with_stun() {
        let stun = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0_u8; 1500];
            let (len, peer) = stun.recv_from(&mut buf).await.unwrap();
            let response = stun_binding_success_response(&buf[..len], peer).unwrap();
            stun.send_to(&response, peer).await.unwrap();
        });

        let ip = discover_public_ip(&stun_addr.to_string()).await.unwrap();

        assert_eq!(ip, IpAddr::from([127, 0, 0, 1]));
    }

    #[tokio::test]
    async fn udp_health_probe_reuses_local_socket() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let peers = Arc::new(Mutex::new(Vec::new()));
        let server_peers = peers.clone();
        tokio::spawn(async move {
            let mut buf = [0; 4096];
            for _ in 0..2 {
                let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
                server_peers.lock().await.push(peer);
                let request = String::from_utf8(buf[..len].to_vec()).unwrap();
                let via = request
                    .lines()
                    .find(|line| line.starts_with("Via:"))
                    .unwrap();
                let response = format!("SIP/2.0 200 OK\r\n{via}\r\nContent-Length: 0\r\n\r\n");
                upstream.send_to(response.as_bytes(), peer).await.unwrap();
            }
        });

        let socket = Arc::new(bind_health_probe_udp_socket(upstream_addr).await.unwrap());
        for _ in 0..2 {
            assert!(
                probe_sip_options(
                    SipOptionsProbe {
                        server: upstream_addr,
                        transport: SipTransport::Udp,
                        uri: "sip:healthcheck@localhost",
                        vary_call_id: false,
                        limit: Duration::from_millis(500),
                        success_codes: &[200],
                    },
                    Some(socket.clone()),
                    None,
                )
                .await
                .healthy
            );
        }

        let peers = peers.lock().await;
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0], peers[1]);
    }

    #[tokio::test]
    async fn health_probe_uses_configured_success_codes() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0; 2048];
            let (_, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket
                .send_to(
                    b"SIP/2.0 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n",
                    peer,
                )
                .await
                .unwrap();
        });

        assert!(
            probe_sip_options(
                SipOptionsProbe {
                    server: addr,
                    transport: SipTransport::Udp,
                    uri: "sip:healthcheck@localhost",
                    vary_call_id: false,
                    limit: Duration::from_millis(500),
                    success_codes: &[200, 405],
                },
                Some(Arc::new(bind_health_probe_udp_socket(addr).await.unwrap())),
                None,
            )
            .await
            .healthy
        );
    }

    #[tokio::test]
    async fn tcp_health_probe_reuses_connection() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let peers = Arc::new(Mutex::new(Vec::new()));
        let server_peers = peers.clone();
        tokio::spawn(async move {
            let (mut stream, peer) = upstream.accept().await.unwrap();
            server_peers.lock().await.push(peer);
            let mut reader = TcpSipReader::new(4096);
            for _ in 0..2 {
                let request = reader.read_message(&mut stream).await.unwrap().unwrap();
                let request = String::from_utf8(request).unwrap();
                let via = request
                    .lines()
                    .find(|line| line.starts_with("Via:"))
                    .unwrap();
                let response = format!("SIP/2.0 200 OK\r\n{via}\r\nContent-Length: 0\r\n\r\n");
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let stream_slot = Arc::new(Mutex::new(None));
        for _ in 0..2 {
            assert!(
                probe_sip_options(
                    SipOptionsProbe {
                        server: upstream_addr,
                        transport: SipTransport::Tcp,
                        uri: "sip:healthcheck@localhost",
                        vary_call_id: false,
                        limit: Duration::from_millis(500),
                        success_codes: &[200],
                    },
                    None,
                    Some(stream_slot.clone()),
                )
                .await
                .healthy
            );
        }

        let peers = peers.lock().await;
        assert_eq!(peers.len(), 1);
    }

    #[tokio::test]
    async fn tcp_connect_health_probe_marks_open_port_healthy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });

        assert!(
            probe_tcp_connect(addr, Duration::from_millis(500))
                .await
                .healthy
        );
    }

    #[tokio::test]
    async fn health_check_runs_before_first_interval() {
        let unavailable = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let group = Arc::new(
            UpstreamGroupRuntime::new(&UpstreamGroupConfig {
                name: "default".to_string(),
                mode: UpstreamMode::RoundRobin,
                health_check: UpstreamHealthCheckConfig {
                    enabled: true,
                    interval_ms: 60_000,
                    timeout_ms: 100,
                    failure_threshold: 1,
                    probe: UpstreamHealthProbeConfig::TcpConnect,
                    ..UpstreamHealthCheckConfig::default()
                },
                servers: vec![unavailable.to_string()],
            })
            .unwrap(),
        );
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state, None));
        let task = tokio::spawn(run_health_checks(group.clone(), replicator, shutdown_rx));

        timeout(Duration::from_secs(1), async {
            loop {
                if !group.health_snapshots()[0].healthy {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        shutdown_tx.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn health_check_skips_backend_probe_until_role_is_active() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (probe_tx, mut probe_rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let mut buf = [0; 2048];
            while let Ok((len, peer)) = upstream.recv_from(&mut buf).await {
                let request = String::from_utf8_lossy(&buf[..len]);
                let via = request
                    .lines()
                    .find(|line| line.starts_with("Via:"))
                    .unwrap_or("Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK-health-test");
                let response = format!("SIP/2.0 200 OK\r\n{via}\r\nContent-Length: 0\r\n\r\n");
                upstream.send_to(response.as_bytes(), peer).await.unwrap();
                let _ = probe_tx.send(()).await;
            }
        });

        let group = Arc::new(
            UpstreamGroupRuntime::new(&UpstreamGroupConfig {
                name: "default".to_string(),
                mode: UpstreamMode::RoundRobin,
                health_check: UpstreamHealthCheckConfig {
                    enabled: true,
                    interval_ms: 20,
                    timeout_ms: 100,
                    probe: UpstreamHealthProbeConfig::Options {
                        transport: SipTransport::Udp,
                        uri: "sip:healthcheck@localhost".to_string(),
                        success_codes: vec![200],
                        vary_call_id: false,
                    },
                    ..UpstreamHealthCheckConfig::default()
                },
                servers: vec![upstream_addr.to_string()],
            })
            .unwrap(),
        );
        let replicator = Arc::new(MutableRoleReplicator::new(ClusterRole::Follower));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_health_checks(group, replicator.clone(), shutdown_rx));

        assert!(
            timeout(Duration::from_millis(200), probe_rx.recv())
                .await
                .is_err()
        );

        replicator.set_role(ClusterRole::Leader).await;
        timeout(Duration::from_secs(2), probe_rx.recv())
            .await
            .unwrap()
            .unwrap();

        shutdown_tx.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[test]
    fn health_check_failure_log_throttles_repeated_failures() {
        let mut log = HealthCheckFailureLog::default();
        let start = Instant::now();

        assert_eq!(log.warn_if_due(start), Some(0));
        assert_eq!(log.warn_if_due(start + Duration::from_secs(1)), None);
        assert_eq!(log.warn_if_due(start + Duration::from_secs(2)), None);
        assert_eq!(
            log.warn_if_due(start + HEALTH_CHECK_FAILURE_LOG_INTERVAL),
            Some(2)
        );
        assert_eq!(
            log.warn_if_due(start + HEALTH_CHECK_FAILURE_LOG_INTERVAL),
            None
        );
        assert_eq!(log.recovered(), Some(1));
        assert_eq!(log.recovered(), None);
        assert_eq!(log.warn_if_due(start), Some(0));
    }

    #[test]
    fn contact_transport_parameter_overrides_listener_transport() {
        let target =
            parse_contact_target("sip:100@127.0.0.1:5061;transport=tcp", SipTransport::Udp)
                .unwrap();

        assert_eq!(target.addr, "127.0.0.1:5061".parse().unwrap());
        assert_eq!(target.transport, SipTransport::Tcp);
    }

    #[test]
    fn contact_target_accepts_full_contact_header_value() {
        let target = parse_contact_target(
            "\"100\" <sip:100@127.0.0.1:5061;transport=tcp>;expires=60",
            SipTransport::Udp,
        )
        .unwrap();

        assert_eq!(target.addr, "127.0.0.1:5061".parse().unwrap());
        assert_eq!(target.transport, SipTransport::Tcp);
    }

    #[test]
    fn contact_target_uses_sip_default_port() {
        let target = parse_contact_target("sip:100@127.0.0.1", SipTransport::Udp).unwrap();

        assert_eq!(target.addr, "127.0.0.1:5060".parse().unwrap());
        assert_eq!(target.transport, SipTransport::Udp);
    }

    #[test]
    fn route_target_uses_typed_route_header_parser() {
        let target = parse_route_target(
            "<sip:127.0.0.1:5061;transport=tcp;lr;du=sip:95.143.188.49:5060>",
            SipTransport::Udp,
        )
        .unwrap();

        assert_eq!(target.addr, "127.0.0.1:5061".parse().unwrap());
        assert_eq!(target.transport, SipTransport::Tcp);
    }

    #[test]
    fn invite_transaction_key_uses_typed_cseq() {
        let message = SipMessage::parse(
            b"INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-client\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: typed-call\r\n\
CSeq:   42   INVITE\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();

        assert_eq!(
            invite_transaction_key(&message).unwrap(),
            Some("z9hG4bK-client:typed-call:42".to_string())
        );
    }

    #[tokio::test]
    async fn tcp_forward_reads_response_by_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0; 2048];
            let _ = stream.read(&mut buf).await.unwrap();
            stream
                .write_all(b"SIP/2.0 200 OK\r\nContent-Length: 4\r\n\r\npong")
                .await
                .unwrap();
        });

        let response = forward_tcp(
            addr,
            b"OPTIONS sip:example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n".to_vec(),
        )
        .await
        .unwrap();

        assert_eq!(
            response,
            b"SIP/2.0 200 OK\r\nContent-Length: 4\r\n\r\npong".to_vec()
        );
    }

    #[tokio::test]
    async fn tcp_reader_splits_pipelined_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(
                    b"OPTIONS sip:a.example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n\
OPTIONS sip:b.example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut reader = TcpSipReader::new(4096);
        let first = reader.read_message(&mut stream).await.unwrap().unwrap();
        let second = reader.read_message(&mut stream).await.unwrap().unwrap();

        assert!(
            String::from_utf8(first)
                .unwrap()
                .contains("sip:a.example.com")
        );
        assert!(
            String::from_utf8(second)
                .unwrap()
                .contains("sip:b.example.com")
        );
    }

    #[tokio::test]
    async fn tcp_reader_accepts_short_content_length_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(
                    b"MESSAGE sip:a.example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1:5061;branch=z9hG4bK-short-cl\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:a.example.com>\r\n\
Call-ID: short-cl\r\n\
CSeq: 1 MESSAGE\r\n\
l: 5\r\n\r\nhello",
                )
                .await
                .unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut reader = TcpSipReader::new(4096);
        let message = reader.read_message(&mut stream).await.unwrap().unwrap();
        assert!(String::from_utf8(message).unwrap().ends_with("hello"));
    }

    #[tokio::test]
    async fn tcp_reader_ignores_keepalive_frames() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(
                    b"\r\n\r\nMESSAGE sip:a.example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1:5061;branch=z9hG4bK-keepalive\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:a.example.com>\r\n\
Call-ID: keepalive\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut reader = TcpSipReader::new(4096);
        let message = reader.read_message(&mut stream).await.unwrap().unwrap();
        assert!(
            String::from_utf8(message)
                .unwrap()
                .contains("Call-ID: keepalive")
        );
    }

    #[tokio::test]
    async fn tcp_proxy_streams_multiple_invite_responses_and_removes_proxy_via() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let server = Arc::new(test_server_with_upstream(upstream_addr));
        let listener = test_tcp_listener();

        tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut reader = TcpSipReader::new(4096);
            let request = reader.read_message(&mut stream).await.unwrap().unwrap();
            let request = String::from_utf8(request).unwrap();
            let vias = request
                .lines()
                .filter(|line| line.starts_with("Via:"))
                .map(str::to_string)
                .collect::<Vec<_>>();
            assert_eq!(vias.len(), 2);
            assert!(vias[0].contains(PROXY_BRANCH_PREFIX));
            assert!(vias[0].contains("SIP/2.0/TCP"));

            for code in ["100 Trying", "180 Ringing", "200 OK"] {
                let response = format!(
                    "SIP/2.0 {code}\r\n\
{proxy_via}\r\n\
{client_via}\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>;tag=b\r\n\
Call-ID: call-1\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
                    proxy_via = vias[0],
                    client_via = vias[1],
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let client_task = tokio::spawn(async move {
            let (stream, peer) = client_listener.accept().await.unwrap();
            server
                .handle_tcp_client(stream, peer, listener)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(client_addr).await.unwrap();
        client
            .write_all(
                b"INVITE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1:5061;branch=z9hG4bK-client\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: call-1\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();

        let mut reader = TcpSipReader::new(4096);
        for code in ["100 Trying", "180 Ringing", "200 OK"] {
            let response = reader.read_message(&mut client).await.unwrap().unwrap();
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with(&format!("SIP/2.0 {code}")));
            assert!(!response.contains(PROXY_BRANCH_PREFIX));
            assert!(response.contains("z9hG4bK-client"));
        }

        drop(client);
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_proxy_keeps_branch_until_final_response_for_non_invite() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let server = Arc::new(test_server_with_upstream(upstream_addr));
        let listener = test_tcp_listener();

        tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut reader = TcpSipReader::new(4096);
            let request = reader.read_message(&mut stream).await.unwrap().unwrap();
            let request = String::from_utf8(request).unwrap();
            let vias = request
                .lines()
                .filter(|line| line.starts_with("Via:"))
                .map(str::to_string)
                .collect::<Vec<_>>();
            assert_eq!(vias.len(), 2);

            for code in ["100 Trying", "200 OK"] {
                let response = format!(
                    "SIP/2.0 {code}\r\n\
{proxy_via}\r\n\
{client_via}\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>;tag=b\r\n\
Call-ID: non-invite-1xx\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
                    proxy_via = vias[0],
                    client_via = vias[1],
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let client_task = tokio::spawn(async move {
            let (stream, peer) = client_listener.accept().await.unwrap();
            server
                .handle_tcp_client(stream, peer, listener)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(client_addr).await.unwrap();
        client
            .write_all(
                b"MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1:5061;branch=z9hG4bK-client-message\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: non-invite-1xx\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();

        let mut reader = TcpSipReader::new(4096);
        for code in ["100 Trying", "200 OK"] {
            let response = reader.read_message(&mut client).await.unwrap().unwrap();
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with(&format!("SIP/2.0 {code}")));
            assert!(!response.contains(PROXY_BRANCH_PREFIX));
            assert!(response.contains("z9hG4bK-client-message"));
        }

        drop(client);
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_upstream_connection_is_reused_for_sequential_requests() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let server = Arc::new(test_server_with_upstream(upstream_addr));
        let listener = test_tcp_listener();

        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut reader = TcpSipReader::new(4096);
            for index in 1..=2 {
                let request = reader.read_message(&mut stream).await.unwrap().unwrap();
                let request = String::from_utf8(request).unwrap();
                let vias = request
                    .lines()
                    .filter(|line| line.starts_with("Via:"))
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                assert_eq!(vias.len(), 2);
                assert!(vias[0].contains(PROXY_BRANCH_PREFIX));
                assert!(vias[0].contains("SIP/2.0/TCP"));

                let response = format!(
                    "SIP/2.0 200 OK\r\n\
{proxy_via}\r\n\
{client_via}\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>;tag=b\r\n\
Call-ID: call-{index}\r\n\
CSeq: {index} MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
                    proxy_via = vias[0],
                    client_via = vias[1],
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let client_task = tokio::spawn(async move {
            let (stream, peer) = client_listener.accept().await.unwrap();
            server
                .handle_tcp_client(stream, peer, listener)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(client_addr).await.unwrap();
        let mut reader = TcpSipReader::new(4096);
        for index in 1..=2 {
            let request = format!(
                "MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1:5061;branch=z9hG4bK-client-{index}\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: call-{index}\r\n\
CSeq: {index} MESSAGE\r\n\
Content-Length: 0\r\n\r\n"
            );
            client.write_all(request.as_bytes()).await.unwrap();
            let response = reader.read_message(&mut client).await.unwrap().unwrap();
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with("SIP/2.0 200 OK"));
            assert!(!response.contains(PROXY_BRANCH_PREFIX));
            assert!(response.contains(&format!("z9hG4bK-client-{index}")));
        }

        drop(client);
        upstream_task.await.unwrap();
        client_task.await.unwrap();
    }
}
