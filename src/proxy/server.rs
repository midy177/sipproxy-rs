use crate::cluster::{ClusterCommand, ClusterReplicator, ContactBinding, SharedState, expires_at};
use crate::config::{
    Config, ProxyListenerConfig, ProxyMetricsConfig, ProxySocketConfig, SipTransport,
    UpstreamGroupConfig, UpstreamHealthCheckConfig, UpstreamHealthProbeConfig,
};
use crate::ha::HaStateSnapshot;
use crate::proxy::affinity::{AffinityTable, AffinityTarget};
use crate::proxy::metrics::ProxyMetrics;
use crate::proxy::registry::{extract_aor, extract_contact, extract_expires};
use crate::proxy::routing::RouteTable;
use crate::sip::{SipMessage, SipStartLine};
use anyhow::{Context, Result, bail};
use axum::{Router, extract::State, routing::get};
use bytes::BytesMut;
use rsipstack::sip::prelude::HeadersExt;
use rsipstack::sip::{
    Transport as RsipTransport, Uri as RsipUri, typed::Contact as RsipContact, uri::Param,
};
use rsipstack::transport::stream::{SipCodec, SipCodecType};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::fmt::Write as _;
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
const UDP_BRANCH_PRUNE_INTERVAL: Duration = Duration::from_secs(1);
const TCP_BRANCH_TTL: Duration = Duration::from_secs(300);
const INVITE_TRANSACTION_TTL: Duration = Duration::from_secs(300);
const PROXY_BRANCH_PREFIX: &str = "z9hG4bK-sigproxy-";
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub struct ProxyServer {
    config: Config,
    state: Arc<SharedState>,
    routes: RouteTable,
    upstreams: UpstreamGroups,
    affinity: AffinityTable,
    metrics: Arc<ProxyMetrics>,
    udp_branches: Mutex<HashMap<String, UdpBranchRoute>>,
    udp_branch_last_prune: Mutex<Instant>,
    invite_transactions: Mutex<HashMap<String, InviteTransactionRoute>>,
    tcp_upstreams: TcpUpstreamPool,
    advertised_addrs: Mutex<HashMap<String, String>>,
}

impl ProxyServer {
    pub fn new(
        config: Config,
        state: Arc<SharedState>,
        _replicator: Arc<dyn ClusterReplicator>,
    ) -> Result<Self> {
        let routes = RouteTable::new(&config.proxy).context("failed to build proxy route table")?;
        let upstreams = UpstreamGroups::new(&config.proxy.upstream_groups)
            .context("failed to build upstream groups")?;
        let max_message_bytes = config.sip.max_message_bytes;
        let affinity_config = config.proxy.affinity.clone();
        Ok(Self {
            config,
            state,
            routes,
            upstreams,
            affinity: AffinityTable::new(affinity_config),
            metrics: Arc::new(ProxyMetrics::default()),
            udp_branches: Mutex::new(HashMap::new()),
            udp_branch_last_prune: Mutex::new(Instant::now()),
            invite_transactions: Mutex::new(HashMap::new()),
            tcp_upstreams: TcpUpstreamPool::new(max_message_bytes),
            advertised_addrs: Mutex::new(HashMap::new()),
        })
    }

    pub async fn run(self: Arc<Self>, shutdown: watch::Receiver<bool>) -> Result<()> {
        let this = self;
        let mut tasks = Vec::new();

        for group in this.upstreams.groups.values() {
            if group.health_check.enabled {
                tasks.push(tokio::spawn(run_health_checks(
                    group.clone(),
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

        let workers_per_listener = this.config.proxy.socket.workers_per_listener;
        for listener in &this.config.proxy.listeners {
            this.log_listener_advertised_addrs(listener).await;
            for worker in 0..workers_per_listener {
                match listener.transport {
                    SipTransport::Udp => {
                        let socket =
                            Arc::new(bind_udp_socket(listener, &this.config.proxy.socket).await?);
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
                            bind_tcp_listener(listener, &this.config.proxy.socket).await?;
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
                }
            }
        }

        for task in tasks {
            task.await??;
        }
        Ok(())
    }

    pub async fn snapshot_state(&self) -> HaStateSnapshot {
        HaStateSnapshot {
            contacts: self.state.snapshot().await,
            affinity: self.affinity.snapshot().await,
        }
    }

    pub async fn install_state_snapshot(&self, snapshot: HaStateSnapshot) {
        self.state.install_snapshot(snapshot.contacts).await;
        self.affinity.install_snapshot(snapshot.affinity).await;
    }

    async fn render_metrics(&self) -> String {
        let mut output = self.metrics.render_prometheus();
        let udp_branch_routes = self.active_udp_branch_count().await;
        let invite_transaction_routes = self.active_invite_transaction_count().await;
        let (tcp_upstream_connections, tcp_branch_routes) =
            self.tcp_upstreams.active_counts().await;
        let affinity_bindings = self.affinity.active_len().await;
        let location_bindings = self.state.contact_count().await;
        let upstream_health = self.upstreams.health_snapshots();

        append_gauge(
            &mut output,
            "proxy_udp_branch_routes",
            udp_branch_routes as u64,
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
        output
    }

    async fn active_udp_branch_count(&self) -> usize {
        let mut branches = self.udp_branches.lock().await;
        prune_udp_branches(&mut branches, Instant::now());
        branches.len()
    }

    async fn active_invite_transaction_count(&self) -> usize {
        let mut transactions = self.invite_transactions.lock().await;
        prune_invite_transactions(&mut transactions, Instant::now());
        transactions.len()
    }

    async fn log_listener_advertised_addrs(&self, listener: &ProxyListenerConfig) {
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
            "SIP advertised addresses resolved"
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

    async fn prune_udp_branches_if_due(
        &self,
        branches: &mut HashMap<String, UdpBranchRoute>,
        now: Instant,
    ) {
        let mut last_prune = self.udp_branch_last_prune.lock().await;
        if now.duration_since(*last_prune) >= UDP_BRANCH_PRUNE_INTERVAL {
            prune_udp_branches(branches, now);
            *last_prune = now;
        }
    }

    async fn remove_udp_branch(&self, branch: &str) {
        self.udp_branches.lock().await.remove(branch);
    }

    async fn remember_successful_forward(
        &self,
        message: &SipMessage,
        target: UpstreamTarget,
        branch: &str,
        invite_transaction_key: Option<String>,
        method: &str,
    ) {
        if let Err(err) = self
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
            warn!(error = %err, "failed to record SIP affinity for forwarded request");
        }

        if method == "INVITE" {
            self.remember_invite_transaction(invite_transaction_key, target, branch.to_string())
                .await;
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
        method: &str,
    ) -> Result<()> {
        loop {
            let response = self
                .recv_upstream_response(responses, upstream, method)
                .await?;
            let response_message = SipMessage::parse(&response)?;
            let is_final = matches!(
                &response_message.start_line,
                SipStartLine::Response { code, .. } if *code >= 200
            );
            if let SipStartLine::Response { code, .. } = &response_message.start_line {
                self.record_upstream_response("tcp", *code);
                self.upstreams.record_passive_result(upstream, *code < 500);
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
                    if self.config.proxy.socket.tcp_nodelay {
                        if let Err(err) = stream.set_nodelay(true) {
                            warn!(%peer, error = %err, "failed to set TCP_NODELAY on SIP connection");
                            continue;
                        }
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
        let message = SipMessage::parse(packet)?;
        if message.is_response() {
            debug!(%peer, "ignoring SIP response received from downstream TCP client");
            return Ok(());
        }

        let Some(method) = message.method().map(str::to_string) else {
            return Ok(());
        };
        self.metrics.incr(
            "sip_requests_total",
            &[("transport", "tcp"), ("method", method.as_str())],
        );

        let mut message = message;
        match decrement_max_forwards(&mut message) {
            Ok(true) => {}
            Ok(false) => {
                let response = SipMessage::response_like(&message, 483, "Too Many Hops");
                self.record_local_response("tcp", 483);
                stream.write_all(&response.to_bytes()).await?;
                return Ok(());
            }
            Err(err) => {
                warn!(%peer, error = %err, "invalid Max-Forwards header");
                let response = SipMessage::response_like(&message, 400, "Bad Request");
                self.record_local_response("tcp", 400);
                stream.write_all(&response.to_bytes()).await?;
                return Ok(());
            }
        }
        if let Err(err) = self
            .forward_tcp_stream(stream, message, peer, listener)
            .await
        {
            error!(error = %format!("{err:#}"), "failed to forward TCP SIP request");
            self.record_forward_error("tcp");
            let response =
                SipMessage::response_like(&SipMessage::parse(packet)?, 503, "Service Unavailable");
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

        let message = SipMessage::parse(packet)?;
        if message.is_response() {
            return self.handle_udp_response(socket, message, peer).await;
        }

        let Some(method) = message.method().map(str::to_string) else {
            return Ok(());
        };
        self.metrics.incr(
            "sip_requests_total",
            &[("transport", "udp"), ("method", method.as_str())],
        );

        let mut message = message;
        match decrement_max_forwards(&mut message) {
            Ok(true) => {}
            Ok(false) => {
                let response = SipMessage::response_like(&message, 483, "Too Many Hops");
                self.record_local_response("udp", 483);
                socket.send_to(&response.to_bytes(), peer).await?;
                return Ok(());
            }
            Err(err) => {
                warn!(%peer, error = %err, "invalid Max-Forwards header");
                let response = SipMessage::response_like(&message, 400, "Bad Request");
                self.record_local_response("udp", 400);
                socket.send_to(&response.to_bytes(), peer).await?;
                return Ok(());
            }
        }
        if let Err(err) = self.forward_udp(socket, message, peer, listener).await {
            error!(error = %format!("{err:#}"), "failed to forward UDP SIP request");
            self.record_forward_error("udp");
            let response =
                SipMessage::response_like(&SipMessage::parse(packet)?, 503, "Service Unavailable");
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
            let mut branches = self.udp_branches.lock().await;
            self.prune_udp_branches_if_due(&mut branches, Instant::now())
                .await;
            branches.get(&branch).copied()
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

        if let SipStartLine::Response { code, .. } = &message.start_line {
            self.record_upstream_response("udp", *code);
            self.upstreams
                .record_passive_result(route.upstream, *code < 500);
        }
        message
            .pop_top_via()?
            .context("upstream response is missing Via")?;
        socket
            .send_to(&message.to_bytes(), route.client_peer)
            .await?;
        Ok(())
    }

    async fn forward_udp(
        &self,
        socket: &UdpSocket,
        message: SipMessage,
        peer: SocketAddr,
        listener: &ProxyListenerConfig,
    ) -> Result<()> {
        let (message, target, branch, invite_transaction_key) =
            self.prepare_forward(message, peer, listener).await?;
        let method = message.method().unwrap_or_default().to_string();

        debug!(
            %peer,
            target = %target.addr,
            transport = %target.transport.as_str(),
            method = %method,
            branch = %branch,
            "forwarding UDP SIP request"
        );
        match target.transport {
            SipTransport::Udp => {
                self.record_forwarded_request("udp", target.transport, Some(method.as_str()));
                {
                    let mut branches = self.udp_branches.lock().await;
                    self.prune_udp_branches_if_due(&mut branches, Instant::now())
                        .await;
                    branches.insert(
                        branch.clone(),
                        UdpBranchRoute {
                            client_peer: peer,
                            upstream: target.addr,
                            created_at: Instant::now(),
                        },
                    );
                }
                if let Err(err) = socket.send_to(&message.to_bytes(), target.addr).await {
                    self.remove_udp_branch(&branch).await;
                    self.upstreams.record_passive_result(target.addr, false);
                    return Err(err).context("failed to send SIP request to upstream UDP socket");
                }
                self.remember_successful_forward(
                    &message,
                    target,
                    &branch,
                    invite_transaction_key,
                    method.as_str(),
                )
                .await;
                Ok(())
            }
            SipTransport::Tcp => {
                self.record_forwarded_request("udp", target.transport, Some(method.as_str()));
                self.forward_udp_to_tcp_upstream(
                    socket,
                    message.to_bytes(),
                    peer,
                    target.addr,
                    branch,
                    invite_transaction_key,
                    method,
                )
                .await
            }
        }
    }

    async fn forward_udp_to_tcp_upstream(
        &self,
        socket: &UdpSocket,
        packet: Vec<u8>,
        client_peer: SocketAddr,
        upstream: SocketAddr,
        branch: String,
        invite_transaction_key: Option<String>,
        method: String,
    ) -> Result<()> {
        let mut responses = match self
            .tcp_upstreams
            .send_request(upstream, branch.clone(), packet.clone())
            .await
        {
            Ok(responses) => responses,
            Err(err) => {
                self.upstreams.record_passive_result(upstream, false);
                return Err(err);
            }
        };
        let target = UpstreamTarget {
            addr: upstream,
            transport: SipTransport::Tcp,
        };
        let message = SipMessage::parse(&packet)?;
        self.remember_successful_forward(
            &message,
            target,
            &branch,
            invite_transaction_key,
            method.as_str(),
        )
        .await;

        self.send_udp_to_tcp_responses(
            socket,
            &mut responses,
            client_peer,
            upstream,
            method.as_str(),
        )
        .await
    }

    async fn forward_tcp_stream(
        &self,
        client_stream: &mut TcpStream,
        message: SipMessage,
        peer: SocketAddr,
        listener: &ProxyListenerConfig,
    ) -> Result<()> {
        let method = message.method().unwrap_or_default().to_string();
        let (message, target, branch, invite_transaction_key) =
            self.prepare_forward(message, peer, listener).await?;
        self.record_forwarded_request("tcp", target.transport, Some(method.as_str()));
        let mut responses = match self
            .tcp_upstreams
            .send_request(target.addr, branch.clone(), message.to_bytes())
            .await
        {
            Ok(responses) => responses,
            Err(err) => {
                self.upstreams.record_passive_result(target.addr, false);
                return Err(err);
            }
        };
        self.remember_successful_forward(
            &message,
            target,
            &branch,
            invite_transaction_key,
            method.as_str(),
        )
        .await;
        loop {
            let response = self
                .recv_upstream_response(&mut responses, target.addr, method.as_str())
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
    ) -> Result<(SipMessage, UpstreamTarget, String, Option<String>)> {
        let request_uri = message
            .request_uri()
            .context("request forwarding requires a request URI")?
            .to_string();
        let method = message.method().unwrap_or_default().to_string();
        let invite_transaction_key = invite_transaction_key(&message)?;
        let transaction_route = if matches!(method.as_str(), "CANCEL" | "ACK") {
            self.lookup_invite_transaction(invite_transaction_key.as_deref())
                .await
        } else {
            None
        };
        let target = if let Some(route) = transaction_route.as_ref() {
            self.record_affinity_lookup("transaction-hit");
            route.target
        } else if let Some(binding) = self.lookup_registration_binding(&request_uri).await {
            self.record_affinity_lookup("location-hit");
            parse_contact_target(&binding.contact, listener.transport)
                .unwrap_or_else(|| self.select_upstream(&request_uri, listener))
        } else if let Some(target) =
            self.request_uri_target_from_upstream(_peer, &request_uri, listener)
        {
            self.record_affinity_lookup("request-uri-target");
            target
        } else if let Some(target) = self.affinity.lookup(&message).await? {
            let target = UpstreamTarget {
                addr: target.addr,
                transport: target.transport,
            };
            if self.upstreams.is_healthy(target.addr) {
                self.record_affinity_lookup("hit");
                target
            } else {
                self.record_affinity_lookup("unhealthy");
                self.select_upstream(&request_uri, listener)
            }
        } else {
            self.record_affinity_lookup("miss");
            self.select_upstream(&request_uri, listener)
        };

        if self.upstreams.contains(_peer) && !self.upstreams.contains(target.addr) {
            message.pop_top_header_value("Route")?;
        }

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
        message.prepend_header(
            "Via",
            format!(
                "SIP/2.0/{} {via_host};branch={branch};rport",
                target.transport.sip_via_token()
            ),
        );

        if self.config.proxy.record_route && should_record_route(&method) {
            for addr in self
                .record_route_addrs(_peer, target.addr, listener)
                .await
                .into_iter()
                .rev()
            {
                message.prepend_header("Record-Route", format!("<sip:{addr};lr>"));
            }
        }
        if method == "REGISTER" {
            if self.config.proxy.rewrite_register_contact {
                self.rewrite_and_store_register_contact(&mut message, &via_host, _peer)
                    .await?;
            } else {
                self.store_register_contact_routes(&message, &via_host, _peer)
                    .await?;
                message.prepend_header("Path", format!("<sip:{via_host};lr>"));
            }
        }

        Ok((message, target, branch, invite_transaction_key))
    }

    fn request_uri_target_from_upstream(
        &self,
        peer: SocketAddr,
        request_uri: &str,
        listener: &ProxyListenerConfig,
    ) -> Option<UpstreamTarget> {
        self.upstreams
            .contains(peer)
            .then(|| parse_contact_target(request_uri, listener.transport))
            .flatten()
            .filter(|target| !self.upstreams.contains(target.addr))
            .filter(|target| !self.is_advertised_or_listener_addr(target.addr, listener))
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
        }) || listener
            .bind
            .parse::<SocketAddr>()
            .ok()
            .filter(|bind| !bind.ip().is_unspecified())
            .is_some_and(|bind| bind == addr)
    }

    async fn advertised_sip_addr(
        &self,
        side: AdvertiseSide,
        listener: &ProxyListenerConfig,
        target: SocketAddr,
    ) -> String {
        let cache_key = format!("{}|{}", side.as_str(), listener.key());
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

    async fn rewrite_and_store_register_contact(
        &self,
        message: &mut SipMessage,
        via_host: &str,
        peer: SocketAddr,
    ) -> Result<()> {
        let original_contact = extract_contact(message).ok().flatten();
        let expires = extract_expires(message);
        let rewritten_contacts = message.rewrite_contact_host(via_host)?;
        for (original, rewritten) in rewritten_contacts {
            self.store_contact_route_keys(&rewritten, &original, peer, expires)
                .await;
        }
        if let (Ok(aor), Some(contact)) = (extract_aor(message), original_contact) {
            self.state
                .apply(ClusterCommand::RegisterContact(ContactBinding {
                    aor,
                    contact,
                    source: peer.to_string(),
                    expires_at_epoch_ms: expires_at(expires),
                }))
                .await;
        }
        Ok(())
    }

    async fn store_register_contact_routes(
        &self,
        message: &SipMessage,
        via_host: &str,
        peer: SocketAddr,
    ) -> Result<()> {
        let expires = extract_expires(message);
        let mut first_contact = None;
        let mut rewritten = message.clone();
        for (original, proxy_contact) in rewritten.rewrite_contact_host(via_host)? {
            if first_contact.is_none() {
                first_contact = Some(original.clone());
            }
            self.store_contact_route_keys(&proxy_contact, &original, peer, expires)
                .await;
        }
        if let (Ok(aor), Some(contact)) = (extract_aor(message), first_contact) {
            self.state
                .apply(ClusterCommand::RegisterContact(ContactBinding {
                    aor,
                    contact,
                    source: peer.to_string(),
                    expires_at_epoch_ms: expires_at(expires),
                }))
                .await;
        }
        Ok(())
    }

    async fn store_contact_route_keys(
        &self,
        route: &str,
        contact: &str,
        peer: SocketAddr,
        expires: Duration,
    ) {
        for aor in registration_route_keys(route) {
            self.state
                .apply(ClusterCommand::RegisterContact(ContactBinding {
                    aor,
                    contact: contact.to_string(),
                    source: peer.to_string(),
                    expires_at_epoch_ms: expires_at(expires),
                }))
                .await;
        }
    }

    fn record_forwarded_request(
        &self,
        downstream_transport: &str,
        upstream_transport: SipTransport,
        method: Option<&str>,
    ) {
        self.metrics.incr(
            "proxy_forwarded_requests_total",
            &[
                ("downstream_transport", downstream_transport),
                ("upstream_transport", upstream_transport.as_str()),
                ("method", method.unwrap_or("UNKNOWN")),
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

    fn record_affinity_lookup(&self, result: &str) {
        self.metrics
            .incr("proxy_affinity_lookup_total", &[("result", result)]);
    }

    async fn lookup_invite_transaction(&self, key: Option<&str>) -> Option<InviteTransactionRoute> {
        let key = key?;
        let mut transactions = self.invite_transactions.lock().await;
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
        let mut transactions = self.invite_transactions.lock().await;
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

    fn select_upstream(&self, uri: &str, listener: &ProxyListenerConfig) -> UpstreamTarget {
        let group = self
            .routes
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
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    let type_line = format!("# TYPE {name} gauge\n");
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
}

#[derive(Debug, Clone, Copy)]
struct UdpBranchRoute {
    client_peer: SocketAddr,
    upstream: SocketAddr,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct InviteTransactionRoute {
    target: UpstreamTarget,
    branch: String,
    created_at: Instant,
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
        branch: String,
        packet: Vec<u8>,
    ) -> Result<mpsc::UnboundedReceiver<Vec<u8>>> {
        let mut last_error = None;
        for _ in 0..2 {
            let connection = self.get_or_connect(target).await?;
            match connection
                .send_request(branch.clone(), packet.clone())
                .await
            {
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
        branch: String,
        packet: Vec<u8>,
    ) -> Result<mpsc::UnboundedReceiver<Vec<u8>>> {
        if !self.is_alive() {
            bail!("upstream SIP TCP connection {} is closed", self.target);
        }

        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut branches = self.branches.lock().await;
            prune_tcp_branches(&mut branches, Instant::now());
            branches.insert(
                branch.clone(),
                TcpBranchRoute {
                    tx,
                    created_at: Instant::now(),
                },
            );
        }

        let write_result = timeout(
            UPSTREAM_TIMEOUT,
            self.writer.lock().await.write_all(&packet),
        )
        .await
        .context("upstream SIP TCP write timed out")?;
        if let Err(err) = write_result {
            self.branches.lock().await.remove(&branch);
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
        Ok(Self { groups })
    }

    fn select(&self, name: &str) -> Result<SocketAddr> {
        let Some(group) = self.groups.get(name) else {
            bail!("unknown upstream group '{name}'");
        };
        group.select()
    }

    fn record_passive_result(&self, server: SocketAddr, healthy: bool) {
        for group in self.groups.values() {
            group.record_passive_result(server, healthy);
        }
    }

    fn is_healthy(&self, server: SocketAddr) -> bool {
        let mut found = false;
        for group in self.groups.values() {
            if group.contains(server) {
                found = true;
                if group.is_healthy(server) {
                    return true;
                }
            }
        }
        !found
    }

    fn contains(&self, server: SocketAddr) -> bool {
        self.groups.values().any(|group| group.contains(server))
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

    fn record_passive_result(&self, server: SocketAddr, healthy: bool) {
        if !self.health_check.enabled {
            return;
        }
        if let Some(index) = self
            .servers
            .iter()
            .position(|candidate| *candidate == server)
        {
            self.record_health_result(index, healthy);
        }
    }

    fn contains(&self, server: SocketAddr) -> bool {
        self.servers.contains(&server)
    }

    fn is_healthy(&self, server: SocketAddr) -> bool {
        let Some(index) = self
            .servers
            .iter()
            .position(|candidate| *candidate == server)
        else {
            return false;
        };
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
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let probes = HealthCheckRuntime::new(&group).await?;
    let interval = Duration::from_millis(group.health_check.interval_ms);
    loop {
        if *shutdown.borrow() {
            break;
        }
        run_health_check_round(group.clone(), &probes).await;
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
    Ok(())
}

struct HealthCheckRuntime {
    udp_sockets: Vec<Option<Arc<UdpSocket>>>,
    tcp_streams: Vec<Option<Arc<Mutex<Option<TcpStream>>>>>,
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
        })
    }

    fn udp_socket(&self, index: usize) -> Option<Arc<UdpSocket>> {
        self.udp_sockets.get(index).cloned().flatten()
    }

    fn tcp_stream(&self, index: usize) -> Option<Arc<Mutex<Option<TcpStream>>>> {
        self.tcp_streams.get(index).cloned().flatten()
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
            warn!(
                group = %group.name,
                %server,
                mode,
                reason = %result.reason.as_deref().unwrap_or("probe returned unhealthy"),
                consecutive_failures = update.consecutive_failures,
                failure_threshold = group.health_check.failure_threshold,
                currently_healthy = update.is_healthy,
                "backend health check failed"
            );
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
        } => {
            probe_sip_options(
                server,
                *transport,
                uri,
                limit,
                success_codes,
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

async fn probe_sip_options(
    server: SocketAddr,
    transport: SipTransport,
    uri: &str,
    limit: Duration,
    success_codes: &[u16],
    udp_socket: Option<Arc<UdpSocket>>,
    tcp_stream: Option<Arc<Mutex<Option<TcpStream>>>>,
) -> HealthProbeResult {
    let future = async {
        match transport {
            SipTransport::Udp => {
                let socket = udp_socket.context("missing UDP health-check socket")?;
                probe_sip_options_udp(server, uri, socket).await
            }
            SipTransport::Tcp => {
                let stream = tcp_stream.context("missing TCP health-check stream")?;
                probe_sip_options_tcp(server, uri, stream).await
            }
        }
    };
    let Ok(response) = timeout(limit, future).await else {
        return HealthProbeResult::failed(format!("SIP OPTIONS timed out after {:?}", limit));
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
            let accepted = if success_codes.is_empty() {
                code < 500
            } else {
                success_codes.contains(&code)
            };
            if accepted {
                HealthProbeResult::healthy()
            } else {
                HealthProbeResult::failed(format!(
                    "SIP OPTIONS returned status {code}, expected one of {success_codes:?}"
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
) -> Result<HealthOptionsRequest> {
    let id = unique_id();
    let branch = format!("z9hG4bK-health-{id}");
    let cseq = cseq_from_id(id);
    let call_id = health_options_call_id(server, transport, uri);
    let transport = match transport {
        SipTransport::Udp => RsipTransport::Udp,
        SipTransport::Tcp => RsipTransport::Tcp,
    };
    let packet = SipMessage::options_request(
        uri,
        transport,
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

fn health_options_call_id(server: SocketAddr, transport: SipTransport, uri: &str) -> String {
    let key = format!(
        "health|{}|{}|{}|{}",
        std::process::id(),
        transport.as_str(),
        server,
        uri
    );
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
    socket: Arc<UdpSocket>,
) -> Result<Vec<u8>> {
    let request =
        build_health_options_request(server, uri, SipTransport::Udp, socket.local_addr()?)?;
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
    let Some(via) = message.header("Via") else {
        return Ok(true);
    };
    Ok(via_branch_param(via).is_none_or(|response_branch| response_branch == branch))
}

fn via_branch_param(via: &str) -> Option<&str> {
    let top_via = via.split(',').next().unwrap_or(via);
    top_via.split(';').skip(1).find_map(|param| {
        let (name, value) = param.trim().split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("branch")
            .then_some(value.trim())
    })
}

async fn probe_sip_options_tcp(
    server: SocketAddr,
    uri: &str,
    stream_slot: Arc<Mutex<Option<TcpStream>>>,
) -> Result<Vec<u8>> {
    let mut stream_guard = stream_slot.lock().await;
    if stream_guard.is_none() {
        *stream_guard = Some(TcpStream::connect(server).await?);
    }

    let stream = stream_guard.as_mut().expect("stream initialized above");
    let request =
        build_health_options_request(server, uri, SipTransport::Tcp, stream.local_addr()?)?;
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

fn registration_route_keys(route: &str) -> Vec<String> {
    let mut keys = Vec::new();
    push_unique_key(&mut keys, route.trim().to_string());

    if let Some(normalized) = normalized_sip_uri_without_params(route) {
        push_unique_key(&mut keys, normalized);
    }

    keys
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
    use crate::cluster::{ClusterCommand, ContactBinding, StandaloneReplicator, expires_at};
    use crate::config::{
        Config, ProxyAffinityConfig, ProxyAffinityKey, ProxyConfig, ProxyListenerConfig,
        ProxySocketConfig, RouteConfig, SipConfig, SipTransport, UpstreamGroupConfig,
        UpstreamHealthCheckConfig, UpstreamMode,
    };
    use tokio::net::UdpSocket;

    fn test_listener() -> ProxyListenerConfig {
        ProxyListenerConfig {
            bind: "127.0.0.1:5060".to_string(),
            transport: SipTransport::Udp,
            upstream_group: "default".to_string(),
        }
    }

    fn test_tcp_listener() -> ProxyListenerConfig {
        ProxyListenerConfig {
            bind: "127.0.0.1:5060".to_string(),
            transport: SipTransport::Tcp,
            upstream_group: "default".to_string(),
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
        let replicator = Arc::new(StandaloneReplicator::new(state.clone()));
        ProxyServer::new(
            Config {
                sip: SipConfig {
                    external_addr: Some("127.0.0.1:5060".to_string()),
                    internal_probe_addr: upstream.to_string(),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
                    rewrite_register_contact,
                    socket: ProxySocketConfig::default(),
                    metrics: Default::default(),
                    affinity: Default::default(),
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
        )
        .unwrap()
    }

    fn test_server_with_dual_advertise(upstream: SocketAddr) -> ProxyServer {
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone()));
        ProxyServer::new(
            Config {
                sip: SipConfig {
                    public_addr: Some("95.40.96.117".to_string()),
                    internal_addr: Some("172.30.0.101".to_string()),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
                    rewrite_register_contact: false,
                    socket: ProxySocketConfig::default(),
                    metrics: Default::default(),
                    affinity: Default::default(),
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
        )
        .unwrap()
    }

    fn test_server_with_upstreams(upstreams: Vec<SocketAddr>) -> ProxyServer {
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone()));
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
                    rewrite_register_contact: false,
                    socket: ProxySocketConfig::default(),
                    metrics: Default::default(),
                    affinity: Default::default(),
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
        )
        .unwrap()
    }

    fn test_server_with_upstreams_and_affinity(
        upstreams: Vec<SocketAddr>,
        affinity: ProxyAffinityConfig,
    ) -> ProxyServer {
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone()));
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
                    rewrite_register_contact: false,
                    socket: ProxySocketConfig::default(),
                    metrics: Default::default(),
                    affinity,
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
        assert!(forwarded.contains("Contact: \"wuly\" <sip:6805@127.0.0.1:5060;ob>;expires=60"));
        assert!(!forwarded.contains("Path:"));

        let binding = server
            .state
            .lookup("sip:6805@127.0.0.1:5060;ob")
            .await
            .unwrap();
        assert_eq!(binding.contact, "sip:6805@10.0.0.10:53109;ob");
        let binding = server
            .state
            .lookup("sip:6805@127.0.0.1:5060")
            .await
            .unwrap();
        assert_eq!(binding.contact, "sip:6805@10.0.0.10:53109;ob");
        let binding = server.state.lookup("sip:6805@example.com").await.unwrap();
        assert_eq!(binding.contact, "sip:6805@10.0.0.10:53109;ob");
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
        let _ = upstream_socket.recv_from(&mut upstream_buf).await.unwrap();

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

        let mut client_buf = [0_u8; 4096];
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
        assert!(metrics.contains("proxy_invite_transaction_routes 0"));
        assert!(metrics.contains("proxy_affinity_bindings 2"));
        assert!(metrics.contains("proxy_location_bindings 0"));
        assert!(metrics.contains(&format!(
            "proxy_upstream_healthy{{group=\"default\",server=\"{}\"}} 1",
            upstream_socket.local_addr().unwrap()
        )));
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
    async fn udp_to_tcp_upstream_streams_multiple_invite_responses() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let proxy_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let server = Arc::new(test_server_with_upstream(upstream_addr));
        let listener = test_listener();

        server
            .state
            .apply(ClusterCommand::RegisterContact(ContactBinding {
                aor: "sip:200@example.com".to_string(),
                contact: format!("<sip:200@{upstream_addr};transport=tcp>"),
                source: "127.0.0.1:5061".to_string(),
                expires_at_epoch_ms: expires_at(Duration::from_secs(60)),
            }))
            .await;

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
                        client_addr,
                        &listener,
                    )
                    .await
                    .unwrap();
            })
        };

        for code in ["100 Trying", "180 Ringing", "200 OK"] {
            let mut client_buf = [0_u8; 4096];
            let (len, _) = client_socket.recv_from(&mut client_buf).await.unwrap();
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

        group.record_passive_result("127.0.0.1:5080".parse().unwrap(), false);

        assert_eq!(group.select().unwrap(), "127.0.0.1:5080".parse().unwrap());
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
        )
        .unwrap();
        let second_request = build_health_options_request(
            server,
            "sip:healthcheck@example.com",
            SipTransport::Udp,
            sent_by,
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
                    upstream_addr,
                    SipTransport::Udp,
                    "sip:healthcheck@localhost",
                    Duration::from_millis(500),
                    &[200],
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
                addr,
                SipTransport::Udp,
                "sip:healthcheck@localhost",
                Duration::from_millis(500),
                &[200, 405],
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
                    upstream_addr,
                    SipTransport::Tcp,
                    "sip:healthcheck@localhost",
                    Duration::from_millis(500),
                    &[200],
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
        let task = tokio::spawn(run_health_checks(group.clone(), shutdown_rx));

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
