use crate::cluster::{ClusterCommand, ClusterReplicator, ContactBinding, SharedState, expires_at};
use crate::config::{
    Config, ProxyListenerConfig, ProxyMetricsConfig, ProxySocketConfig, SipTransport,
    UpstreamGroupConfig, UpstreamHealthCheckConfig,
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
use rsipstack::sip::{Transport as RsipTransport, typed::Contact as RsipContact, uri::Param};
use rsipstack::transport::stream::{SipCodec, SipCodecType};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::time::timeout;
use tokio_util::codec::Decoder;
use tracing::{debug, error, info, warn};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_BRANCH_TTL: Duration = Duration::from_secs(300);
const TCP_BRANCH_TTL: Duration = Duration::from_secs(300);
const INVITE_TRANSACTION_TTL: Duration = Duration::from_secs(300);
const PROXY_BRANCH_PREFIX: &str = "z9hG4bK-sigproxy-";

pub struct ProxyServer {
    config: Config,
    state: Arc<SharedState>,
    replicator: Arc<dyn ClusterReplicator>,
    routes: RouteTable,
    upstreams: UpstreamGroups,
    affinity: AffinityTable,
    metrics: Arc<ProxyMetrics>,
    udp_branches: Mutex<HashMap<String, UdpBranchRoute>>,
    invite_transactions: Mutex<HashMap<String, InviteTransactionRoute>>,
    tcp_upstreams: TcpUpstreamPool,
}

impl ProxyServer {
    pub fn new(
        config: Config,
        state: Arc<SharedState>,
        replicator: Arc<dyn ClusterReplicator>,
    ) -> Self {
        let routes = RouteTable::new(&config.proxy)
            .expect("configuration should be validated before building proxy server");
        let upstreams = UpstreamGroups::new(&config.proxy.upstream_groups)
            .expect("configuration should be validated before building proxy server");
        let max_message_bytes = config.sip.max_message_bytes;
        let affinity_config = config.proxy.affinity.clone();
        Self {
            config,
            state,
            replicator,
            routes,
            upstreams,
            affinity: AffinityTable::new(affinity_config),
            metrics: Arc::new(ProxyMetrics::default()),
            udp_branches: Mutex::new(HashMap::new()),
            invite_transactions: Mutex::new(HashMap::new()),
            tcp_upstreams: TcpUpstreamPool::new(max_message_bytes),
        }
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
                this.metrics.clone(),
                shutdown.clone(),
            )));
        }

        let workers_per_listener = this.config.proxy.socket.workers_per_listener;
        for listener in &this.config.proxy.listeners {
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
                    let (len, peer) = received?;
                    let packet = &buf[..len];
                    if let Err(err) = self.handle_udp_packet(&socket, packet, peer, &listener).await {
                        warn!(%peer, error = %err, "failed to handle UDP SIP packet");
                    }
                }
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
                    let (stream, peer) = accepted?;
                    if self.config.proxy.socket.tcp_nodelay {
                        stream.set_nodelay(true)?;
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
        match method.as_str() {
            "OPTIONS" => {
                let response = SipMessage::response_like(&message, 200, "OK");
                self.record_local_response("tcp", 200);
                stream.write_all(&response.to_bytes()).await?;
            }
            "REGISTER" => {
                let response = self.handle_register(message, peer).await?;
                self.record_local_response("tcp", 200);
                stream.write_all(&response.to_bytes()).await?;
            }
            _ => {
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
                    error!(error = %err, "failed to forward TCP SIP request");
                    self.record_forward_error("tcp");
                    let response = SipMessage::response_like(
                        &SipMessage::parse(packet)?,
                        503,
                        "Service Unavailable",
                    );
                    self.record_local_response("tcp", 503);
                    stream.write_all(&response.to_bytes()).await?;
                }
            }
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
        match method.as_str() {
            "OPTIONS" => {
                let response = SipMessage::response_like(&message, 200, "OK");
                self.record_local_response("udp", 200);
                socket.send_to(&response.to_bytes(), peer).await?;
            }
            "REGISTER" => {
                let response = self.handle_register(message, peer).await?;
                self.record_local_response("udp", 200);
                socket.send_to(&response.to_bytes(), peer).await?;
            }
            _ => {
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
                    error!(error = %err, "failed to forward UDP SIP request");
                    self.record_forward_error("udp");
                    let response = SipMessage::response_like(
                        &SipMessage::parse(packet)?,
                        503,
                        "Service Unavailable",
                    );
                    self.record_local_response("udp", 503);
                    socket.send_to(&response.to_bytes(), peer).await?;
                }
            }
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
            prune_udp_branches(&mut branches, Instant::now());
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

        if let SipStartLine::Response { code, .. } = message.start_line {
            self.record_upstream_response("udp", code);
        }
        message
            .pop_top_via()?
            .context("upstream response is missing Via")?;
        socket
            .send_to(&message.to_bytes(), route.client_peer)
            .await?;
        Ok(())
    }

    async fn handle_register(&self, message: SipMessage, peer: SocketAddr) -> Result<SipMessage> {
        let aor = extract_aor(&message)?;
        let expires = extract_expires(&message);
        let command = if expires.is_zero() {
            ClusterCommand::UnregisterContact { aor }
        } else if let Some(contact) = extract_contact(&message)? {
            ClusterCommand::RegisterContact(ContactBinding {
                aor,
                contact,
                source: peer.to_string(),
                expires_at_epoch_ms: expires_at(expires),
            })
        } else {
            ClusterCommand::UnregisterContact { aor }
        };

        self.replicator.submit(command).await?;
        Ok(SipMessage::response_like(&message, 200, "OK"))
    }

    async fn forward_udp(
        &self,
        socket: &UdpSocket,
        message: SipMessage,
        peer: SocketAddr,
        listener: &ProxyListenerConfig,
    ) -> Result<()> {
        let (message, target, branch) = self.prepare_forward(message, peer, listener).await?;

        debug!(
            %peer,
            target = %target.addr,
            transport = %target.transport.as_str(),
            method = ?message.method(),
            branch = %branch,
            "forwarding UDP SIP request"
        );
        match target.transport {
            SipTransport::Udp => {
                self.record_forwarded_request("udp", target.transport, message.method());
                {
                    let mut branches = self.udp_branches.lock().await;
                    prune_udp_branches(&mut branches, Instant::now());
                    branches.insert(
                        branch,
                        UdpBranchRoute {
                            client_peer: peer,
                            upstream: target.addr,
                            created_at: Instant::now(),
                        },
                    );
                }
                socket.send_to(&message.to_bytes(), target.addr).await?;
                Ok(())
            }
            SipTransport::Tcp => {
                self.record_forwarded_request("udp", target.transport, message.method());
                let response = forward_tcp(target.addr, message.to_bytes()).await?;
                let response = self.finalize_upstream_response(response, &branch)?;
                socket.send_to(&response, peer).await?;
                Ok(())
            }
        }
    }

    async fn forward_tcp_stream(
        &self,
        client_stream: &mut TcpStream,
        message: SipMessage,
        peer: SocketAddr,
        listener: &ProxyListenerConfig,
    ) -> Result<()> {
        let method = message.method().unwrap_or_default().to_string();
        let (message, target, branch) = self.prepare_forward(message, peer, listener).await?;
        self.record_forwarded_request("tcp", target.transport, Some(method.as_str()));
        let mut responses = self
            .tcp_upstreams
            .send_request(
                target.addr,
                branch.clone(),
                method.clone(),
                message.to_bytes(),
            )
            .await?;
        loop {
            let response = timeout(UPSTREAM_TIMEOUT, responses.recv())
                .await
                .context("upstream SIP TCP response timed out")?
                .context("upstream SIP TCP response channel closed")?;
            let response_message = SipMessage::parse(&response)?;
            let is_final = matches!(
                response_message.start_line,
                SipStartLine::Response { code, .. } if code >= 200
            );
            if let SipStartLine::Response { code, .. } = response_message.start_line {
                self.record_upstream_response("tcp", code);
            }
            client_stream.write_all(&response).await?;
            if method != "INVITE" || is_final {
                break;
            }
        }
        Ok(())
    }

    async fn prepare_forward(
        &self,
        mut message: SipMessage,
        peer: SocketAddr,
        listener: &ProxyListenerConfig,
    ) -> Result<(SipMessage, UpstreamTarget, String)> {
        let request_uri = message
            .request_uri()
            .context("request forwarding requires a request URI")?
            .to_string();
        let method = message.method().unwrap_or_default().to_string();
        let invite_transaction_key = invite_transaction_key(&message)?;
        let target = if matches!(method.as_str(), "CANCEL" | "ACK")
            && let Some(target) = self
                .lookup_invite_transaction(invite_transaction_key.as_deref())
                .await
        {
            self.record_affinity_lookup("transaction-hit");
            target
        } else if let Some(binding) = self.state.lookup(&request_uri).await {
            self.record_affinity_lookup("location-hit");
            parse_contact_target(&binding.contact, listener.transport)
                .unwrap_or_else(|| self.select_upstream(&request_uri, listener))
        } else if let Some(target) = self.affinity.lookup(&message).await? {
            self.record_affinity_lookup("hit");
            UpstreamTarget {
                addr: target.addr,
                transport: target.transport,
            }
        } else {
            self.record_affinity_lookup("miss");
            self.select_upstream(&request_uri, listener)
        };

        let branch = format!("{PROXY_BRANCH_PREFIX}{}", monotonic_id());
        let via_host = self
            .config
            .sip
            .external_addr
            .clone()
            .or_else(|| Some(listener.bind.clone()))
            .unwrap_or_else(|| "127.0.0.1:5060".to_string());
        message.prepend_header(
            "Via",
            format!(
                "SIP/2.0/{} {via_host};branch={branch};received={}",
                listener.transport.sip_via_token(),
                peer.ip()
            ),
        );

        if self.config.proxy.record_route
            && should_record_route(&method)
            && let Some(external) = &self.config.sip.external_addr
        {
            message.prepend_header("Record-Route", format!("<sip:{external};lr>"));
        }

        self.affinity
            .remember(
                &message,
                AffinityTarget {
                    addr: target.addr,
                    transport: target.transport,
                },
            )
            .await?;

        if method == "INVITE" {
            self.remember_invite_transaction(invite_transaction_key, target)
                .await;
        }

        Ok((message, target, branch))
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

    async fn lookup_invite_transaction(&self, key: Option<&str>) -> Option<UpstreamTarget> {
        let key = key?;
        let mut transactions = self.invite_transactions.lock().await;
        prune_invite_transactions(&mut transactions, Instant::now());
        transactions.get(key).map(|route| route.target)
    }

    async fn remember_invite_transaction(&self, key: Option<String>, target: UpstreamTarget) {
        let Some(key) = key else {
            return;
        };
        let mut transactions = self.invite_transactions.lock().await;
        prune_invite_transactions(&mut transactions, Instant::now());
        transactions.insert(
            key,
            InviteTransactionRoute {
                target,
                created_at: Instant::now(),
            },
        );
    }

    fn finalize_upstream_response(&self, response: Vec<u8>, branch: &str) -> Result<Vec<u8>> {
        let mut message = SipMessage::parse(&response)?;
        let response_branch = message
            .top_via_branch()?
            .context("upstream response is missing top Via branch")?;
        if response_branch != branch {
            bail!(
                "upstream response top Via branch '{}' did not match proxy branch '{}'",
                response_branch,
                branch
            );
        }
        message
            .pop_top_via()?
            .context("upstream response is missing Via")?;
        Ok(message.to_bytes())
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
    metrics: Arc<ProxyMetrics>,
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
        .with_state(metrics);
    info!(bind = %bind_addr, "proxy metrics listener started");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
        .context("proxy metrics HTTP server failed")
}

async fn metrics_handler(State(metrics): State<Arc<ProxyMetrics>>) -> String {
    metrics.render_prometheus()
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

#[derive(Debug, Clone, Copy)]
struct InviteTransactionRoute {
    target: UpstreamTarget,
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
        method: String,
        packet: Vec<u8>,
    ) -> Result<mpsc::UnboundedReceiver<Vec<u8>>> {
        let mut last_error = None;
        for _ in 0..2 {
            let connection = self.get_or_connect(target).await?;
            match connection
                .send_request(branch.clone(), method.clone(), packet.clone())
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
}

struct TcpUpstreamConnection {
    target: SocketAddr,
    writer: Mutex<OwnedWriteHalf>,
    branches: Mutex<HashMap<String, TcpBranchRoute>>,
    alive: AtomicBool,
}

struct TcpBranchRoute {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    method: String,
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
        method: String,
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
                    method,
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
        message.start_line,
        SipStartLine::Response { code, .. } if code >= 200
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
        let remove_after_send = route.method != "INVITE" || is_final;
        if remove_after_send {
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
}

struct UpstreamGroupRuntime {
    name: String,
    servers: Vec<SocketAddr>,
    health: Vec<AtomicBool>,
    next: AtomicUsize,
    health_check: UpstreamHealthCheckConfig,
}

impl UpstreamGroupRuntime {
    fn new(config: &UpstreamGroupConfig) -> Result<Self> {
        let servers = config
            .servers
            .iter()
            .map(|server| {
                server
                    .parse::<SocketAddr>()
                    .with_context(|| format!("invalid server in upstream group '{}'", config.name))
            })
            .collect::<Result<Vec<_>>>()?;
        let health = servers.iter().map(|_| AtomicBool::new(true)).collect();
        Ok(Self {
            name: config.name.clone(),
            servers,
            health,
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

    fn set_health(&self, index: usize, healthy: bool) {
        self.health[index].store(healthy, Ordering::Relaxed);
    }
}

async fn run_health_checks(
    group: Arc<UpstreamGroupRuntime>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let interval = Duration::from_millis(group.health_check.interval_ms);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(interval) => {
                for (index, server) in group.servers.iter().copied().enumerate() {
                    let healthy = probe_sip_options(
                        server,
                        group.health_check.transport,
                        &group.health_check.options_uri,
                        Duration::from_millis(group.health_check.timeout_ms),
                    ).await;
                    group.set_health(index, healthy);
                    debug!(
                        group = %group.name,
                        %server,
                        healthy,
                        "backend health check completed"
                    );
                }
            }
        }
    }
    Ok(())
}

async fn probe_sip_options(
    server: SocketAddr,
    transport: SipTransport,
    uri: &str,
    limit: Duration,
) -> bool {
    let packet = format!(
        "OPTIONS {uri} SIP/2.0\r\n\
         Via: SIP/2.0/{} 127.0.0.1:0;branch=z9hG4bK-health-{}\r\n\
         From: <sip:healthcheck@localhost>;tag=health\r\n\
         To: <{uri}>\r\n\
         Call-ID: health-{}\r\n\
         CSeq: 1 OPTIONS\r\n\
         Content-Length: 0\r\n\r\n",
        transport.sip_via_token(),
        monotonic_id(),
        monotonic_id()
    )
    .into_bytes();

    let future = async {
        match transport {
            SipTransport::Udp => forward_udp_once(server, packet).await,
            SipTransport::Tcp => forward_tcp(server, packet).await,
        }
    };
    let Ok(response) = timeout(limit, future).await else {
        return false;
    };
    let Ok(response) = response else {
        return false;
    };
    let Ok(message) = SipMessage::parse(&response) else {
        return false;
    };
    match message.start_line {
        SipStartLine::Response { code, .. } => code < 500,
        SipStartLine::Request { .. } => false,
    }
}

async fn forward_udp_once(target: SocketAddr, packet: Vec<u8>) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(&packet, target).await?;
    let mut buf = vec![0; 65_535];
    let (len, _) = timeout(UPSTREAM_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .context("upstream SIP response timed out")??;
    Ok(buf[..len].to_vec())
}

fn prune_udp_branches(branches: &mut HashMap<String, UdpBranchRoute>, now: Instant) {
    branches.retain(|_, route| now.duration_since(route.created_at) <= UDP_BRANCH_TTL);
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

fn sip_transport_from_rsip(transport: RsipTransport) -> Option<SipTransport> {
    match transport.protocol() {
        RsipTransport::Udp => Some(SipTransport::Udp),
        RsipTransport::Tcp => Some(SipTransport::Tcp),
        _ => None,
    }
}

fn monotonic_id() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::StandaloneReplicator;
    use crate::config::{
        Config, ProxyAffinityConfig, ProxyConfig, ProxyListenerConfig, ProxySocketConfig,
        RouteConfig, SipConfig, SipTransport, UpstreamGroupConfig, UpstreamHealthCheckConfig,
        UpstreamMode,
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
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone()));
        ProxyServer::new(
            Config {
                sip: SipConfig {
                    external_addr: Some("127.0.0.1:5060".to_string()),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
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
    }

    fn test_server() -> ProxyServer {
        test_server_with_upstream("127.0.0.1:5080".parse().unwrap())
    }

    fn test_server_with_upstreams(upstreams: Vec<SocketAddr>) -> ProxyServer {
        let state = Arc::new(SharedState::default());
        let replicator = Arc::new(StandaloneReplicator::new(state.clone()));
        ProxyServer::new(
            Config {
                sip: SipConfig {
                    external_addr: Some("127.0.0.1:5060".to_string()),
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
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
                    ..SipConfig::default()
                },
                proxy: ProxyConfig {
                    record_route: true,
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
    }

    #[tokio::test]
    async fn options_gets_local_ok() {
        let server = test_server();
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        server
            .handle_udp_packet(
                &proxy_socket,
                b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK1\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:example.com>\r\n\
Call-ID: c1\r\n\
CSeq: 1 OPTIONS\r\n\r\n",
                client_socket.local_addr().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let response = buf[..len].to_vec();
        let text = String::from_utf8(response).unwrap();
        assert!(text.starts_with("SIP/2.0 200 OK"));
        assert!(text.contains("CSeq: 1 OPTIONS"));
    }

    #[tokio::test]
    async fn register_updates_shared_state() {
        let server = test_server();
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        server
            .handle_udp_packet(
                &proxy_socket,
                b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK1\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:100@example.com>\r\n\
Contact: <sip:100@127.0.0.1:5061>;expires=60\r\n\
Call-ID: c1\r\n\
CSeq: 1 REGISTER\r\n\r\n",
                "127.0.0.1:5061".parse().unwrap(),
                &test_listener(),
            )
            .await
            .unwrap();

        let binding = server.state.lookup("sip:100@example.com").await.unwrap();
        assert_eq!(binding.contact, "sip:100@127.0.0.1:5061");
    }

    #[tokio::test]
    async fn metrics_records_local_and_forwarded_udp_requests() {
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

        let metrics = server.metrics.render_prometheus();
        assert!(metrics.contains("sip_requests_total{transport=\"udp\",method=\"OPTIONS\"} 1"));
        assert!(metrics.contains("sip_requests_total{transport=\"udp\",method=\"MESSAGE\"} 1"));
        assert!(metrics.contains("sip_local_responses_total{transport=\"udp\",code=\"200\"} 1"));
        assert!(metrics.contains(
            "proxy_forwarded_requests_total{downstream_transport=\"udp\",upstream_transport=\"udp\",method=\"MESSAGE\"} 1"
        ));
        assert!(metrics.contains("proxy_affinity_lookup_total{result=\"miss\"} 1"));
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

            for code in ["100 Trying", "180 Ringing"] {
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

        for code in ["100 Trying", "180 Ringing"] {
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
        let register = SipMessage::parse(
            b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK1\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:100@example.com>\r\n\
Contact: <sip:100@127.0.0.1:5061>;expires=60\r\n\
Call-ID: c1\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();
        source
            .handle_register(register, "127.0.0.1:5061".parse().unwrap())
            .await
            .unwrap();

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

    #[tokio::test]
    async fn health_probe_marks_parseable_non_5xx_response_healthy() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0; 2048];
            let (_, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket
                .send_to(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n", peer)
                .await
                .unwrap();
        });

        assert!(
            probe_sip_options(
                addr,
                SipTransport::Udp,
                "sip:healthcheck@localhost",
                Duration::from_millis(500)
            )
            .await
        );
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
