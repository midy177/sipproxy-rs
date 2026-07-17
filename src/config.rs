use anyhow::{Context, Result, bail};
use rsipstack::sip::{Scheme, Uri};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub node: NodeConfig,
    #[serde(default)]
    pub sip: SipConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub ha: HaConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node: NodeConfig::default(),
            sip: SipConfig::default(),
            proxy: ProxyConfig::default(),
            ha: HaConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let content = expand_env_placeholders(&content)
            .with_context(|| format!("failed to expand config {}", path.display()))?;
        let config: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn write_example(path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        fs::write(path, example_config()).with_context(|| {
            format!(
                "failed to write example configuration to {}",
                path.display()
            )
        })?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.node.id == 0 {
            bail!("node.id must be greater than 0");
        }
        if self.sip.max_message_bytes == 0 {
            bail!("sip.max_message_bytes must be greater than 0");
        }
        for (name, value) in [
            ("sip.external_addr", self.sip.external_addr.as_deref()),
            ("sip.public_addr", self.sip.public_addr.as_deref()),
            ("sip.internal_addr", self.sip.internal_addr.as_deref()),
        ] {
            if let Some(value) = value
                && !value.trim().is_empty()
            {
                validate_advertised_addr(value)
                    .with_context(|| format!("{name} must be host or host:port"))?;
            }
        }
        if let Some(server) = &self.sip.public_stun_server
            && !server.trim().is_empty()
        {
            validate_host_port(server).context("sip.public_stun_server must be host:port")?;
        }
        if !self.sip.internal_probe_addr.trim().is_empty() {
            validate_host_port(&self.sip.internal_probe_addr)
                .context("sip.internal_probe_addr must be host:port")?;
        }
        if self.proxy.listeners.is_empty() {
            bail!("proxy.listeners must contain at least one SIP listener");
        }
        if self.proxy.upstream_groups.is_empty() {
            bail!("proxy.upstream_groups must contain at least one backend group");
        }
        if self.proxy.socket.workers_per_listener == 0 {
            bail!("proxy.socket.workers_per_listener must be greater than 0");
        }
        if self.proxy.socket.workers_per_listener > 1 && !self.proxy.socket.reuse_port {
            bail!(
                "proxy.socket.reuse_port must be true when workers_per_listener is greater than 1"
            );
        }
        if matches!(self.proxy.socket.recv_buffer_bytes, Some(0)) {
            bail!("proxy.socket.recv_buffer_bytes must be greater than 0 when set");
        }
        if matches!(self.proxy.socket.send_buffer_bytes, Some(0)) {
            bail!("proxy.socket.send_buffer_bytes must be greater than 0 when set");
        }
        if self.proxy.metrics.enabled {
            self.proxy
                .metrics
                .bind_addr
                .parse::<SocketAddr>()
                .context("proxy.metrics.bind_addr must be a SocketAddr when metrics is enabled")?;
        }
        if self.proxy.affinity.enabled && self.proxy.affinity.ttl_seconds == 0 {
            bail!("proxy.affinity.ttl_seconds must be greater than 0 when affinity is enabled");
        }
        if self.proxy.register_routing == Some(RegisterRoutingMode::Path)
            && self.proxy.rewrite_register_contact
        {
            bail!(
                "proxy.register_routing = \"path\" conflicts with legacy proxy.rewrite_register_contact = true"
            );
        }

        let mut group_names = HashSet::new();
        for group in &self.proxy.upstream_groups {
            if !group_names.insert(group.name.as_str()) {
                bail!("duplicate proxy upstream group '{}'", group.name);
            }
            if group.servers.is_empty() {
                bail!(
                    "proxy upstream group '{}' must contain at least one server",
                    group.name
                );
            }
            if group.health_check.enabled {
                if group.health_check.interval_ms == 0 {
                    bail!(
                        "proxy upstream group '{}' health_check.interval_ms must be greater than 0",
                        group.name
                    );
                }
                if group.health_check.timeout_ms == 0 {
                    bail!(
                        "proxy upstream group '{}' health_check.timeout_ms must be greater than 0",
                        group.name
                    );
                }
                if group.health_check.success_threshold == 0 {
                    bail!(
                        "proxy upstream group '{}' health_check.success_threshold must be greater than 0",
                        group.name
                    );
                }
                if group.health_check.failure_threshold == 0 {
                    bail!(
                        "proxy upstream group '{}' health_check.failure_threshold must be greater than 0",
                        group.name
                    );
                }
                if let UpstreamHealthProbeConfig::Options {
                    uri, success_codes, ..
                } = &group.health_check.probe
                {
                    let parsed_uri = uri.parse::<Uri>().with_context(|| {
                        format!(
                            "proxy upstream group '{}' health_check.probe.uri must be a SIP URI",
                            group.name
                        )
                    })?;
                    if !matches!(parsed_uri.scheme, Some(Scheme::Sip | Scheme::Sips)) {
                        bail!(
                            "proxy upstream group '{}' health_check.probe.uri must use sip or sips scheme",
                            group.name
                        );
                    }
                    for code in success_codes {
                        if !(100..=699).contains(code) {
                            bail!(
                                "proxy upstream group '{}' health_check.probe.success_codes must contain valid SIP status codes",
                                group.name
                            );
                        }
                    }
                }
            }
            for server in &group.servers {
                validate_host_port(server).with_context(|| {
                    format!(
                        "proxy upstream group '{}' server must be host:port",
                        group.name
                    )
                })?;
            }
        }

        let mut listener_keys = HashSet::new();
        for listener in &self.proxy.listeners {
            listener.bind.parse::<SocketAddr>().with_context(|| {
                format!(
                    "proxy listener '{} {}' bind must be host:port SocketAddr",
                    listener.transport.as_str(),
                    listener.bind
                )
            })?;
            if !group_names.contains(listener.upstream_group.as_str()) {
                bail!(
                    "proxy listener '{} {}' references unknown upstream_group '{}'",
                    listener.transport.as_str(),
                    listener.bind,
                    listener.upstream_group
                );
            }
            let key = listener.key();
            if !listener_keys.insert(key.clone()) {
                bail!("duplicate proxy listener '{key}'");
            }
        }

        for route in &self.proxy.routes {
            if !group_names.contains(route.upstream_group.as_str()) {
                bail!(
                    "proxy route '{}' references unknown upstream_group '{}'",
                    route.name,
                    route.upstream_group
                );
            }
            if let Some(listener) = &route.listener
                && !listener_keys.contains(listener)
            {
                bail!(
                    "proxy route '{}' references unknown listener '{}'",
                    route.name,
                    listener
                );
            }
        }
        if self.ha.leader_check_interval_ms == 0 {
            bail!("ha.leader_check_interval_ms must be greater than 0");
        }
        if self.ha.active_standby.enabled {
            self.ha
                .active_standby
                .heartbeat_bind
                .parse::<SocketAddr>()
                .context("ha.active_standby.heartbeat_bind must be a SocketAddr when enabled")?;
            self.ha
                .active_standby
                .peer_heartbeat_addr
                .as_ref()
                .context("ha.active_standby.peer_heartbeat_addr must be set when enabled")?
                .parse::<SocketAddr>()
                .context(
                    "ha.active_standby.peer_heartbeat_addr must be a SocketAddr when enabled",
                )?;
            if self.ha.active_standby.heartbeat_interval_ms == 0 {
                bail!("ha.active_standby.heartbeat_interval_ms must be greater than 0");
            }
            if self.ha.active_standby.failover_timeout_ms
                <= self.ha.active_standby.heartbeat_interval_ms
            {
                bail!(
                    "ha.active_standby.failover_timeout_ms must be greater than heartbeat_interval_ms"
                );
            }
        }
        if self.ha.replication.enabled {
            self.ha
                .replication
                .bind_addr
                .parse::<SocketAddr>()
                .context(
                    "ha.replication.bind_addr must be a SocketAddr when replication is enabled",
                )?;
            self.ha
                .replication
                .peer_addr
                .as_ref()
                .context("ha.replication.peer_addr must be set when replication is enabled")?
                .parse::<SocketAddr>()
                .context(
                    "ha.replication.peer_addr must be a SocketAddr when replication is enabled",
                )?;
            if self.ha.replication.pull_interval_ms == 0 {
                bail!("ha.replication.pull_interval_ms must be greater than 0");
            }
            if self.ha.replication.request_timeout_ms == 0 {
                bail!("ha.replication.request_timeout_ms must be greater than 0");
            }
        }
        Ok(())
    }
}

fn expand_env_placeholders(input: &str) -> Result<String> {
    expand_env_placeholders_with(input, |name| env::var(name).ok())
}

fn expand_env_placeholders_with(
    input: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String> {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            output.push(ch);
            continue;
        }

        match chars.peek().copied() {
            Some('{') => {
                chars.next();
                let mut expression = String::new();
                let mut closed = false;
                for ch in chars.by_ref() {
                    if ch == '}' {
                        closed = true;
                        break;
                    }
                    expression.push(ch);
                }
                if !closed {
                    bail!("unclosed environment placeholder '${{{expression}'");
                }
                output.push_str(&resolve_env_expression(&expression, &lookup)?);
            }
            Some(next) if is_env_name_start(next) => {
                let mut name = String::new();
                while let Some(next) = chars.peek().copied() {
                    if !is_env_name_continue(next) {
                        break;
                    }
                    name.push(next);
                    chars.next();
                }
                output.push_str(&lookup_env_required(&name, &lookup)?);
            }
            _ => output.push('$'),
        }
    }
    Ok(output)
}

fn resolve_env_expression(
    expression: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String> {
    let (name, default) = expression
        .split_once(":-")
        .map_or((expression, None), |(name, default)| (name, Some(default)));
    if !is_valid_env_name(name) {
        bail!("invalid environment placeholder name '{name}'");
    }
    match lookup(name) {
        Some(value) if !value.is_empty() => Ok(value),
        Some(value) if default.is_none() => Ok(value),
        _ => default
            .map(str::to_string)
            .map_or_else(|| lookup_env_required(name, lookup), Ok),
    }
}

fn lookup_env_required(name: &str, lookup: impl Fn(&str) -> Option<String>) -> Result<String> {
    if !is_valid_env_name(name) {
        bail!("invalid environment placeholder name '{name}'");
    }
    lookup(name).with_context(|| format!("environment variable '{name}' is not set"))
}

fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(is_env_name_start) && chars.all(is_env_name_continue)
}

fn is_env_name_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn is_env_name_continue(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn validate_host_port(value: &str) -> Result<()> {
    if value.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        bail!("missing port");
    };
    if host.trim().is_empty() {
        bail!("missing host");
    }
    port.parse::<u16>().context("invalid port")?;
    Ok(())
}

fn validate_advertised_addr(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("missing host");
    }
    if value.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    if let Some((host, port)) = split_host_port(value) {
        if host.trim().is_empty() {
            bail!("missing host");
        }
        port.parse::<u16>().context("invalid port")?;
    }
    Ok(())
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub id: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self { id: 1 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipConfig {
    /// Legacy single advertised address. Used as a fallback when public_addr or
    /// internal_addr is not set.
    pub external_addr: Option<String>,
    pub public_addr: Option<String>,
    pub internal_addr: Option<String>,
    pub public_stun_server: Option<String>,
    #[serde(default = "default_internal_probe_addr")]
    pub internal_probe_addr: String,
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,
}

impl Default for SipConfig {
    fn default() -> Self {
        Self {
            external_addr: None,
            public_addr: None,
            internal_addr: None,
            public_stun_server: None,
            internal_probe_addr: default_internal_probe_addr(),
            max_message_bytes: default_max_message_bytes(),
        }
    }
}

fn default_internal_probe_addr() -> String {
    "8.8.8.8:53".to_string()
}

fn default_max_message_bytes() -> usize {
    65_535
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub record_route: bool,
    #[serde(default)]
    pub register_routing: Option<RegisterRoutingMode>,
    #[serde(default)]
    pub rewrite_register_contact: bool,
    #[serde(default)]
    pub socket: ProxySocketConfig,
    #[serde(default)]
    pub metrics: ProxyMetricsConfig,
    #[serde(default)]
    pub affinity: ProxyAffinityConfig,
    #[serde(default)]
    pub listeners: Vec<ProxyListenerConfig>,
    #[serde(default)]
    pub upstream_groups: Vec<UpstreamGroupConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            record_route: true,
            register_routing: None,
            rewrite_register_contact: false,
            socket: ProxySocketConfig::default(),
            metrics: ProxyMetricsConfig::default(),
            affinity: ProxyAffinityConfig::default(),
            listeners: vec![ProxyListenerConfig {
                bind: "0.0.0.0:5060".to_string(),
                transport: SipTransport::Udp,
                upstream_group: "default".to_string(),
            }],
            upstream_groups: vec![UpstreamGroupConfig {
                name: "default".to_string(),
                mode: UpstreamMode::RoundRobin,
                health_check: UpstreamHealthCheckConfig::default(),
                servers: vec!["127.0.0.1:5080".to_string()],
            }],
            routes: Vec::new(),
        }
    }
}

impl ProxyConfig {
    pub fn effective_register_routing(&self) -> RegisterRoutingMode {
        self.register_routing.unwrap_or_else(|| {
            if self.rewrite_register_contact {
                RegisterRoutingMode::ContactRewrite
            } else {
                RegisterRoutingMode::Path
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegisterRoutingMode {
    Path,
    ContactRewrite,
}

impl RegisterRoutingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::ContactRewrite => "contact-rewrite",
        }
    }
}

impl Default for RegisterRoutingMode {
    fn default() -> Self {
        Self::Path
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyMetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_bind_addr")]
    pub bind_addr: String,
}

impl Default for ProxyMetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_metrics_bind_addr(),
        }
    }
}

fn default_metrics_bind_addr() -> String {
    "127.0.0.1:9100".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAffinityConfig {
    #[serde(default = "default_affinity_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub key: ProxyAffinityKey,
    #[serde(default = "default_affinity_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl Default for ProxyAffinityConfig {
    fn default() -> Self {
        Self {
            enabled: default_affinity_enabled(),
            key: ProxyAffinityKey::default(),
            ttl_seconds: default_affinity_ttl_seconds(),
        }
    }
}

fn default_affinity_enabled() -> bool {
    true
}

fn default_affinity_ttl_seconds() -> u64 {
    3600
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyAffinityKey {
    DialogId,
    CallId,
    RequestUri,
}

impl Default for ProxyAffinityKey {
    fn default() -> Self {
        Self::DialogId
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySocketConfig {
    #[serde(default)]
    pub reuse_port: bool,
    #[serde(default = "default_workers_per_listener")]
    pub workers_per_listener: usize,
    #[serde(default)]
    pub recv_buffer_bytes: Option<usize>,
    #[serde(default)]
    pub send_buffer_bytes: Option<usize>,
    #[serde(default = "default_tcp_nodelay")]
    pub tcp_nodelay: bool,
}

impl Default for ProxySocketConfig {
    fn default() -> Self {
        Self {
            reuse_port: false,
            workers_per_listener: default_workers_per_listener(),
            recv_buffer_bytes: None,
            send_buffer_bytes: None,
            tcp_nodelay: default_tcp_nodelay(),
        }
    }
}

fn default_workers_per_listener() -> usize {
    1
}

fn default_tcp_nodelay() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SipTransport {
    Udp,
    Tcp,
}

impl Default for SipTransport {
    fn default() -> Self {
        Self::Udp
    }
}

impl SipTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }

    pub fn sip_via_token(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyListenerConfig {
    pub bind: String,
    pub transport: SipTransport,
    pub upstream_group: String,
}

impl ProxyListenerConfig {
    pub fn key(&self) -> String {
        format!("{}/{}", self.transport.as_str(), self.bind)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamGroupConfig {
    pub name: String,
    #[serde(default)]
    pub mode: UpstreamMode,
    #[serde(default)]
    pub health_check: UpstreamHealthCheckConfig,
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamMode {
    RoundRobin,
}

impl Default for UpstreamMode {
    fn default() -> Self {
        Self::RoundRobin
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamHealthCheckConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_health_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_health_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_health_success_threshold")]
    pub success_threshold: usize,
    #[serde(default = "default_health_failure_threshold")]
    pub failure_threshold: usize,
    #[serde(default)]
    pub probe: UpstreamHealthProbeConfig,
}

impl Default for UpstreamHealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_ms: default_health_interval_ms(),
            timeout_ms: default_health_timeout_ms(),
            success_threshold: default_health_success_threshold(),
            failure_threshold: default_health_failure_threshold(),
            probe: UpstreamHealthProbeConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum UpstreamHealthProbeConfig {
    Options {
        #[serde(default)]
        transport: SipTransport,
        #[serde(default = "default_health_options_uri")]
        uri: String,
        #[serde(default = "default_health_success_codes")]
        success_codes: Vec<u16>,
    },
    TcpConnect,
}

impl Default for UpstreamHealthProbeConfig {
    fn default() -> Self {
        Self::Options {
            transport: SipTransport::Udp,
            uri: default_health_options_uri(),
            success_codes: default_health_success_codes(),
        }
    }
}

fn default_health_interval_ms() -> u64 {
    5_000
}

fn default_health_timeout_ms() -> u64 {
    1_000
}

fn default_health_options_uri() -> String {
    "sip:healthcheck@localhost".to_string()
}

fn default_health_success_codes() -> Vec<u16> {
    vec![200, 202, 405, 481]
}

fn default_health_success_threshold() -> usize {
    2
}

fn default_health_failure_threshold() -> usize {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub name: String,
    pub listener: Option<String>,
    pub domain: Option<String>,
    pub prefix: Option<String>,
    pub upstream_group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaConfig {
    #[serde(default = "default_ha_leader_check_interval_ms")]
    pub leader_check_interval_ms: u64,
    #[serde(default)]
    pub active_standby: HaActiveStandbyConfig,
    #[serde(default)]
    pub replication: HaReplicationConfig,
    #[serde(default)]
    pub addon: HaAddonConfig,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            leader_check_interval_ms: default_ha_leader_check_interval_ms(),
            active_standby: HaActiveStandbyConfig::default(),
            replication: HaReplicationConfig::default(),
            addon: HaAddonConfig::Noop,
        }
    }
}

fn default_ha_leader_check_interval_ms() -> u64 {
    1_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaActiveStandbyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub initial_role: HaInitialRole,
    #[serde(default = "default_ha_heartbeat_bind")]
    pub heartbeat_bind: String,
    #[serde(default)]
    pub peer_heartbeat_addr: Option<String>,
    #[serde(default = "default_ha_heartbeat_interval_ms")]
    pub heartbeat_interval_ms: u64,
    #[serde(default = "default_ha_failover_timeout_ms")]
    pub failover_timeout_ms: u64,
}

impl Default for HaActiveStandbyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            initial_role: HaInitialRole::default(),
            heartbeat_bind: default_ha_heartbeat_bind(),
            peer_heartbeat_addr: None,
            heartbeat_interval_ms: default_ha_heartbeat_interval_ms(),
            failover_timeout_ms: default_ha_failover_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HaInitialRole {
    Active,
    Standby,
}

impl Default for HaInitialRole {
    fn default() -> Self {
        Self::Standby
    }
}

fn default_ha_heartbeat_bind() -> String {
    "127.0.0.1:7900".to_string()
}

fn default_ha_heartbeat_interval_ms() -> u64 {
    1_000
}

fn default_ha_failover_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaReplicationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ha_replication_bind")]
    pub bind_addr: String,
    #[serde(default)]
    pub peer_addr: Option<String>,
    #[serde(default = "default_ha_replication_pull_interval_ms")]
    pub pull_interval_ms: u64,
    #[serde(default = "default_ha_replication_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

impl Default for HaReplicationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_ha_replication_bind(),
            peer_addr: None,
            pull_interval_ms: default_ha_replication_pull_interval_ms(),
            request_timeout_ms: default_ha_replication_request_timeout_ms(),
        }
    }
}

fn default_ha_replication_bind() -> String {
    "127.0.0.1:7901".to_string()
}

fn default_ha_replication_pull_interval_ms() -> u64 {
    10_000
}

fn default_ha_replication_request_timeout_ms() -> u64 {
    2_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum HaAddonConfig {
    Noop,
    Command {
        on_become_leader: Option<String>,
        on_step_down: Option<String>,
        #[serde(default = "default_command_timeout_ms")]
        timeout_ms: u64,
    },
}

impl Default for HaAddonConfig {
    fn default() -> Self {
        Self::Noop
    }
}

fn default_command_timeout_ms() -> u64 {
    5_000
}

pub fn example_config() -> &'static str {
    r#"# sigproxy-rs example configuration

[node]
id = 1

[sip]
public_addr = "127.0.0.1"
internal_addr = "127.0.0.1"
public_stun_server = ""
internal_probe_addr = "8.8.8.8:53"
max_message_bytes = 65535

[proxy]
record_route = true
register_routing = "path"

[proxy.socket]
reuse_port = false
workers_per_listener = 1
recv_buffer_bytes = 4194304
send_buffer_bytes = 4194304
tcp_nodelay = true

[proxy.metrics]
enabled = false
bind_addr = "127.0.0.1:9100"

[proxy.affinity]
enabled = true
key = "dialog-id"
ttl_seconds = 3600

[[proxy.upstream_groups]]
name = "default"
mode = "round-robin"
servers = ["127.0.0.1:5080"]

[proxy.upstream_groups.health_check]
enabled = true
interval_ms = 5000
timeout_ms = 1000
success_threshold = 2
failure_threshold = 3

[proxy.upstream_groups.health_check.probe]
mode = "options"
transport = "udp"
uri = "sip:healthcheck@127.0.0.1"
success_codes = [200, 202, 405, 481]

[[proxy.listeners]]
bind = "127.0.0.1:5060"
transport = "udp"
upstream_group = "default"

[[proxy.listeners]]
bind = "127.0.0.1:5060"
transport = "tcp"
upstream_group = "default"

[ha]
leader_check_interval_ms = 1000

[ha.active_standby]
enabled = false
initial_role = "standby"
heartbeat_bind = "127.0.0.1:7900"
peer_heartbeat_addr = "127.0.0.1:7900"
heartbeat_interval_ms = 1000
failover_timeout_ms = 5000

[ha.replication]
enabled = false
bind_addr = "127.0.0.1:7901"
peer_addr = "127.0.0.1:7902"
pull_interval_ms = 10000
request_timeout_ms = 2000

[ha.addon]
type = "noop"

# Command addon example for later EIP binding integration:
# [ha.addon]
# type = "command"
# on_become_leader = "/usr/local/bin/bind-eip.sh"
# on_step_down = "/usr/local/bin/unbind-eip.sh"
# timeout_ms = 5000
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_is_valid() {
        let config: Config = toml::from_str(example_config()).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn parses_register_routing_mode() {
        let config: Config = toml::from_str(
            r#"
[proxy]
register_routing = "contact-rewrite"

[[proxy.listeners]]
bind = "127.0.0.1:5060"
transport = "udp"
upstream_group = "default"

[[proxy.upstream_groups]]
name = "default"
servers = ["127.0.0.1:5080"]
"#,
        )
        .unwrap();

        assert_eq!(
            config.proxy.effective_register_routing(),
            RegisterRoutingMode::ContactRewrite
        );
        config.validate().unwrap();
    }

    #[test]
    fn legacy_rewrite_register_contact_selects_contact_rewrite_mode() {
        let config = Config {
            proxy: ProxyConfig {
                rewrite_register_contact: true,
                ..ProxyConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            config.proxy.effective_register_routing(),
            RegisterRoutingMode::ContactRewrite
        );
        config.validate().unwrap();
    }

    #[test]
    fn rejects_conflicting_register_routing_config() {
        let config: Config = toml::from_str(
            r#"
[proxy]
register_routing = "path"
rewrite_register_contact = true
"#,
        )
        .unwrap();

        assert!(config.validate().is_err());
    }

    #[test]
    fn expands_environment_placeholders() {
        let expanded = expand_env_placeholders_with(
            r#"external_addr = "${SIP_ADDR}"
bind = "$BIND_ADDR"
port = ${PORT:-5060}
fallback = "${EMPTY:-default-value}"
literal = "$-not-a-placeholder"
"#,
            |name| match name {
                "SIP_ADDR" => Some("10.10.16.41:5060".to_string()),
                "BIND_ADDR" => Some("0.0.0.0:5060".to_string()),
                "EMPTY" => Some(String::new()),
                _ => None,
            },
        )
        .unwrap();

        assert!(expanded.contains(r#"external_addr = "10.10.16.41:5060""#));
        assert!(expanded.contains(r#"bind = "0.0.0.0:5060""#));
        assert!(expanded.contains("port = 5060"));
        assert!(expanded.contains(r#"fallback = "default-value""#));
        assert!(expanded.contains(r#"literal = "$-not-a-placeholder""#));
    }

    #[test]
    fn rejects_missing_environment_placeholder() {
        let err = expand_env_placeholders_with("${MISSING}", |_| None).unwrap_err();
        assert!(
            err.to_string()
                .contains("environment variable 'MISSING' is not set")
        );
    }

    #[test]
    fn rejects_config_without_listeners() {
        let config = Config {
            proxy: ProxyConfig {
                listeners: Vec::new(),
                ..ProxyConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_listener_workers_without_reuse_port() {
        let config = Config {
            proxy: ProxyConfig {
                socket: ProxySocketConfig {
                    workers_per_listener: 2,
                    reuse_port: false,
                    ..ProxySocketConfig::default()
                },
                ..ProxyConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_invalid_metrics_bind_addr_when_enabled() {
        let config = Config {
            proxy: ProxyConfig {
                metrics: ProxyMetricsConfig {
                    enabled: true,
                    bind_addr: "not-a-socket".to_string(),
                },
                ..ProxyConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_max_message_bytes() {
        let config = Config {
            sip: SipConfig {
                max_message_bytes: 0,
                ..SipConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn accepts_hostname_upstream_servers_for_startup_resolution() {
        let mut config = Config::default();
        config.proxy.upstream_groups[0].servers = vec!["edge0.example.com:5060".to_string()];

        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_health_check_thresholds() {
        let mut config = Config::default();
        config.proxy.upstream_groups[0].health_check = UpstreamHealthCheckConfig {
            enabled: true,
            failure_threshold: 0,
            ..UpstreamHealthCheckConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_invalid_health_check_success_code() {
        let mut config = Config::default();
        config.proxy.upstream_groups[0].health_check = UpstreamHealthCheckConfig {
            enabled: true,
            probe: UpstreamHealthProbeConfig::Options {
                transport: SipTransport::Udp,
                uri: "sip:healthcheck@example.com".to_string(),
                success_codes: vec![99],
            },
            ..UpstreamHealthCheckConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_invalid_health_check_options_uri() {
        let mut config = Config::default();
        config.proxy.upstream_groups[0].health_check = UpstreamHealthCheckConfig {
            enabled: true,
            probe: UpstreamHealthProbeConfig::Options {
                transport: SipTransport::Udp,
                uri: "http://healthcheck.example.com".to_string(),
                success_codes: vec![200],
            },
            ..UpstreamHealthCheckConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_active_standby_without_peer_heartbeat() {
        let config = Config {
            ha: HaConfig {
                active_standby: HaActiveStandbyConfig {
                    enabled: true,
                    peer_heartbeat_addr: None,
                    ..HaActiveStandbyConfig::default()
                },
                ..HaConfig::default()
            },
            ..Config::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_ha_replication_without_peer_addr() {
        let config = Config {
            ha: HaConfig {
                replication: HaReplicationConfig {
                    enabled: true,
                    peer_addr: None,
                    ..HaReplicationConfig::default()
                },
                ..HaConfig::default()
            },
            ..Config::default()
        };

        assert!(config.validate().is_err());
    }
}
