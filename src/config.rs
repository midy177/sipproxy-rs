use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub ha: HaConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node: NodeConfig::default(),
            sip: SipConfig::default(),
            proxy: ProxyConfig::default(),
            cluster: ClusterConfig::default(),
            ha: HaConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
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
            for server in &group.servers {
                server.parse::<SocketAddr>().with_context(|| {
                    format!(
                        "proxy upstream group '{}' server must be host:port SocketAddr",
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
        if matches!(self.cluster.mode, ClusterMode::Raft) {
            self.cluster
                .bind_addr
                .parse::<SocketAddr>()
                .context("cluster.bind_addr must be a SocketAddr in raft mode")?;
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
            if let Some(peer_addr) = &self.ha.active_standby.peer_heartbeat_addr {
                peer_addr.parse::<SocketAddr>().context(
                    "ha.active_standby.peer_heartbeat_addr must be a SocketAddr when enabled",
                )?;
            }
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
            if let Some(peer_addr) = &self.ha.replication.peer_addr {
                peer_addr.parse::<SocketAddr>().context(
                    "ha.replication.peer_addr must be a SocketAddr when replication is enabled",
                )?;
            }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub id: u64,
    pub advertise_addr: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            id: 1,
            advertise_addr: "127.0.0.1".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipConfig {
    pub external_addr: Option<String>,
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,
}

impl Default for SipConfig {
    fn default() -> Self {
        Self {
            external_addr: None,
            max_message_bytes: default_max_message_bytes(),
        }
    }
}

fn default_max_message_bytes() -> usize {
    65_535
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub record_route: bool,
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
    #[serde(default)]
    pub transport: SipTransport,
    #[serde(default = "default_health_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_health_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_health_options_uri")]
    pub options_uri: String,
}

impl Default for UpstreamHealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transport: SipTransport::Udp,
            interval_ms: default_health_interval_ms(),
            timeout_ms: default_health_timeout_ms(),
            options_uri: default_health_options_uri(),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub name: String,
    pub listener: Option<String>,
    pub domain: Option<String>,
    pub prefix: Option<String>,
    pub upstream_group: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ClusterMode {
    Standalone,
    Raft,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    #[serde(default)]
    pub mode: ClusterMode,
    #[serde(default = "default_cluster_bind")]
    pub bind_addr: String,
    #[serde(default)]
    pub peers: Vec<ClusterPeer>,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            mode: ClusterMode::Standalone,
            bind_addr: default_cluster_bind(),
            peers: Vec::new(),
            data_dir: default_data_dir(),
        }
    }
}

impl Default for ClusterMode {
    fn default() -> Self {
        Self::Standalone
    }
}

fn default_cluster_bind() -> String {
    "127.0.0.1:7000".to_string()
}

fn default_data_dir() -> String {
    "./data".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterPeer {
    pub id: u64,
    pub raft_addr: String,
    pub sip_addr: String,
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
advertise_addr = "10.0.0.11"

[sip]
external_addr = "sip.example.com:5060"
max_message_bytes = 65535

[proxy]
record_route = true

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
transport = "udp"
interval_ms = 5000
timeout_ms = 1000
options_uri = "sip:healthcheck@127.0.0.1"

[[proxy.upstream_groups]]
name = "pbx-a"
mode = "round-robin"
servers = ["10.0.1.10:5060", "10.0.1.11:5060"]

[proxy.upstream_groups.health_check]
enabled = true
transport = "udp"
interval_ms = 5000
timeout_ms = 1000
options_uri = "sip:healthcheck@pbx-a"

[[proxy.listeners]]
bind = "0.0.0.0:5060"
transport = "udp"
upstream_group = "default"

[[proxy.listeners]]
bind = "0.0.0.0:5060"
transport = "tcp"
upstream_group = "default"

[[proxy.listeners]]
bind = "0.0.0.0:5080"
transport = "udp"
upstream_group = "pbx-a"

[[proxy.listeners]]
bind = "0.0.0.0:5080"
transport = "tcp"
upstream_group = "pbx-a"

[[proxy.routes]]
name = "tenant-a-on-5060"
listener = "udp/0.0.0.0:5060"
domain = "tenant-a.example.com"
prefix = "sip:1"
upstream_group = "pbx-a"

[cluster]
mode = "standalone"
bind_addr = "127.0.0.1:7000"
data_dir = "./data/node-1"

[[cluster.peers]]
id = 1
raft_addr = "10.0.0.11:7000"
sip_addr = "10.0.0.11:5060"

[[cluster.peers]]
id = 2
raft_addr = "10.0.0.12:7000"
sip_addr = "10.0.0.12:5060"

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
}
