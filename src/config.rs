use anyhow::{Context, Result, bail};
use rsipstack::sip::{Scheme, Uri};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub node: NodeConfig,
    #[serde(default)]
    pub sip: SipConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub persistence: PersistenceConfig,
    #[serde(default)]
    pub ha: HaConfig,
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
        if self.proxy.socket.workers_per_listener == 0 && !self.proxy.socket.reuse_port {
            bail!("proxy.socket.reuse_port must be true when workers_per_listener is 0 (auto)");
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
        validate_security_config(&self.proxy.security, "proxy.security")?;
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
                    uri,
                    success_codes,
                    transport,
                    ..
                } = &group.health_check.probe
                {
                    if *transport == SipTransport::TcpUdp {
                        bail!(
                            "proxy upstream group '{}' health_check.probe.transport must be udp or tcp",
                            group.name
                        );
                    }
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
        let mut route_listener_keys = HashSet::new();
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
            if let Some(security) = &listener.security {
                validate_security_config(
                    security,
                    &format!(
                        "proxy listener '{} {}' security",
                        listener.transport.as_str(),
                        listener.bind
                    ),
                )?;
            }
            route_listener_keys.insert(listener.key());
            for concrete_listener in listener.concrete_listeners() {
                let key = concrete_listener.key();
                if !listener_keys.insert(key.clone()) {
                    bail!("duplicate proxy listener '{key}'");
                }
                route_listener_keys.insert(key);
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
                && !route_listener_keys.contains(listener)
            {
                bail!(
                    "proxy route '{}' references unknown listener '{}'",
                    route.name,
                    listener
                );
            }
        }
        validate_upstream_targets_do_not_loop_to_proxy(self)?;
        if self.ha.leader_check_interval_ms == 0 {
            bail!("ha.leader_check_interval_ms must be greater than 0");
        }
        let persistence = self.persistence_config();
        let persistence_path = self.persistence_config_path();
        if persistence.enabled {
            if persistence.path.trim().is_empty() {
                bail!("{persistence_path}.path must not be empty when persistence is enabled");
            }
            if persistence.cleanup_interval_ms == 0 {
                bail!(
                    "{persistence_path}.cleanup_interval_ms must be greater than 0 when persistence is enabled"
                );
            }
            if persistence.event_retention_seconds == 0 {
                bail!(
                    "{persistence_path}.event_retention_seconds must be greater than 0 when persistence is enabled"
                );
            }
        }
        let active_standby = self.ha.active_standby_config();
        if active_standby.enabled {
            active_standby
                .heartbeat_bind
                .parse::<SocketAddr>()
                .context("ha.heartbeat_bind must be a SocketAddr when HA is enabled")?;
            active_standby
                .peer_heartbeat_addr
                .as_ref()
                .context("ha.peer_heartbeat_addr must be set when HA is enabled")?
                .parse::<SocketAddr>()
                .context("ha.peer_heartbeat_addr must be a SocketAddr when HA is enabled")?;
            if active_standby.heartbeat_interval_ms == 0 {
                bail!("ha.heartbeat_interval_ms must be greater than 0");
            }
            if active_standby.failover_timeout_ms <= active_standby.heartbeat_interval_ms {
                bail!("ha.failover_timeout_ms must be greater than heartbeat_interval_ms");
            }
        }
        let replication = self.ha.replication_config();
        if replication.enabled {
            replication
                .bind_addr
                .parse::<SocketAddr>()
                .context("ha.replication_bind_addr must be a SocketAddr when HA is enabled")?;
            replication
                .peer_addr
                .as_ref()
                .context("ha.peer_replication_addr must be set when HA is enabled")?
                .parse::<SocketAddr>()
                .context("ha.peer_replication_addr must be a SocketAddr when HA is enabled")?;
            if replication.pull_interval_ms == 0 {
                bail!("ha.replication_pull_interval_ms must be greater than 0");
            }
            if replication.request_timeout_ms == 0 {
                bail!("ha.replication_request_timeout_ms must be greater than 0");
            }
        }
        Ok(())
    }

    pub fn persistence_config(&self) -> &PersistenceConfig {
        &self.persistence
    }

    pub fn persistence_config_path(&self) -> &'static str {
        "persistence"
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

fn validate_upstream_targets_do_not_loop_to_proxy(config: &Config) -> Result<()> {
    for configured_listener in &config.proxy.listeners {
        for listener in configured_listener.concrete_listeners() {
            let listener_groups =
                upstream_groups_used_by_listener(&config.proxy, configured_listener, &listener);
            let self_addrs = proxy_self_addrs_for_listener(&config.sip, &listener);
            if self_addrs.is_empty() {
                continue;
            }

            for group_name in listener_groups {
                let Some(group) = config
                    .proxy
                    .upstream_groups
                    .iter()
                    .find(|group| group.name == group_name)
                else {
                    continue;
                };
                for server in &group.servers {
                    let Ok(server_addr) = server.parse::<SocketAddr>() else {
                        continue;
                    };
                    if let Some((source, _)) = self_addrs
                        .iter()
                        .find(|(_, self_addr)| *self_addr == server_addr)
                    {
                        bail!(
                            "proxy upstream group '{}' server '{}' points back to this proxy listener '{}' via {}; use a real backend address to avoid SIP forwarding loops",
                            group.name,
                            server,
                            listener.key(),
                            source
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn upstream_groups_used_by_listener(
    proxy: &ProxyConfig,
    configured_listener: &ProxyListenerConfig,
    listener: &ProxyListenerConfig,
) -> HashSet<String> {
    let mut groups = HashSet::new();
    groups.insert(listener.upstream_group.clone());
    let configured_key = configured_listener.key();
    let listener_key = listener.key();
    for route in &proxy.routes {
        let applies = route.listener.as_ref().is_none_or(|route_listener| {
            route_listener == &listener_key || route_listener == &configured_key
        });
        if applies {
            groups.insert(route.upstream_group.clone());
        }
    }
    groups
}

fn proxy_self_addrs_for_listener(
    sip: &SipConfig,
    listener: &ProxyListenerConfig,
) -> Vec<(&'static str, SocketAddr)> {
    let default_port = listener_port(listener);
    let mut addrs = Vec::new();
    for (source, value) in [
        ("sip.external_addr", sip.external_addr.as_deref()),
        ("sip.public_addr", sip.public_addr.as_deref()),
        ("sip.internal_addr", sip.internal_addr.as_deref()),
    ] {
        if let Some(value) = value.and_then(|value| parse_ip_socket_addr(value, default_port)) {
            addrs.push((source, value));
        }
    }
    if let Ok(bind) = listener.bind.parse::<SocketAddr>()
        && !bind.ip().is_unspecified()
    {
        addrs.push(("listener.bind", bind));
    }
    addrs
}

fn parse_ip_socket_addr(value: &str, default_port: u16) -> Option<SocketAddr> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Some((host, port)) = split_host_port(value) {
        let ip = host.trim_matches(['[', ']']).parse::<IpAddr>().ok()?;
        let port = port.parse::<u16>().ok()?;
        return Some(SocketAddr::new(ip, port));
    }
    let ip = value.trim_matches(['[', ']']).parse::<IpAddr>().ok()?;
    Some(SocketAddr::new(ip, default_port))
}

fn listener_port(listener: &ProxyListenerConfig) -> u16 {
    listener
        .bind
        .parse::<SocketAddr>()
        .map(|addr| addr.port())
        .unwrap_or(5060)
}

fn validate_security_config(config: &ProxySecurityConfig, path: &str) -> Result<()> {
    for (name, cidrs) in [
        ("trusted_cidrs", config.trusted_cidrs.as_deref()),
        ("allow_cidrs", config.allow_cidrs.as_deref()),
        ("deny_cidrs", config.deny_cidrs.as_deref()),
    ] {
        if let Some(cidrs) = cidrs {
            for cidr in cidrs {
                validate_cidr(cidr).with_context(|| format!("{path}.{name} contains '{cidr}'"))?;
            }
        }
    }

    if config
        .prefilter
        .invalid_log_sample_per_minute
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.prefilter.invalid_log_sample_per_minute must be greater than 0 when set");
    }
    validate_geo_security_config(&config.geo, &format!("{path}.geo"))?;
    validate_threat_intel_security_config(&config.threat_intel, &format!("{path}.threat_intel"))?;
    validate_dynamic_ban_config(&config.dynamic_ban, &format!("{path}.dynamic_ban"))?;
    validate_flood_security_config(&config.flood, &format!("{path}.flood"))?;
    validate_xdp_security_config(&config.xdp, &format!("{path}.xdp"))?;

    if config
        .ip_rate_limit
        .packets_per_second
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.ip_rate_limit.packets_per_second must be greater than 0 when set");
    }
    if config.ip_rate_limit.burst.is_some_and(|value| value == 0) {
        bail!("{path}.ip_rate_limit.burst must be greater than 0 when set");
    }
    if config
        .ip_rate_limit
        .parse_errors_per_minute
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.ip_rate_limit.parse_errors_per_minute must be greater than 0 when set");
    }

    if config
        .sip_rate_limit
        .register_per_minute_per_aor
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.sip_rate_limit.register_per_minute_per_aor must be greater than 0 when set");
    }
    if config
        .sip_rate_limit
        .invite_per_minute_per_aor
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.sip_rate_limit.invite_per_minute_per_aor must be greater than 0 when set");
    }
    Ok(())
}

fn validate_xdp_security_config(config: &ProxyXdpSecurityConfig, path: &str) -> Result<()> {
    if let Some(interfaces) = config.interfaces.as_deref() {
        for interface in interfaces {
            if interface.trim().is_empty() {
                bail!("{path}.interfaces must not contain empty interface names");
            }
        }
    }
    if config
        .max_deny_cidrs_entries
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.max_deny_cidrs_entries must be greater than 0 when set");
    }
    if config.max_geo_cidrs_entries.is_some_and(|value| value == 0) {
        bail!("{path}.max_geo_cidrs_entries must be greater than 0 when set");
    }
    Ok(())
}

fn validate_geo_security_config(config: &ProxyGeoSecurityConfig, path: &str) -> Result<()> {
    if config
        .provider_base_url
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("{path}.provider_base_url must not be empty when set");
    }
    if config
        .cache_dir
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("{path}.cache_dir must not be empty when set");
    }
    if config
        .refresh_interval_seconds
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.refresh_interval_seconds must be greater than 0 when set");
    }
    if config
        .request_timeout_seconds
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.request_timeout_seconds must be greater than 0 when set");
    }
    if config.request_retries.is_some_and(|value| value == 0) {
        bail!("{path}.request_retries must be greater than 0 when set");
    }
    for (name, countries) in [
        ("allow.countries", config.allow.countries.as_deref()),
        ("deny.countries", config.deny.countries.as_deref()),
    ] {
        if let Some(countries) = countries {
            for country in countries {
                validate_country_code(country)
                    .with_context(|| format!("{path}.{name} contains '{country}'"))?;
            }
        }
    }
    Ok(())
}

fn validate_threat_intel_security_config(
    config: &ProxyThreatIntelSecurityConfig,
    path: &str,
) -> Result<()> {
    if config
        .cache_dir
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("{path}.cache_dir must not be empty when set");
    }
    if config
        .refresh_interval_seconds
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.refresh_interval_seconds must be greater than 0 when set");
    }
    if config
        .request_timeout_seconds
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.request_timeout_seconds must be greater than 0 when set");
    }
    if config.request_retries.is_some_and(|value| value == 0) {
        bail!("{path}.request_retries must be greater than 0 when set");
    }
    if let Some(sources) = &config.sources {
        for (index, source) in sources.iter().enumerate() {
            let source_path = format!("{path}.sources[{index}]");
            if source.name.trim().is_empty() {
                bail!("{source_path}.name must not be empty");
            }
            if source.url.trim().is_empty() {
                bail!("{source_path}.url must not be empty");
            }
            if source.min_score.is_some_and(|value| value == 0) {
                bail!("{source_path}.min_score must be greater than 0 when set");
            }
        }
    }
    Ok(())
}

fn validate_dynamic_ban_config(config: &ProxyDynamicBanConfig, path: &str) -> Result<()> {
    if config.ban_seconds.is_some_and(|value| value == 0) {
        bail!("{path}.ban_seconds must be greater than 0 when set");
    }
    if config
        .invalid_packets_per_minute
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.invalid_packets_per_minute must be greater than 0 when set");
    }
    if config
        .parse_errors_per_minute
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.parse_errors_per_minute must be greater than 0 when set");
    }
    if config
        .sip_rate_violations_per_minute
        .is_some_and(|value| value == 0)
    {
        bail!("{path}.sip_rate_violations_per_minute must be greater than 0 when set");
    }
    Ok(())
}

fn validate_flood_security_config(config: &ProxyFloodSecurityConfig, path: &str) -> Result<()> {
    for (field, value) in [
        ("udp_packets_per_second", config.udp_packets_per_second),
        ("udp_burst", config.udp_burst),
        ("tcp_packets_per_second", config.tcp_packets_per_second),
        ("tcp_burst", config.tcp_burst),
        (
            "tcp_syn_packets_per_second",
            config.tcp_syn_packets_per_second,
        ),
        ("tcp_syn_burst", config.tcp_syn_burst),
        (
            "tcp_ack_packets_per_second",
            config.tcp_ack_packets_per_second,
        ),
        ("tcp_ack_burst", config.tcp_ack_burst),
        ("icmp_packets_per_second", config.icmp_packets_per_second),
        ("icmp_burst", config.icmp_burst),
        ("block_seconds", config.block_seconds),
    ] {
        if value.is_some_and(|value| value == 0) {
            bail!("{path}.{field} must be greater than 0 when set");
        }
    }
    Ok(())
}

fn validate_country_code(value: &str) -> Result<()> {
    let value = value.trim();
    if value.len() != 2 || !value.chars().all(|ch| ch.is_ascii_alphabetic()) {
        bail!("country code must contain two ASCII letters");
    }
    Ok(())
}

fn normalize_country_codes(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim().to_ascii_uppercase())
        .collect()
}

fn default_geo_provider_base_url() -> String {
    "http://www.ipdeny.com/ipblocks/data/countries/{country}.zone".to_string()
}

fn default_geo_cache_dir() -> String {
    "/var/lib/sigproxy-rs/geo".to_string()
}

fn default_geo_refresh_interval_seconds() -> u64 {
    86_400
}

fn default_geo_request_timeout_seconds() -> u64 {
    10
}

fn default_geo_request_retries() -> u32 {
    3
}

fn default_geo_allow_partial() -> bool {
    true
}

fn default_threat_cache_dir() -> String {
    "/var/lib/sigproxy-rs/threat".to_string()
}

fn default_threat_refresh_interval_seconds() -> u64 {
    86_400
}

fn default_threat_request_timeout_seconds() -> u64 {
    10
}

fn default_threat_request_retries() -> u32 {
    3
}

fn default_threat_allow_partial() -> bool {
    true
}

fn default_threat_sources() -> Vec<EffectiveProxyThreatIntelSourceConfig> {
    vec![
        EffectiveProxyThreatIntelSourceConfig {
            name: "ipsum".to_string(),
            url: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt".to_string(),
            format: ProxyThreatIntelFormat::Ipsum,
            min_score: Some(3),
        },
        EffectiveProxyThreatIntelSourceConfig {
            name: "spamhaus-drop".to_string(),
            url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
            format: ProxyThreatIntelFormat::SpamhausDrop,
            min_score: None,
        },
    ]
}

fn validate_cidr(value: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() {
        bail!("CIDR must not be empty");
    }
    let Some((addr, prefix)) = value.split_once('/') else {
        value.parse::<IpAddr>().context("invalid IP address")?;
        return Ok(());
    };
    let addr = addr.parse::<IpAddr>().context("invalid IP address")?;
    let prefix = prefix.parse::<u8>().context("invalid CIDR prefix")?;
    let max_prefix = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        bail!("CIDR prefix must be at most {max_prefix}");
    }
    Ok(())
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
    pub security: ProxySecurityConfig,
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
            security: ProxySecurityConfig::default(),
            listeners: vec![ProxyListenerConfig {
                bind: "0.0.0.0:5060".to_string(),
                transport: SipTransport::Udp,
                upstream_group: "default".to_string(),
                security: None,
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
        self.register_routing.unwrap_or({
            if self.rewrite_register_contact {
                RegisterRoutingMode::ContactRewrite
            } else {
                RegisterRoutingMode::Path
            }
        })
    }

    pub fn effective_security_for_listener(
        &self,
        listener: &ProxyListenerConfig,
    ) -> EffectiveProxySecurityConfig {
        let mut effective = EffectiveProxySecurityConfig::default_security();
        self.security.apply_to_effective(&mut effective);
        if let Some(security) = &listener.security {
            security.apply_to_effective(&mut effective);
        }
        effective
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxySecurityConfig {
    #[serde(default)]
    pub preset: Option<ProxySecurityPreset>,
    #[serde(default)]
    pub trusted_cidrs: Option<Vec<String>>,
    #[serde(default)]
    pub allow_cidrs: Option<Vec<String>>,
    #[serde(default)]
    pub deny_cidrs: Option<Vec<String>>,
    #[serde(default)]
    pub prefilter: ProxySecurityPrefilterConfig,
    #[serde(default)]
    pub geo: ProxyGeoSecurityConfig,
    #[serde(default)]
    pub threat_intel: ProxyThreatIntelSecurityConfig,
    #[serde(default)]
    pub dynamic_ban: ProxyDynamicBanConfig,
    #[serde(default)]
    pub flood: ProxyFloodSecurityConfig,
    #[serde(default)]
    pub ip_rate_limit: ProxyIpRateLimitConfig,
    #[serde(default)]
    pub sip_rate_limit: ProxySipRateLimitConfig,
    #[serde(default)]
    pub sip_policy: ProxySipPolicyConfig,
    #[serde(default)]
    pub xdp: ProxyXdpSecurityConfig,
}

impl ProxySecurityConfig {
    fn apply_to_effective(&self, effective: &mut EffectiveProxySecurityConfig) {
        if let Some(preset) = self.preset {
            *effective = EffectiveProxySecurityConfig::for_preset(preset);
        }
        if let Some(trusted_cidrs) = &self.trusted_cidrs {
            effective.trusted_cidrs = trusted_cidrs.clone();
        }
        if let Some(allow_cidrs) = &self.allow_cidrs {
            effective.allow_cidrs = allow_cidrs.clone();
        }
        if let Some(deny_cidrs) = &self.deny_cidrs {
            effective.deny_cidrs = deny_cidrs.clone();
        }
        self.prefilter.apply_to_effective(&mut effective.prefilter);
        self.geo.apply_to_effective(&mut effective.geo);
        self.threat_intel
            .apply_to_effective(&mut effective.threat_intel);
        self.dynamic_ban
            .apply_to_effective(&mut effective.dynamic_ban);
        self.flood.apply_to_effective(&mut effective.flood);
        self.ip_rate_limit
            .apply_to_effective(&mut effective.ip_rate_limit);
        self.sip_rate_limit
            .apply_to_effective(&mut effective.sip_rate_limit);
        self.sip_policy
            .apply_to_effective(&mut effective.sip_policy);
        self.xdp.apply_to_effective(&mut effective.xdp);
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyGeoSecurityConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub provider: Option<ProxyGeoProvider>,
    #[serde(default)]
    pub provider_base_url: Option<String>,
    #[serde(default)]
    pub cache_dir: Option<String>,
    #[serde(default)]
    pub refresh_interval_seconds: Option<u64>,
    #[serde(default)]
    pub startup_refresh: Option<ProxyGeoStartupRefresh>,
    #[serde(default)]
    pub fail_open: Option<bool>,
    #[serde(default)]
    pub unknown_country: Option<ProxyGeoUnknownCountryPolicy>,
    #[serde(default)]
    pub request_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub request_retries: Option<u32>,
    #[serde(default)]
    pub allow_partial: Option<bool>,
    #[serde(default)]
    pub allow: ProxyGeoCountryListConfig,
    #[serde(default)]
    pub deny: ProxyGeoCountryListConfig,
}

impl ProxyGeoSecurityConfig {
    fn apply_to_effective(&self, effective: &mut EffectiveProxyGeoSecurityConfig) {
        if let Some(enabled) = self.enabled {
            effective.enabled = enabled;
        }
        if let Some(provider) = self.provider {
            effective.provider = provider;
        }
        if let Some(provider_base_url) = &self.provider_base_url {
            effective.provider_base_url = provider_base_url.clone();
        }
        if let Some(cache_dir) = &self.cache_dir {
            effective.cache_dir = cache_dir.clone();
        }
        if let Some(refresh_interval_seconds) = self.refresh_interval_seconds {
            effective.refresh_interval_seconds = refresh_interval_seconds;
        }
        if let Some(startup_refresh) = self.startup_refresh {
            effective.startup_refresh = startup_refresh;
        }
        if let Some(fail_open) = self.fail_open {
            effective.fail_open = fail_open;
        }
        if let Some(unknown_country) = self.unknown_country {
            effective.unknown_country = unknown_country;
        }
        if let Some(request_timeout_seconds) = self.request_timeout_seconds {
            effective.request_timeout_seconds = request_timeout_seconds;
        }
        if let Some(request_retries) = self.request_retries {
            effective.request_retries = request_retries;
        }
        if let Some(allow_partial) = self.allow_partial {
            effective.allow_partial = allow_partial;
        }
        if let Some(countries) = &self.allow.countries {
            effective.allow_countries = normalize_country_codes(countries);
        }
        if let Some(countries) = &self.deny.countries {
            effective.deny_countries = normalize_country_codes(countries);
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyThreatIntelSecurityConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub cache_dir: Option<String>,
    #[serde(default)]
    pub refresh_interval_seconds: Option<u64>,
    #[serde(default)]
    pub startup_refresh: Option<ProxyGeoStartupRefresh>,
    #[serde(default)]
    pub fail_open: Option<bool>,
    #[serde(default)]
    pub request_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub request_retries: Option<u32>,
    #[serde(default)]
    pub allow_partial: Option<bool>,
    #[serde(default)]
    pub sources: Option<Vec<ProxyThreatIntelSourceConfig>>,
}

impl ProxyThreatIntelSecurityConfig {
    fn apply_to_effective(&self, effective: &mut EffectiveProxyThreatIntelSecurityConfig) {
        if let Some(enabled) = self.enabled {
            effective.enabled = enabled;
        }
        if let Some(cache_dir) = &self.cache_dir {
            effective.cache_dir = cache_dir.clone();
        }
        if let Some(refresh_interval_seconds) = self.refresh_interval_seconds {
            effective.refresh_interval_seconds = refresh_interval_seconds;
        }
        if let Some(startup_refresh) = self.startup_refresh {
            effective.startup_refresh = startup_refresh;
        }
        if let Some(fail_open) = self.fail_open {
            effective.fail_open = fail_open;
        }
        if let Some(request_timeout_seconds) = self.request_timeout_seconds {
            effective.request_timeout_seconds = request_timeout_seconds;
        }
        if let Some(request_retries) = self.request_retries {
            effective.request_retries = request_retries;
        }
        if let Some(allow_partial) = self.allow_partial {
            effective.allow_partial = allow_partial;
        }
        if let Some(sources) = &self.sources {
            effective.sources = sources
                .iter()
                .filter(|source| source.enabled.unwrap_or(true))
                .map(EffectiveProxyThreatIntelSourceConfig::from_config)
                .collect();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyThreatIntelSourceConfig {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub format: ProxyThreatIntelFormat,
    #[serde(default)]
    pub min_score: Option<u32>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyThreatIntelFormat {
    #[default]
    Cidr,
    Ips,
    Ipsum,
    SpamhausDrop,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyGeoCountryListConfig {
    #[serde(default)]
    pub countries: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyGeoProvider {
    #[default]
    Ipdeny,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyGeoStartupRefresh {
    Blocking,
    Background,
    #[default]
    Disabled,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyGeoUnknownCountryPolicy {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyDynamicBanConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub ban_seconds: Option<u64>,
    #[serde(default)]
    pub invalid_packets_per_minute: Option<u64>,
    #[serde(default)]
    pub parse_errors_per_minute: Option<u64>,
    #[serde(default)]
    pub sip_rate_violations_per_minute: Option<u64>,
}

impl ProxyDynamicBanConfig {
    fn apply_to_effective(&self, effective: &mut EffectiveProxyDynamicBanConfig) {
        if let Some(enabled) = self.enabled {
            effective.enabled = enabled;
        }
        if let Some(ban_seconds) = self.ban_seconds {
            effective.ban_seconds = ban_seconds;
        }
        if let Some(invalid_packets_per_minute) = self.invalid_packets_per_minute {
            effective.invalid_packets_per_minute = invalid_packets_per_minute;
        }
        if let Some(parse_errors_per_minute) = self.parse_errors_per_minute {
            effective.parse_errors_per_minute = parse_errors_per_minute;
        }
        if let Some(sip_rate_violations_per_minute) = self.sip_rate_violations_per_minute {
            effective.sip_rate_violations_per_minute = sip_rate_violations_per_minute;
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyFloodSecurityConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub udp_packets_per_second: Option<u64>,
    #[serde(default)]
    pub udp_burst: Option<u64>,
    #[serde(default)]
    pub tcp_packets_per_second: Option<u64>,
    #[serde(default)]
    pub tcp_burst: Option<u64>,
    #[serde(default)]
    pub tcp_syn_packets_per_second: Option<u64>,
    #[serde(default)]
    pub tcp_syn_burst: Option<u64>,
    #[serde(default)]
    pub tcp_ack_packets_per_second: Option<u64>,
    #[serde(default)]
    pub tcp_ack_burst: Option<u64>,
    #[serde(default)]
    pub icmp_packets_per_second: Option<u64>,
    #[serde(default)]
    pub icmp_burst: Option<u64>,
    #[serde(default)]
    pub block_seconds: Option<u64>,
}

impl ProxyFloodSecurityConfig {
    fn apply_to_effective(&self, effective: &mut EffectiveProxyFloodSecurityConfig) {
        if let Some(enabled) = self.enabled {
            effective.enabled = enabled;
        }
        if let Some(udp_packets_per_second) = self.udp_packets_per_second {
            effective.udp_packets_per_second = udp_packets_per_second;
        }
        if let Some(udp_burst) = self.udp_burst {
            effective.udp_burst = udp_burst;
        }
        if let Some(tcp_packets_per_second) = self.tcp_packets_per_second {
            effective.tcp_packets_per_second = tcp_packets_per_second;
        }
        if let Some(tcp_burst) = self.tcp_burst {
            effective.tcp_burst = tcp_burst;
        }
        if let Some(tcp_syn_packets_per_second) = self.tcp_syn_packets_per_second {
            effective.tcp_syn_packets_per_second = tcp_syn_packets_per_second;
        }
        if let Some(tcp_syn_burst) = self.tcp_syn_burst {
            effective.tcp_syn_burst = tcp_syn_burst;
        }
        if let Some(tcp_ack_packets_per_second) = self.tcp_ack_packets_per_second {
            effective.tcp_ack_packets_per_second = tcp_ack_packets_per_second;
        }
        if let Some(tcp_ack_burst) = self.tcp_ack_burst {
            effective.tcp_ack_burst = tcp_ack_burst;
        }
        if let Some(icmp_packets_per_second) = self.icmp_packets_per_second {
            effective.icmp_packets_per_second = icmp_packets_per_second;
        }
        if let Some(icmp_burst) = self.icmp_burst {
            effective.icmp_burst = icmp_burst;
        }
        if let Some(block_seconds) = self.block_seconds {
            effective.block_seconds = block_seconds;
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxySecurityPreset {
    #[default]
    Off,
    Trusted,
    Public,
    Strict,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxySecurityPrefilterConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub drop_invalid_start_line: Option<bool>,
    #[serde(default)]
    pub drop_non_sip_methods: Option<bool>,
    #[serde(default)]
    pub log_invalid_packets: Option<bool>,
    #[serde(default)]
    pub invalid_log_sample_per_minute: Option<u64>,
}

impl ProxySecurityPrefilterConfig {
    fn apply_to_effective(&self, effective: &mut EffectiveProxySecurityPrefilterConfig) {
        if let Some(enabled) = self.enabled {
            effective.enabled = enabled;
        }
        if let Some(drop_invalid_start_line) = self.drop_invalid_start_line {
            effective.drop_invalid_start_line = drop_invalid_start_line;
        }
        if let Some(drop_non_sip_methods) = self.drop_non_sip_methods {
            effective.drop_non_sip_methods = drop_non_sip_methods;
        }
        if let Some(log_invalid_packets) = self.log_invalid_packets {
            effective.log_invalid_packets = log_invalid_packets;
        }
        if let Some(invalid_log_sample_per_minute) = self.invalid_log_sample_per_minute {
            effective.invalid_log_sample_per_minute = invalid_log_sample_per_minute;
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyIpRateLimitConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub packets_per_second: Option<u64>,
    #[serde(default)]
    pub burst: Option<u64>,
    #[serde(default)]
    pub parse_errors_per_minute: Option<u64>,
    #[serde(default)]
    pub block_seconds: Option<u64>,
}

impl ProxyIpRateLimitConfig {
    fn apply_to_effective(&self, effective: &mut EffectiveProxyIpRateLimitConfig) {
        if let Some(enabled) = self.enabled {
            effective.enabled = enabled;
        }
        if let Some(packets_per_second) = self.packets_per_second {
            effective.packets_per_second = packets_per_second;
        }
        if let Some(burst) = self.burst {
            effective.burst = burst;
        }
        if let Some(parse_errors_per_minute) = self.parse_errors_per_minute {
            effective.parse_errors_per_minute = parse_errors_per_minute;
        }
        if let Some(block_seconds) = self.block_seconds {
            effective.block_seconds = block_seconds;
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxySipRateLimitConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub register_per_minute_per_aor: Option<u64>,
    #[serde(default)]
    pub invite_per_minute_per_aor: Option<u64>,
    #[serde(default)]
    pub block_seconds: Option<u64>,
}

impl ProxySipRateLimitConfig {
    fn apply_to_effective(&self, effective: &mut EffectiveProxySipRateLimitConfig) {
        if let Some(enabled) = self.enabled {
            effective.enabled = enabled;
        }
        if let Some(register_per_minute_per_aor) = self.register_per_minute_per_aor {
            effective.register_per_minute_per_aor = register_per_minute_per_aor;
        }
        if let Some(invite_per_minute_per_aor) = self.invite_per_minute_per_aor {
            effective.invite_per_minute_per_aor = invite_per_minute_per_aor;
        }
        if let Some(block_seconds) = self.block_seconds {
            effective.block_seconds = block_seconds;
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxySipPolicyConfig {
    #[serde(default)]
    pub require_registered_invite_source: Option<bool>,
    #[serde(default)]
    pub registered_invite_source_match: Option<ProxyRegisteredInviteSourceMatch>,
}

impl ProxySipPolicyConfig {
    fn apply_to_effective(&self, effective: &mut EffectiveProxySipPolicyConfig) {
        if let Some(require_registered_invite_source) = self.require_registered_invite_source {
            effective.require_registered_invite_source = require_registered_invite_source;
        }
        if let Some(registered_invite_source_match) = self.registered_invite_source_match {
            effective.registered_invite_source_match = registered_invite_source_match;
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyRegisteredInviteSourceMatch {
    #[default]
    Ip,
    IpPort,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyXdpSecurityConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub interfaces: Option<Vec<String>>,
    #[serde(default)]
    pub detach_stale: Option<bool>,
    #[serde(default)]
    pub fail_open: Option<bool>,
    #[serde(default)]
    pub sync_dynamic_ban: Option<bool>,
    #[serde(default)]
    pub cidr_filter: Option<bool>,
    #[serde(default)]
    pub geo_filter: Option<bool>,
    #[serde(default)]
    pub threat_intel: Option<bool>,
    #[serde(default)]
    pub ip_rate_limit: Option<bool>,
    #[serde(default)]
    pub auto_size_maps: Option<bool>,
    #[serde(default)]
    pub max_deny_cidrs_entries: Option<u32>,
    #[serde(default)]
    pub max_geo_cidrs_entries: Option<u32>,
}

impl ProxyXdpSecurityConfig {
    fn apply_to_effective(&self, effective: &mut EffectiveProxyXdpSecurityConfig) {
        if let Some(enabled) = self.enabled {
            effective.enabled = enabled;
        }
        if let Some(interfaces) = &self.interfaces {
            effective.interfaces = interfaces.clone();
        }
        if let Some(detach_stale) = self.detach_stale {
            effective.detach_stale = detach_stale;
        }
        if let Some(fail_open) = self.fail_open {
            effective.fail_open = fail_open;
        }
        if let Some(sync_dynamic_ban) = self.sync_dynamic_ban {
            effective.sync_dynamic_ban = sync_dynamic_ban;
        }
        if let Some(cidr_filter) = self.cidr_filter {
            effective.cidr_filter = cidr_filter;
        }
        if let Some(geo_filter) = self.geo_filter {
            effective.geo_filter = geo_filter;
        }
        if let Some(threat_intel) = self.threat_intel {
            effective.threat_intel = threat_intel;
        }
        if let Some(ip_rate_limit) = self.ip_rate_limit {
            effective.ip_rate_limit = ip_rate_limit;
        }
        if let Some(auto_size_maps) = self.auto_size_maps {
            effective.auto_size_maps = auto_size_maps;
        }
        if let Some(max_deny_cidrs_entries) = self.max_deny_cidrs_entries {
            effective.max_deny_cidrs_entries = max_deny_cidrs_entries;
        }
        if let Some(max_geo_cidrs_entries) = self.max_geo_cidrs_entries {
            effective.max_geo_cidrs_entries = max_geo_cidrs_entries;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveProxySecurityConfig {
    pub preset: ProxySecurityPreset,
    pub trusted_cidrs: Vec<String>,
    pub allow_cidrs: Vec<String>,
    pub deny_cidrs: Vec<String>,
    pub prefilter: EffectiveProxySecurityPrefilterConfig,
    pub geo: EffectiveProxyGeoSecurityConfig,
    pub threat_intel: EffectiveProxyThreatIntelSecurityConfig,
    pub dynamic_ban: EffectiveProxyDynamicBanConfig,
    pub flood: EffectiveProxyFloodSecurityConfig,
    pub ip_rate_limit: EffectiveProxyIpRateLimitConfig,
    pub sip_rate_limit: EffectiveProxySipRateLimitConfig,
    pub sip_policy: EffectiveProxySipPolicyConfig,
    pub xdp: EffectiveProxyXdpSecurityConfig,
}

impl EffectiveProxySecurityConfig {
    pub fn enabled(&self) -> bool {
        self.prefilter.enabled
            || self.geo.enabled
            || self.threat_intel.enabled
            || self.dynamic_ban.enabled
            || self.flood.enabled
            || self.ip_rate_limit.enabled
            || self.sip_rate_limit.enabled
            || self.sip_policy.require_registered_invite_source
    }

    pub fn for_preset(preset: ProxySecurityPreset) -> Self {
        match preset {
            ProxySecurityPreset::Off => Self {
                preset,
                trusted_cidrs: Vec::new(),
                allow_cidrs: Vec::new(),
                deny_cidrs: Vec::new(),
                prefilter: EffectiveProxySecurityPrefilterConfig {
                    enabled: false,
                    drop_invalid_start_line: false,
                    drop_non_sip_methods: false,
                    log_invalid_packets: true,
                    invalid_log_sample_per_minute: 10,
                },
                geo: EffectiveProxyGeoSecurityConfig::default(),
                threat_intel: EffectiveProxyThreatIntelSecurityConfig::default(),
                dynamic_ban: EffectiveProxyDynamicBanConfig::default(),
                flood: EffectiveProxyFloodSecurityConfig::default(),
                ip_rate_limit: EffectiveProxyIpRateLimitConfig {
                    enabled: false,
                    packets_per_second: 0,
                    burst: 0,
                    parse_errors_per_minute: 0,
                    block_seconds: 0,
                },
                sip_rate_limit: EffectiveProxySipRateLimitConfig {
                    enabled: false,
                    register_per_minute_per_aor: 0,
                    invite_per_minute_per_aor: 0,
                    block_seconds: 0,
                },
                sip_policy: EffectiveProxySipPolicyConfig::default(),
                xdp: EffectiveProxyXdpSecurityConfig::default(),
            },
            ProxySecurityPreset::Trusted => Self {
                preset,
                trusted_cidrs: Vec::new(),
                allow_cidrs: Vec::new(),
                deny_cidrs: Vec::new(),
                prefilter: EffectiveProxySecurityPrefilterConfig {
                    enabled: true,
                    drop_invalid_start_line: true,
                    drop_non_sip_methods: true,
                    log_invalid_packets: true,
                    invalid_log_sample_per_minute: 20,
                },
                geo: EffectiveProxyGeoSecurityConfig::default(),
                threat_intel: EffectiveProxyThreatIntelSecurityConfig::default(),
                dynamic_ban: EffectiveProxyDynamicBanConfig {
                    enabled: true,
                    ban_seconds: 60,
                    invalid_packets_per_minute: 60,
                    parse_errors_per_minute: 60,
                    sip_rate_violations_per_minute: 30,
                },
                flood: EffectiveProxyFloodSecurityConfig::default(),
                ip_rate_limit: EffectiveProxyIpRateLimitConfig {
                    enabled: true,
                    packets_per_second: 200,
                    burst: 400,
                    parse_errors_per_minute: 60,
                    block_seconds: 60,
                },
                sip_rate_limit: EffectiveProxySipRateLimitConfig {
                    enabled: true,
                    register_per_minute_per_aor: 60,
                    invite_per_minute_per_aor: 120,
                    block_seconds: 60,
                },
                sip_policy: EffectiveProxySipPolicyConfig::default(),
                xdp: EffectiveProxyXdpSecurityConfig::default(),
            },
            ProxySecurityPreset::Public => Self {
                preset,
                trusted_cidrs: Vec::new(),
                allow_cidrs: Vec::new(),
                deny_cidrs: Vec::new(),
                prefilter: EffectiveProxySecurityPrefilterConfig {
                    enabled: true,
                    drop_invalid_start_line: true,
                    drop_non_sip_methods: true,
                    log_invalid_packets: true,
                    invalid_log_sample_per_minute: 10,
                },
                geo: EffectiveProxyGeoSecurityConfig::default(),
                threat_intel: EffectiveProxyThreatIntelSecurityConfig::default(),
                dynamic_ban: EffectiveProxyDynamicBanConfig {
                    enabled: true,
                    ban_seconds: 300,
                    invalid_packets_per_minute: 30,
                    parse_errors_per_minute: 20,
                    sip_rate_violations_per_minute: 10,
                },
                flood: EffectiveProxyFloodSecurityConfig::default(),
                ip_rate_limit: EffectiveProxyIpRateLimitConfig {
                    enabled: true,
                    packets_per_second: 50,
                    burst: 100,
                    parse_errors_per_minute: 20,
                    block_seconds: 300,
                },
                sip_rate_limit: EffectiveProxySipRateLimitConfig {
                    enabled: true,
                    register_per_minute_per_aor: 20,
                    invite_per_minute_per_aor: 60,
                    block_seconds: 300,
                },
                sip_policy: EffectiveProxySipPolicyConfig::default(),
                xdp: EffectiveProxyXdpSecurityConfig::default(),
            },
            ProxySecurityPreset::Strict => Self {
                preset,
                trusted_cidrs: Vec::new(),
                allow_cidrs: Vec::new(),
                deny_cidrs: Vec::new(),
                prefilter: EffectiveProxySecurityPrefilterConfig {
                    enabled: true,
                    drop_invalid_start_line: true,
                    drop_non_sip_methods: true,
                    log_invalid_packets: true,
                    invalid_log_sample_per_minute: 5,
                },
                geo: EffectiveProxyGeoSecurityConfig::default(),
                threat_intel: EffectiveProxyThreatIntelSecurityConfig::default(),
                dynamic_ban: EffectiveProxyDynamicBanConfig {
                    enabled: true,
                    ban_seconds: 900,
                    invalid_packets_per_minute: 10,
                    parse_errors_per_minute: 5,
                    sip_rate_violations_per_minute: 5,
                },
                flood: EffectiveProxyFloodSecurityConfig::default(),
                ip_rate_limit: EffectiveProxyIpRateLimitConfig {
                    enabled: true,
                    packets_per_second: 15,
                    burst: 30,
                    parse_errors_per_minute: 5,
                    block_seconds: 900,
                },
                sip_rate_limit: EffectiveProxySipRateLimitConfig {
                    enabled: true,
                    register_per_minute_per_aor: 10,
                    invite_per_minute_per_aor: 30,
                    block_seconds: 900,
                },
                sip_policy: EffectiveProxySipPolicyConfig::default(),
                xdp: EffectiveProxyXdpSecurityConfig::default(),
            },
        }
    }

    pub fn default_security() -> Self {
        let mut config = Self::for_preset(ProxySecurityPreset::Off);
        config.dynamic_ban = EffectiveProxyDynamicBanConfig {
            enabled: true,
            ban_seconds: 3600,
            invalid_packets_per_minute: 30,
            parse_errors_per_minute: 20,
            sip_rate_violations_per_minute: 10,
        };
        config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveProxyXdpSecurityConfig {
    pub enabled: bool,
    pub interfaces: Vec<String>,
    pub detach_stale: bool,
    pub fail_open: bool,
    pub sync_dynamic_ban: bool,
    pub cidr_filter: bool,
    pub geo_filter: bool,
    pub threat_intel: bool,
    pub ip_rate_limit: bool,
    pub auto_size_maps: bool,
    pub max_deny_cidrs_entries: u32,
    pub max_geo_cidrs_entries: u32,
}

impl Default for EffectiveProxyXdpSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: Vec::new(),
            detach_stale: true,
            fail_open: true,
            sync_dynamic_ban: true,
            cidr_filter: true,
            geo_filter: true,
            threat_intel: true,
            ip_rate_limit: true,
            auto_size_maps: true,
            max_deny_cidrs_entries: 262_144,
            max_geo_cidrs_entries: 1_048_576,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveProxyThreatIntelSecurityConfig {
    pub enabled: bool,
    pub cache_dir: String,
    pub refresh_interval_seconds: u64,
    pub startup_refresh: ProxyGeoStartupRefresh,
    pub fail_open: bool,
    pub request_timeout_seconds: u64,
    pub request_retries: u32,
    pub allow_partial: bool,
    pub sources: Vec<EffectiveProxyThreatIntelSourceConfig>,
}

impl Default for EffectiveProxyThreatIntelSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cache_dir: default_threat_cache_dir(),
            refresh_interval_seconds: default_threat_refresh_interval_seconds(),
            startup_refresh: ProxyGeoStartupRefresh::default(),
            fail_open: true,
            request_timeout_seconds: default_threat_request_timeout_seconds(),
            request_retries: default_threat_request_retries(),
            allow_partial: default_threat_allow_partial(),
            sources: default_threat_sources(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EffectiveProxyThreatIntelSourceConfig {
    pub name: String,
    pub url: String,
    pub format: ProxyThreatIntelFormat,
    pub min_score: Option<u32>,
}

impl EffectiveProxyThreatIntelSourceConfig {
    fn from_config(config: &ProxyThreatIntelSourceConfig) -> Self {
        Self {
            name: config.name.trim().to_string(),
            url: config.url.trim().to_string(),
            format: config.format,
            min_score: config.min_score,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveProxyGeoSecurityConfig {
    pub enabled: bool,
    pub provider: ProxyGeoProvider,
    pub provider_base_url: String,
    pub cache_dir: String,
    pub refresh_interval_seconds: u64,
    pub startup_refresh: ProxyGeoStartupRefresh,
    pub fail_open: bool,
    pub unknown_country: ProxyGeoUnknownCountryPolicy,
    pub request_timeout_seconds: u64,
    pub request_retries: u32,
    pub allow_partial: bool,
    pub allow_countries: Vec<String>,
    pub deny_countries: Vec<String>,
}

impl Default for EffectiveProxyGeoSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: ProxyGeoProvider::default(),
            provider_base_url: default_geo_provider_base_url(),
            cache_dir: default_geo_cache_dir(),
            refresh_interval_seconds: default_geo_refresh_interval_seconds(),
            startup_refresh: ProxyGeoStartupRefresh::default(),
            fail_open: true,
            unknown_country: ProxyGeoUnknownCountryPolicy::default(),
            request_timeout_seconds: default_geo_request_timeout_seconds(),
            request_retries: default_geo_request_retries(),
            allow_partial: default_geo_allow_partial(),
            allow_countries: Vec::new(),
            deny_countries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveProxyDynamicBanConfig {
    pub enabled: bool,
    pub ban_seconds: u64,
    pub invalid_packets_per_minute: u64,
    pub parse_errors_per_minute: u64,
    pub sip_rate_violations_per_minute: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveProxyFloodSecurityConfig {
    pub enabled: bool,
    pub udp_packets_per_second: u64,
    pub udp_burst: u64,
    pub tcp_packets_per_second: u64,
    pub tcp_burst: u64,
    pub tcp_syn_packets_per_second: u64,
    pub tcp_syn_burst: u64,
    pub tcp_ack_packets_per_second: u64,
    pub tcp_ack_burst: u64,
    pub icmp_packets_per_second: u64,
    pub icmp_burst: u64,
    pub block_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveProxySecurityPrefilterConfig {
    pub enabled: bool,
    pub drop_invalid_start_line: bool,
    pub drop_non_sip_methods: bool,
    pub log_invalid_packets: bool,
    pub invalid_log_sample_per_minute: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveProxyIpRateLimitConfig {
    pub enabled: bool,
    pub packets_per_second: u64,
    pub burst: u64,
    pub parse_errors_per_minute: u64,
    pub block_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveProxySipRateLimitConfig {
    pub enabled: bool,
    pub register_per_minute_per_aor: u64,
    pub invite_per_minute_per_aor: u64,
    pub block_seconds: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveProxySipPolicyConfig {
    pub require_registered_invite_source: bool,
    pub registered_invite_source_match: ProxyRegisteredInviteSourceMatch,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegisterRoutingMode {
    #[default]
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

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyAffinityKey {
    #[default]
    DialogId,
    CallId,
    RequestUri,
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

impl ProxySocketConfig {
    pub fn resolved_workers_per_listener(&self) -> usize {
        if self.workers_per_listener == 0 {
            std::thread::available_parallelism().map_or(1, usize::from)
        } else {
            self.workers_per_listener
        }
    }
}

fn default_workers_per_listener() -> usize {
    1
}

fn default_tcp_nodelay() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SipTransport {
    #[default]
    Udp,
    Tcp,
    #[serde(rename = "tcp_udp", alias = "tcp-udp")]
    TcpUdp,
}

impl SipTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::TcpUdp => "tcp_udp",
        }
    }

    pub fn sip_via_token(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::TcpUdp => "TCP_UDP",
        }
    }

    pub fn concrete_transports(self) -> &'static [SipTransport] {
        match self {
            Self::Udp => &[Self::Udp],
            Self::Tcp => &[Self::Tcp],
            Self::TcpUdp => &[Self::Udp, Self::Tcp],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyListenerConfig {
    pub bind: String,
    pub transport: SipTransport,
    pub upstream_group: String,
    #[serde(default)]
    pub security: Option<ProxySecurityConfig>,
}

impl ProxyListenerConfig {
    pub fn key(&self) -> String {
        format!("{}/{}", self.transport.as_str(), self.bind)
    }

    pub fn with_transport(&self, transport: SipTransport) -> Self {
        let mut listener = self.clone();
        listener.transport = transport;
        listener
    }

    pub fn concrete_listeners(&self) -> Vec<Self> {
        self.transport
            .concrete_transports()
            .iter()
            .map(|transport| self.with_transport(*transport))
            .collect()
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

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamMode {
    #[default]
    RoundRobin,
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
        #[serde(default)]
        vary_call_id: bool,
    },
    TcpConnect,
}

impl Default for UpstreamHealthProbeConfig {
    fn default() -> Self {
        Self::Options {
            transport: SipTransport::Udp,
            uri: default_health_options_uri(),
            success_codes: default_health_success_codes(),
            vary_call_id: false,
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
#[serde(deny_unknown_fields)]
pub struct HaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ha_leader_check_interval_ms")]
    pub leader_check_interval_ms: u64,
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
    #[serde(default = "default_ha_replication_bind")]
    pub replication_bind_addr: String,
    #[serde(default)]
    pub peer_replication_addr: Option<String>,
    #[serde(default = "default_ha_replication_pull_interval_ms")]
    pub replication_pull_interval_ms: u64,
    #[serde(default = "default_ha_replication_request_timeout_ms")]
    pub replication_request_timeout_ms: u64,
    #[serde(default)]
    pub addon: HaAddonConfig,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            leader_check_interval_ms: default_ha_leader_check_interval_ms(),
            initial_role: HaInitialRole::default(),
            heartbeat_bind: default_ha_heartbeat_bind(),
            peer_heartbeat_addr: None,
            heartbeat_interval_ms: default_ha_heartbeat_interval_ms(),
            failover_timeout_ms: default_ha_failover_timeout_ms(),
            replication_bind_addr: default_ha_replication_bind(),
            peer_replication_addr: None,
            replication_pull_interval_ms: default_ha_replication_pull_interval_ms(),
            replication_request_timeout_ms: default_ha_replication_request_timeout_ms(),
            addon: HaAddonConfig::Noop,
        }
    }
}

impl HaConfig {
    pub fn active_standby_config(&self) -> HaActiveStandbyConfig {
        HaActiveStandbyConfig {
            enabled: self.enabled,
            initial_role: self.initial_role,
            heartbeat_bind: self.heartbeat_bind.clone(),
            peer_heartbeat_addr: self.peer_heartbeat_addr.clone(),
            heartbeat_interval_ms: self.heartbeat_interval_ms,
            failover_timeout_ms: self.failover_timeout_ms,
        }
    }

    pub fn replication_config(&self) -> HaReplicationConfig {
        HaReplicationConfig {
            enabled: self.enabled,
            bind_addr: self.replication_bind_addr.clone(),
            peer_addr: self.peer_replication_addr.clone(),
            pull_interval_ms: self.replication_pull_interval_ms,
            request_timeout_ms: self.replication_request_timeout_ms,
        }
    }
}

fn default_ha_leader_check_interval_ms() -> u64 {
    1_000
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistenceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_persistence_path")]
    pub path: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "default_persistence_event_retention_seconds")]
    pub event_retention_seconds: u64,
    #[serde(default = "default_persistence_cleanup_interval_ms")]
    pub cleanup_interval_ms: u64,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_persistence_path(),
            required: false,
            event_retention_seconds: default_persistence_event_retention_seconds(),
            cleanup_interval_ms: default_persistence_cleanup_interval_ms(),
        }
    }
}

fn default_persistence_path() -> String {
    "/var/lib/sigproxy-rs/ha/state.db".to_string()
}

fn default_persistence_event_retention_seconds() -> u64 {
    3_600
}

fn default_persistence_cleanup_interval_ms() -> u64 {
    60_000
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

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HaInitialRole {
    Active,
    #[default]
    Standby,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum HaAddonConfig {
    #[default]
    Noop,
    Command {
        on_become_leader: Option<String>,
        on_step_down: Option<String>,
        #[serde(default = "default_command_timeout_ms")]
        timeout_ms: u64,
    },
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

[proxy.security]
# Off by default unless configured. Presets: "off", "trusted", "public", "strict".
preset = "off"

[persistence]
enabled = false
path = "/var/lib/sigproxy-rs/ha/state.db"
required = false
event_retention_seconds = 3600
cleanup_interval_ms = 60000

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
    fn parses_top_level_persistence_config() {
        let config: Config = toml::from_str(
            r#"
[persistence]
enabled = true
path = "/tmp/sigproxy-state.db"
required = true
event_retention_seconds = 7200
cleanup_interval_ms = 30000

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

        config.validate().unwrap();
        let persistence = config.persistence_config();
        assert_eq!(config.persistence_config_path(), "persistence");
        assert!(persistence.enabled);
        assert_eq!(persistence.path, "/tmp/sigproxy-state.db");
        assert!(persistence.required);
        assert_eq!(persistence.event_retention_seconds, 7200);
        assert_eq!(persistence.cleanup_interval_ms, 30000);
    }

    #[test]
    fn rejects_legacy_ha_persistence_config() {
        let err = toml::from_str::<Config>(
            r#"
[ha.persistence]
enabled = true
path = "/tmp/old-state.db"
required = false
event_retention_seconds = 3600
cleanup_interval_ms = 60000

[[proxy.listeners]]
bind = "127.0.0.1:5060"
transport = "udp"
upstream_group = "default"

[[proxy.upstream_groups]]
name = "default"
servers = ["127.0.0.1:5080"]
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
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
    fn security_defaults_to_dynamic_ban_enabled() {
        let config = Config::default();
        let effective = config
            .proxy
            .effective_security_for_listener(&config.proxy.listeners[0]);

        assert_eq!(effective.preset, ProxySecurityPreset::Off);
        assert!(effective.enabled());
        assert!(effective.dynamic_ban.enabled);
        assert_eq!(effective.dynamic_ban.ban_seconds, 3600);
        config.validate().unwrap();
    }

    #[test]
    fn explicit_off_preset_disables_security() {
        let config = Config {
            proxy: ProxyConfig {
                security: ProxySecurityConfig {
                    preset: Some(ProxySecurityPreset::Off),
                    ..ProxySecurityConfig::default()
                },
                ..ProxyConfig::default()
            },
            ..Config::default()
        };
        let effective = config
            .proxy
            .effective_security_for_listener(&config.proxy.listeners[0]);

        assert!(!effective.enabled());
        assert!(!effective.dynamic_ban.enabled);
        config.validate().unwrap();
    }

    #[test]
    fn listener_security_overrides_global_security_partially() {
        let config: Config = toml::from_str(
            r#"
[proxy.security]
preset = "public"
trusted_cidrs = ["10.0.0.0/8"]

[proxy.security.sip_rate_limit]
invite_per_minute_per_aor = 60

[proxy.security.sip_policy]
require_registered_invite_source = true
registered_invite_source_match = "ip"

[[proxy.listeners]]
bind = "127.0.0.1:5060"
transport = "udp"
upstream_group = "default"

[proxy.listeners.security.sip_rate_limit]
invite_per_minute_per_aor = 12

[proxy.listeners.security.sip_policy]
registered_invite_source_match = "ip-port"

[[proxy.upstream_groups]]
name = "default"
servers = ["127.0.0.1:5080"]
"#,
        )
        .unwrap();

        config.validate().unwrap();
        let effective = config
            .proxy
            .effective_security_for_listener(&config.proxy.listeners[0]);
        assert_eq!(effective.preset, ProxySecurityPreset::Public);
        assert_eq!(effective.trusted_cidrs, vec!["10.0.0.0/8"]);
        assert_eq!(effective.sip_rate_limit.invite_per_minute_per_aor, 12);
        assert_eq!(effective.sip_rate_limit.register_per_minute_per_aor, 20);
        assert!(effective.sip_policy.require_registered_invite_source);
        assert_eq!(
            effective.sip_policy.registered_invite_source_match,
            ProxyRegisteredInviteSourceMatch::IpPort
        );
    }

    #[test]
    fn parses_geo_and_dynamic_ban_security_config() {
        let config: Config = toml::from_str(
            r#"
[proxy.security.geo]
enabled = true
cache_dir = "/tmp/sigproxy-geo"
startup_refresh = "disabled"
unknown_country = "deny"
request_retries = 5
allow_partial = true

[proxy.security.geo.deny]
countries = ["ru", "ir"]

[proxy.security.dynamic_ban]
enabled = true
ban_seconds = 600
invalid_packets_per_minute = 10
parse_errors_per_minute = 5
sip_rate_violations_per_minute = 3

[[proxy.listeners]]
bind = "127.0.0.1:5060"
transport = "udp"
upstream_group = "default"

[proxy.listeners.security.geo.allow]
countries = ["cn"]

[[proxy.upstream_groups]]
name = "default"
servers = ["127.0.0.1:5080"]
"#,
        )
        .unwrap();

        config.validate().unwrap();
        let effective = config
            .proxy
            .effective_security_for_listener(&config.proxy.listeners[0]);
        assert!(effective.geo.enabled);
        assert_eq!(effective.geo.request_retries, 5);
        assert!(effective.geo.allow_partial);
        assert_eq!(effective.geo.deny_countries, vec!["RU", "IR"]);
        assert_eq!(effective.geo.allow_countries, vec!["CN"]);
        assert!(effective.dynamic_ban.enabled);
        assert_eq!(effective.dynamic_ban.ban_seconds, 600);
    }

    #[test]
    fn parses_xdp_security_config() {
        let config: Config = toml::from_str(
            r#"
[proxy.security.xdp]
enabled = true
interfaces = ["eth0"]
detach_stale = true
fail_open = true
sync_dynamic_ban = true
cidr_filter = true
geo_filter = false
ip_rate_limit = true
auto_size_maps = true
max_deny_cidrs_entries = 524288
max_geo_cidrs_entries = 524288

[[proxy.listeners]]
bind = "127.0.0.1:5060"
transport = "udp"
upstream_group = "default"

[proxy.listeners.security.xdp]
geo_filter = true

[[proxy.upstream_groups]]
name = "default"
servers = ["127.0.0.1:5080"]
"#,
        )
        .unwrap();

        config.validate().unwrap();
        let effective = config
            .proxy
            .effective_security_for_listener(&config.proxy.listeners[0]);
        assert!(effective.xdp.enabled);
        assert_eq!(effective.xdp.interfaces, vec!["eth0"]);
        assert!(effective.xdp.detach_stale);
        assert!(effective.xdp.fail_open);
        assert!(effective.xdp.sync_dynamic_ban);
        assert!(effective.xdp.cidr_filter);
        assert!(effective.xdp.geo_filter);
        assert!(effective.xdp.ip_rate_limit);
        assert!(effective.xdp.auto_size_maps);
        assert_eq!(effective.xdp.max_deny_cidrs_entries, 524_288);
        assert_eq!(effective.xdp.max_geo_cidrs_entries, 524_288);
    }

    #[test]
    fn tcp_udp_listener_expands_to_udp_and_tcp() {
        let config: Config = toml::from_str(
            r#"
[[proxy.listeners]]
bind = "127.0.0.1:5060"
transport = "tcp_udp"
upstream_group = "default"

[[proxy.upstream_groups]]
name = "default"
servers = ["127.0.0.1:5080"]
"#,
        )
        .unwrap();

        config.validate().unwrap();
        let concrete = config.proxy.listeners[0].concrete_listeners();
        assert_eq!(concrete.len(), 2);
        assert_eq!(concrete[0].key(), "udp/127.0.0.1:5060");
        assert_eq!(concrete[1].key(), "tcp/127.0.0.1:5060");
    }

    #[test]
    fn tcp_udp_route_listener_key_validates() {
        let config: Config = toml::from_str(
            r#"
[[proxy.listeners]]
bind = "127.0.0.1:5060"
transport = "tcp_udp"
upstream_group = "default"

[[proxy.routes]]
name = "tenant-a"
listener = "tcp_udp/127.0.0.1:5060"
upstream_group = "default"

[[proxy.upstream_groups]]
name = "default"
servers = ["127.0.0.1:5080"]
"#,
        )
        .unwrap();

        config.validate().unwrap();
    }

    #[test]
    fn tcp_udp_listener_conflicts_with_explicit_same_protocol_listener() {
        let config: Config = toml::from_str(
            r#"
[[proxy.listeners]]
bind = "127.0.0.1:5060"
transport = "tcp_udp"
upstream_group = "default"

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

        let err = config.validate().unwrap_err();
        assert!(format!("{err:#}").contains("duplicate proxy listener 'udp/127.0.0.1:5060'"));
    }

    #[test]
    fn rejects_invalid_security_cidr() {
        let config: Config = toml::from_str(
            r#"
[proxy.security]
preset = "public"
deny_cidrs = ["10.0.0.0/99"]
"#,
        )
        .unwrap();

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_invalid_geo_country_code() {
        let config: Config = toml::from_str(
            r#"
[proxy.security.geo.deny]
countries = ["USA"]
"#,
        )
        .unwrap();

        assert!(config.validate().is_err());
    }

    #[test]
    fn enabled_xdp_without_interfaces_uses_auto_selection() {
        let config: Config = toml::from_str(
            r#"
[proxy.security.xdp]
enabled = true

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

        config.validate().unwrap();
        let effective = config
            .proxy
            .effective_security_for_listener(&config.proxy.listeners[0]);
        assert!(effective.xdp.enabled);
        assert!(effective.xdp.interfaces.is_empty());
    }

    #[test]
    fn rejects_zero_security_rate() {
        let config: Config = toml::from_str(
            r#"
[proxy.security]
preset = "public"

[proxy.security.ip_rate_limit]
packets_per_second = 0
"#,
        )
        .unwrap();

        assert!(config.validate().is_err());
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
    fn allows_auto_listener_workers_with_reuse_port() {
        let config = Config {
            proxy: ProxyConfig {
                socket: ProxySocketConfig {
                    workers_per_listener: 0,
                    reuse_port: true,
                    ..ProxySocketConfig::default()
                },
                ..ProxyConfig::default()
            },
            ..Config::default()
        };
        config.validate().unwrap();
        assert!(config.proxy.socket.resolved_workers_per_listener() >= 1);
    }

    #[test]
    fn rejects_auto_listener_workers_without_reuse_port() {
        let config = Config {
            proxy: ProxyConfig {
                socket: ProxySocketConfig {
                    workers_per_listener: 0,
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
    fn rejects_upstream_server_matching_internal_addr() {
        let mut config = Config {
            sip: SipConfig {
                internal_addr: Some("172.30.0.254".to_string()),
                ..SipConfig::default()
            },
            ..Config::default()
        };
        config.proxy.listeners[0].bind = "0.0.0.0:5060".to_string();
        config.proxy.upstream_groups[0].servers = vec!["172.30.0.254:5060".to_string()];

        let err = config.validate().unwrap_err();

        assert!(
            err.to_string()
                .contains("points back to this proxy listener")
        );
    }

    #[test]
    fn rejects_route_upstream_server_matching_listener_bind() {
        let mut config = Config::default();
        config.proxy.listeners[0].bind = "127.0.0.1:5060".to_string();
        config.proxy.upstream_groups.push(UpstreamGroupConfig {
            name: "loop".to_string(),
            mode: UpstreamMode::RoundRobin,
            health_check: UpstreamHealthCheckConfig::default(),
            servers: vec!["127.0.0.1:5060".to_string()],
        });
        config.proxy.routes.push(RouteConfig {
            name: "loop-route".to_string(),
            listener: None,
            domain: Some("example.com".to_string()),
            prefix: None,
            upstream_group: "loop".to_string(),
        });

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("listener.bind"));
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
                vary_call_id: false,
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
                vary_call_id: false,
            },
            ..UpstreamHealthCheckConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn parses_health_check_options_vary_call_id() {
        let config: Config = toml::from_str(
            r#"
[[proxy.listeners]]
bind = "127.0.0.1:5060"
transport = "udp"
upstream_group = "default"

[[proxy.upstream_groups]]
name = "default"
servers = ["127.0.0.1:5080"]

[proxy.upstream_groups.health_check]
enabled = true

[proxy.upstream_groups.health_check.probe]
mode = "options"
vary_call_id = true
"#,
        )
        .unwrap();

        config.validate().unwrap();
        let UpstreamHealthProbeConfig::Options { vary_call_id, .. } =
            config.proxy.upstream_groups[0].health_check.probe
        else {
            panic!("expected OPTIONS health-check probe");
        };
        assert!(vary_call_id);
    }

    #[test]
    fn rejects_active_standby_without_peer_heartbeat() {
        let config = Config {
            ha: HaConfig {
                enabled: true,
                peer_heartbeat_addr: None,
                peer_replication_addr: Some("127.0.0.1:7901".to_string()),
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
                enabled: true,
                peer_heartbeat_addr: Some("127.0.0.1:7900".to_string()),
                peer_replication_addr: None,
                ..HaConfig::default()
            },
            ..Config::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn flattened_ha_enabled_enables_role_and_replication() {
        let ha: HaConfig = toml::from_str(
            r#"
enabled = true
initial_role = "active"
heartbeat_bind = "127.0.0.1:7900"
peer_heartbeat_addr = "127.0.0.2:7900"
replication_bind_addr = "127.0.0.1:7901"
peer_replication_addr = "127.0.0.2:7901"
replication_pull_interval_ms = 1000
"#,
        )
        .unwrap();

        let active_standby = ha.active_standby_config();
        let replication = ha.replication_config();
        assert!(active_standby.enabled);
        assert_eq!(active_standby.initial_role, HaInitialRole::Active);
        assert_eq!(
            active_standby.peer_heartbeat_addr.as_deref(),
            Some("127.0.0.2:7900")
        );
        assert!(replication.enabled);
        assert_eq!(replication.bind_addr, "127.0.0.1:7901");
        assert_eq!(replication.peer_addr.as_deref(), Some("127.0.0.2:7901"));
        assert_eq!(replication.pull_interval_ms, 1000);
    }

    #[test]
    fn rejects_legacy_ha_active_standby_subtable() {
        let err = toml::from_str::<Config>(
            r#"
[ha.active_standby]
enabled = true
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }
}
