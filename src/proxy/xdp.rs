use crate::config::{
    EffectiveProxySecurityConfig, ProxyConfig, ProxyGeoUnknownCountryPolicy, SipTransport,
};
use crate::proxy::geo::GeoRuntime;
use crate::proxy::threat::ThreatRuntime;
use anyhow::{Context, Result, bail};
#[cfg(target_os = "linux")]
use aya::{
    Ebpf, EbpfLoader, Pod,
    maps::MapInfo,
    maps::{Array as AyaArray, HashMap as AyaHashMap, LpmTrie, MapData, lpm_trie::Key as LpmKey},
    programs::{Xdp, XdpMode},
};
#[cfg(target_os = "linux")]
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeSet, HashMap as StdHashMap};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex as StdMutex;
use std::time::Instant;
#[cfg(target_os = "linux")]
use std::time::Instant as StdInstant;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

#[cfg(target_os = "linux")]
const XDP_OBJECT_PATH: &str = "/usr/local/share/sigproxy/sigproxy_xdp.o";
#[cfg(target_os = "linux")]
const XDP_PIN_DIR: &str = "/sys/fs/bpf/sigproxy/v3";
#[cfg(target_os = "linux")]
const XDP_PROG_DIR: &str = "/sys/fs/bpf/sigproxy/v3/progs";
#[cfg(target_os = "linux")]
const XDP_MAP_DIR: &str = "/sys/fs/bpf/sigproxy/v3/maps";
#[cfg(target_os = "linux")]
const XDP_BLOCKED_IPS_MAP: &str = "/sys/fs/bpf/sigproxy/v3/maps/blocked_ips";
#[cfg(target_os = "linux")]
const XDP_LISTENER_POLICIES_MAP: &str = "/sys/fs/bpf/sigproxy/v3/maps/listener_policies";
#[cfg(target_os = "linux")]
const XDP_ALLOW_CIDRS_MAP: &str = "/sys/fs/bpf/sigproxy/v3/maps/allow_cidrs";
#[cfg(target_os = "linux")]
const XDP_DENY_CIDRS_MAP: &str = "/sys/fs/bpf/sigproxy/v3/maps/deny_cidrs";
#[cfg(target_os = "linux")]
const XDP_TRUSTED_CIDRS_MAP: &str = "/sys/fs/bpf/sigproxy/v3/maps/trusted_cidrs";
#[cfg(target_os = "linux")]
const XDP_GEO_CIDRS_MAP: &str = "/sys/fs/bpf/sigproxy/v3/maps/geo_cidrs";
#[cfg(target_os = "linux")]
const XDP_STATS_MAP: &str = "/sys/fs/bpf/sigproxy/v3/maps/stats";
const XDP_PROTO_ICMP: u8 = 1;
const XDP_PROTO_TCP: u8 = 6;
const XDP_PROTO_UDP: u8 = 17;
const XDP_POLICY_CIDR_ALLOW_ENABLED: u64 = 1 << 0;
const XDP_POLICY_GEO_ENABLED: u64 = 1 << 1;
const XDP_POLICY_GEO_UNKNOWN_ALLOW: u64 = 1 << 2;
const XDP_POLICY_GEO_ALLOW_HAS_ENTRIES: u64 = 1 << 3;
const XDP_POLICY_IP_RATE_LIMIT_ENABLED: u64 = 1 << 4;
const XDP_POLICY_FLOOD_ENABLED: u64 = 1 << 5;
const XDP_COUNTRY_WORDS: usize = 11;
const XDP_STAT_NAMES: [&str; 13] = [
    "pass",
    "blocklist-drop",
    "deny-cidr-drop",
    "not-allowed-cidr-drop",
    "geo-unknown-drop",
    "geo-deny-drop",
    "geo-not-allowed-drop",
    "rate-limit-drop",
    "udp-flood-drop",
    "tcp-flood-drop",
    "tcp-syn-flood-drop",
    "tcp-ack-flood-drop",
    "icmp-flood-drop",
];
#[cfg(target_os = "linux")]
const XDP_GEO_SYNC_PROGRESS_INTERVAL: usize = 10_000;
#[cfg(target_os = "linux")]
const XDP_DENY_CIDRS_DEFAULT_MAX_ENTRIES: u32 = 65_536;
#[cfg(target_os = "linux")]
const XDP_GEO_CIDRS_DEFAULT_MAX_ENTRIES: u32 = 262_144;
const XDP_GEO_CIDRS_DEFAULT_MAX_CONFIG_ENTRIES: u32 = 1_048_576;

pub struct XdpRuntime {
    requested: bool,
    sync_dynamic_ban: bool,
    control_plane: Option<XdpControlPlane>,
    backend: Option<XdpBackend>,
}

#[derive(Debug)]
struct XdpControlPlane {
    blocks: Mutex<StdHashMap<XdpBlockKey, XdpBlockEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct XdpBlockKey {
    listener_key: String,
    ip: IpAddr,
}

#[derive(Debug, Clone)]
struct XdpBlockEntry {
    until: Instant,
    _reason: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct XdpListenerSpec {
    listener_key: String,
    l4_proto: u8,
    port: u16,
    policy: XdpListenerPolicySpec,
}

#[derive(Debug, Clone, Hash)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct XdpListenerPolicySpec {
    flags: u64,
    packets_per_second: u32,
    burst: u32,
    udp_flood_packets_per_second: u32,
    udp_flood_burst: u32,
    tcp_flood_packets_per_second: u32,
    tcp_flood_burst: u32,
    tcp_syn_flood_packets_per_second: u32,
    tcp_syn_flood_burst: u32,
    tcp_ack_flood_packets_per_second: u32,
    tcp_ack_flood_burst: u32,
    icmp_flood_packets_per_second: u32,
    icmp_flood_burst: u32,
    geo_allow: [u64; XDP_COUNTRY_WORDS],
    geo_deny: [u64; XDP_COUNTRY_WORDS],
    trusted_cidrs: Vec<XdpCidrPrefix>,
    allow_cidrs: Vec<XdpCidrPrefix>,
    deny_cidrs: Vec<XdpCidrPrefix>,
    threat_intel: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct XdpCidrPrefix {
    addr: IpAddr,
    prefix: u8,
}

enum XdpBackend {
    #[cfg(target_os = "linux")]
    Aya(AyaXdpBackend),
}

#[derive(Debug, Clone, Copy)]
struct XdpMapSizing {
    auto_size_maps: bool,
    max_deny_cidrs_entries: u32,
    max_geo_cidrs_entries: u32,
}

impl XdpMapSizing {
    fn apply(&mut self, config: &crate::config::EffectiveProxyXdpSecurityConfig) {
        self.auto_size_maps &= config.auto_size_maps;
        self.max_deny_cidrs_entries = self
            .max_deny_cidrs_entries
            .max(config.max_deny_cidrs_entries);
        self.max_geo_cidrs_entries = self.max_geo_cidrs_entries.max(config.max_geo_cidrs_entries);
    }
}

impl Default for XdpMapSizing {
    fn default() -> Self {
        Self {
            auto_size_maps: true,
            max_deny_cidrs_entries: 262_144,
            max_geo_cidrs_entries: XDP_GEO_CIDRS_DEFAULT_MAX_CONFIG_ENTRIES,
        }
    }
}

impl XdpRuntime {
    pub fn new(
        config: &ProxyConfig,
        geo: Option<&Arc<GeoRuntime>>,
        threat: Option<&Arc<ThreatRuntime>>,
    ) -> Result<Self> {
        let mut requested = false;
        let mut fail_closed = false;
        let mut sync_dynamic_ban = false;
        let mut detach_stale = true;
        let mut map_sizing = XdpMapSizing::default();
        let mut interfaces = BTreeSet::new();
        let mut listener_count = 0_usize;
        let mut listeners = Vec::new();
        let mut icmp_flood_policy: Option<XdpListenerPolicySpec> = None;

        for configured_listener in &config.listeners {
            for listener in configured_listener.concrete_listeners() {
                let effective = config.effective_security_for_listener(&listener);
                if !effective.xdp.enabled {
                    continue;
                }
                requested = true;
                listener_count += 1;
                fail_closed |= !effective.xdp.fail_open;
                sync_dynamic_ban |= effective.xdp.sync_dynamic_ban;
                detach_stale &= effective.xdp.detach_stale;
                map_sizing.apply(&effective.xdp);
                interfaces.extend(effective.xdp.interfaces.iter().cloned());
                listeners.push(XdpListenerSpec::from_listener(&listener, &effective)?);
                if let Some(policy) = XdpListenerPolicySpec::icmp_flood_from_security(&effective) {
                    if let Some(existing) = &mut icmp_flood_policy {
                        existing.merge_icmp_flood(policy);
                    } else {
                        icmp_flood_policy = Some(policy);
                    }
                }
            }
        }
        if let Some(policy) = icmp_flood_policy {
            listeners.push(XdpListenerSpec {
                listener_key: "icmp/*:0".to_string(),
                l4_proto: XDP_PROTO_ICMP,
                port: 0,
                policy,
            });
        }

        let backend = if requested {
            match XdpBackend::attach(
                &interfaces,
                &listeners,
                geo,
                threat,
                detach_stale,
                map_sizing,
            ) {
                Ok(backend) => backend,
                Err(err) if fail_closed => {
                    return Err(err.context("proxy.security.xdp is enabled with fail_open=false"));
                }
                Err(err) => {
                    let interfaces = render_interfaces(&interfaces);
                    warn!(
                        interfaces = %interfaces,
                        listeners = listener_count,
                        error = %format!("{err:#}"),
                        "proxy.security.xdp requested; continuing with user-space security because XDP kernel offload could not be attached"
                    );
                    None
                }
            }
        } else {
            None
        };

        if requested {
            let interfaces = render_interfaces(&interfaces);
            if backend.is_some() {
                info!(
                    interfaces = %interfaces,
                    listeners = listener_count,
                    "proxy.security.xdp attached"
                );
            }
        }

        Ok(Self {
            requested,
            sync_dynamic_ban,
            control_plane: requested.then(XdpControlPlane::default),
            backend,
        })
    }

    pub async fn sync_ip_block(
        &self,
        listener_key: &str,
        ip: IpAddr,
        until: Instant,
        reason: &str,
    ) {
        if !self.requested || !self.sync_dynamic_ban {
            return;
        }
        if let Some(control_plane) = &self.control_plane {
            control_plane
                .sync_ip_block(listener_key, ip, until, reason)
                .await;
        }
        if let Some(backend) = &self.backend {
            if let Err(err) = backend.sync_ip_block(listener_key, ip).await {
                warn!(
                    listener = %listener_key,
                    %ip,
                    reason,
                    error = %format!("{err:#}"),
                    "failed to sync XDP blocklist entry"
                );
            }
        } else {
            debug!(
                listener = %listener_key,
                %ip,
                reason,
                ?until,
                "recorded XDP blocklist sync intent without attached kernel backend"
            );
        }
    }

    pub async fn prune_expired(&self) {
        if !self.requested {
            return;
        }
        let mut expired = Vec::new();
        if let Some(control_plane) = &self.control_plane {
            expired = control_plane.prune_expired(Instant::now()).await;
        }
        if let Some(backend) = &self.backend {
            for key in expired {
                if let Err(err) = backend.remove_ip_block(&key).await {
                    warn!(
                        listener = %key.listener_key,
                        ip = %key.ip,
                        error = %format!("{err:#}"),
                        "failed to remove expired XDP blocklist entry"
                    );
                }
            }
        } else {
            debug!("pruned XDP control-plane state without attached kernel backend");
        }
    }

    pub fn sync_static_policy(
        &self,
        geo: Option<&Arc<GeoRuntime>>,
        threat: Option<&Arc<ThreatRuntime>>,
    ) {
        let Some(backend) = &self.backend else {
            return;
        };
        if let Err(err) = backend.sync_static_policy(geo, threat) {
            warn!(
                error = %format!("{err:#}"),
                "failed to sync XDP static policy maps"
            );
        }
    }

    pub fn stats(&self) -> Vec<(&'static str, u64)> {
        if let Some(backend) = &self.backend {
            return backend.stats();
        }
        XDP_STAT_NAMES.iter().map(|name| (*name, 0)).collect()
    }

    #[cfg(test)]
    async fn control_plane_block_count(&self) -> usize {
        let Some(control_plane) = &self.control_plane else {
            return 0;
        };
        control_plane.blocks.lock().await.len()
    }
}

impl Default for XdpControlPlane {
    fn default() -> Self {
        Self {
            blocks: Mutex::new(StdHashMap::new()),
        }
    }
}

impl XdpControlPlane {
    async fn sync_ip_block(&self, listener_key: &str, ip: IpAddr, until: Instant, reason: &str) {
        self.blocks.lock().await.insert(
            XdpBlockKey {
                listener_key: listener_key.to_string(),
                ip,
            },
            XdpBlockEntry {
                until,
                _reason: reason.to_string(),
            },
        );
    }

    async fn prune_expired(&self, now: Instant) -> Vec<XdpBlockKey> {
        let mut blocks = self.blocks.lock().await;
        let expired = blocks
            .iter()
            .filter(|(_, entry)| entry.until <= now)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in &expired {
            blocks.remove(key);
        }
        expired
    }
}

impl XdpListenerSpec {
    fn from_listener(
        listener: &crate::config::ProxyListenerConfig,
        security: &EffectiveProxySecurityConfig,
    ) -> Result<Self> {
        let bind = listener
            .bind
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid XDP listener bind '{}'", listener.bind))?;
        let l4_proto = match listener.transport {
            SipTransport::Udp => XDP_PROTO_UDP,
            SipTransport::Tcp => XDP_PROTO_TCP,
            SipTransport::TcpUdp => bail!("XDP listener transport must be expanded before attach"),
        };
        Ok(Self {
            listener_key: listener.key(),
            l4_proto,
            port: bind.port(),
            policy: XdpListenerPolicySpec::from_security(security)?,
        })
    }
}

impl XdpListenerPolicySpec {
    fn from_security(security: &EffectiveProxySecurityConfig) -> Result<Self> {
        let mut flags = 0_u64;
        let trusted_cidrs = if security.xdp.cidr_filter {
            parse_xdp_cidrs(&security.trusted_cidrs)?
        } else {
            Vec::new()
        };
        let allow_cidrs = if security.xdp.cidr_filter {
            parse_xdp_cidrs(&security.allow_cidrs)?
        } else {
            Vec::new()
        };
        let deny_cidrs = if security.xdp.cidr_filter {
            parse_xdp_cidrs(&security.deny_cidrs)?
        } else {
            Vec::new()
        };
        if !allow_cidrs.is_empty() {
            flags |= XDP_POLICY_CIDR_ALLOW_ENABLED;
        }

        let mut geo_allow = [0_u64; XDP_COUNTRY_WORDS];
        let mut geo_deny = [0_u64; XDP_COUNTRY_WORDS];
        if security.xdp.geo_filter && security.geo.enabled {
            flags |= XDP_POLICY_GEO_ENABLED;
            if matches!(
                security.geo.unknown_country,
                ProxyGeoUnknownCountryPolicy::Allow
            ) {
                flags |= XDP_POLICY_GEO_UNKNOWN_ALLOW;
            }
            if !security.geo.allow_countries.is_empty() {
                flags |= XDP_POLICY_GEO_ALLOW_HAS_ENTRIES;
            }
            for country in &security.geo.allow_countries {
                set_country_bit(&mut geo_allow, country)?;
            }
            for country in &security.geo.deny_countries {
                set_country_bit(&mut geo_deny, country)?;
            }
        }
        let threat_intel = security.xdp.threat_intel && security.threat_intel.enabled;

        let mut packets_per_second = 0_u32;
        let mut burst = 0_u32;
        if security.xdp.ip_rate_limit
            && security.ip_rate_limit.enabled
            && security.ip_rate_limit.packets_per_second > 0
            && security.ip_rate_limit.burst > 0
        {
            flags |= XDP_POLICY_IP_RATE_LIMIT_ENABLED;
            packets_per_second = security
                .ip_rate_limit
                .packets_per_second
                .min(u64::from(u32::MAX)) as u32;
            burst = security.ip_rate_limit.burst.min(u64::from(u32::MAX)) as u32;
        }
        let (
            udp_flood_packets_per_second,
            udp_flood_burst,
            tcp_flood_packets_per_second,
            tcp_flood_burst,
            tcp_syn_flood_packets_per_second,
            tcp_syn_flood_burst,
            tcp_ack_flood_packets_per_second,
            tcp_ack_flood_burst,
            icmp_flood_packets_per_second,
            icmp_flood_burst,
        ) = flood_fields(security);
        if udp_flood_packets_per_second > 0
            || tcp_flood_packets_per_second > 0
            || tcp_syn_flood_packets_per_second > 0
            || tcp_ack_flood_packets_per_second > 0
            || icmp_flood_packets_per_second > 0
        {
            flags |= XDP_POLICY_FLOOD_ENABLED;
        }

        Ok(Self {
            flags,
            packets_per_second,
            burst,
            udp_flood_packets_per_second,
            udp_flood_burst,
            tcp_flood_packets_per_second,
            tcp_flood_burst,
            tcp_syn_flood_packets_per_second,
            tcp_syn_flood_burst,
            tcp_ack_flood_packets_per_second,
            tcp_ack_flood_burst,
            icmp_flood_packets_per_second,
            icmp_flood_burst,
            geo_allow,
            geo_deny,
            trusted_cidrs,
            allow_cidrs,
            deny_cidrs,
            threat_intel,
        })
    }

    fn icmp_flood_from_security(security: &EffectiveProxySecurityConfig) -> Option<Self> {
        let (_, _, _, _, _, _, _, _, icmp_flood_packets_per_second, icmp_flood_burst) =
            flood_fields(security);
        if icmp_flood_packets_per_second == 0 || icmp_flood_burst == 0 {
            return None;
        }
        Some(Self {
            flags: XDP_POLICY_FLOOD_ENABLED,
            packets_per_second: 0,
            burst: 0,
            udp_flood_packets_per_second: 0,
            udp_flood_burst: 0,
            tcp_flood_packets_per_second: 0,
            tcp_flood_burst: 0,
            tcp_syn_flood_packets_per_second: 0,
            tcp_syn_flood_burst: 0,
            tcp_ack_flood_packets_per_second: 0,
            tcp_ack_flood_burst: 0,
            icmp_flood_packets_per_second,
            icmp_flood_burst,
            geo_allow: [0; XDP_COUNTRY_WORDS],
            geo_deny: [0; XDP_COUNTRY_WORDS],
            trusted_cidrs: Vec::new(),
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            threat_intel: false,
        })
    }

    fn merge_icmp_flood(&mut self, other: Self) {
        self.icmp_flood_packets_per_second = self
            .icmp_flood_packets_per_second
            .max(other.icmp_flood_packets_per_second);
        self.icmp_flood_burst = self.icmp_flood_burst.max(other.icmp_flood_burst);
    }
}

fn flood_fields(
    security: &EffectiveProxySecurityConfig,
) -> (u32, u32, u32, u32, u32, u32, u32, u32, u32, u32) {
    if !security.flood.enabled {
        return (0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
    (
        limit_u32(security.flood.udp_packets_per_second),
        limit_u32(security.flood.udp_burst),
        limit_u32(security.flood.tcp_packets_per_second),
        limit_u32(security.flood.tcp_burst),
        limit_u32(security.flood.tcp_syn_packets_per_second),
        limit_u32(security.flood.tcp_syn_burst),
        limit_u32(security.flood.tcp_ack_packets_per_second),
        limit_u32(security.flood.tcp_ack_burst),
        limit_u32(security.flood.icmp_packets_per_second),
        limit_u32(security.flood.icmp_burst),
    )
}

fn limit_u32(value: u64) -> u32 {
    value.min(u64::from(u32::MAX)) as u32
}

fn render_interfaces(interfaces: &BTreeSet<String>) -> String {
    if interfaces.is_empty() {
        "auto".to_string()
    } else {
        interfaces.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

fn parse_xdp_cidrs(values: &[String]) -> Result<Vec<XdpCidrPrefix>> {
    values.iter().map(|value| parse_xdp_cidr(value)).collect()
}

fn parse_xdp_cidr(value: &str) -> Result<XdpCidrPrefix> {
    let value = value.trim();
    let (addr, prefix) = if let Some((addr, prefix)) = value.split_once('/') {
        (
            addr.parse::<IpAddr>()
                .with_context(|| format!("invalid XDP CIDR address '{value}'"))?,
            Some(
                prefix
                    .parse::<u8>()
                    .with_context(|| format!("invalid XDP CIDR prefix '{value}'"))?,
            ),
        )
    } else {
        (
            value
                .parse::<IpAddr>()
                .with_context(|| format!("invalid XDP CIDR address '{value}'"))?,
            None,
        )
    };
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let prefix = prefix.unwrap_or(max);
    if prefix > max {
        bail!("XDP CIDR prefix in '{value}' must be at most {max}");
    }
    Ok(XdpCidrPrefix { addr, prefix })
}

fn set_country_bit(bits: &mut [u64; XDP_COUNTRY_WORDS], country: &str) -> Result<()> {
    let country = country.trim().as_bytes();
    if country.len() != 2 || !country.iter().all(u8::is_ascii_alphabetic) {
        bail!("invalid XDP geo country code");
    }
    let first = country[0].to_ascii_uppercase();
    let second = country[1].to_ascii_uppercase();
    let bit = usize::from(first - b'A') * 26 + usize::from(second - b'A');
    let word = bit / 64;
    let shift = bit % 64;
    if word >= XDP_COUNTRY_WORDS {
        bail!("invalid XDP geo country bit index");
    }
    bits[word] |= 1_u64 << shift;
    Ok(())
}

impl XdpBackend {
    fn attach(
        interfaces: &BTreeSet<String>,
        listeners: &[XdpListenerSpec],
        geo: Option<&Arc<GeoRuntime>>,
        threat: Option<&Arc<ThreatRuntime>>,
        detach_stale: bool,
        map_sizing: XdpMapSizing,
    ) -> Result<Option<Self>> {
        attach_backend(interfaces, listeners, geo, threat, detach_stale, map_sizing)
    }

    async fn sync_ip_block(&self, listener_key: &str, ip: IpAddr) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        let _ = (listener_key, ip);
        match self {
            #[cfg(target_os = "linux")]
            Self::Aya(backend) => backend.sync_ip_block(listener_key, ip),
            #[cfg(not(target_os = "linux"))]
            _ => unreachable!("XDP backend cannot be constructed on non-Linux targets"),
        }
    }

    async fn remove_ip_block(&self, key: &XdpBlockKey) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        let _ = key;
        match self {
            #[cfg(target_os = "linux")]
            Self::Aya(backend) => backend.remove_ip_block(key),
            #[cfg(not(target_os = "linux"))]
            _ => unreachable!("XDP backend cannot be constructed on non-Linux targets"),
        }
    }

    fn stats(&self) -> Vec<(&'static str, u64)> {
        #[cfg(not(target_os = "linux"))]
        {
            XDP_STAT_NAMES.iter().map(|name| (*name, 0)).collect()
        }
        #[cfg(target_os = "linux")]
        match self {
            Self::Aya(backend) => backend.stats(),
        }
    }

    fn sync_static_policy(
        &self,
        geo: Option<&Arc<GeoRuntime>>,
        threat: Option<&Arc<ThreatRuntime>>,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (geo, threat);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        match self {
            Self::Aya(backend) => backend.sync_static_policy(geo, threat),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn attach_backend(
    _interfaces: &BTreeSet<String>,
    _listeners: &[XdpListenerSpec],
    _geo: Option<&Arc<GeoRuntime>>,
    _threat: Option<&Arc<ThreatRuntime>>,
    _detach_stale: bool,
    _map_sizing: XdpMapSizing,
) -> Result<Option<XdpBackend>> {
    bail!("XDP kernel offload is only supported on Linux")
}

#[cfg(target_os = "linux")]
fn attach_backend(
    interfaces: &BTreeSet<String>,
    listeners: &[XdpListenerSpec],
    geo: Option<&Arc<GeoRuntime>>,
    threat: Option<&Arc<ThreatRuntime>>,
    detach_stale: bool,
    map_sizing: XdpMapSizing,
) -> Result<Option<XdpBackend>> {
    Ok(Some(XdpBackend::Aya(AyaXdpBackend::attach(
        interfaces,
        listeners,
        geo,
        threat,
        detach_stale,
        map_sizing,
    )?)))
}

#[cfg(target_os = "linux")]
struct AyaXdpBackend {
    ebpf: Ebpf,
    listeners: Vec<XdpListenerSpec>,
    blocked_ips: StdMutex<AyaHashMap<MapData, XdpIpKey, XdpIpValue>>,
    listener_policies: StdMutex<AyaHashMap<MapData, XdpListenerKey, XdpListenerPolicy>>,
    allow_cidrs: StdMutex<LpmTrie<MapData, XdpLpmData, XdpCidrValue>>,
    deny_cidrs: StdMutex<LpmTrie<MapData, XdpLpmData, XdpCidrValue>>,
    trusted_cidrs: StdMutex<LpmTrie<MapData, XdpLpmData, XdpCidrValue>>,
    geo_cidrs: StdMutex<LpmTrie<MapData, XdpGeoLpmData, XdpGeoValue>>,
    stats: StdMutex<AyaArray<MapData, u64>>,
    static_state: StdMutex<XdpStaticState>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct XdpStaticState {
    keys: XdpStaticKeys,
    fingerprint: Option<u64>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct XdpStaticKeys {
    listener_policies: BTreeSet<XdpListenerKey>,
    allow_cidrs: BTreeSet<Vec<u8>>,
    deny_cidrs: BTreeSet<Vec<u8>>,
    trusted_cidrs: BTreeSet<Vec<u8>>,
    geo_cidrs: BTreeSet<Vec<u8>>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct XdpStaticPlan {
    keys: XdpStaticKeys,
    fingerprint: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct XdpMapCapacities {
    deny_cidrs: u32,
    geo_cidrs: u32,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
struct XdpListenerKey {
    l4_proto: u8,
    pad: u8,
    dport: u16,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
struct XdpIpKey {
    family: u8,
    l4_proto: u8,
    dport: u16,
    src: [u8; 16],
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct XdpIpValue {
    enabled: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
struct XdpLpmData {
    family: u8,
    l4_proto: u8,
    dport: u16,
    addr: [u8; 16],
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
struct XdpGeoLpmData {
    family: u8,
    pad: [u8; 3],
    addr: [u8; 16],
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct XdpCidrValue {
    enabled: u8,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct XdpGeoValue {
    country: u16,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct XdpListenerPolicy {
    flags: u64,
    packets_per_second: u32,
    burst: u32,
    udp_flood_packets_per_second: u32,
    udp_flood_burst: u32,
    tcp_flood_packets_per_second: u32,
    tcp_flood_burst: u32,
    tcp_syn_flood_packets_per_second: u32,
    tcp_syn_flood_burst: u32,
    tcp_ack_flood_packets_per_second: u32,
    tcp_ack_flood_burst: u32,
    icmp_flood_packets_per_second: u32,
    icmp_flood_burst: u32,
    geo_allow: [u64; XDP_COUNTRY_WORDS],
    geo_deny: [u64; XDP_COUNTRY_WORDS],
}

#[cfg(target_os = "linux")]
unsafe impl Pod for XdpListenerKey {}
#[cfg(target_os = "linux")]
unsafe impl Pod for XdpIpKey {}
#[cfg(target_os = "linux")]
unsafe impl Pod for XdpIpValue {}
#[cfg(target_os = "linux")]
unsafe impl Pod for XdpLpmData {}
#[cfg(target_os = "linux")]
unsafe impl Pod for XdpGeoLpmData {}
#[cfg(target_os = "linux")]
unsafe impl Pod for XdpCidrValue {}
#[cfg(target_os = "linux")]
unsafe impl Pod for XdpGeoValue {}
#[cfg(target_os = "linux")]
unsafe impl Pod for XdpListenerPolicy {}

#[cfg(target_os = "linux")]
impl AyaXdpBackend {
    fn attach(
        interfaces: &BTreeSet<String>,
        listeners: &[XdpListenerSpec],
        geo: Option<&Arc<GeoRuntime>>,
        threat: Option<&Arc<ThreatRuntime>>,
        detach_stale: bool,
        map_sizing: XdpMapSizing,
    ) -> Result<Self> {
        ensure_bpffs_dirs()?;
        if !Path::new(XDP_OBJECT_PATH).exists() {
            bail!("XDP object {XDP_OBJECT_PATH} is missing");
        }
        let geo_prefixes = geo
            .map(|runtime| runtime.xdp_prefixes())
            .unwrap_or_default();
        let threat_prefixes = threat
            .map(|runtime| runtime.xdp_prefixes())
            .unwrap_or_default();
        let capacities =
            compute_xdp_map_capacities(listeners, &geo_prefixes, &threat_prefixes, map_sizing)?;
        prepare_pinned_map_capacity(
            "deny_cidrs",
            Path::new(XDP_DENY_CIDRS_MAP),
            capacities.deny_cidrs,
        )?;
        prepare_pinned_map_capacity(
            "geo_cidrs",
            Path::new(XDP_GEO_CIDRS_MAP),
            capacities.geo_cidrs,
        )?;

        let mut ebpf = EbpfLoader::new()
            .map_max_entries("deny_cidrs", capacities.deny_cidrs)
            .map_max_entries("geo_cidrs", capacities.geo_cidrs)
            .map_pin_path("blocked_ips", Path::new(XDP_BLOCKED_IPS_MAP))
            .map_pin_path("listener_policies", Path::new(XDP_LISTENER_POLICIES_MAP))
            .map_pin_path("allow_cidrs", Path::new(XDP_ALLOW_CIDRS_MAP))
            .map_pin_path("deny_cidrs", Path::new(XDP_DENY_CIDRS_MAP))
            .map_pin_path("trusted_cidrs", Path::new(XDP_TRUSTED_CIDRS_MAP))
            .map_pin_path("geo_cidrs", Path::new(XDP_GEO_CIDRS_MAP))
            .map_pin_path("stats", Path::new(XDP_STATS_MAP))
            .load_file(XDP_OBJECT_PATH)
            .context("failed to load XDP object with aya")?;
        info!(
            object = XDP_OBJECT_PATH,
            deny_cidrs_max_entries = capacities.deny_cidrs,
            geo_cidrs_max_entries = capacities.geo_cidrs,
            "XDP object loaded with aya; preparing maps"
        );

        let mut backend = Self {
            blocked_ips: StdMutex::new(take_hash_map(&mut ebpf, "blocked_ips")?),
            listener_policies: StdMutex::new(take_hash_map(&mut ebpf, "listener_policies")?),
            allow_cidrs: StdMutex::new(take_lpm_map(&mut ebpf, "allow_cidrs")?),
            deny_cidrs: StdMutex::new(take_lpm_map(&mut ebpf, "deny_cidrs")?),
            trusted_cidrs: StdMutex::new(take_lpm_map(&mut ebpf, "trusted_cidrs")?),
            geo_cidrs: StdMutex::new(take_geo_lpm_map(&mut ebpf, "geo_cidrs")?),
            stats: StdMutex::new(take_array(&mut ebpf, "stats")?),
            ebpf,
            listeners: listeners.to_vec(),
            static_state: StdMutex::new(XdpStaticState::default()),
        };
        backend.clear_dynamic_blocklist()?;
        info!("syncing initial XDP static policy maps");
        backend.sync_static_policy_prefixes(&geo_prefixes, &threat_prefixes)?;
        let resolved_interfaces = resolve_interfaces(interfaces)?;
        info!(
            interfaces = %resolved_interfaces.join(","),
            "attaching XDP program to resolved interfaces"
        );
        if detach_stale {
            detach_stale_sigproxy_xdp(&resolved_interfaces)?;
        }
        backend.attach_interfaces(resolved_interfaces)?;
        Ok(backend)
    }

    fn attach_interfaces(&mut self, interfaces: Vec<String>) -> Result<()> {
        let program: &mut Xdp = self
            .ebpf
            .program_mut("sigproxy_xdp")
            .context("XDP program 'sigproxy_xdp' is missing from object")?
            .try_into()
            .context("BPF program 'sigproxy_xdp' is not an XDP program")?;
        program.load().context("failed to load XDP program")?;
        for interface in interfaces {
            let mode = attach_xdp_program(program, &interface)?;
            info!(
                interface = %interface,
                mode,
                "XDP program attached to interface"
            );
        }
        Ok(())
    }

    fn sync_static_policy(
        &self,
        geo: Option<&Arc<GeoRuntime>>,
        threat: Option<&Arc<ThreatRuntime>>,
    ) -> Result<()> {
        let geo_prefixes = geo
            .map(|runtime| runtime.xdp_prefixes())
            .unwrap_or_default();
        let threat_prefixes = threat
            .map(|runtime| runtime.xdp_prefixes())
            .unwrap_or_default();
        self.sync_static_policy_prefixes(&geo_prefixes, &threat_prefixes)
    }

    fn sync_static_policy_prefixes(
        &self,
        geo_prefixes: &[crate::proxy::geo::GeoIpPrefix],
        threat_prefixes: &[crate::proxy::threat::ThreatIpPrefix],
    ) -> Result<()> {
        let started = StdInstant::now();
        let plan = self.build_static_sync_plan(geo_prefixes, threat_prefixes)?;
        {
            let current = self
                .static_state
                .lock()
                .expect("XDP static state lock poisoned");
            if current.fingerprint == Some(plan.fingerprint) {
                debug!(
                    listeners = self.listeners.len(),
                    geo_prefixes = geo_prefixes.len(),
                    threat_prefixes = threat_prefixes.len(),
                    fingerprint = plan.fingerprint,
                    "XDP static policy maps unchanged; skipping sync"
                );
                return Ok(());
            }
        }
        info!(
            listeners = self.listeners.len(),
            geo_prefixes = geo_prefixes.len(),
            threat_prefixes = threat_prefixes.len(),
            "XDP static policy sync started"
        );
        {
            let mut listener_policies = self
                .listener_policies
                .lock()
                .expect("XDP listener policy map lock poisoned");
            let mut trusted_cidrs = self
                .trusted_cidrs
                .lock()
                .expect("XDP trusted CIDR map lock poisoned");
            let mut allow_cidrs = self
                .allow_cidrs
                .lock()
                .expect("XDP allow CIDR map lock poisoned");
            let mut deny_cidrs = self
                .deny_cidrs
                .lock()
                .expect("XDP deny CIDR map lock poisoned");
            for spec in &self.listeners {
                let listener_key = make_listener_key(spec.l4_proto, spec.port);
                let policy = encode_listener_policy(&spec.policy);
                listener_policies
                    .insert(listener_key, policy, 0)
                    .with_context(|| {
                        format!("failed to sync XDP listener policy {}", spec.listener_key)
                    })?;

                for cidr in &spec.policy.trusted_cidrs {
                    let key = make_lpm_key(spec.l4_proto, spec.port, cidr.addr, cidr.prefix);
                    trusted_cidrs.insert(&key, XdpCidrValue { enabled: 1 }, 0)?;
                }
                for cidr in &spec.policy.allow_cidrs {
                    let key = make_lpm_key(spec.l4_proto, spec.port, cidr.addr, cidr.prefix);
                    allow_cidrs.insert(&key, XdpCidrValue { enabled: 1 }, 0)?;
                }
                for cidr in &spec.policy.deny_cidrs {
                    let key = make_lpm_key(spec.l4_proto, spec.port, cidr.addr, cidr.prefix);
                    deny_cidrs.insert(&key, XdpCidrValue { enabled: 1 }, 0)?;
                }
                if spec.policy.threat_intel {
                    for prefix in threat_prefixes {
                        let key =
                            make_lpm_key(spec.l4_proto, spec.port, prefix.addr, prefix.prefix);
                        deny_cidrs.insert(&key, XdpCidrValue { enabled: 1 }, 0)?;
                    }
                }
            }
        }
        if xdp_geo_enabled(&self.listeners) {
            let mut geo_cidrs = self
                .geo_cidrs
                .lock()
                .expect("XDP geo CIDR map lock poisoned");
            for (index, prefix) in geo_prefixes.iter().enumerate() {
                let key = make_geo_lpm_key(prefix.addr, prefix.prefix);
                geo_cidrs.insert(
                    &key,
                    XdpGeoValue {
                        country: prefix.country,
                    },
                    0,
                )?;
                let synced = index + 1;
                if synced % XDP_GEO_SYNC_PROGRESS_INTERVAL == 0 {
                    debug!(
                        synced,
                        total = geo_prefixes.len(),
                        "XDP geo CIDR map sync progress"
                    );
                }
            }
        }
        self.delete_stale_static_keys(plan.keys, plan.fingerprint)?;
        info!(
            listeners = self.listeners.len(),
            geo_prefixes = geo_prefixes.len(),
            threat_prefixes = threat_prefixes.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "XDP static policy maps synced"
        );
        Ok(())
    }

    fn build_static_sync_plan(
        &self,
        geo_prefixes: &[crate::proxy::geo::GeoIpPrefix],
        threat_prefixes: &[crate::proxy::threat::ThreatIpPrefix],
    ) -> Result<XdpStaticPlan> {
        let keys = build_xdp_static_keys(&self.listeners, geo_prefixes, threat_prefixes);
        let mut hasher = DefaultHasher::new();
        for spec in &self.listeners {
            spec.listener_key.hash(&mut hasher);
            spec.l4_proto.hash(&mut hasher);
            spec.port.hash(&mut hasher);
            spec.policy.hash(&mut hasher);
            if spec.policy.threat_intel {
                for prefix in threat_prefixes {
                    prefix.addr.hash(&mut hasher);
                    prefix.prefix.hash(&mut hasher);
                }
            }
        }
        if xdp_geo_enabled(&self.listeners) {
            for prefix in geo_prefixes {
                prefix.addr.hash(&mut hasher);
                prefix.prefix.hash(&mut hasher);
                prefix.country.hash(&mut hasher);
            }
        }
        keys.listener_policies.hash(&mut hasher);
        keys.allow_cidrs.hash(&mut hasher);
        keys.deny_cidrs.hash(&mut hasher);
        keys.trusted_cidrs.hash(&mut hasher);
        keys.geo_cidrs.hash(&mut hasher);
        Ok(XdpStaticPlan {
            keys,
            fingerprint: hasher.finish(),
        })
    }

    fn delete_stale_static_keys(&self, next: XdpStaticKeys, fingerprint: u64) -> Result<()> {
        let mut current = self
            .static_state
            .lock()
            .expect("XDP static state lock poisoned");
        let mut listener_policies = self
            .listener_policies
            .lock()
            .expect("XDP listener policy map lock poisoned");
        let mut trusted_cidrs = self
            .trusted_cidrs
            .lock()
            .expect("XDP trusted CIDR map lock poisoned");
        let mut allow_cidrs = self
            .allow_cidrs
            .lock()
            .expect("XDP allow CIDR map lock poisoned");
        let mut deny_cidrs = self
            .deny_cidrs
            .lock()
            .expect("XDP deny CIDR map lock poisoned");
        let mut geo_cidrs = self
            .geo_cidrs
            .lock()
            .expect("XDP geo CIDR map lock poisoned");
        delete_stale_hash_keys(
            &mut listener_policies,
            &current.keys.listener_policies,
            &next.listener_policies,
        )?;
        delete_stale_lpm_keys(
            &mut allow_cidrs,
            &current.keys.allow_cidrs,
            &next.allow_cidrs,
        )?;
        delete_stale_lpm_keys(&mut deny_cidrs, &current.keys.deny_cidrs, &next.deny_cidrs)?;
        delete_stale_lpm_keys(
            &mut trusted_cidrs,
            &current.keys.trusted_cidrs,
            &next.trusted_cidrs,
        )?;
        delete_stale_geo_lpm_keys(&mut geo_cidrs, &current.keys.geo_cidrs, &next.geo_cidrs)?;
        current.keys = next;
        current.fingerprint = Some(fingerprint);
        Ok(())
    }

    fn clear_dynamic_blocklist(&self) -> Result<()> {
        let mut blocked_ips = self
            .blocked_ips
            .lock()
            .expect("XDP blocked IP map lock poisoned");
        let keys = blocked_ips
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to list pinned XDP blocked IP keys")?;
        let count = keys.len();
        for key in keys {
            blocked_ips
                .remove(&key)
                .context("failed to clear pinned XDP blocked IP entry")?;
        }
        if count > 0 {
            info!(
                entries = count,
                "cleared pinned XDP dynamic blocklist on attach"
            );
        }
        Ok(())
    }

    fn sync_ip_block(&self, listener_key: &str, ip: IpAddr) -> Result<()> {
        for spec in self
            .listeners
            .iter()
            .filter(|spec| spec.listener_key == listener_key)
        {
            let mut blocked_ips = self
                .blocked_ips
                .lock()
                .expect("XDP blocked IP map lock poisoned");
            let key = make_ip_key(spec.l4_proto, spec.port, ip);
            blocked_ips.insert(key, XdpIpValue { enabled: 1 }, 0)?;
        }
        Ok(())
    }

    fn remove_ip_block(&self, key: &XdpBlockKey) -> Result<()> {
        for spec in self
            .listeners
            .iter()
            .filter(|spec| spec.listener_key == key.listener_key)
        {
            let mut blocked_ips = self
                .blocked_ips
                .lock()
                .expect("XDP blocked IP map lock poisoned");
            let encoded = make_ip_key(spec.l4_proto, spec.port, key.ip);
            blocked_ips.remove(&encoded)?;
        }
        Ok(())
    }

    fn stats(&self) -> Vec<(&'static str, u64)> {
        XDP_STAT_NAMES
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let stats = self.stats.lock().expect("XDP stats map lock poisoned");
                let value = stats.get(&(index as u32), 0).unwrap_or(0);
                (*name, value)
            })
            .collect()
    }
}

#[cfg(target_os = "linux")]
fn build_xdp_static_keys(
    listeners: &[XdpListenerSpec],
    geo_prefixes: &[crate::proxy::geo::GeoIpPrefix],
    threat_prefixes: &[crate::proxy::threat::ThreatIpPrefix],
) -> XdpStaticKeys {
    let mut keys = XdpStaticKeys::default();
    for spec in listeners {
        let listener_key = make_listener_key(spec.l4_proto, spec.port);
        keys.listener_policies.insert(listener_key);

        for cidr in &spec.policy.trusted_cidrs {
            let key = make_lpm_key(spec.l4_proto, spec.port, cidr.addr, cidr.prefix);
            keys.trusted_cidrs.insert(encode_lpm_key_bytes(&key));
        }
        for cidr in &spec.policy.allow_cidrs {
            let key = make_lpm_key(spec.l4_proto, spec.port, cidr.addr, cidr.prefix);
            keys.allow_cidrs.insert(encode_lpm_key_bytes(&key));
        }
        for cidr in &spec.policy.deny_cidrs {
            let key = make_lpm_key(spec.l4_proto, spec.port, cidr.addr, cidr.prefix);
            keys.deny_cidrs.insert(encode_lpm_key_bytes(&key));
        }
        if spec.policy.threat_intel {
            for prefix in threat_prefixes {
                let key = make_lpm_key(spec.l4_proto, spec.port, prefix.addr, prefix.prefix);
                keys.deny_cidrs.insert(encode_lpm_key_bytes(&key));
            }
        }
    }
    if xdp_geo_enabled(listeners) {
        for prefix in geo_prefixes {
            let key = make_geo_lpm_key(prefix.addr, prefix.prefix);
            keys.geo_cidrs.insert(encode_geo_lpm_key_bytes(&key));
        }
    }
    keys
}

#[cfg(target_os = "linux")]
fn xdp_geo_enabled(listeners: &[XdpListenerSpec]) -> bool {
    listeners
        .iter()
        .any(|spec| spec.policy.flags & XDP_POLICY_GEO_ENABLED != 0)
}

#[cfg(target_os = "linux")]
fn compute_xdp_map_capacities(
    listeners: &[XdpListenerSpec],
    geo_prefixes: &[crate::proxy::geo::GeoIpPrefix],
    threat_prefixes: &[crate::proxy::threat::ThreatIpPrefix],
    sizing: XdpMapSizing,
) -> Result<XdpMapCapacities> {
    let keys = build_xdp_static_keys(listeners, geo_prefixes, threat_prefixes);
    Ok(XdpMapCapacities {
        deny_cidrs: desired_xdp_map_entries(
            "deny_cidrs",
            keys.deny_cidrs.len(),
            XDP_DENY_CIDRS_DEFAULT_MAX_ENTRIES,
            sizing.max_deny_cidrs_entries,
            sizing.auto_size_maps,
        )?,
        geo_cidrs: desired_xdp_map_entries(
            "geo_cidrs",
            keys.geo_cidrs.len(),
            XDP_GEO_CIDRS_DEFAULT_MAX_ENTRIES,
            sizing.max_geo_cidrs_entries,
            sizing.auto_size_maps,
        )?,
    })
}

#[cfg(target_os = "linux")]
fn desired_xdp_map_entries(
    map_name: &str,
    required_entries: usize,
    default_entries: u32,
    max_entries: u32,
    auto_size: bool,
) -> Result<u32> {
    let required_entries = u32::try_from(required_entries)
        .with_context(|| format!("XDP {map_name} map requires too many entries"))?;
    if max_entries < default_entries {
        bail!(
            "XDP {map_name} configured max_entries {} is below default capacity {}",
            max_entries,
            default_entries
        );
    }
    if required_entries > default_entries && !auto_size {
        bail!(
            "XDP {map_name} map requires {} entries but object capacity is {}; enable proxy.security.xdp.auto_size_maps or increase the BPF map capacity",
            required_entries,
            default_entries
        );
    }
    if required_entries > max_entries {
        bail!(
            "XDP {map_name} map requires {} entries but configured max_entries is {}; increase proxy.security.xdp.max_{}_entries or reduce enabled XDP listeners/prefix sources",
            required_entries,
            max_entries,
            map_name
        );
    }
    if !auto_size {
        return Ok(default_entries);
    }
    if required_entries <= default_entries {
        return Ok(default_entries);
    }

    let target = required_entries
        .saturating_mul(2)
        .checked_next_power_of_two()
        .unwrap_or(max_entries)
        .min(max_entries)
        .max(default_entries);
    Ok(target)
}

#[cfg(target_os = "linux")]
fn prepare_pinned_map_capacity(map_name: &str, path: &Path, required_entries: u32) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let info = MapInfo::from_pin(path)
        .with_context(|| format!("failed to inspect pinned XDP map {}", path.display()))?;
    let current_entries = info.max_entries();
    if current_entries >= required_entries {
        return Ok(());
    }
    fs::remove_file(path).with_context(|| {
        format!(
            "failed to remove undersized pinned XDP map {} before recreating it",
            path.display()
        )
    })?;
    info!(
        map = map_name,
        path = %path.display(),
        current_max_entries = current_entries,
        required_max_entries = required_entries,
        "removed undersized pinned XDP map so it can be recreated"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn attach_xdp_program(program: &mut Xdp, interface: &str) -> Result<&'static str> {
    let native = program.attach(interface, XdpMode::Driver);
    if native.is_ok() {
        return Ok("driver");
    }
    program
        .attach(interface, XdpMode::Skb)
        .map(|_| "skb")
        .with_context(|| {
            format!(
                "native XDP attach failed ({:#}); generic XDP attach also failed",
                native.unwrap_err()
            )
        })
}

#[cfg(target_os = "linux")]
fn detach_stale_sigproxy_xdp(interfaces: &[String]) -> Result<()> {
    for interface in interfaces {
        let output = Command::new("ip")
            .args(["-details", "link", "show", "dev", interface])
            .output()
            .with_context(|| format!("failed to inspect XDP state on interface {interface}"))?;
        if !output.status.success() {
            bail!(
                "failed to inspect XDP state on interface {interface}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("prog/xdp") {
            continue;
        }
        if !stdout.contains("name sigproxy_xdp") {
            debug!(
                interface,
                "leaving existing non-sigproxy XDP program attached"
            );
            continue;
        }
        info!(
            interface,
            "detaching stale sigproxy XDP program before attach"
        );
        let output = Command::new("ip")
            .args(["link", "set", "dev", interface, "xdp", "off"])
            .output()
            .with_context(|| format!("failed to detach stale sigproxy XDP from {interface}"))?;
        if !output.status.success() {
            bail!(
                "failed to detach stale sigproxy XDP from {interface}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_bpffs_dirs() -> Result<()> {
    ensure_bpffs_mounted()?;
    std::fs::create_dir_all(XDP_PROG_DIR).context("failed to create XDP program pin dir")?;
    std::fs::create_dir_all(XDP_MAP_DIR).context("failed to create XDP map pin dir")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_bpffs_mounted() -> Result<()> {
    let bpffs = Path::new("/sys/fs/bpf");
    if !bpffs.exists() {
        bail!(
            "bpffs mount point /sys/fs/bpf does not exist; mount bpffs on the host and bind it into the container, for example `mount -t bpf bpf /sys/fs/bpf` and `docker run --mount type=bind,source=/sys/fs/bpf,target=/sys/fs/bpf`"
        );
    }
    let mounts = std::fs::read_to_string("/proc/mounts").context("failed to read /proc/mounts")?;
    if !bpffs_mounted_in_proc_mounts(&mounts, "/sys/fs/bpf") {
        bail!(
            "/sys/fs/bpf exists but is not a bpffs mount; mount bpffs on the host and bind it into the container before enabling proxy.security.xdp"
        );
    }
    std::fs::create_dir_all(XDP_PIN_DIR).context("failed to create XDP bpffs pin dir")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn bpffs_mounted_in_proc_mounts(mounts: &str, path: &str) -> bool {
    mounts.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.len() >= 3 && unescape_proc_mount_path(fields[1]) == path && fields[2] == "bpf"
    })
}

#[cfg(target_os = "linux")]
fn unescape_proc_mount_path(path: &str) -> String {
    path.replace("\\040", " ")
}

#[cfg(target_os = "linux")]
fn resolve_interfaces(interfaces: &BTreeSet<String>) -> Result<Vec<String>> {
    if !interfaces.is_empty() {
        return Ok(interfaces.iter().cloned().collect());
    }
    default_route_interfaces()
}

#[cfg(target_os = "linux")]
fn default_route_interfaces() -> Result<Vec<String>> {
    let routes = std::fs::read_to_string("/proc/net/route")
        .context("failed to read /proc/net/route for XDP interface auto-selection")?;
    let mut interfaces = routes
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() > 2 && fields[1] == "00000000").then(|| fields[0].to_string())
        })
        .collect::<Vec<_>>();
    interfaces.sort();
    interfaces.dedup();
    if interfaces.is_empty() {
        bail!("failed to auto-select XDP interface from default route");
    }
    Ok(interfaces)
}

#[cfg(target_os = "linux")]
fn take_hash_map<K: Pod, V: Pod>(ebpf: &mut Ebpf, name: &str) -> Result<AyaHashMap<MapData, K, V>> {
    ebpf.take_map(name)
        .with_context(|| format!("XDP map '{name}' is missing from object"))?
        .try_into()
        .with_context(|| format!("XDP map '{name}' has an unexpected type or layout"))
}

#[cfg(target_os = "linux")]
fn take_lpm_map<V: Pod>(ebpf: &mut Ebpf, name: &str) -> Result<LpmTrie<MapData, XdpLpmData, V>> {
    ebpf.take_map(name)
        .with_context(|| format!("XDP LPM map '{name}' is missing from object"))?
        .try_into()
        .with_context(|| format!("XDP LPM map '{name}' has an unexpected type or layout"))
}

#[cfg(target_os = "linux")]
fn take_geo_lpm_map<V: Pod>(
    ebpf: &mut Ebpf,
    name: &str,
) -> Result<LpmTrie<MapData, XdpGeoLpmData, V>> {
    ebpf.take_map(name)
        .with_context(|| format!("XDP LPM map '{name}' is missing from object"))?
        .try_into()
        .with_context(|| format!("XDP LPM map '{name}' has an unexpected type or layout"))
}

#[cfg(target_os = "linux")]
fn take_array<V: Pod>(ebpf: &mut Ebpf, name: &str) -> Result<AyaArray<MapData, V>> {
    ebpf.take_map(name)
        .with_context(|| format!("XDP array map '{name}' is missing from object"))?
        .try_into()
        .with_context(|| format!("XDP array map '{name}' has an unexpected type or layout"))
}

#[cfg(target_os = "linux")]
fn delete_stale_hash_keys<K: Copy + Ord + Pod, V: Pod>(
    map: &mut AyaHashMap<MapData, K, V>,
    current: &BTreeSet<K>,
    next: &BTreeSet<K>,
) -> Result<()> {
    for key in current.difference(next) {
        map.remove(key)
            .context("failed to delete stale XDP hash key")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn delete_stale_lpm_keys<V: Pod>(
    map: &mut LpmTrie<MapData, XdpLpmData, V>,
    current: &BTreeSet<Vec<u8>>,
    next: &BTreeSet<Vec<u8>>,
) -> Result<()> {
    for raw in current.difference(next) {
        let key = decode_lpm_key_bytes(raw)?;
        map.remove(&key)
            .context("failed to delete stale XDP LPM key")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn delete_stale_geo_lpm_keys<V: Pod>(
    map: &mut LpmTrie<MapData, XdpGeoLpmData, V>,
    current: &BTreeSet<Vec<u8>>,
    next: &BTreeSet<Vec<u8>>,
) -> Result<()> {
    for raw in current.difference(next) {
        let key = decode_geo_lpm_key_bytes(raw)?;
        map.remove(&key)
            .context("failed to delete stale XDP geo LPM key")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn make_listener_key(l4_proto: u8, port: u16) -> XdpListenerKey {
    XdpListenerKey {
        l4_proto,
        pad: 0,
        dport: port.to_be(),
    }
}

#[cfg(target_os = "linux")]
fn make_ip_key(l4_proto: u8, port: u16, ip: IpAddr) -> XdpIpKey {
    let mut src = [0_u8; 16];
    let family = match ip {
        IpAddr::V4(ip) => {
            src[..4].copy_from_slice(&ip.octets());
            4
        }
        IpAddr::V6(ip) => {
            src.copy_from_slice(&ip.octets());
            6
        }
    };
    XdpIpKey {
        family,
        l4_proto,
        dport: port.to_be(),
        src,
    }
}

#[cfg(target_os = "linux")]
fn encode_listener_policy(policy: &XdpListenerPolicySpec) -> XdpListenerPolicy {
    XdpListenerPolicy {
        flags: policy.flags,
        packets_per_second: policy.packets_per_second,
        burst: policy.burst,
        udp_flood_packets_per_second: policy.udp_flood_packets_per_second,
        udp_flood_burst: policy.udp_flood_burst,
        tcp_flood_packets_per_second: policy.tcp_flood_packets_per_second,
        tcp_flood_burst: policy.tcp_flood_burst,
        tcp_syn_flood_packets_per_second: policy.tcp_syn_flood_packets_per_second,
        tcp_syn_flood_burst: policy.tcp_syn_flood_burst,
        tcp_ack_flood_packets_per_second: policy.tcp_ack_flood_packets_per_second,
        tcp_ack_flood_burst: policy.tcp_ack_flood_burst,
        icmp_flood_packets_per_second: policy.icmp_flood_packets_per_second,
        icmp_flood_burst: policy.icmp_flood_burst,
        geo_allow: policy.geo_allow,
        geo_deny: policy.geo_deny,
    }
}

#[cfg(target_os = "linux")]
fn make_lpm_key(l4_proto: u8, port: u16, addr: IpAddr, prefix: u8) -> LpmKey<XdpLpmData> {
    let family = match addr {
        IpAddr::V4(_) => 4_u8,
        IpAddr::V6(_) => 6_u8,
    };
    let mut bytes = [0_u8; 16];
    match addr {
        IpAddr::V4(ip) => {
            bytes[..4].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => bytes.copy_from_slice(&ip.octets()),
    }
    LpmKey::new(
        u32::from(32 + prefix),
        XdpLpmData {
            family,
            l4_proto,
            dport: port.to_be(),
            addr: bytes,
        },
    )
}

#[cfg(target_os = "linux")]
fn make_geo_lpm_key(addr: IpAddr, prefix: u8) -> LpmKey<XdpGeoLpmData> {
    let family = match addr {
        IpAddr::V4(_) => 4_u8,
        IpAddr::V6(_) => 6_u8,
    };
    let mut bytes = [0_u8; 16];
    match addr {
        IpAddr::V4(ip) => {
            bytes[..4].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => bytes.copy_from_slice(&ip.octets()),
    }
    LpmKey::new(
        u32::from(32 + prefix),
        XdpGeoLpmData {
            family,
            pad: [0; 3],
            addr: bytes,
        },
    )
}

#[cfg(target_os = "linux")]
fn encode_lpm_key_bytes(key: &LpmKey<XdpLpmData>) -> Vec<u8> {
    let data = key.data();
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&key.prefix_len().to_ne_bytes());
    out.push(data.family);
    out.push(data.l4_proto);
    out.extend_from_slice(&data.dport.to_ne_bytes());
    out.extend_from_slice(&data.addr);
    out
}

#[cfg(target_os = "linux")]
fn encode_geo_lpm_key_bytes(key: &LpmKey<XdpGeoLpmData>) -> Vec<u8> {
    let data = key.data();
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&key.prefix_len().to_ne_bytes());
    out.push(data.family);
    out.extend_from_slice(&data.pad);
    out.extend_from_slice(&data.addr);
    out
}

#[cfg(target_os = "linux")]
fn decode_lpm_key_bytes(raw: &[u8]) -> Result<LpmKey<XdpLpmData>> {
    if raw.len() != 24 {
        bail!("invalid encoded XDP LPM key length {}", raw.len());
    }
    let prefix_len = u32::from_ne_bytes(raw[0..4].try_into().unwrap());
    let mut addr = [0_u8; 16];
    addr.copy_from_slice(&raw[8..24]);
    Ok(LpmKey::new(
        prefix_len,
        XdpLpmData {
            family: raw[4],
            l4_proto: raw[5],
            dport: u16::from_ne_bytes(raw[6..8].try_into().unwrap()),
            addr,
        },
    ))
}

#[cfg(target_os = "linux")]
fn decode_geo_lpm_key_bytes(raw: &[u8]) -> Result<LpmKey<XdpGeoLpmData>> {
    if raw.len() != 24 {
        bail!("invalid encoded XDP geo LPM key length {}", raw.len());
    }
    let prefix_len = u32::from_ne_bytes(raw[0..4].try_into().unwrap());
    let mut addr = [0_u8; 16];
    addr.copy_from_slice(&raw[8..24]);
    Ok(LpmKey::new(
        prefix_len,
        XdpGeoLpmData {
            family: raw[4],
            pad: raw[5..8].try_into().unwrap(),
            addr,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        EffectiveProxyGeoSecurityConfig, EffectiveProxyIpRateLimitConfig,
        EffectiveProxySecurityConfig, EffectiveProxySecurityPrefilterConfig,
        EffectiveProxySipPolicyConfig, EffectiveProxySipRateLimitConfig, ProxyConfig,
        ProxyGeoUnknownCountryPolicy, ProxySecurityConfig, ProxySecurityPreset,
        ProxyXdpSecurityConfig,
    };
    use std::time::Duration;

    #[tokio::test]
    async fn fail_open_runtime_records_blocklist_sync_intent() {
        let runtime = XdpRuntime::new(
            &ProxyConfig {
                security: ProxySecurityConfig {
                    xdp: ProxyXdpSecurityConfig {
                        enabled: Some(true),
                        fail_open: Some(true),
                        sync_dynamic_ban: Some(true),
                        ..ProxyXdpSecurityConfig::default()
                    },
                    ..ProxySecurityConfig::default()
                },
                ..ProxyConfig::default()
            },
            None,
            None,
        )
        .unwrap();

        runtime
            .sync_ip_block(
                "udp/0.0.0.0:5060",
                "203.0.113.10".parse().unwrap(),
                Instant::now() + Duration::from_secs(60),
                "dynamic-ban",
            )
            .await;

        assert_eq!(runtime.control_plane_block_count().await, 1);
    }

    #[tokio::test]
    async fn xdp_control_plane_prunes_expired_blocks() {
        let runtime = XdpRuntime::new(
            &ProxyConfig {
                security: ProxySecurityConfig {
                    xdp: ProxyXdpSecurityConfig {
                        enabled: Some(true),
                        fail_open: Some(true),
                        sync_dynamic_ban: Some(true),
                        ..ProxyXdpSecurityConfig::default()
                    },
                    ..ProxySecurityConfig::default()
                },
                ..ProxyConfig::default()
            },
            None,
            None,
        )
        .unwrap();

        runtime
            .sync_ip_block(
                "udp/0.0.0.0:5060",
                "203.0.113.10".parse().unwrap(),
                Instant::now() - Duration::from_secs(1),
                "dynamic-ban",
            )
            .await;
        runtime.prune_expired().await;

        assert_eq!(runtime.control_plane_block_count().await, 0);
    }

    #[test]
    fn parses_xdp_cidr_prefixes() {
        assert_eq!(
            parse_xdp_cidr("203.0.113.0/24").unwrap(),
            XdpCidrPrefix {
                addr: "203.0.113.0".parse().unwrap(),
                prefix: 24
            }
        );
        assert_eq!(
            parse_xdp_cidr("2001:db8::/32").unwrap(),
            XdpCidrPrefix {
                addr: "2001:db8::".parse().unwrap(),
                prefix: 32
            }
        );
    }

    #[cfg(target_os = "linux")]
    fn xdp_test_policy(flags: u64) -> XdpListenerPolicySpec {
        XdpListenerPolicySpec {
            flags,
            packets_per_second: 0,
            burst: 0,
            udp_flood_packets_per_second: 0,
            udp_flood_burst: 0,
            tcp_flood_packets_per_second: 0,
            tcp_flood_burst: 0,
            tcp_syn_flood_packets_per_second: 0,
            tcp_syn_flood_burst: 0,
            tcp_ack_flood_packets_per_second: 0,
            tcp_ack_flood_burst: 0,
            icmp_flood_packets_per_second: 0,
            icmp_flood_burst: 0,
            geo_allow: [0; XDP_COUNTRY_WORDS],
            geo_deny: [0; XDP_COUNTRY_WORDS],
            trusted_cidrs: Vec::new(),
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            threat_intel: false,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn geo_cidrs_are_shared_across_xdp_listeners() {
        let policy = xdp_test_policy(XDP_POLICY_GEO_ENABLED);
        let listeners = vec![
            XdpListenerSpec {
                listener_key: "udp/0.0.0.0:5060".to_string(),
                l4_proto: XDP_PROTO_UDP,
                port: 5060,
                policy: policy.clone(),
            },
            XdpListenerSpec {
                listener_key: "tcp/0.0.0.0:5060".to_string(),
                l4_proto: XDP_PROTO_TCP,
                port: 5060,
                policy: policy.clone(),
            },
            XdpListenerSpec {
                listener_key: "udp/0.0.0.0:5092".to_string(),
                l4_proto: XDP_PROTO_UDP,
                port: 5092,
                policy: policy.clone(),
            },
            XdpListenerSpec {
                listener_key: "tcp/0.0.0.0:5092".to_string(),
                l4_proto: XDP_PROTO_TCP,
                port: 5092,
                policy,
            },
        ];
        let geo_prefixes = vec![
            crate::proxy::geo::GeoIpPrefix {
                addr: "203.0.113.0".parse().unwrap(),
                prefix: 24,
                country: u16::from_be_bytes(*b"US"),
            },
            crate::proxy::geo::GeoIpPrefix {
                addr: "198.51.100.0".parse().unwrap(),
                prefix: 24,
                country: u16::from_be_bytes(*b"HK"),
            },
        ];

        let keys = build_xdp_static_keys(&listeners, &geo_prefixes, &[]);

        assert_eq!(keys.geo_cidrs.len(), geo_prefixes.len());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn auto_sizes_deny_cidrs_for_threat_prefix_fanout() {
        assert_eq!(
            desired_xdp_map_entries(
                "deny_cidrs",
                19_846 * 5,
                XDP_DENY_CIDRS_DEFAULT_MAX_ENTRIES,
                262_144,
                true,
            )
            .unwrap(),
            262_144
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reports_deny_cidrs_capacity_when_auto_size_is_disabled() {
        let err = desired_xdp_map_entries(
            "deny_cidrs",
            19_846 * 5,
            XDP_DENY_CIDRS_DEFAULT_MAX_ENTRIES,
            262_144,
            false,
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("requires 99230 entries"));
    }

    #[test]
    fn encodes_country_bitset() {
        let mut bits = [0_u64; XDP_COUNTRY_WORDS];
        set_country_bit(&mut bits, "CN").unwrap();
        let bit = usize::from(b'C' - b'A') * 26 + usize::from(b'N' - b'A');
        assert_ne!(bits[bit / 64] & (1_u64 << (bit % 64)), 0);
    }

    #[test]
    fn listener_policy_includes_trusted_cidrs_and_xdp_flags() {
        let policy = XdpListenerPolicySpec::from_security(&EffectiveProxySecurityConfig {
            preset: ProxySecurityPreset::Public,
            trusted_cidrs: vec!["10.0.0.0/8".to_string()],
            allow_cidrs: vec!["0.0.0.0/0".to_string()],
            deny_cidrs: vec!["203.0.113.0/24".to_string()],
            prefilter: EffectiveProxySecurityPrefilterConfig {
                enabled: true,
                drop_invalid_start_line: true,
                drop_non_sip_methods: true,
                log_invalid_packets: true,
                invalid_log_sample_per_minute: 10,
            },
            geo: EffectiveProxyGeoSecurityConfig {
                enabled: true,
                unknown_country: ProxyGeoUnknownCountryPolicy::Deny,
                allow_countries: vec!["CN".to_string()],
                deny_countries: vec!["RU".to_string()],
                ..EffectiveProxyGeoSecurityConfig::default()
            },
            threat_intel: Default::default(),
            dynamic_ban: Default::default(),
            flood: Default::default(),
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
            xdp: crate::config::EffectiveProxyXdpSecurityConfig {
                enabled: true,
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
                max_geo_cidrs_entries: 262_144,
            },
        })
        .unwrap();

        assert_eq!(policy.trusted_cidrs.len(), 1);
        assert_eq!(policy.allow_cidrs.len(), 1);
        assert_eq!(policy.deny_cidrs.len(), 1);
        assert_ne!(policy.flags & XDP_POLICY_CIDR_ALLOW_ENABLED, 0);
        assert_ne!(policy.flags & XDP_POLICY_GEO_ENABLED, 0);
        assert_eq!(policy.flags & XDP_POLICY_GEO_UNKNOWN_ALLOW, 0);
        assert_ne!(policy.flags & XDP_POLICY_GEO_ALLOW_HAS_ENTRIES, 0);
        assert_ne!(policy.flags & XDP_POLICY_IP_RATE_LIMIT_ENABLED, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detects_bpffs_mount_from_proc_mounts() {
        let mounts = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\nbpf /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0\n";

        assert!(bpffs_mounted_in_proc_mounts(mounts, "/sys/fs/bpf"));
        assert!(!bpffs_mounted_in_proc_mounts(mounts, "/run/bpf"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn decodes_proc_mount_escaped_spaces() {
        let mounts = "bpf /sys/fs/my\\040bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0\n";

        assert!(bpffs_mounted_in_proc_mounts(mounts, "/sys/fs/my bpf"));
    }
}
