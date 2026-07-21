use crate::config::{
    EffectiveProxySecurityConfig, EffectiveProxyThreatIntelSecurityConfig,
    EffectiveProxyThreatIntelSourceConfig, ProxyGeoStartupRefresh, ProxyThreatIntelFormat,
};
use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::sleep;
use tracing::{info, warn};

const CACHE_MAGIC: &[u8; 4] = b"STHR";
const CACHE_VERSION: u16 = 1;
const CACHE_FILE_NAME: &str = "threat.sthr";
const THREAT_FETCH_CONCURRENCY: usize = 8;
const EMBEDDED_THREAT_CACHE: &[u8] = &[
    b'S', b'T', b'H', b'R', 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[derive(Debug, Clone)]
pub struct ThreatCacheBuildSource {
    pub name: String,
    pub url: String,
    pub format: ProxyThreatIntelFormat,
    pub min_score: Option<u32>,
}

pub async fn build_threat_cache(
    sources: Vec<ThreatCacheBuildSource>,
    output: &Path,
    timeout_seconds: u64,
    retries: u32,
    allow_partial: bool,
) -> Result<()> {
    let source = ThreatSourceConfig {
        cache_path: output.to_path_buf(),
        refresh_interval: Duration::from_secs(86_400),
        startup_refresh: ProxyGeoStartupRefresh::Disabled,
        request_timeout: Duration::from_secs(timeout_seconds),
        request_retries: retries.max(1),
        allow_partial,
        sources: sources
            .into_iter()
            .map(|source| EffectiveProxyThreatIntelSourceConfig {
                name: source.name,
                url: source.url,
                format: source.format,
                min_score: source.min_score,
            })
            .collect(),
    };
    let snapshot = fetch_threat_snapshot(&source).await?;
    write_cache(&source.cache_path, &snapshot)?;
    Ok(())
}

#[derive(Debug)]
pub struct ThreatRuntime {
    source: ThreatSourceConfig,
    snapshot: ArcSwap<ThreatSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct ThreatIpPrefix {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl ThreatRuntime {
    pub fn new(configs: &[EffectiveProxySecurityConfig]) -> Result<Option<Arc<Self>>> {
        let enabled_configs = configs
            .iter()
            .filter(|config| config.threat_intel.enabled)
            .map(|config| &config.threat_intel)
            .collect::<Vec<_>>();
        if enabled_configs.is_empty() {
            return Ok(None);
        }

        let source = ThreatSourceConfig::from_configs(&enabled_configs)?;
        let snapshot = load_cache_or_embedded(&source.cache_path)?;
        info!(
            cache = %source.cache_path.display(),
            ipv4_ranges = snapshot.ipv4.len(),
            ipv6_ranges = snapshot.ipv6.len(),
            startup_refresh = ?source.startup_refresh,
            "threat intel snapshot loaded"
        );
        Ok(Some(Arc::new(Self {
            source,
            snapshot: ArcSwap::from_pointee(snapshot),
        })))
    }

    pub async fn spawn_refresh_task(
        self: &Arc<Self>,
        shutdown: watch::Receiver<bool>,
    ) -> Option<JoinHandle<Result<()>>> {
        match self.source.startup_refresh {
            ProxyGeoStartupRefresh::Disabled => None,
            ProxyGeoStartupRefresh::Blocking => {
                if let Err(err) = self.refresh_once().await {
                    warn!(
                        error = %format!("{err:#}"),
                        "failed to refresh threat intel before starting listeners; using cached or embedded threat snapshot"
                    );
                }
                Some(tokio::spawn(self.clone().run_refresh_loop(shutdown)))
            }
            ProxyGeoStartupRefresh::Background => {
                Some(tokio::spawn(self.clone().run_refresh_loop(shutdown)))
            }
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.snapshot.load().contains(ip)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn xdp_prefixes(&self) -> Vec<ThreatIpPrefix> {
        self.snapshot.load().xdp_prefixes()
    }

    async fn run_refresh_loop(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        if let Err(err) = self.refresh_once().await {
            warn!(
                error = %format!("{err:#}"),
                "failed to refresh threat intel; using cached or embedded threat snapshot"
            );
        }

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = sleep(self.source.refresh_interval) => {
                    if let Err(err) = self.refresh_once().await {
                        warn!(
                            error = %format!("{err:#}"),
                            "failed to refresh threat intel; keeping previous threat snapshot"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    async fn refresh_once(&self) -> Result<()> {
        if self.source.sources.is_empty() {
            return Ok(());
        }
        let snapshot = fetch_threat_snapshot(&self.source).await?;
        write_cache(&self.source.cache_path, &snapshot)?;
        self.snapshot.store(Arc::new(snapshot));
        info!(
            cache = %self.source.cache_path.display(),
            sources = self.source.sources.len(),
            "threat intel cache refreshed"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ThreatPolicy {
    pub enabled: bool,
    pub fail_open: bool,
}

impl ThreatPolicy {
    pub fn from_config(config: &EffectiveProxyThreatIntelSecurityConfig) -> Self {
        Self {
            enabled: config.enabled,
            fail_open: config.fail_open,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatDecision {
    Allow,
    Drop(&'static str),
}

pub fn evaluate_threat_policy(
    policy: &ThreatPolicy,
    runtime: Option<&Arc<ThreatRuntime>>,
    ip: IpAddr,
) -> ThreatDecision {
    if !policy.enabled {
        return ThreatDecision::Allow;
    }
    let Some(runtime) = runtime else {
        return if policy.fail_open {
            ThreatDecision::Allow
        } else {
            ThreatDecision::Drop("threat-intel-unavailable")
        };
    };
    if runtime.contains(ip) {
        ThreatDecision::Drop("threat-intel")
    } else {
        ThreatDecision::Allow
    }
}

#[derive(Debug)]
struct ThreatSourceConfig {
    cache_path: PathBuf,
    refresh_interval: Duration,
    startup_refresh: ProxyGeoStartupRefresh,
    request_timeout: Duration,
    request_retries: u32,
    allow_partial: bool,
    sources: Vec<EffectiveProxyThreatIntelSourceConfig>,
}

impl ThreatSourceConfig {
    fn from_configs(configs: &[&EffectiveProxyThreatIntelSecurityConfig]) -> Result<Self> {
        let source = configs[0];
        for config in configs.iter().skip(1) {
            if config.cache_dir != source.cache_dir
                || config.refresh_interval_seconds != source.refresh_interval_seconds
                || config.startup_refresh != source.startup_refresh
                || config.request_timeout_seconds != source.request_timeout_seconds
                || config.request_retries != source.request_retries
                || config.allow_partial != source.allow_partial
                || config.sources != source.sources
            {
                bail!(
                    "all enabled proxy.security.threat_intel listener configs must use the same cache_dir, refresh_interval_seconds, startup_refresh, request_timeout_seconds, request_retries, allow_partial, and sources"
                );
            }
        }
        Ok(Self {
            cache_path: PathBuf::from(&source.cache_dir).join(CACHE_FILE_NAME),
            refresh_interval: Duration::from_secs(source.refresh_interval_seconds),
            startup_refresh: source.startup_refresh,
            request_timeout: Duration::from_secs(source.request_timeout_seconds),
            request_retries: source.request_retries,
            allow_partial: source.allow_partial,
            sources: source.sources.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ThreatSnapshot {
    created_at_epoch_seconds: u64,
    prefixes: Vec<ThreatIpPrefix>,
    ipv4: Vec<IpRangeV4>,
    ipv6: Vec<IpRangeV6>,
}

impl ThreatSnapshot {
    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => lookup_v4(&self.ipv4, u32::from(ip)),
            IpAddr::V6(ip) => lookup_v6(&self.ipv6, u128::from(ip)),
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn xdp_prefixes(&self) -> Vec<ThreatIpPrefix> {
        self.prefixes.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpRangeV4 {
    start: u32,
    end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpRangeV6 {
    start: u128,
    end: u128,
}

async fn fetch_threat_snapshot(source: &ThreatSourceConfig) -> Result<ThreatSnapshot> {
    let client = Client::builder().timeout(source.request_timeout).build()?;
    let mut prefixes = Vec::new();
    let mut loaded_sources = 0usize;
    let mut skipped_sources = 0usize;
    let mut sources = source.sources.iter().cloned();
    let mut tasks = JoinSet::new();
    for _ in 0..THREAT_FETCH_CONCURRENCY.min(source.sources.len()) {
        if let Some(feed) = sources.next() {
            spawn_threat_fetch(&mut tasks, &client, source.request_retries, feed);
        }
    }

    while let Some(result) = tasks.join_next().await {
        match result.context("threat intel fetch task failed")? {
            Ok((feed, body)) => match parse_threat_feed(&feed, &body) {
                Ok(mut parsed) => {
                    loaded_sources += 1;
                    prefixes.append(&mut parsed);
                }
                Err(err) if source.allow_partial => {
                    skipped_sources += 1;
                    warn!(
                        source = %feed.name,
                        error = %format!("{err:#}"),
                        "skipping threat intel source after parse failure while building partial snapshot"
                    );
                }
                Err(err) => return Err(err),
            },
            Err(err) if source.allow_partial => {
                skipped_sources += 1;
                warn!(
                    error = %format!("{err:#}"),
                    "skipping threat intel source after fetch failure while building partial snapshot"
                );
            }
            Err(err) => return Err(err),
        }
        if let Some(feed) = sources.next() {
            spawn_threat_fetch(&mut tasks, &client, source.request_retries, feed);
        }
    }

    if loaded_sources == 0 && skipped_sources > 0 {
        bail!("all threat intel sources failed");
    }

    Ok(build_snapshot(prefixes))
}

fn spawn_threat_fetch(
    tasks: &mut JoinSet<Result<(EffectiveProxyThreatIntelSourceConfig, String)>>,
    client: &Client,
    retries: u32,
    feed: EffectiveProxyThreatIntelSourceConfig,
) {
    let client = client.clone();
    tasks.spawn(async move {
        let mut last_err = None;
        for attempt in 1..=retries.max(1) {
            match client.get(&feed.url).send().await {
                Ok(response) => match response.error_for_status() {
                    Ok(response) => return Ok((feed, response.text().await?)),
                    Err(err) => last_err = Some(err.into()),
                },
                Err(err) => last_err = Some(err.into()),
            }
            if attempt < retries.max(1) {
                sleep(Duration::from_millis(200 * u64::from(attempt))).await;
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("empty retry loop")))
    });
}

fn parse_threat_feed(
    feed: &EffectiveProxyThreatIntelSourceConfig,
    body: &str,
) -> Result<Vec<ThreatIpPrefix>> {
    match feed.format {
        ProxyThreatIntelFormat::Cidr | ProxyThreatIntelFormat::Ips => parse_line_prefixes(body),
        ProxyThreatIntelFormat::Ipsum => parse_ipsum(body, feed.min_score.unwrap_or(1)),
        ProxyThreatIntelFormat::SpamhausDrop => parse_spamhaus_drop(body),
    }
    .with_context(|| format!("failed to parse threat intel source {}", feed.name))
}

fn parse_line_prefixes(body: &str) -> Result<Vec<ThreatIpPrefix>> {
    let mut prefixes = Vec::new();
    for line in body.lines() {
        let Some(token) = first_prefix_token(line) else {
            continue;
        };
        if let Some(prefix) = parse_prefix(token)? {
            prefixes.push(prefix);
        }
    }
    Ok(prefixes)
}

fn parse_ipsum(body: &str, min_score: u32) -> Result<Vec<ThreatIpPrefix>> {
    let mut prefixes = Vec::new();
    for line in body.lines() {
        let clean = strip_comment(line);
        let mut parts = clean.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        let score = parts
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1);
        if score < min_score {
            continue;
        }
        if let Some(prefix) = parse_prefix(ip)? {
            prefixes.push(prefix);
        }
    }
    Ok(prefixes)
}

fn parse_spamhaus_drop(body: &str) -> Result<Vec<ThreatIpPrefix>> {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        let mut prefixes = Vec::new();
        collect_json_cidrs(&value, &mut prefixes)?;
        if !prefixes.is_empty() {
            return Ok(prefixes);
        }
    }
    parse_line_prefixes(body)
}

fn collect_json_cidrs(value: &Value, prefixes: &mut Vec<ThreatIpPrefix>) -> Result<()> {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_json_cidrs(item, prefixes)?;
            }
        }
        Value::Object(map) => {
            if let Some(Value::String(cidr)) = map.get("cidr").or_else(|| map.get("prefix")) {
                if let Some(prefix) = parse_prefix(cidr)? {
                    prefixes.push(prefix);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn first_prefix_token(line: &str) -> Option<&str> {
    strip_comment(line)
        .split_whitespace()
        .find(|token| token.parse::<IpAddr>().is_ok() || token.contains('/'))
}

fn strip_comment(line: &str) -> &str {
    line.split(['#', ';']).next().unwrap_or("").trim()
}

fn parse_prefix(token: &str) -> Result<Option<ThreatIpPrefix>> {
    let token = token.trim().trim_matches(',').trim_matches('"');
    if token.is_empty() {
        return Ok(None);
    }
    if let Some((addr, prefix)) = token.split_once('/') {
        let addr = addr.parse::<IpAddr>()?;
        let prefix = prefix.parse::<u8>()?;
        validate_prefix(addr, prefix)?;
        return Ok(Some(ThreatIpPrefix { addr, prefix }));
    }
    let addr = token.parse::<IpAddr>()?;
    let prefix = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    Ok(Some(ThreatIpPrefix { addr, prefix }))
}

fn validate_prefix(addr: IpAddr, prefix: u8) -> Result<()> {
    match addr {
        IpAddr::V4(_) if prefix <= 32 => Ok(()),
        IpAddr::V6(_) if prefix <= 128 => Ok(()),
        IpAddr::V4(_) => bail!("IPv4 prefix length {prefix} exceeds 32"),
        IpAddr::V6(_) => bail!("IPv6 prefix length {prefix} exceeds 128"),
    }
}

fn build_snapshot(prefixes: Vec<ThreatIpPrefix>) -> ThreatSnapshot {
    let mut unique = HashSet::new();
    let mut normalized = Vec::new();
    for prefix in prefixes {
        let prefix = normalize_prefix(prefix);
        if unique.insert(prefix) {
            normalized.push(prefix);
        }
    }
    normalized.sort_by_key(|prefix| {
        (
            prefix.addr.is_ipv6(),
            ip_to_u128(prefix.addr),
            prefix.prefix,
        )
    });

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for prefix in &normalized {
        match prefix.addr {
            IpAddr::V4(addr) => {
                let (start, end) = prefix_range_v4(addr, prefix.prefix);
                ipv4.push(IpRangeV4 { start, end });
            }
            IpAddr::V6(addr) => {
                let (start, end) = prefix_range_v6(addr, prefix.prefix);
                ipv6.push(IpRangeV6 { start, end });
            }
        }
    }
    ipv4 = merge_v4_ranges(ipv4);
    ipv6 = merge_v6_ranges(ipv6);

    ThreatSnapshot {
        created_at_epoch_seconds: now_epoch_seconds(),
        prefixes: normalized,
        ipv4,
        ipv6,
    }
}

fn normalize_prefix(prefix: ThreatIpPrefix) -> ThreatIpPrefix {
    match prefix.addr {
        IpAddr::V4(addr) => {
            let (start, _) = prefix_range_v4(addr, prefix.prefix);
            ThreatIpPrefix {
                addr: IpAddr::V4(Ipv4Addr::from(start)),
                prefix: prefix.prefix,
            }
        }
        IpAddr::V6(addr) => {
            let (start, _) = prefix_range_v6(addr, prefix.prefix);
            ThreatIpPrefix {
                addr: IpAddr::V6(Ipv6Addr::from(start)),
                prefix: prefix.prefix,
            }
        }
    }
}

fn prefix_range_v4(addr: Ipv4Addr, prefix: u8) -> (u32, u32) {
    let value = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let start = value & mask;
    let end = start | !mask;
    (start, end)
}

fn prefix_range_v6(addr: Ipv6Addr, prefix: u8) -> (u128, u128) {
    let value = u128::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    let start = value & mask;
    let end = start | !mask;
    (start, end)
}

fn merge_v4_ranges(mut ranges: Vec<IpRangeV4>) -> Vec<IpRangeV4> {
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut merged: Vec<IpRangeV4> = Vec::new();
    for range in ranges {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    merged
}

fn merge_v6_ranges(mut ranges: Vec<IpRangeV6>) -> Vec<IpRangeV6> {
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut merged: Vec<IpRangeV6> = Vec::new();
    for range in ranges {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    merged
}

fn lookup_v4(ranges: &[IpRangeV4], ip: u32) -> bool {
    let mut low = 0usize;
    let mut high = ranges.len();
    while low < high {
        let mid = low + (high - low) / 2;
        let range = ranges[mid];
        if ip < range.start {
            high = mid;
        } else if ip > range.end {
            low = mid + 1;
        } else {
            return true;
        }
    }
    false
}

fn lookup_v6(ranges: &[IpRangeV6], ip: u128) -> bool {
    let mut low = 0usize;
    let mut high = ranges.len();
    while low < high {
        let mid = low + (high - low) / 2;
        let range = ranges[mid];
        if ip < range.start {
            high = mid;
        } else if ip > range.end {
            low = mid + 1;
        } else {
            return true;
        }
    }
    false
}

fn load_cache_or_embedded(path: &Path) -> Result<ThreatSnapshot> {
    match fs::read(path) {
        Ok(bytes) => {
            let snapshot = decode_cache(&bytes).with_context(|| {
                format!(
                    "failed to decode threat intel binary cache {}",
                    path.display()
                )
            })?;
            info!(
                cache = %path.display(),
                bytes = bytes.len(),
                "loaded threat intel binary cache from disk"
            );
            Ok(snapshot)
        }
        Err(err) => {
            warn!(
                cache = %path.display(),
                error = %err,
                "failed to read threat intel binary cache; using embedded empty threat snapshot"
            );
            decode_cache(EMBEDDED_THREAT_CACHE)
        }
    }
}

fn write_cache(path: &Path, snapshot: &ThreatSnapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create threat cache dir {}", parent.display()))?;
    }
    let tmp_path = path.with_extension("tmp");
    let bytes = encode_cache(snapshot)?;
    let mut file = fs::File::create(&tmp_path).with_context(|| {
        format!(
            "failed to create threat cache temp file {}",
            tmp_path.display()
        )
    })?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("failed to replace threat cache {}", path.display()))?;
    Ok(())
}

fn encode_cache(snapshot: &ThreatSnapshot) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(18 + snapshot.prefixes.len() * 18);
    bytes.extend_from_slice(CACHE_MAGIC);
    bytes.extend_from_slice(&CACHE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&snapshot.created_at_epoch_seconds.to_be_bytes());
    bytes.extend_from_slice(&(snapshot.prefixes.len() as u32).to_be_bytes());
    for prefix in &snapshot.prefixes {
        match prefix.addr {
            IpAddr::V4(addr) => {
                bytes.push(4);
                bytes.push(prefix.prefix);
                bytes.extend_from_slice(&u128::from(u32::from(addr)).to_be_bytes());
            }
            IpAddr::V6(addr) => {
                bytes.push(6);
                bytes.push(prefix.prefix);
                bytes.extend_from_slice(&u128::from(addr).to_be_bytes());
            }
        }
    }
    Ok(bytes)
}

fn decode_cache(bytes: &[u8]) -> Result<ThreatSnapshot> {
    if bytes.len() < 18 {
        bail!("threat intel cache too short");
    }
    if &bytes[0..4] != CACHE_MAGIC {
        bail!("invalid threat intel cache magic");
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != CACHE_VERSION {
        bail!("unsupported threat intel cache version {version}");
    }
    let created_at_epoch_seconds = u64::from_be_bytes(bytes[6..14].try_into()?);
    let count = u32::from_be_bytes(bytes[14..18].try_into()?) as usize;
    let expected = 18 + count * 18;
    if bytes.len() != expected {
        bail!(
            "invalid threat intel cache length {}, expected {expected}",
            bytes.len()
        );
    }
    let mut prefixes = Vec::with_capacity(count);
    let mut offset = 18usize;
    for _ in 0..count {
        let family = bytes[offset];
        let prefix = bytes[offset + 1];
        let value = u128::from_be_bytes(bytes[offset + 2..offset + 18].try_into()?);
        offset += 18;
        let addr = match family {
            4 => {
                validate_prefix(IpAddr::V4(Ipv4Addr::UNSPECIFIED), prefix)?;
                IpAddr::V4(Ipv4Addr::from(value as u32))
            }
            6 => {
                validate_prefix(IpAddr::V6(Ipv6Addr::UNSPECIFIED), prefix)?;
                IpAddr::V6(Ipv6Addr::from(value))
            }
            _ => bail!("invalid threat intel cache address family {family}"),
        };
        prefixes.push(ThreatIpPrefix { addr, prefix });
    }
    let mut snapshot = build_snapshot(prefixes);
    snapshot.created_at_epoch_seconds = created_at_epoch_seconds;
    Ok(snapshot)
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(ip) => u128::from(u32::from(ip)),
        IpAddr::V6(ip) => u128::from(ip),
    }
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipsum_with_min_score() {
        let prefixes = parse_ipsum("1.1.1.1 2\n2.2.2.0/24 5\n", 3).unwrap();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].addr, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 0)));
        assert_eq!(prefixes[0].prefix, 24);
    }

    #[test]
    fn snapshot_lookup_matches_merged_ranges() {
        let snapshot = build_snapshot(vec![ThreatIpPrefix {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix: 8,
        }]);
        assert!(snapshot.contains(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10))));
        assert!(!snapshot.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn cache_round_trip_preserves_prefixes() {
        let snapshot = build_snapshot(vec![
            ThreatIpPrefix {
                addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                prefix: 32,
            },
            ThreatIpPrefix {
                addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                prefix: 128,
            },
        ]);
        let decoded = decode_cache(&encode_cache(&snapshot).unwrap()).unwrap();
        assert!(decoded.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(decoded.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }
}
