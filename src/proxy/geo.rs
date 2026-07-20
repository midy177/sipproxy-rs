use crate::config::{
    EffectiveProxyGeoSecurityConfig, EffectiveProxySecurityConfig, ProxyGeoProvider,
    ProxyGeoStartupRefresh,
};
use anyhow::{Context, Result, bail};
use reqwest::Client;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::sleep;
use tracing::{info, warn};

const CACHE_MAGIC: &[u8; 4] = b"SGEO";
const CACHE_VERSION: u16 = 1;
const CACHE_FILE_NAME: &str = "geo.sgeo";
const GEO_FETCH_CONCURRENCY: usize = 16;
const EMBEDDED_GEO_CACHE: &[u8] = &[
    b'S', b'G', b'E', b'O', 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

const ALL_COUNTRIES: &[&str] = &[
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AR", "AS", "AT", "AU", "AW", "AX", "AZ", "BA",
    "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BW",
    "BY", "BZ", "CA", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV",
    "CW", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "ER", "ES", "ET", "FI",
    "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN",
    "GP", "GQ", "GR", "GT", "GU", "GW", "GY", "HK", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM",
    "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
    "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY",
    "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS",
    "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP",
    "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PR", "PS", "PT", "PW",
    "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SI", "SK", "SL",
    "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TG", "TH", "TJ", "TK",
    "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "US", "UY", "UZ", "VA", "VC",
    "VE", "VG", "VI", "VN", "VU", "WS", "YE", "YT", "ZA", "ZM", "ZW",
];

pub async fn build_ipdeny_cache(
    countries: &[String],
    output: &Path,
    provider_base_url: &str,
    timeout_seconds: u64,
    retries: u32,
    allow_partial: bool,
) -> Result<()> {
    let countries = expand_country_selection(countries)?;
    let source = GeoSourceConfig {
        provider: ProxyGeoProvider::Ipdeny,
        provider_base_url: provider_base_url.to_string(),
        cache_path: output.to_path_buf(),
        refresh_interval: Duration::from_secs(86_400),
        startup_refresh: ProxyGeoStartupRefresh::Disabled,
        request_timeout: Duration::from_secs(timeout_seconds),
        request_retries: retries.max(1),
        allow_partial,
        countries,
    };
    let snapshot = fetch_geo_snapshot(&source).await?;
    write_cache(&source.cache_path, &snapshot)?;
    Ok(())
}

#[derive(Debug)]
pub struct GeoRuntime {
    source: GeoSourceConfig,
    snapshot: RwLock<Arc<GeoSnapshot>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct GeoIpPrefix {
    pub addr: IpAddr,
    pub prefix: u8,
    pub country: u16,
}

impl GeoRuntime {
    pub fn new(configs: &[EffectiveProxySecurityConfig]) -> Result<Option<Arc<Self>>> {
        let enabled_configs = configs
            .iter()
            .filter(|config| config.geo.enabled)
            .map(|config| &config.geo)
            .collect::<Vec<_>>();
        if enabled_configs.is_empty() {
            return Ok(None);
        }

        let source = GeoSourceConfig::from_configs(&enabled_configs)?;
        let snapshot = load_cache_or_embedded(&source.cache_path)?;
        info!(
            cache = %source.cache_path.display(),
            ipv4_ranges = snapshot.ipv4.len(),
            ipv6_ranges = snapshot.ipv6.len(),
            startup_refresh = ?source.startup_refresh,
            "geo snapshot loaded"
        );
        Ok(Some(Arc::new(Self {
            source,
            snapshot: RwLock::new(Arc::new(snapshot)),
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
                        "failed to refresh geo cache before starting listeners; using cached or embedded geo snapshot"
                    );
                }
                Some(tokio::spawn(self.clone().run_refresh_loop(shutdown)))
            }
            ProxyGeoStartupRefresh::Background => {
                Some(tokio::spawn(self.clone().run_refresh_loop(shutdown)))
            }
        }
    }

    fn lookup_country_code(&self, ip: IpAddr) -> Option<u16> {
        let snapshot = self
            .snapshot
            .read()
            .expect("geo snapshot lock poisoned")
            .clone();
        snapshot.lookup_country(ip)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn xdp_prefixes(&self) -> Vec<GeoIpPrefix> {
        self.snapshot
            .read()
            .expect("geo snapshot lock poisoned")
            .xdp_prefixes()
    }

    async fn run_refresh_loop(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        if let Err(err) = self.refresh_once().await {
            warn!(
                error = %format!("{err:#}"),
                "failed to refresh geo cache; using cached or embedded geo snapshot"
            );
        }

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = sleep(self.source.refresh_interval) => {
                    if let Err(err) = self.refresh_once().await {
                        warn!(
                            error = %format!("{err:#}"),
                            "failed to refresh geo cache; keeping previous geo snapshot"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    async fn refresh_once(&self) -> Result<()> {
        if self.source.countries.is_empty() {
            return Ok(());
        }
        let snapshot = fetch_geo_snapshot(&self.source).await?;
        write_cache(&self.source.cache_path, &snapshot)?;
        *self.snapshot.write().expect("geo snapshot lock poisoned") = Arc::new(snapshot);
        info!(
            cache = %self.source.cache_path.display(),
            countries = self.source.countries.len(),
            "geo cache refreshed"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GeoPolicy {
    pub enabled: bool,
    pub fail_open: bool,
    pub unknown_country_allows: bool,
    allow_countries: Vec<u16>,
    deny_countries: Vec<u16>,
}

impl GeoPolicy {
    pub fn from_config(config: &EffectiveProxyGeoSecurityConfig) -> Self {
        Self {
            enabled: config.enabled,
            fail_open: config.fail_open,
            unknown_country_allows: matches!(
                config.unknown_country,
                crate::config::ProxyGeoUnknownCountryPolicy::Allow
            ),
            allow_countries: config
                .allow_countries
                .iter()
                .filter_map(|country| encode_country(country).ok())
                .collect(),
            deny_countries: config
                .deny_countries
                .iter()
                .filter_map(|country| encode_country(country).ok())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoDecision {
    Allow,
    Drop(&'static str),
}

pub fn evaluate_geo_policy(
    policy: &GeoPolicy,
    runtime: Option<&Arc<GeoRuntime>>,
    ip: IpAddr,
) -> GeoDecision {
    if !policy.enabled {
        return GeoDecision::Allow;
    }
    let Some(runtime) = runtime else {
        return if policy.fail_open {
            GeoDecision::Allow
        } else {
            GeoDecision::Drop("geo-unavailable")
        };
    };
    let Some(country) = runtime.lookup_country_code(ip) else {
        return if policy.unknown_country_allows {
            GeoDecision::Allow
        } else {
            GeoDecision::Drop("geo-unknown-country")
        };
    };
    if policy.deny_countries.contains(&country) {
        return GeoDecision::Drop("geo-deny-country");
    }
    if !policy.allow_countries.is_empty() && !policy.allow_countries.contains(&country) {
        return GeoDecision::Drop("geo-not-allowed-country");
    }
    GeoDecision::Allow
}

#[derive(Debug)]
struct GeoSourceConfig {
    provider: ProxyGeoProvider,
    provider_base_url: String,
    cache_path: PathBuf,
    refresh_interval: Duration,
    startup_refresh: ProxyGeoStartupRefresh,
    request_timeout: Duration,
    request_retries: u32,
    allow_partial: bool,
    countries: Vec<String>,
}

impl GeoSourceConfig {
    fn from_configs(configs: &[&EffectiveProxyGeoSecurityConfig]) -> Result<Self> {
        let source = configs[0];
        for config in configs.iter().skip(1) {
            if config.provider != source.provider
                || config.provider_base_url != source.provider_base_url
                || config.cache_dir != source.cache_dir
                || config.refresh_interval_seconds != source.refresh_interval_seconds
                || config.startup_refresh != source.startup_refresh
                || config.request_timeout_seconds != source.request_timeout_seconds
            {
                bail!(
                    "all enabled proxy.security.geo listener configs must use the same provider, provider_base_url, cache_dir, refresh_interval_seconds, startup_refresh, and request_timeout_seconds"
                );
            }
        }
        let mut countries = HashSet::new();
        for config in configs {
            countries.extend(
                config
                    .allow_countries
                    .iter()
                    .map(|country| country.to_string()),
            );
            countries.extend(
                config
                    .deny_countries
                    .iter()
                    .map(|country| country.to_string()),
            );
        }
        let mut countries = countries.into_iter().collect::<Vec<_>>();
        countries.sort();
        Ok(Self {
            provider: source.provider,
            provider_base_url: source.provider_base_url.clone(),
            cache_path: PathBuf::from(&source.cache_dir).join(CACHE_FILE_NAME),
            refresh_interval: Duration::from_secs(source.refresh_interval_seconds),
            startup_refresh: source.startup_refresh,
            request_timeout: Duration::from_secs(source.request_timeout_seconds),
            request_retries: 3,
            allow_partial: false,
            countries,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeoSnapshot {
    created_at_epoch_seconds: u64,
    ipv4: Vec<IpRangeV4>,
    ipv6: Vec<IpRangeV6>,
}

impl GeoSnapshot {
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            created_at_epoch_seconds: 0,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        }
    }

    fn lookup_country(&self, ip: IpAddr) -> Option<u16> {
        match ip {
            IpAddr::V4(ip) => lookup_v4(&self.ipv4, u32::from(ip)),
            IpAddr::V6(ip) => lookup_v6(&self.ipv6, u128::from(ip)),
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn xdp_prefixes(&self) -> Vec<GeoIpPrefix> {
        let mut prefixes = Vec::new();
        for range in &self.ipv4 {
            append_range_prefixes(
                u128::from(range.start),
                u128::from(range.end),
                32,
                range.country,
                &mut prefixes,
            );
        }
        for range in &self.ipv6 {
            append_range_prefixes(range.start, range.end, 128, range.country, &mut prefixes);
        }
        prefixes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpRangeV4 {
    start: u32,
    end: u32,
    country: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpRangeV6 {
    start: u128,
    end: u128,
    country: u16,
}

async fn fetch_geo_snapshot(source: &GeoSourceConfig) -> Result<GeoSnapshot> {
    let client = Client::builder().timeout(source.request_timeout).build()?;
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut loaded_countries = 0usize;
    let mut skipped_countries = 0usize;
    let mut countries = source.countries.iter().cloned();
    let mut tasks = JoinSet::new();
    for _ in 0..GEO_FETCH_CONCURRENCY.min(source.countries.len()) {
        if let Some(country) = countries.next() {
            spawn_geo_fetch(
                &mut tasks,
                &client,
                source.provider,
                &source.provider_base_url,
                source.request_retries,
                country,
            );
        }
    }

    while let Some(result) = tasks.join_next().await {
        match result.context("geo fetch task failed")? {
            Ok((country, body)) => {
                match append_country_ranges(&country, &body, &mut ipv4, &mut ipv6)
                    .with_context(|| format!("failed to parse geo ranges for {country}"))
                {
                    Ok(()) => {
                        loaded_countries += 1;
                    }
                    Err(err) if source.allow_partial => {
                        skipped_countries += 1;
                        warn!(
                            country = %country,
                            error = %format!("{err:#}"),
                            "skipping geo country after parse failure while building partial geo snapshot"
                        );
                    }
                    Err(err) => return Err(err),
                }
            }
            Err(err) if source.allow_partial => {
                skipped_countries += 1;
                warn!(
                    error = %format!("{err:#}"),
                    "skipping geo country after fetch failure while building partial geo snapshot"
                );
            }
            Err(err) => return Err(err),
        }
        if let Some(country) = countries.next() {
            spawn_geo_fetch(
                &mut tasks,
                &client,
                source.provider,
                &source.provider_base_url,
                source.request_retries,
                country,
            );
        }
    }
    if loaded_countries == 0 && !source.countries.is_empty() {
        bail!("failed to fetch any geo country ranges");
    }
    if skipped_countries > 0 {
        warn!(
            loaded_countries,
            skipped_countries, "built partial geo snapshot"
        );
    }
    normalize_v4_ranges(&mut ipv4);
    normalize_v6_ranges(&mut ipv6);
    validate_non_overlapping_v4(&ipv4)?;
    validate_non_overlapping_v6(&ipv6)?;
    Ok(GeoSnapshot {
        created_at_epoch_seconds: unix_now_seconds(),
        ipv4,
        ipv6,
    })
}

fn spawn_geo_fetch(
    tasks: &mut JoinSet<Result<(String, String)>>,
    client: &Client,
    provider: ProxyGeoProvider,
    provider_base_url: &str,
    request_retries: u32,
    country: String,
) {
    let client = client.clone();
    let provider_base_url = provider_base_url.to_string();
    tasks.spawn(async move {
        let body = fetch_country_body_with_retries(
            &client,
            provider,
            &provider_base_url,
            &country,
            request_retries,
        )
        .await
        .with_context(|| format!("failed to fetch geo ranges for {country}"))?;
        Ok((country, body))
    });
}

async fn fetch_country_body_with_retries(
    client: &Client,
    provider: ProxyGeoProvider,
    provider_base_url: &str,
    country: &str,
    request_retries: u32,
) -> Result<String> {
    let attempts = request_retries.max(1);
    let mut last_error = None;
    for attempt in 1..=attempts {
        match fetch_country_body(client, provider, provider_base_url, country).await {
            Ok(body) => return Ok(body),
            Err(err) => {
                last_error = Some(err);
                if attempt < attempts {
                    let backoff = Duration::from_millis(200 * u64::from(attempt));
                    sleep(backoff).await;
                }
            }
        }
    }
    Err(last_error.expect("at least one geo fetch attempt is made"))
}

async fn fetch_country_body(
    client: &Client,
    provider: ProxyGeoProvider,
    provider_base_url: &str,
    country: &str,
) -> Result<String> {
    match provider {
        ProxyGeoProvider::Ipdeny => {
            let url = render_provider_url(provider_base_url, country);
            Ok(client
                .get(url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?)
        }
    }
}

fn render_provider_url(template: &str, country: &str) -> String {
    template
        .replace("{country}", &country.to_ascii_lowercase())
        .replace("{COUNTRY}", &country.to_ascii_uppercase())
}

fn expand_country_selection(values: &[String]) -> Result<Vec<String>> {
    let mut countries = HashSet::new();
    for value in values {
        for country in value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if country.eq_ignore_ascii_case("all") {
                countries.extend(ALL_COUNTRIES.iter().map(|country| (*country).to_string()));
            } else {
                countries.insert(decode_country(encode_country(country)?));
            }
        }
    }
    let mut countries = countries.into_iter().collect::<Vec<_>>();
    countries.sort();
    if countries.is_empty() {
        bail!("at least one country or 'all' is required");
    }
    Ok(countries)
}

fn append_country_ranges(
    country: &str,
    body: &str,
    ipv4: &mut Vec<IpRangeV4>,
    ipv6: &mut Vec<IpRangeV6>,
) -> Result<()> {
    let country = encode_country(country)?;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (addr, prefix) = parse_cidr_parts(line)?;
        match addr {
            IpAddr::V4(addr) => {
                let (start, end) = ipv4_range(addr, prefix)?;
                ipv4.push(IpRangeV4 {
                    start,
                    end,
                    country,
                });
            }
            IpAddr::V6(addr) => {
                let (start, end) = ipv6_range(addr, prefix)?;
                ipv6.push(IpRangeV6 {
                    start,
                    end,
                    country,
                });
            }
        }
    }
    Ok(())
}

fn load_cache_or_embedded(cache_path: &PathBuf) -> Result<GeoSnapshot> {
    match fs::read(cache_path) {
        Ok(bytes) => match decode_cache(&bytes) {
            Ok(snapshot) => {
                info!(
                    cache = %cache_path.display(),
                    bytes = bytes.len(),
                    "loaded geo binary cache from disk"
                );
                Ok(snapshot)
            }
            Err(err) => {
                warn!(
                    cache = %cache_path.display(),
                    error = %format!("{err:#}"),
                    "geo binary cache rejected; using embedded empty geo snapshot; rebuild the cache with `sigproxy geo-cache build`"
                );
                decode_cache(EMBEDDED_GEO_CACHE)
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            warn!(
                cache = %cache_path.display(),
                "geo binary cache not found; using embedded empty geo snapshot"
            );
            decode_cache(EMBEDDED_GEO_CACHE)
        }
        Err(err) => {
            warn!(
                cache = %cache_path.display(),
                error = %err,
                "failed to open geo binary cache; using embedded geo snapshot"
            );
            decode_cache(EMBEDDED_GEO_CACHE)
        }
    }
}

fn write_cache(cache_path: &PathBuf, snapshot: &GeoSnapshot) -> Result<()> {
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create geo cache dir {}", parent.display()))?;
    }
    let tmp_path = cache_path.with_extension("sgeo.tmp");
    let bytes = encode_cache(snapshot)?;
    {
        let mut file = fs::File::create(&tmp_path)
            .with_context(|| format!("failed to write geo cache {}", tmp_path.display()))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, cache_path).with_context(|| {
        format!(
            "failed to replace geo cache {} with {}",
            cache_path.display(),
            tmp_path.display()
        )
    })?;
    Ok(())
}

fn encode_cache(snapshot: &GeoSnapshot) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(22 + snapshot.ipv4.len() * 10 + snapshot.ipv6.len() * 34);
    out.extend_from_slice(CACHE_MAGIC);
    out.extend_from_slice(&CACHE_VERSION.to_be_bytes());
    out.extend_from_slice(&snapshot.created_at_epoch_seconds.to_be_bytes());
    out.extend_from_slice(&(snapshot.ipv4.len() as u32).to_be_bytes());
    out.extend_from_slice(&(snapshot.ipv6.len() as u32).to_be_bytes());
    for range in &snapshot.ipv4 {
        out.extend_from_slice(&range.start.to_be_bytes());
        out.extend_from_slice(&range.end.to_be_bytes());
        out.extend_from_slice(&range.country.to_be_bytes());
    }
    for range in &snapshot.ipv6 {
        out.extend_from_slice(&range.start.to_be_bytes());
        out.extend_from_slice(&range.end.to_be_bytes());
        out.extend_from_slice(&range.country.to_be_bytes());
    }
    Ok(out)
}

fn decode_cache(bytes: &[u8]) -> Result<GeoSnapshot> {
    let mut reader = CacheReader::new(bytes);
    if reader.take(4)? != CACHE_MAGIC {
        bail!("invalid geo cache magic");
    }
    let version = reader.u16()?;
    if version != CACHE_VERSION {
        bail!("unsupported geo cache version {version}");
    }
    let created_at_epoch_seconds = reader.u64()?;
    let v4_count = reader.u32()? as usize;
    let v6_count = reader.u32()? as usize;
    let mut ipv4 = Vec::with_capacity(v4_count);
    for _ in 0..v4_count {
        ipv4.push(IpRangeV4 {
            start: reader.u32()?,
            end: reader.u32()?,
            country: reader.u16()?,
        });
    }
    let mut ipv6 = Vec::with_capacity(v6_count);
    for _ in 0..v6_count {
        ipv6.push(IpRangeV6 {
            start: reader.u128()?,
            end: reader.u128()?,
            country: reader.u16()?,
        });
    }
    if !reader.is_empty() {
        bail!("trailing bytes in geo cache");
    }
    validate_non_overlapping_v4(&ipv4)?;
    validate_non_overlapping_v6(&ipv6)?;
    Ok(GeoSnapshot {
        created_at_epoch_seconds,
        ipv4,
        ipv6,
    })
}

struct CacheReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CacheReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .context("geo cache offset overflow")?;
        if end > self.bytes.len() {
            bail!("truncated geo cache");
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn lookup_v4(ranges: &[IpRangeV4], ip: u32) -> Option<u16> {
    let mut low = 0;
    let mut high = ranges.len();
    while low < high {
        let mid = low + (high - low) / 2;
        let range = ranges[mid];
        if ip < range.start {
            high = mid;
        } else if ip > range.end {
            low = mid + 1;
        } else {
            return Some(range.country);
        }
    }
    None
}

fn lookup_v6(ranges: &[IpRangeV6], ip: u128) -> Option<u16> {
    let mut low = 0;
    let mut high = ranges.len();
    while low < high {
        let mid = low + (high - low) / 2;
        let range = ranges[mid];
        if ip < range.start {
            high = mid;
        } else if ip > range.end {
            low = mid + 1;
        } else {
            return Some(range.country);
        }
    }
    None
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn append_range_prefixes(
    mut start: u128,
    end: u128,
    bits: u8,
    country: u16,
    prefixes: &mut Vec<GeoIpPrefix>,
) {
    while start <= end {
        let aligned_bits = if start == 0 {
            bits
        } else {
            (start.trailing_zeros() as u8).min(bits)
        };
        let mut prefix = bits - aligned_bits;
        loop {
            let block_bits = bits - prefix;
            let block_end = prefix_block_end(start, block_bits);
            if block_end <= end {
                prefixes.push(GeoIpPrefix {
                    addr: prefix_addr(start, bits),
                    prefix,
                    country,
                });
                if block_end == u128::MAX {
                    return;
                }
                start = block_end + 1;
                break;
            }
            prefix += 1;
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn prefix_block_end(start: u128, block_bits: u8) -> u128 {
    if block_bits == 128 {
        u128::MAX
    } else {
        start + ((1_u128 << block_bits) - 1)
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn prefix_addr(value: u128, bits: u8) -> IpAddr {
    if bits == 32 {
        IpAddr::V4(Ipv4Addr::from(value as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(value))
    }
}

fn normalize_v4_ranges(ranges: &mut Vec<IpRangeV4>) {
    ranges.sort_by_key(|range| (range.start, range.end, range.country));
    let mut normalized: Vec<IpRangeV4> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(last) = normalized.last_mut()
            && last.country == range.country
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
            continue;
        }
        normalized.push(range);
    }
    *ranges = normalized;
}

fn normalize_v6_ranges(ranges: &mut Vec<IpRangeV6>) {
    ranges.sort_by_key(|range| (range.start, range.end, range.country));
    let mut normalized: Vec<IpRangeV6> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(last) = normalized.last_mut()
            && last.country == range.country
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
            continue;
        }
        normalized.push(range);
    }
    *ranges = normalized;
}

fn validate_non_overlapping_v4(ranges: &[IpRangeV4]) -> Result<()> {
    for pair in ranges.windows(2) {
        if pair[0].end >= pair[1].start {
            bail!("geo IPv4 cache contains overlapping ranges");
        }
    }
    Ok(())
}

fn validate_non_overlapping_v6(ranges: &[IpRangeV6]) -> Result<()> {
    for pair in ranges.windows(2) {
        if pair[0].end >= pair[1].start {
            bail!("geo IPv6 cache contains overlapping ranges");
        }
    }
    Ok(())
}

fn parse_cidr_parts(value: &str) -> Result<(IpAddr, u8)> {
    if let Some((addr, prefix)) = value.split_once('/') {
        let addr = addr.parse::<IpAddr>()?;
        let prefix = prefix.parse::<u8>()?;
        Ok((addr, prefix))
    } else {
        let addr = value.parse::<IpAddr>()?;
        let prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Ok((addr, prefix))
    }
}

fn ipv4_range(addr: Ipv4Addr, prefix: u8) -> Result<(u32, u32)> {
    if prefix > 32 {
        bail!("IPv4 prefix must be at most 32");
    }
    let addr = u32::from(addr);
    if prefix == 0 {
        return Ok((0, u32::MAX));
    }
    let mask = u32::MAX << (32 - prefix);
    let start = addr & mask;
    let end = start | !mask;
    Ok((start, end))
}

fn ipv6_range(addr: Ipv6Addr, prefix: u8) -> Result<(u128, u128)> {
    if prefix > 128 {
        bail!("IPv6 prefix must be at most 128");
    }
    let addr = u128::from(addr);
    if prefix == 0 {
        return Ok((0, u128::MAX));
    }
    let mask = u128::MAX << (128 - prefix);
    let start = addr & mask;
    let end = start | !mask;
    Ok((start, end))
}

fn encode_country(value: &str) -> Result<u16> {
    let value = value.trim().as_bytes();
    if value.len() != 2 || !value.iter().all(u8::is_ascii_alphabetic) {
        bail!("invalid country code");
    }
    Ok(u16::from_be_bytes([
        value[0].to_ascii_uppercase(),
        value[1].to_ascii_uppercase(),
    ]))
}

fn decode_country(value: u16) -> String {
    let bytes = value.to_be_bytes();
    String::from_utf8_lossy(&bytes).to_string()
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
pub(crate) fn test_cache_bytes(country: &str, body: &str) -> Vec<u8> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    append_country_ranges(country, body, &mut ipv4, &mut ipv6).unwrap();
    normalize_v4_ranges(&mut ipv4);
    normalize_v6_ranges(&mut ipv6);
    encode_cache(&GeoSnapshot {
        created_at_epoch_seconds: 1,
        ipv4,
        ipv6,
    })
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn binary_cache_round_trips_and_lookups_ranges() {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        append_country_ranges("CN", "1.2.3.0/24\n2001:db8::/32\n", &mut ipv4, &mut ipv6).unwrap();
        normalize_v4_ranges(&mut ipv4);
        normalize_v6_ranges(&mut ipv6);
        let snapshot = GeoSnapshot {
            created_at_epoch_seconds: 7,
            ipv4,
            ipv6,
        };

        let decoded = decode_cache(&encode_cache(&snapshot).unwrap()).unwrap();
        assert_eq!(
            decoded.lookup_country("1.2.3.4".parse().unwrap()),
            Some(encode_country("CN").unwrap())
        );
        assert_eq!(
            decoded.lookup_country("2001:db8::1".parse().unwrap()),
            Some(encode_country("CN").unwrap())
        );
        assert_eq!(decoded.lookup_country("1.2.4.1".parse().unwrap()), None);
    }

    #[test]
    fn embedded_cache_decodes_to_empty_snapshot() {
        assert_eq!(
            decode_cache(EMBEDDED_GEO_CACHE).unwrap(),
            GeoSnapshot::empty()
        );
    }

    #[test]
    fn all_country_selection_excludes_ipdeny_region_aggregate_zones() {
        let countries = expand_country_selection(&["all".to_string()]).unwrap();

        assert!(countries.contains(&"CN".to_string()));
        assert!(countries.contains(&"US".to_string()));
        assert!(!countries.contains(&"AP".to_string()));
        assert!(!countries.contains(&"EU".to_string()));
    }

    #[test]
    fn rejected_disk_cache_falls_back_to_embedded_snapshot() {
        let cache_dir = tempfile::tempdir().unwrap();
        let cache_path = cache_dir.path().join(CACHE_FILE_NAME);
        fs::write(&cache_path, b"bad-cache").unwrap();

        assert_eq!(
            load_cache_or_embedded(&cache_path).unwrap(),
            GeoSnapshot::empty()
        );
    }

    #[test]
    fn normalizes_overlapping_same_country_ranges() {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        append_country_ranges("CN", "1.0.0.0/8\n1.2.3.0/24\n", &mut ipv4, &mut ipv6).unwrap();
        normalize_v4_ranges(&mut ipv4);
        validate_non_overlapping_v4(&ipv4).unwrap();
        let snapshot = GeoSnapshot {
            created_at_epoch_seconds: 1,
            ipv4,
            ipv6,
        };

        assert_eq!(
            snapshot.lookup_country("1.50.0.1".parse().unwrap()),
            Some(encode_country("CN").unwrap())
        );
        assert_eq!(
            snapshot.lookup_country("1.2.3.4".parse().unwrap()),
            Some(encode_country("CN").unwrap())
        );
    }

    #[test]
    fn xdp_prefixes_cover_geo_ranges() {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        append_country_ranges("CN", "1.2.3.0/24\n2001:db8::/126\n", &mut ipv4, &mut ipv6).unwrap();
        normalize_v4_ranges(&mut ipv4);
        normalize_v6_ranges(&mut ipv6);
        let snapshot = GeoSnapshot {
            created_at_epoch_seconds: 1,
            ipv4,
            ipv6,
        };
        let prefixes = snapshot.xdp_prefixes();

        assert!(prefixes.iter().any(|prefix| {
            prefix.addr == "1.2.3.0".parse::<IpAddr>().unwrap() && prefix.prefix == 24
        }));
        assert!(prefixes.iter().any(|prefix| {
            prefix.addr == "2001:db8::".parse::<IpAddr>().unwrap() && prefix.prefix == 126
        }));
    }

    #[test]
    fn evaluates_allow_and_deny_policy() {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        append_country_ranges("US", "203.0.113.0/24\n", &mut ipv4, &mut ipv6).unwrap();
        let runtime = Arc::new(GeoRuntime {
            source: GeoSourceConfig {
                provider: ProxyGeoProvider::Ipdeny,
                provider_base_url: String::new(),
                cache_path: PathBuf::from("unused"),
                refresh_interval: Duration::from_secs(60),
                startup_refresh: ProxyGeoStartupRefresh::Disabled,
                request_timeout: Duration::from_secs(1),
                request_retries: 1,
                allow_partial: false,
                countries: vec!["US".to_string()],
            },
            snapshot: RwLock::new(Arc::new(GeoSnapshot {
                created_at_epoch_seconds: 0,
                ipv4,
                ipv6,
            })),
        });
        let policy = GeoPolicy {
            enabled: true,
            fail_open: true,
            unknown_country_allows: true,
            allow_countries: Vec::new(),
            deny_countries: vec![encode_country("US").unwrap()],
        };

        assert_eq!(
            evaluate_geo_policy(&policy, Some(&runtime), "203.0.113.1".parse().unwrap()),
            GeoDecision::Drop("geo-deny-country")
        );
        assert_eq!(
            evaluate_geo_policy(&policy, Some(&runtime), "198.51.100.1".parse().unwrap()),
            GeoDecision::Allow
        );
    }

    #[tokio::test]
    async fn partial_geo_fetch_keeps_successful_countries_when_one_country_fails() {
        let (base_url, server) = spawn_geo_test_server(2).await;
        let source = GeoSourceConfig {
            provider: ProxyGeoProvider::Ipdeny,
            provider_base_url: format!("{base_url}/{{country}}.zone"),
            cache_path: PathBuf::from("unused"),
            refresh_interval: Duration::from_secs(60),
            startup_refresh: ProxyGeoStartupRefresh::Disabled,
            request_timeout: Duration::from_secs(1),
            request_retries: 1,
            allow_partial: true,
            countries: vec!["AX".to_string(), "CN".to_string()],
        };

        let snapshot = fetch_geo_snapshot(&source).await.unwrap();
        assert_eq!(
            snapshot.lookup_country("1.2.3.4".parse().unwrap()),
            Some(encode_country("CN").unwrap())
        );
        assert_eq!(
            snapshot.lookup_country("198.51.100.1".parse().unwrap()),
            None
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn geo_fetch_fails_without_partial_when_one_country_fails() {
        let (base_url, server) = spawn_geo_test_server(2).await;
        let source = GeoSourceConfig {
            provider: ProxyGeoProvider::Ipdeny,
            provider_base_url: format!("{base_url}/{{country}}.zone"),
            cache_path: PathBuf::from("unused"),
            refresh_interval: Duration::from_secs(60),
            startup_refresh: ProxyGeoStartupRefresh::Disabled,
            request_timeout: Duration::from_secs(1),
            request_retries: 1,
            allow_partial: false,
            countries: vec!["AX".to_string(), "CN".to_string()],
        };

        let err = fetch_geo_snapshot(&source).await.unwrap_err();
        assert!(format!("{err:#}").contains("failed to fetch geo ranges for AX"));

        server.abort();
    }

    async fn spawn_geo_test_server(max_requests: usize) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            for _ in 0..max_requests {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).await.unwrap();
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let response = if request.contains("/cn.zone") {
                        "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n1.2.3.0/24\n"
                    } else {
                        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    };
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        (format!("http://{addr}"), handle)
    }
}
