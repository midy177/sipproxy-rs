# SIP Listener Security Plan

## Goals

- Keep sigproxy as a lightweight RFC-compatible SIP proxy.
- Enable dynamic ban by default while keeping geo and preset rate filters
  explicit.
- Make internet-facing listeners easy to protect without forcing every
  deployment to copy a large security block.
- Scope protection to listeners, because public UDP, private UDP, and TCP can
  have different exposure and traffic profiles.

## Configuration Shape

Global defaults live under `[proxy.security]`:

```toml
[proxy.security]
preset = "public"
trusted_cidrs = ["172.30.0.0/16"]
deny_cidrs = []
allow_cidrs = []

[proxy.security.ip_rate_limit]
packets_per_second = 50
burst = 100
parse_errors_per_minute = 20
block_seconds = 300

[proxy.security.sip_rate_limit]
register_per_minute_per_aor = 20
invite_per_minute_per_aor = 60
block_seconds = 300

[proxy.security.sip_policy]
require_registered_invite_source = true
registered_invite_source_match = "ip"

[proxy.security.geo]
enabled = true
provider = "ipdeny"
cache_dir = "/var/lib/sigproxy-rs/geo"
refresh_interval_seconds = 86400
startup_refresh = "disabled"
fail_open = true
unknown_country = "allow"

[proxy.security.geo.deny]
countries = ["RU", "IR", "KP"]

[proxy.security.dynamic_ban]
enabled = true
ban_seconds = 3600
invalid_packets_per_minute = 30
parse_errors_per_minute = 20
sip_rate_violations_per_minute = 10
```

Each `[[proxy.listeners]]` can override only the fields it needs:

```toml
[[proxy.listeners]]
bind = "0.0.0.0:5060"
transport = "udp"
upstream_group = "default"

[proxy.listeners.security]
preset = "strict"
trusted_cidrs = ["172.30.0.0/16"]
```

Preset values are `off`, `trusted`, `public`, and `strict`. Without an explicit
preset, dynamic ban is enabled with conservative defaults. `preset = "off"`
fully disables listener security.

Geo data is stored as a binary cache file named `geo.sgeo` under `cache_dir`.
The cache format is a compact sorted range table:

- IPv4: `u32 start`, `u32 end`, `u16 country`.
- IPv6: `u128 start`, `u128 end`, `u16 country`.

Container images can ship a prebuilt `/var/lib/sigproxy-rs/geo/geo.sgeo`.
Runtime refresh defaults to disabled; use `startup_refresh = "background"` only
when the running process should refresh geo data after startup.
When the file is missing or unreadable, sigproxy uses an embedded empty
snapshot and keeps serving traffic. Runtime download only happens when
`startup_refresh` is explicitly set to `background` or `blocking`.

Build-time cache generation:

```bash
sigproxy geo-cache build --countries all --output /var/lib/sigproxy-rs/geo/geo.sgeo --retries 3 --allow-partial
docker build -t sigproxy-rs .
```

The Dockerfile defaults `GEO_COUNTRIES=all`, so image builds preseed the geo
cache unless `--build-arg GEO_COUNTRIES=` is passed. It also defaults
`GEO_RETRIES=3` and `GEO_ALLOW_PARTIAL=true`, so transient failures for a single
country are skipped with a warning instead of failing the whole image build.
`all` excludes ipdeny aggregate zones such as `AP` and `EU` because those
regional ranges overlap concrete countries.

## Runtime Order

For UDP packets:

1. Ignore CRLF keepalive and handle STUN before SIP security checks.
2. Apply listener CIDR rules: deny, allow, trusted. `deny_cidrs` has the
   highest priority when ranges overlap.
3. Apply per-listener per-IP packet token bucket.
4. Apply per-listener geo allow/deny using the in-memory binary range snapshot.
5. Drop invalid or non-SIP start lines when prefiltering is enabled.
6. Parse SIP. When security is enabled, parse errors are sampled and dropped
   instead of surfacing as public-scan WARN logs.
7. Apply SIP identity limits for `REGISTER` and `INVITE`.
8. Continue normal proxy forwarding.

For TCP messages, the same listener CIDR, geo, packet prefilter, parse-error,
dynamic-ban, and SIP identity checks run after TCP framing produces a SIP
message buffer. TCP has no STUN/CRLF UDP keepalive handling.

`ACK` and `CANCEL` skip SIP identity limits so existing INVITE transactions can
finish cleanly.

## RFC Compatibility

The proxy does not become a registrar, B2BUA, or authentication endpoint. It
only drops invalid traffic or returns local `503 Service Unavailable` when a
valid SIP request exceeds listener policy. Normal SIP header handling, routing,
Record-Route, Via, Path, rport, and upstream affinity remain unchanged.

## XDP Offload Plan

XDP is an optional acceleration layer, not the SIP proxy main path. It should
only enforce L3/L4 decisions that do not require SIP parsing:

- Listener CIDR allow/deny/trusted lists.
- Geo allow/deny CIDR ranges from the binary geo cache.
- Per-listener per-source-IP packet token buckets.
- Dynamic IP blocklist entries installed by sigproxy after user-space
  detection.

SIP semantic checks stay in user space:

- `REGISTER`/`INVITE` per-AoR limits.
- SIP parse-error classification.
- Authentication-failure counters.
- Via, Record-Route, Route, Path, rport, affinity, and forwarding logic.

Proposed configuration:

```toml
[proxy.security.xdp]
enabled = false
interfaces = [] # empty or omitted means auto-select by listener bind/default route
detach_stale = true # only detach stale sigproxy_xdp, never third-party XDP
fail_open = true
sync_dynamic_ban = true
cidr_filter = true
geo_filter = true
ip_rate_limit = true
```

Implemented XDP scope:

1. Config parsing for `[proxy.security.xdp]`, scoped globally with
   per-listener effective policy keyed by protocol and bind port. When
   `interfaces` is empty or omitted, sigproxy auto-selects the interface from
   the default route visible to the process.
2. Dynamic IP blocklist offload with `blocked_ips`:
   `listener/proto/port/src_ip -> enabled`. User-space detection remains
   authoritative; installed bans are mirrored into XDP and pruned when expired.
3. CIDR allow/deny offload with LPM trie maps generated from listener security
   config.
4. Geo country allow/deny offload with an LPM trie generated from the loaded
   binary `geo.sgeo` snapshot plus per-listener country bitsets.
5. Per-source-IP packet token bucket offload with an LRU hash keyed by
   `listener/proto/port/src_ip`.
6. XDP pass/drop counters exposed as
   `proxy_xdp_packets_total{action="..."}`.
7. SIP semantic limits stay in user space: REGISTER/INVITE AoR limits,
   registered INVITE source policy, parse-error classification, Via,
   Record-Route, Route, Path, rport, affinity, and forwarding logic.
8. bpffs must be mounted at `/sys/fs/bpf` and bind-mounted into containers;
   `fail_open=true` falls back to user-space security when the mount is
   missing, while `fail_open=false` rejects startup.
5. Export XDP pass/drop counters through the existing metrics endpoint.
6. If attach or map population fails and `fail_open = true`, log a warning and
   continue with user-space security only. If `fail_open = false`, fail startup.

Runtime requirements for real XDP offload:

- Linux host with XDP-capable kernel.
- `CAP_NET_ADMIN` and `CAP_BPF` in the container; older kernels may also need
  `CAP_SYS_ADMIN`.
- `/sys/fs/bpf` mounted and writable by the process.
- Access to the target network interface, typically with host networking or a
  container network setup that exposes the interface.
- `iproute2` is required only when `detach_stale = true`, so startup can remove
  stale `sigproxy_xdp` programs left by an earlier process. `bpftool` is not
  required at runtime.

Performance expectation: public internet scans, floods, geo-denied sources, and
already banned IPs are dropped before socket receive. Valid SIP and SIP-semantic
limits continue through the current RFC-compatible user-space path.

## Follow-Up Work

- Add authentication-failure counters once proxy-visible auth failures are
  classified from upstream responses.
- Add optional metrics for active blocks and token bucket drops per listener.
- Implement optional XDP offload for CIDR, geo, IP packet rate, and dynamic IP
  blocklist enforcement.
