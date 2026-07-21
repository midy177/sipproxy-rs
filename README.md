# sigproxy-rs

`sigproxy-rs` is a Layer-7 SIP-aware stateless proxy / load balancer written in
Rust. The current mainline focuses on SIP-aware routing, affinity, registration
handling, upstream health checks, and correct request/response forwarding for
UDP and TCP SIP.

The proxy uses `rsipstack` for SIP parsing, serialization, typed headers, URI
handling, and TCP SIP framing where those APIs fit the stateless proxy path.

## Current Scope

Implemented mainline behavior:

- UDP and TCP SIP listeners.
- Listener-to-upstream-group mapping.
- Static route overrides by listener, domain, and URI prefix.
- SIP-aware affinity / session persistence by `dialog-id`, `call-id`, or
  `request-uri`.
- Transparent forwarding for SIP requests including REGISTER and OPTIONS.
- Upstream health checks using SIP `OPTIONS` or TCP connect probes.
- UDP SIP port compatibility for softphone STUN Binding Requests and CRLF
  keepalives.
- Stateless forwarding with proxy `Via` insertion and response `Via` removal.
- UDP response routing through a stable listener socket.
- TCP downstream framing and upstream connection reuse.
- INVITE provisional/final response forwarding.
- Lightweight INVITE transaction routing so `CANCEL` and `ACK` can hit the same
  upstream as the original INVITE.
- `Max-Forwards` proxy behavior.
- Optional Prometheus text metrics endpoint.
- `clap` CLI for running and validating configuration.

Out of current mainline scope:

- Full PBX behavior.
- B2BUA behavior.
- RTP / media proxy.
- Full SIP transaction state machine.
- Full SIP dialog ownership.
- Active-active multi-writer clustering.
- Built-in cloud EIP / VIP provider integrations.

Active-standby HA and snapshot replication are available as optional deployment
building blocks. Floating endpoint movement is delegated to the configured HA
addon hook.

## Quick Start

Generate an example configuration:

```bash
cargo run --bin sigproxy -- config init --output config.toml
```

Validate configuration:

```bash
cargo run --bin sigproxy -- config check --config config.toml
```

Run the proxy:

```bash
cargo run --bin sigproxy -- run --config config.toml
```

For a release build:

```bash
cargo build --release
./target/release/sigproxy run --config config.toml
```

## Minimal Configuration

Listeners are configured only under `[[proxy.listeners]]`. Each listener points
to an upstream group.

```toml
[node]
id = 1

[sip]
public_addr = "95.40.96.117"
internal_addr = "172.30.0.101"
public_stun_server = ""
internal_probe_addr = "8.8.8.8:53"
max_message_bytes = 65535

[proxy]
record_route = true
# "path" keeps REGISTER Contact unchanged and adds Path for standard proxy/PLB.
# Use "contact-rewrite" only for PBX/registrar compatibility deployments.
register_routing = "path"

[proxy.socket]
# Keep reuse_port disabled for simple deployments. Enable it for high PPS UDP
# listeners before raising workers_per_listener; workers_per_listener = 0 means
# auto CPU count and requires reuse_port = true.
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
name = "pbx-a"
mode = "round-robin"
servers = ["127.0.0.1:5080", "127.0.0.1:5081"]

[proxy.upstream_groups.health_check]
enabled = true
interval_ms = 5000
timeout_ms = 1000
success_threshold = 2
failure_threshold = 3

[proxy.upstream_groups.health_check.probe]
mode = "options"
transport = "udp"
uri = "sip:healthcheck@pbx-a"
success_codes = [200, 202, 405, 481]

[[proxy.listeners]]
bind = "0.0.0.0:5060"
transport = "udp"
upstream_group = "pbx-a"

[[proxy.listeners]]
bind = "0.0.0.0:5060"
transport = "tcp"
upstream_group = "pbx-a"

[ha]
leader_check_interval_ms = 1000

[persistence]
enabled = true
path = "/var/lib/sigproxy-rs/ha/state.db"
required = false
event_retention_seconds = 3600
cleanup_interval_ms = 60000

[ha.active_standby]
enabled = false

[ha.replication]
enabled = false

[ha.addon]
type = "noop"
```

Use `public_addr` for the address public SIP clients can reach, and
`internal_addr` for the address upstream PBX servers can reach. `Via` and
`Path` use the address for the next hop. Dialog-forming requests crossing
between public and internal sides get two `Record-Route` headers so each side
keeps a reachable route.

`public_addr` and `internal_addr` may be just a host/IP; when the port is
omitted, sigproxy uses the port from the matching SIP listener.

When `[persistence]` is enabled, sigproxy stores REGISTER location,
affinity bindings, and the HA event log in local SQLite WAL mode. In a
two-node active/standby pair, standby pulls `/ha/events` incrementally and
falls back to `/ha/snapshot` when its checkpoint is behind the retained event
log. The SQLite file is node-local and must not be shared between pods.

If `internal_addr` is empty or omitted, sigproxy probes `internal_probe_addr`
with a UDP socket and advertises that local address. If `public_addr` is empty
or omitted, set `public_stun_server` so sigproxy can discover the public IP with
STUN; the advertised port still comes from the SIP listener.

`external_addr` is still accepted as a legacy single advertised address and is
used as a fallback when `public_addr` or `internal_addr` is not set. When no
usable advertised address is set, or it is loopback/unspecified such as
`127.0.0.1:5060` or `0.0.0.0:5060`, the proxy derives an upstream-facing local
address automatically.

Use `examples/single-node.toml` for a fuller local example.

Configuration files support environment placeholders before TOML parsing:
`${VAR}`, `$VAR`, and `${VAR:-default}`. Keep quotes around values that expand
to TOML strings, for example `public_addr = "${SIP_PUBLIC_ADDR}"`.

## Examples

The repository keeps only the main deployment shapes:

- `examples/single-node.toml`: local single-node stateless SIP-aware proxy.
- `examples/active-standby-node1.toml`: two-node active-standby, node 1 starts active.
- `examples/active-standby-node2.toml`: two-node active-standby, node 2 starts standby.

For a commented template that lists every supported configuration field, see
`docs/config-template.toml`.

The active-standby examples use the `noop` HA addon, so they do not move SIP
traffic by themselves. Production active-standby deployments still need a
VIP/EIP/LB hook or equivalent traffic steering so only the active node receives
client SIP traffic. Command hooks are treated as required fencing hooks for
active-standby role changes: promotion succeeds only after
`on_become_leader` succeeds, and hook timeout terminates the hook process.

## Upstream Health Checks

Health checks are configured per upstream group. The default active mode is
`options`, which sends SIP `OPTIONS` and treats configured SIP response codes as
successful. `tcp-connect` is also available for lightweight TCP port checks.

```toml
[proxy.upstream_groups.health_check]
enabled = true
interval_ms = 5000
timeout_ms = 1000
success_threshold = 2
failure_threshold = 3

[proxy.upstream_groups.health_check.probe]
mode = "options"
transport = "udp"
uri = "sip:healthcheck@pbx-a"
success_codes = [200, 202, 405, 481]
```

`OPTIONS` is useful because it checks the SIP application path, but it still
does not prove that all real call flows are healthy. When health checks are
enabled, the proxy also applies passive health feedback from real forwarding:
upstream send/connect failures and `5xx` responses count as failures; non-`5xx`
upstream responses count as successes.

The first active probe runs immediately when the proxy starts. Servers in the
same group are probed concurrently, and each OPTIONS Via uses the probe
socket's actual local address with `rport` so standards-compliant upstreams can
return the response to the correct socket.

For TCP-only upstream groups, a lightweight check can be expressed as:

```toml
[proxy.upstream_groups.health_check]
enabled = true
interval_ms = 5000
timeout_ms = 1000
success_threshold = 2
failure_threshold = 3

[proxy.upstream_groups.health_check.probe]
mode = "tcp-connect"
```

## Routing Model

The default path is listener-based:

```toml
[[proxy.listeners]]
bind = "0.0.0.0:5060"
transport = "udp"
upstream_group = "pbx-a"
```

Optional route entries can override the listener default:

```toml
[[proxy.routes]]
name = "tenant-a-on-5060"
listener = "udp/0.0.0.0:5060"
domain = "tenant-a.example.com"
prefix = "sip:1"
upstream_group = "pbx-a"
```

Route selection order is:

1. Match listener key.
2. Match request URI domain when configured.
3. Match request URI prefix when configured.
4. Fall back to the listener's `upstream_group`.

## Affinity

Affinity is configured under `[proxy.affinity]`:

```toml
[proxy.affinity]
enabled = true
key = "dialog-id"
ttl_seconds = 3600
```

Supported keys:

- `dialog-id`: direction-independent dialog key when both tags exist, with
  `Call-ID` fallback.
- `call-id`: all messages with the same `Call-ID` prefer the same upstream.
- `request-uri`: messages with the same request URI prefer the same upstream.

The proxy also records a lightweight INVITE transaction route:

- `INVITE` records `client Via branch + Call-ID + CSeq number -> upstream`.
- `CANCEL` and `ACK` try that mapping before normal affinity.

This improves SIP-aware session persistence without turning the proxy into a
stateful SIP transaction proxy.

## Listener Security

Security is configured globally under `[proxy.security]` and can be overridden
per listener with `[proxy.listeners.security]`. Dynamic ban is enabled by
default; set `preset = "off"` to explicitly disable all listener security.

```toml
[proxy.security]
preset = "public"
trusted_cidrs = ["172.30.0.0/16"]

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
cache_dir = "/var/lib/sigproxy-rs/geo"
startup_refresh = "disabled"
request_retries = 3
allow_partial = true

[proxy.security.geo.deny]
countries = ["RU", "IR", "KP"]

[proxy.security.threat_intel]
enabled = true
cache_dir = "/var/lib/sigproxy-rs/threat"
startup_refresh = "disabled"
request_retries = 3
allow_partial = true

[proxy.security.dynamic_ban]
enabled = true
ban_seconds = 3600
invalid_packets_per_minute = 30
parse_errors_per_minute = 20
sip_rate_violations_per_minute = 10

[proxy.security.flood]
enabled = true
udp_packets_per_second = 200
udp_burst = 400
tcp_packets_per_second = 200
tcp_burst = 400
tcp_syn_packets_per_second = 100
tcp_syn_burst = 200
tcp_ack_packets_per_second = 200
tcp_ack_burst = 400
icmp_packets_per_second = 50
icmp_burst = 100
block_seconds = 300
```

Presets are `off`, `trusted`, `public`, and `strict`. SIP listeners apply
CIDR allow/deny checks, listener-scoped geo country checks, threat-intel CIDR
checks, raw packet flood limits, packet and parse-error rate limits,
fail2ban-style dynamic bans, invalid start-line prefiltering, and
`REGISTER`/`INVITE` SIP identity limits. `ACK` and `CANCEL` are not
SIP-rate-limited so transaction cleanup is not disrupted. Geo data is loaded
from a binary `geo.sgeo` cache in `cache_dir`; threat intel is loaded from
`threat.sthr`. Both use an embedded empty snapshot as the startup fallback. By
default, runtime refresh is disabled so container deployments use the caches
built into the image.

`[proxy.security.flood]` is a raw packet flood guard applied before SIP method
rate limits. It is listener-scoped and source-IP based. XDP offloads UDP flood,
TCP flood, TCP SYN flood, TCP ACK flood, and ICMP/ICMPv6 flood token buckets
when `[proxy.security.xdp]` is enabled. ICMP is enforced as an interface-level
pseudo listener because ICMP has no SIP listener port.

When `require_registered_invite_source = true`, initial `INVITE` requests from
client-side peers must use a From AoR that has an active REGISTER binding, and
the source must match the registered source IP by default. Use
`registered_invite_source_match = "ip-port"` only for environments where the
client NAT source port is stable. The default `"ip"` mode is a source-IP-level
guard, not end-to-end identity authentication: multiple devices behind the same
public NAT IP can satisfy this check for each other. `"ip-port"` is stricter but
can reject legitimate clients when NAT source ports drift.

Build or preseed the binary geo cache with:

```bash
sigproxy geo-cache build --countries all --output /var/lib/sigproxy-rs/geo/geo.sgeo --retries 3 --allow-partial
```

Build or preseed the binary threat-intel cache with the built-in IPSum and
Spamhaus DROP sources:

```bash
sigproxy threat-cache build --output /var/lib/sigproxy-rs/threat/threat.sthr --retries 3 --allow-partial
```

The Dockerfile downloads and builds the full geo cache and default threat cache
at image build time by default (`GEO_COUNTRIES=all`, `GEO_RETRIES=3`,
`GEO_ALLOW_PARTIAL=true`, `THREAT_CACHE=true`, `THREAT_RETRIES=3`,
`THREAT_ALLOW_PARTIAL=true`). A temporary failure for one country or source is
skipped with a warning so the image can still embed the entries that were
fetched successfully. Runtime startup does not download geo or threat data
unless `startup_refresh = "background"` or `"blocking"` is explicitly
configured. When runtime refresh is enabled, `request_retries` and
`allow_partial` apply to the refresh path as well.

`all` expands to country and territory zones only; ipdeny aggregate zones such
as `AP` and `EU` are intentionally excluded because they overlap concrete
country ranges.

```bash
docker build -t sigproxy-rs .
```

Set `startup_refresh = "background"` only when the running process should
refresh the geo cache after startup.

To skip geo download during image build, pass an empty build arg:

```bash
docker build --build-arg GEO_COUNTRIES= -t sigproxy-rs .
```

When `[proxy.security.xdp]` is enabled, the Docker image also builds and ships
`/usr/local/share/sigproxy/sigproxy_xdp.o`. XDP offloads listener-scoped dynamic
IP blocklists, CIDR allow/deny rules, threat-intel CIDRs, geo country
allow/deny rules generated from `geo.sgeo`, and per-source-IP packet token
buckets. SIP semantic checks
such as REGISTER/INVITE AoR limits and registered-INVITE-source policy remain
in user space. XDP drop/pass counters are exposed as
`proxy_xdp_packets_total{action="..."}`. The userspace control plane loads,
attaches, and updates XDP maps directly through aya; runtime `bpftool` is not
required. When `detach_stale = true`, sigproxy uses the `ip` command from
`iproute2` to remove only stale `sigproxy_xdp` programs before attaching; the
official image includes it. Running with XDP requires Linux privileges such as
`CAP_NET_ADMIN` and `CAP_BPF` plus access to bpffs at `/sys/fs/bpf`; otherwise
`fail_open = true` falls back to user-space security, while `fail_open = false`
rejects startup.

On the host, make sure bpffs is mounted before starting the container:

```bash
mountpoint -q /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
docker run --cap-add NET_ADMIN --cap-add BPF \
  --mount type=bind,source=/sys/fs/bpf,target=/sys/fs/bpf \
  sigproxy-rs
```

For Kubernetes, use `hostNetwork: true`, privileged security context, and a
`hostPath` mount for `/sys/fs/bpf`; see [docs/kubernetes-xdp.md](docs/kubernetes-xdp.md).

## REGISTER / OPTIONS

`REGISTER` and downstream `OPTIONS` requests are forwarded to the selected
upstream like other SIP requests. The proxy does not act as a registrar or
local OPTIONS responder on the normal signaling path.

## Response Path

For forwarded requests, the proxy:

1. Adds a proxy `Via`.
2. Records proxy branch routing metadata.
3. Parses upstream responses.
4. Verifies the top `Via` branch belongs to this proxy.
5. Removes the proxy `Via`.
6. Sends the response back to the original client side.

INVITE responses may include multiple provisional responses before a final
response. UDP uses a stable socket for UDP upstream responses; TCP upstream
responses are dispatched by proxy branch through the reused upstream connection,
including UDP client to TCP upstream forwarding.

## Metrics

Enable metrics:

```toml
[proxy.metrics]
enabled = true
bind_addr = "127.0.0.1:9100"
```

Then scrape:

```bash
curl http://127.0.0.1:9100/metrics
```

Current counters cover SIP requests, local responses, upstream responses,
forwarded requests, forwarding errors, and affinity lookups. Runtime gauges
cover UDP branch routes, TCP upstream connections, TCP branch routes, INVITE
transaction routes, affinity bindings, location bindings, and per-upstream
health state with consecutive success/failure counters.

When `[persistence]` is enabled, metrics also expose
`proxy_persistence_latest_event_seq`, `proxy_persistence_last_applied_seq`,
`proxy_persistence_event_rows`, `proxy_persistence_event_lag`,
`proxy_persistence_event_appends_total`, and
`proxy_persistence_sqlite_write_failures_total`. Active-standby replication
pulls are tracked separately with `proxy_ha_event_pulls_total`,
`proxy_ha_snapshot_pulls_total`, and `proxy_ha_snapshot_fallbacks_total`.

## Benchmark

See [docs/benchmark.md](docs/benchmark.md).

Example local run:

```bash
python3 tools/sip_bench.py mock-upstream --bind 127.0.0.1:5080
cargo run --bin sigproxy -- run --config examples/single-node.toml
python3 tools/sip_bench.py udp --scenario invite --target 127.0.0.1:5060 --requests 10000 --concurrency 64
```

## Development

Run checks:

```bash
cargo fmt --check
cargo check
cargo test
```

The project currently has focused unit tests for configuration validation, SIP
message wrapping, registry parsing, affinity, routing, proxy forwarding, TCP
framing, metrics, and selected active-standby HA boundary modules.

## Design Notes

The current proxy is intentionally stateless at the SIP transaction layer. It
does not own retransmission behavior, fork aggregation, response caching, or
dialog state as a B2BUA would. Instead, it keeps the smallest routing state
needed for SIP-aware affinity and correct response return paths.

This keeps the proxy closer to a SIP-aware load balancer while still handling
important Layer-7 correctness that a pure Layer-4 load balancer cannot provide.
