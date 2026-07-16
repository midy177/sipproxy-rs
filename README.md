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
- REGISTER handling with an in-memory location registry.
- Upstream health checks using SIP `OPTIONS`.
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
- Raft or active-standby HA as a production main path.
- EIP / VIP floating endpoint control.

HA and Raft-related modules may exist in the tree as future addon boundaries,
but the current deliverable is the stateless SIP-aware proxy.

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
advertise_addr = "127.0.0.1"

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
name = "pbx-a"
mode = "round-robin"
servers = ["127.0.0.1:5080", "127.0.0.1:5081"]

[proxy.upstream_groups.health_check]
enabled = true
transport = "udp"
interval_ms = 5000
timeout_ms = 1000
options_uri = "sip:healthcheck@pbx-a"

[[proxy.listeners]]
bind = "0.0.0.0:5060"
transport = "udp"
upstream_group = "pbx-a"

[[proxy.listeners]]
bind = "0.0.0.0:5060"
transport = "tcp"
upstream_group = "pbx-a"

[cluster]
mode = "standalone"
bind_addr = "127.0.0.1:7000"
data_dir = "./data/node-1"

[ha]
leader_check_interval_ms = 1000

[ha.active_standby]
enabled = false

[ha.replication]
enabled = false

[ha.addon]
type = "noop"
```

Use `examples/single-node.toml` for a fuller local example.

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

## REGISTER / Location

`REGISTER` is handled locally:

- The AOR is extracted from `To`, falling back to `From`.
- `Contact` and `expires` are parsed through `rsipstack` typed APIs.
- The location registry is stored in memory.
- Requests to a registered AOR may be routed to that registered contact.

## Response Path

For forwarded requests, the proxy:

1. Adds a proxy `Via`.
2. Records proxy branch routing metadata.
3. Parses upstream responses.
4. Verifies the top `Via` branch belongs to this proxy.
5. Removes the proxy `Via`.
6. Sends the response back to the original client side.

INVITE responses may include multiple provisional responses before a final
response. UDP uses a stable socket for upstream responses; TCP uses message
framing and upstream connection reuse.

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
forwarded requests, forwarding errors, and affinity lookups.

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
framing, metrics, and selected HA/Raft boundary modules.

## Design Notes

The current proxy is intentionally stateless at the SIP transaction layer. It
does not own retransmission behavior, fork aggregation, response caching, or
dialog state as a B2BUA would. Instead, it keeps the smallest routing state
needed for SIP-aware affinity and correct response return paths.

This keeps the proxy closer to a SIP-aware load balancer while still handling
important Layer-7 correctness that a pure Layer-4 load balancer cannot provide.
