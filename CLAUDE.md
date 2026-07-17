# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sigproxy-rs` is a **Layer-7 SIP-aware stateless proxy / load balancer** for UDP and TCP SIP. It is *not* a B2BUA and owns no SIP transaction state (no retransmission, fork aggregation, or response caching). It keeps only the minimal routing state needed for SIP-aware affinity and correct response return paths.

The mainline deliverable is the stateless proxy. The `cluster/` (Raft) and `ha/` (active-standby, replication, EIP/VIP addons) modules exist in-tree as **addon boundaries** for future HA work, not as the production main path — the README and `docs/implementation-plan.md` (written in Chinese) scope this explicitly.

## Commands

```bash
cargo fmt --check        # formatting gate
cargo check              # fast typecheck
cargo test               # all unit tests (co-located as #[cfg(test)] mod tests in each module)
cargo test --lib <name>  # run a single test (e.g. cargo test --lib rejects_zero_max_message_bytes)
cargo build --release    # release build -> ./target/release/sigproxy
```

Run the binary (uses `clap` subcommands):

```bash
sigproxy run --config config.toml                  # run the proxy
sigproxy config init --output config.toml          # write example config
sigproxy config init --stdout                      # print example config
sigproxy config check --config config.toml         # validate and exit
sigproxy cluster status --config config.toml       # print node role/leader
```

Generate a starter config first with `cargo run --bin sigproxy -- config init --output config.toml`, or copy `examples/single-node.toml`. A commented reference of every field lives in `docs/config-template.toml`.

Benchmark with the included Python harness (see `docs/benchmark.md`):

```bash
python3 tools/sip_bench.py mock-upstream --bind 127.0.0.1:5080   # in one shell
cargo run --bin sigproxy -- run --config examples/single-node.toml
python3 tools/sip_bench.py udp --scenario invite --target 127.0.0.1:5060 --requests 10000 --concurrency 64
```

## Architecture

### Module layout (`src/lib.rs`)

- **`sip`** — thin wrapper over `rsipstack` (the SIP parser/serializer/typed-headers/TCP-framing crate). `sip/message.rs` wraps `rsipstack::sip::SipMessage` and exposes the helpers the proxy actually needs (`method`, `request_uri`, `top_via_branch`, `pop_top_via`). **Do not hand-roll SIP/URI/header parsing or Content-Length framing** — prefer `rsipstack` typed APIs and only add a thin wrapper here when it falls short.
- **`proxy`** (`proxy/server.rs` is the core, ~3000 lines) — the stateless LB main path: UDP/TCP listeners, upstream selection, affinity, REGISTER/location handling, health checks, request forwarding, and response return.
- **`config`** — TOML config structs, `Config::load`/`validate`, and `example_config()`.
- **`app`** — wires the runtime together (see below).
- **`cluster`** — `SharedState` (in-memory contact registry), the `ClusterReplicator` trait, and a `raft.rs` openraft implementation. Standalone by default.
- **`ha`** — active-standby runtime, heartbeat/failover, state replication over HTTP, and a pluggable addon (`noop` / `command` for EIP/VIP binding scripts).

### Runtime composition (`src/app.rs`)

`app::run` builds a `SharedState`, a base `ClusterReplicator` (standalone or raft), optionally wraps it in `ActiveStandbyReplicator`, then spawns four tasks under a shared `watch::channel<bool>` shutdown signal:
1. `run_leader_monitor` — periodically refreshes the node's role and fires the HA addon on transitions.
2. `ProxyServer::run` — the SIP proxy itself.
3. `run_state_replication` — optional active→standby snapshot pull.
4. `run_active_standby` — optional heartbeat/failover loop.

`run()` awaits Ctrl-C, broadcasts shutdown, and joins all tasks before returning.

### The proxy-branch Via mechanism (key to understanding forwarding)

Because the proxy is stateless at the SIP transaction layer, response routing is solved with **proxy-inserted Via branches** rather than transaction state:

- On every forwarded request the proxy inserts its own `Via` whose branch is `PROXY_BRANCH_PREFIX` (`"z9hG4bK-sigproxy-"`) + a monotonic id (`src/proxy/server.rs:37,687`).
- It records the mapping `branch → (client peer, upstream, listener)` in one of three short-lived (300s TTL) tables: `udp_branches`, `invite_transactions` (extra route for `CANCEL`/`ACK` to hit the original INVITE's upstream), and `tcp_upstreams` (a connection pool keyed by upstream, whose reader demuxes responses by branch).
- On a response, it verifies the top Via branch starts with `PROXY_BRANCH_PREFIX` (i.e. this proxy inserted it), pops it (`SipMessage::pop_top_via`), and uses the recorded branch route to send the response back to the original client — including UDP-client→TCP-upstream bridging and INVITE provisional responses.

`UpstreamGroups` round-robins across servers and consults the `AffinityTable` + passive health feedback (send/connect failures and `5xx` count as failures). `RouteTable::select` picks an upstream group by listener → URI domain → URI prefix specificity, falling back to the listener's `upstream_group`.

### Config validation contract

`Config::validate()` runs structural checks (non-empty listeners/upstream groups, valid `SocketAddr`s, threshold > 0, no duplicate group/listener names, route/listener cross-references, health-check URI scheme, etc.). Because validation runs before the server is constructed, `ProxyServer::new` and `RouteTable::new` use `.expect("configuration should be validated...")` for things `validate()` already guaranteed — keep that contract intact when adding config: **validate in `Config::validate`, not in the server constructor**.

## Conventions

- **Rust edition 2024**; `rsipstack` is pinned at `=0.5.16` (exact) and `tokio` at `1.52.2`.
- Tests are co-located as `#[cfg(test)] mod tests` at the bottom of each module — `proxy/server.rs` alone has ~30 integration tests covering forwarding, Via insertion/removal, and TCP framing.
- Logging via `tracing`/`tracing-subscriber`; default env filter is `sigproxy_rs=info,openraft=warn,warn` (override with `RUST_LOG`).
- Config enums serialize as kebab-case (`#[serde(rename_all = "kebab-case")]`) and tagged unions use `tag = "mode"`/`tag = "type"` — match this for any new config field.
- Metrics (Prometheus text format, optional under `[proxy.metrics]`) are served by an axum `Router`; the same axum stack backs the HA replication HTTP endpoint.
