# Benchmark Results

This file records benchmark runs that are useful as local baselines. The
methodology and benchmark tool usage are documented in
[benchmark.md](benchmark.md).

## 2026-07-22 Local UDP Matrix

Environment:

- Host OS: macOS 26.5.2, build 25F84.
- Git revision: `df6114a` with local uncommitted clippy cleanup changes.
- Binary: `cargo build --release --bin sigproxy`.
- Runtime log filter: `RUST_LOG=error`.
- Sigproxy bind: `127.0.0.1:15060/udp`.
- Metrics bind: `127.0.0.1:19100`.
- Mock upstream: `127.0.0.1:15080/udp`.
- Benchmark client concurrency: 64.
- Health check: disabled for all matrix runs.

Interpretation notes:

- `baseline-off` uses `preset = "off"`, persistence disabled,
  `reuse_port = false`, and `workers_per_listener = 1`.
- `persistence-on` changes only `[persistence].enabled = true`.
- `reuse-port-auto` changes only `reuse_port = true` and
  `workers_per_listener = 0`.
- `public-default` uses the default `preset = "public"` limits. This is an
  admission/limit behavior sample, not a throughput comparison. The client
  timeout was set to 100 ms for this group because most packets are expected to
  be dropped by rate limits instead of receiving SIP responses.
- `udp-fire --payload invalid` reports client-side send PPS. It does not wait
  for responses, so latency is not applicable.

### Baseline Size Sweep

| Requests | Scenario | Sent | OK | Timeout | Error | RPS/PPS | Mean ms | p50 ms | p95 ms | p99 ms | Max ms |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | OPTIONS | 10,000 | 10,000 | 0 | 0 | 24,979.11 | 1.838 | 1.646 | 4.020 | 5.470 | 9.362 |
| 10,000 | REGISTER | 10,000 | 10,000 | 0 | 0 | 24,482.09 | 1.906 | 1.686 | 4.192 | 5.515 | 9.404 |
| 10,000 | INVITE | 10,000 | 10,000 | 0 | 0 | 14,651.71 | 3.621 | 3.363 | 7.347 | 9.519 | 12.863 |
| 10,000 | invalid drop | 10,000 | 10,000 | 0 | 0 | 131,502.09 | N/A | N/A | N/A | N/A | N/A |
| 100,000 | OPTIONS | 100,000 | 100,000 | 0 | 0 | 24,834.48 | 1.897 | 1.683 | 4.171 | 5.628 | 11.799 |
| 100,000 | REGISTER | 100,000 | 100,000 | 0 | 0 | 23,897.20 | 1.981 | 1.755 | 4.301 | 5.838 | 11.555 |
| 100,000 | INVITE | 100,000 | 100,000 | 0 | 0 | 12,686.70 | 4.753 | 4.468 | 8.099 | 11.797 | 59.850 |
| 100,000 | invalid drop | 100,000 | 100,000 | 0 | 0 | 136,549.62 | N/A | N/A | N/A | N/A | N/A |
| 1,000,000 | OPTIONS | 1,000,000 | 1,000,000 | 0 | 0 | 17,278.79 | 3.394 | 3.566 | 7.134 | 8.517 | 42.678 |
| 1,000,000 | REGISTER | 1,000,000 | 1,000,000 | 0 | 0 | 14,552.71 | 4.125 | 4.105 | 9.048 | 11.317 | 103.953 |
| 1,000,000 | INVITE | 1,000,000 | 1,000,000 | 0 | 0 | 6,326.78 | 9.933 | 9.721 | 20.647 | 26.093 | 115.322 |
| 1,000,000 | invalid drop | 1,000,000 | 1,000,000 | 0 | 0 | 108,645.59 | N/A | N/A | N/A | N/A | N/A |

### 100k Configuration Comparison

| Config | Scenario | Sent | OK | Timeout | Error | RPS/PPS | Mean ms | p50 ms | p95 ms | p99 ms | Max ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline-off | OPTIONS | 100,000 | 100,000 | 0 | 0 | 24,834.48 | 1.897 | 1.683 | 4.171 | 5.628 | 11.799 |
| baseline-off | REGISTER | 100,000 | 100,000 | 0 | 0 | 23,897.20 | 1.981 | 1.755 | 4.301 | 5.838 | 11.555 |
| baseline-off | INVITE | 100,000 | 100,000 | 0 | 0 | 12,686.70 | 4.753 | 4.468 | 8.099 | 11.797 | 59.850 |
| baseline-off | invalid drop | 100,000 | 100,000 | 0 | 0 | 136,549.62 | N/A | N/A | N/A | N/A | N/A |
| persistence-on | OPTIONS | 100,000 | 100,000 | 0 | 0 | 21,481.80 | 2.203 | 1.943 | 4.860 | 6.557 | 14.369 |
| persistence-on | REGISTER | 100,000 | 100,000 | 0 | 0 | 5,510.04 | 11.606 | 11.028 | 17.458 | 20.936 | 55.805 |
| persistence-on | INVITE | 100,000 | 100,000 | 0 | 0 | 11,816.28 | 5.038 | 5.052 | 7.814 | 10.634 | 21.070 |
| persistence-on | invalid drop | 100,000 | 100,000 | 0 | 0 | 135,672.39 | N/A | N/A | N/A | N/A | N/A |
| reuse-port-auto | OPTIONS | 100,000 | 100,000 | 0 | 0 | 24,874.70 | 1.892 | 1.681 | 4.176 | 5.556 | 13.118 |
| reuse-port-auto | REGISTER | 100,000 | 100,000 | 0 | 0 | 23,792.81 | 1.993 | 1.768 | 4.332 | 5.869 | 11.547 |
| reuse-port-auto | INVITE | 100,000 | 100,000 | 0 | 0 | 14,048.33 | 4.146 | 4.203 | 6.985 | 9.222 | 17.624 |
| reuse-port-auto | invalid drop | 100,000 | 100,000 | 0 | 0 | 136,140.81 | N/A | N/A | N/A | N/A | N/A |

### Public Preset Admission Sample

Each response scenario below was run against a fresh sigproxy process so one
scenario's block state did not contaminate the next scenario.

| Scenario | Sent | OK | Timeout | Error | RPS/PPS | Mean ms | p50 ms | p95 ms | p99 ms | Max ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| OPTIONS | 10,000 | 50 | 9,950 | 0 | 3.17 | 0.833 | 0.647 | 1.754 | 1.881 | 1.881 |
| REGISTER | 10,000 | 31 | 9,969 | 0 | 1.96 | 0.614 | 0.559 | 0.985 | 1.427 | 1.427 |
| INVITE | 10,000 | 25 | 9,975 | 0 | 1.58 | 0.969 | 0.775 | 1.969 | 2.502 | 2.502 |
| invalid drop | 10,000 | 10,000 | 0 | 0 | 129,305.12 | N/A | N/A | N/A | N/A | N/A |

### Matrix Takeaways

- The baseline UDP path handled all response scenarios up to 1M requests with
  zero timeout and zero client socket errors.
- Sustained 1M INVITE is the weakest response path in this local setup:
  throughput dropped to 6,326.78 RPS and p99 rose to 26.093 ms.
- SQLite persistence has the largest measured cost on REGISTER: 100k REGISTER
  fell from 23,897.20 RPS to 5,510.04 RPS because REGISTER writes location,
  affinity, and HA event state.
- `reuse_port=true` with auto workers was neutral for OPTIONS/REGISTER on
  loopback, but improved 100k INVITE from 12,686.70 RPS to 14,048.33 RPS.
- The default `public` preset correctly behaves like a rate-limited admission
  policy under a single-IP flood. It should not be used as a raw throughput
  comparison without either trusted sources or intentionally relaxed limits.

Raw result files:

- `target/bench/matrix/baseline-off/10k/*.json`
- `target/bench/matrix/baseline-off/100k/*.json`
- `target/bench/matrix/baseline-off/1m/*.json`
- `target/bench/matrix/persistence-on/100k/*.json`
- `target/bench/matrix/reuse-port-auto/100k/*.json`
- `target/bench/matrix/public-default/10k/*.json`

## 2026-07-22 Optional Persistence Hot-Path Optimization

Changes under test:

- Optional persistence writes (`required = false`) are moved off the SIP request
  hot path.
- In-memory state still applies before `submit()` returns.
- SQLite/contact/affinity/HA event writes are performed in the background.
- The second iteration uses one background writer that drains pending writes and
  commits them in batches of up to 1024 queued write units per SQLite
  transaction.
- `required = true` continues to synchronously persist and fail closed.

Environment:

- Same host, bind addresses, mock upstream, and release binary setup as the
  local UDP matrix above.
- Config: `preset = "off"`, persistence enabled, `required = false`,
  `reuse_port = false`, `workers_per_listener = 1`.
- Scenario: `udp --scenario register`.
- Requests: 100,000.
- Concurrency: 64.

| Version | Sent | OK | Timeout | Error | RPS | Mean ms | p50 ms | p95 ms | p99 ms | Max ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Before optimization | 100,000 | 100,000 | 0 | 0 | 5,510.04 | 11.606 | 11.028 | 17.458 | 20.936 | 55.805 |
| Background write, per-call task | 100,000 | 100,000 | 0 | 0 | 21,191.32 | 2.318 | 2.227 | 4.863 | 6.613 | 12.590 |
| Background writer, batched transaction | 100,000 | 100,000 | 0 | 0 | 23,372.72 | 2.038 | 1.825 | 4.428 | 6.061 | 12.059 |

Metrics after the batched writer run:

- `proxy_persistence_latest_event_seq 500000`
- `proxy_persistence_event_rows 500000`
- `proxy_persistence_event_appends_total{result="success"} 500000`
- `proxy_persistence_event_appends_total{result="failure"} 0`
- `proxy_persistence_sqlite_write_failures_total 0`

Result:

- REGISTER throughput with optional persistence improved by 4.24x versus the
  original synchronous optional write path.
- Batched background writes improved throughput by another 10.29% versus the
  first background-write iteration.
- p99 latency fell from 20.936 ms to 6.061 ms.
- SQLite/event-log writes completed in the background without recorded write
  failures.

Raw result files:

- `target/bench/optimization/persistence-on/100k/register.json`
- `target/bench/optimization/persistence-on/100k/metrics.txt`
- `target/bench/optimization/persistence-on/100k/register-batched.json`
- `target/bench/optimization/persistence-on/100k/metrics-batched.txt`

## 2026-07-22 UDP Non-INVITE Branch Cleanup

Change under test:

- UDP branch routes now carry a `remove_on_final` flag.
- Non-INVITE UDP routes are removed after a final upstream response is
  forwarded to the client.
- INVITE UDP routes are still retained until TTL so forked or repeated final
  responses can be forwarded.

Environment:

- Same host, bind addresses, mock upstream, and release binary setup as the
  local UDP matrix above.
- `OPTIONS` run uses `preset = "off"` and persistence disabled.
- `REGISTER` run uses `preset = "off"`, persistence enabled,
  `required = false`, and the batched background persistence writer.
- Concurrency: 64.

| Scenario | Version | Sent | OK | Timeout | Error | RPS | Mean ms | p50 ms | p95 ms | p99 ms | Max ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1M OPTIONS | Before cleanup | 1,000,000 | 1,000,000 | 0 | 0 | 17,278.79 | 3.394 | 3.566 | 7.134 | 8.517 | 42.678 |
| 1M OPTIONS | After cleanup | 1,000,000 | 1,000,000 | 0 | 0 | 22,972.94 | 2.063 | 1.815 | 4.569 | 6.194 | 25.787 |
| 100k REGISTER + persistence | After cleanup | 100,000 | 100,000 | 0 | 0 | 23,133.97 | 2.039 | 1.810 | 4.517 | 6.092 | 12.003 |

Metrics after the optimized runs:

- `target/bench/optimization/branch-cleanup/1m/options-metrics.txt`:
  `proxy_udp_branch_routes 0`.
- `target/bench/optimization/branch-cleanup/100k/register-persistence-metrics.txt`:
  `proxy_udp_branch_routes 0`.
- REGISTER persistence metrics also reported `500000` successful event appends,
  `0` event append failures, and `0` SQLite write failures.

Result:

- 1M OPTIONS throughput improved by 32.96% versus the previous long-run
  baseline.
- 1M OPTIONS p99 fell from 8.517 ms to 6.194 ms.
- Non-INVITE UDP response routes no longer remain active until TTL after final
  responses.

Raw result files:

- `target/bench/optimization/branch-cleanup/1m/options.json`
- `target/bench/optimization/branch-cleanup/1m/options-metrics.txt`
- `target/bench/optimization/branch-cleanup/100k/register-persistence.json`
- `target/bench/optimization/branch-cleanup/100k/register-persistence-metrics.txt`

## 2026-07-22 Local UDP Baseline

Environment:

- Host OS: macOS 26.5.2, build 25F84.
- Git revision: `df6114a` with local uncommitted clippy cleanup changes.
- Binary: `cargo build --release --bin sigproxy`.
- Sigproxy bind: `127.0.0.1:15060/udp`.
- Metrics bind: `127.0.0.1:19100`.
- Mock upstream: `127.0.0.1:15080/udp`.
- Benchmark config: `target/bench/local-bench.toml`.
- Security preset: `off`.
- Persistence: disabled.
- Upstream health check: disabled.
- Requests per scenario: 10,000.
- Concurrency: 64.

The following table uses the final sequential run for each scenario. An earlier
parallel smoke run was discarded for baseline purposes because multiple clients
competed for the same listener.

| Scenario | Command | Sent | OK | Timeout | Error | RPS | Mean ms | p50 ms | p95 ms | p99 ms | Max ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| OPTIONS | `udp --scenario options` | 10,000 | 10,000 | 0 | 0 | 24,667.04 | 1.862 | 1.660 | 4.120 | 5.476 | 9.667 |
| REGISTER | `udp --scenario register` | 10,000 | 10,000 | 0 | 0 | 24,402.89 | 1.900 | 1.689 | 4.190 | 5.572 | 8.507 |
| INVITE | `udp --scenario invite` | 10,000 | 10,000 | 0 | 0 | 13,107.53 | 4.186 | 3.906 | 8.654 | 12.056 | 31.958 |
| invalid drop | `udp-fire --payload invalid` | 10,000 | 10,000 | 0 | 0 | 96,505.19 | N/A | N/A | N/A | N/A | N/A |

Raw result files:

- `target/bench/local/options.json`
- `target/bench/local/register.json`
- `target/bench/local/invite.json`
- `target/bench/local/drop-invalid.json`
- `target/bench/local/metrics.txt`

Metrics snapshot notes:

- `sip_requests_total{transport="udp",method="OPTIONS"} 20000`
- `sip_requests_total{transport="udp",method="REGISTER"} 20000`
- `sip_requests_total{transport="udp",method="INVITE"} 20000`
- `sip_upstream_responses_total{transport="udp",class="2xx"} 60000`
- `proxy_upstream_healthy{group="default",server="127.0.0.1:15080"} 1`

The metrics counters include both the discarded parallel smoke run and the
final sequential baseline, so use the JSON files and the table above for
per-scenario throughput and latency comparisons.

Commands:

```bash
cargo build --release --bin sigproxy
python3 tools/sip_bench.py mock-upstream --bind 127.0.0.1:15080
./target/release/sigproxy run --config target/bench/local-bench.toml
python3 tools/sip_bench.py udp --scenario options --target 127.0.0.1:15060 --requests 10000 --concurrency 64 --output target/bench/local/options.json
python3 tools/sip_bench.py udp --scenario register --target 127.0.0.1:15060 --requests 10000 --concurrency 64 --output target/bench/local/register.json
python3 tools/sip_bench.py udp --scenario invite --target 127.0.0.1:15060 --requests 10000 --concurrency 64 --output target/bench/local/invite.json
python3 tools/sip_bench.py udp-fire --payload invalid --target 127.0.0.1:15060 --requests 10000 --concurrency 64 --output target/bench/local/drop-invalid.json
curl -s http://127.0.0.1:19100/metrics -o target/bench/local/metrics.txt
```
