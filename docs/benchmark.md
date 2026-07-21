# SIP Benchmark

`tools/sip_bench.py` is a small UDP SIP benchmark helper that uses only the
Python standard library.

The goal is to keep a repeatable baseline before swapping concurrency
containers such as DashMap or scc. Capture the same matrix before and after a
change, then compare RPS, latency, CPU, memory, and packet drops.

## Scenarios

- `options`: measures local `OPTIONS -> 200 OK`.
- `register`: measures local `REGISTER -> 200 OK` and location writes.
- `invite`: measures proxied `INVITE` until the final response.
- `udp-fire`: sends packets without waiting for responses. Use this for
  prefilter, dynamic-ban, geo, firewall, and XDP drop-path PPS tests.

## Basic Usage

Start sigproxy with `examples/single-node.toml`, then run:

```bash
python3 tools/sip_bench.py udp --scenario options --target 127.0.0.1:5060 --requests 10000 --concurrency 64
python3 tools/sip_bench.py udp --scenario register --target 127.0.0.1:5060 --requests 10000 --concurrency 64
```

Equivalent Make targets:

```bash
make bench-options BENCH_TARGET=127.0.0.1:5060 BENCH_REQUESTS=10000 BENCH_CONCURRENCY=64
make bench-register BENCH_TARGET=127.0.0.1:5060 BENCH_REQUESTS=10000 BENCH_CONCURRENCY=64
```

For proxied INVITE tests, start a mock upstream matching the configured backend:

```bash
python3 tools/sip_bench.py mock-upstream --bind 127.0.0.1:5080
python3 tools/sip_bench.py udp --scenario invite --target 127.0.0.1:5060 --requests 10000 --concurrency 64
```

Equivalent Make targets:

```bash
make bench-mock-upstream BENCH_UPSTREAM=127.0.0.1:5080
make bench-invite BENCH_TARGET=127.0.0.1:5060 BENCH_REQUESTS=10000 BENCH_CONCURRENCY=64
```

For drop-path PPS tests:

```bash
python3 tools/sip_bench.py udp-fire --payload invalid --target 127.0.0.1:5060 --requests 100000 --concurrency 128
python3 tools/sip_bench.py udp-fire --payload dtls --target 127.0.0.1:5060 --requests 100000 --concurrency 128
make bench-drop BENCH_TARGET=127.0.0.1:5060 BENCH_REQUESTS=100000 BENCH_CONCURRENCY=128
```

JSON output for reports:

```bash
python3 tools/sip_bench.py udp --scenario options --json
python3 tools/sip_bench.py udp --scenario options --output target/bench/options.json
```

## Report Fields

- `metadata`: command, target, scenario or payload, request count, concurrency.
- `sent`: total requests attempted.
- `ok`: requests with a response for `udp`, or successful `sendto` calls for
  `udp-fire`.
- `timeout`: requests without response before `--timeout-ms`.
- `error`: socket errors.
- `rps`: successful responses per second.
- `latency_ms`: min, mean, p50, p95, p99, max. This is `null` for `udp-fire`
  because it does not wait for responses.

## Recommended Matrix

Run each row with at least three request counts, for example 10k, 100k, and 1M.
Keep `BENCH_CONCURRENCY` fixed while comparing code changes.

| Case | Command | What it stresses |
| --- | --- | --- |
| OPTIONS | `make bench-options` | packet parse, local response, security checks |
| REGISTER | `make bench-register` | location writes, persistence, affinity |
| INVITE | `make bench-invite` | route selection, branch state, upstream response path |
| invalid drop | `make bench-drop` | prefilter, parse-error dynamic ban, user-space drop |
| DTLS-like drop | `tools/sip_bench.py udp-fire --payload dtls ...` | non-SIP UDP drop and scanner traffic |

Repeat the matrix with:

- `proxy.security.xdp.enabled = false`
- `proxy.security.xdp.enabled = true`
- `[persistence].enabled = false`
- `[persistence].enabled = true`
- `proxy.socket.reuse_port = false`, `workers_per_listener = 1`
- `proxy.socket.reuse_port = true`, `workers_per_listener = 0`

## Host Metrics

Collect host-level data during each run:

```bash
pidstat -p $(pgrep sigproxy) 1
sar -n UDP,DEV 1
ss -u -a
curl -s http://127.0.0.1:9100/metrics
```

On Kubernetes, capture:

```bash
kubectl top pod -n middleware
kubectl logs -n middleware deploy/sigproxy --since=5m
kubectl exec -n middleware deploy/sigproxy -- curl -s http://127.0.0.1:9100/metrics
```

For XDP runs, also check whether the program is attached to the expected
interface:

```bash
ip -details link show dev ens5
```

## Notes

- The script is UDP-only for now.
- `invite` waits until a final SIP response, so provisional responses are not
  counted as successful completion.
- `udp-fire` intentionally does not verify that sigproxy received or dropped
  packets. Use sigproxy metrics, host counters, and XDP stats to validate
  receive/drop behavior.
- For apples-to-apples benchmark runs, use a release build:

```bash
cargo build --release
./target/release/sigproxy run --config examples/single-node.toml
```

Keep one result directory per commit:

```bash
BENCH_OUT=target/bench/$(git rev-parse --short HEAD) make bench-options
BENCH_OUT=target/bench/$(git rev-parse --short HEAD) make bench-register
BENCH_OUT=target/bench/$(git rev-parse --short HEAD) make bench-drop
```
