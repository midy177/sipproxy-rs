# SIP Benchmark

`tools/sip_bench.py` is a small UDP SIP benchmark helper that uses only the
Python standard library.

## Scenarios

- `options`: measures local `OPTIONS -> 200 OK`.
- `register`: measures local `REGISTER -> 200 OK` and location writes.
- `invite`: measures proxied `INVITE` until the final response.

## Basic Usage

Start sigproxy with `examples/single-node.toml`, then run:

```bash
python3 tools/sip_bench.py udp --scenario options --target 127.0.0.1:5060 --requests 10000 --concurrency 64
python3 tools/sip_bench.py udp --scenario register --target 127.0.0.1:5060 --requests 10000 --concurrency 64
```

For proxied INVITE tests, start a mock upstream matching the configured backend:

```bash
python3 tools/sip_bench.py mock-upstream --bind 127.0.0.1:5080
python3 tools/sip_bench.py udp --scenario invite --target 127.0.0.1:5060 --requests 10000 --concurrency 64
```

JSON output for reports:

```bash
python3 tools/sip_bench.py udp --scenario options --json
```

## Report Fields

- `sent`: total requests attempted.
- `ok`: requests with a response.
- `timeout`: requests without response before `--timeout-ms`.
- `error`: socket errors.
- `rps`: successful responses per second.
- `latency_ms`: min, mean, p50, p95, p99, max.

## Notes

- The script is UDP-only for now.
- `invite` waits until a final SIP response, so provisional responses are not
  counted as successful completion.
- For apples-to-apples benchmark runs, use a release build:

```bash
cargo build --release
./target/release/sigproxy run --config examples/single-node.toml
```
