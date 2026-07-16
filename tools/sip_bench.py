#!/usr/bin/env python3
"""Small UDP SIP benchmark helper for sigproxy-rs.

The script intentionally uses only the Python standard library so it can run on
developer machines and CI hosts without extra packages.
"""

from __future__ import annotations

import argparse
import json
import queue
import socket
import statistics
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Iterable


CRLF = "\r\n"


@dataclass
class BenchResult:
    sent: int
    ok: int
    timeout: int
    error: int
    elapsed_s: float
    latencies_ms: list[float]


def parse_addr(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise argparse.ArgumentTypeError("address must be host:port")
    try:
        return host, int(port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc


def header_values(message: str, name: str) -> list[str]:
    prefix = name.lower() + ":"
    values = []
    for line in message.splitlines():
        if line.lower().startswith(prefix):
            values.append(line.split(":", 1)[1].strip())
    return values


def first_header(message: str, name: str, default: str = "") -> str:
    values = header_values(message, name)
    return values[0] if values else default


def response_code(message: str) -> int | None:
    first = message.splitlines()[0] if message else ""
    parts = first.split()
    if len(parts) >= 2 and parts[0].startswith("SIP/2.0"):
        try:
            return int(parts[1])
        except ValueError:
            return None
    return None


def build_request(scenario: str, index: int, domain: str, from_user: str, to_user: str) -> bytes:
    call_id = f"{scenario}-{index}-{uuid.uuid4().hex}@sigproxy-bench"
    branch = f"z9hG4bK-bench-{scenario}-{index}-{uuid.uuid4().hex[:12]}"
    local = f"{from_user}@bench.local"

    if scenario == "options":
        method = "OPTIONS"
        uri = f"sip:{domain}"
        cseq = "1 OPTIONS"
        extra = ""
    elif scenario == "register":
        method = "REGISTER"
        uri = f"sip:{domain}"
        cseq = "1 REGISTER"
        extra = f"Contact: <sip:{from_user}@127.0.0.1:5061>;expires=60{CRLF}"
    elif scenario == "invite":
        method = "INVITE"
        uri = f"sip:{to_user}@{domain}"
        cseq = "1 INVITE"
        extra = ""
    else:
        raise ValueError(f"unknown scenario {scenario}")

    return (
        f"{method} {uri} SIP/2.0{CRLF}"
        f"Via: SIP/2.0/UDP 127.0.0.1:5061;branch={branch}{CRLF}"
        f"Max-Forwards: 70{CRLF}"
        f"From: <sip:{local}>;tag=bench{index}{CRLF}"
        f"To: <{uri}>{CRLF}"
        f"Call-ID: {call_id}{CRLF}"
        f"CSeq: {cseq}{CRLF}"
        f"{extra}"
        f"Content-Length: 0{CRLF}{CRLF}"
    ).encode()


def run_udp_bench(args: argparse.Namespace) -> int:
    target = parse_addr(args.target)
    jobs: queue.Queue[int] = queue.Queue()
    for index in range(args.requests):
        jobs.put(index)

    lock = threading.Lock()
    latencies: list[float] = []
    counts = {"ok": 0, "timeout": 0, "error": 0}
    started = time.perf_counter()

    def worker() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(args.timeout_ms / 1000)
        while True:
            try:
                index = jobs.get_nowait()
            except queue.Empty:
                break

            packet = build_request(args.scenario, index, args.domain, args.from_user, args.to_user)
            sent_at = time.perf_counter()
            try:
                sock.sendto(packet, target)
                while True:
                    data, _ = sock.recvfrom(args.recv_bytes)
                    code = response_code(data.decode(errors="replace"))
                    if args.scenario != "invite" or (code is not None and code >= 200):
                        break
                elapsed_ms = (time.perf_counter() - sent_at) * 1000
                with lock:
                    counts["ok"] += 1
                    latencies.append(elapsed_ms)
            except socket.timeout:
                with lock:
                    counts["timeout"] += 1
            except OSError:
                with lock:
                    counts["error"] += 1
            finally:
                jobs.task_done()
        sock.close()

    threads = [threading.Thread(target=worker) for _ in range(args.concurrency)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    elapsed_s = time.perf_counter() - started
    result = BenchResult(
        sent=args.requests,
        ok=counts["ok"],
        timeout=counts["timeout"],
        error=counts["error"],
        elapsed_s=elapsed_s,
        latencies_ms=latencies,
    )
    print_report(result, args.json)
    return 0 if result.error == 0 and result.timeout == 0 else 1


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100) * (len(ordered) - 1)))))
    return ordered[index]


def print_report(result: BenchResult, as_json: bool) -> None:
    rps = result.ok / result.elapsed_s if result.elapsed_s > 0 else 0
    payload = {
        "sent": result.sent,
        "ok": result.ok,
        "timeout": result.timeout,
        "error": result.error,
        "elapsed_s": round(result.elapsed_s, 6),
        "rps": round(rps, 2),
        "latency_ms": {
            "min": round(min(result.latencies_ms), 3) if result.latencies_ms else None,
            "mean": round(statistics.fmean(result.latencies_ms), 3)
            if result.latencies_ms
            else None,
            "p50": round(percentile(result.latencies_ms, 50), 3)
            if result.latencies_ms
            else None,
            "p95": round(percentile(result.latencies_ms, 95), 3)
            if result.latencies_ms
            else None,
            "p99": round(percentile(result.latencies_ms, 99), 3)
            if result.latencies_ms
            else None,
            "max": round(max(result.latencies_ms), 3) if result.latencies_ms else None,
        },
    }

    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    print(f"sent={payload['sent']} ok={payload['ok']} timeout={payload['timeout']} error={payload['error']}")
    print(f"elapsed_s={payload['elapsed_s']} rps={payload['rps']}")
    print(
        "latency_ms "
        f"min={payload['latency_ms']['min']} "
        f"mean={payload['latency_ms']['mean']} "
        f"p50={payload['latency_ms']['p50']} "
        f"p95={payload['latency_ms']['p95']} "
        f"p99={payload['latency_ms']['p99']} "
        f"max={payload['latency_ms']['max']}"
    )


def build_response(request: str, status: str) -> bytes:
    via_lines = [f"Via: {value}" for value in header_values(request, "Via")]
    headers = [
        f"SIP/2.0 {status}",
        *via_lines,
        f"From: {first_header(request, 'From')}",
        f"To: {first_header(request, 'To')};tag=bench-upstream"
        if "tag=" not in first_header(request, "To")
        else f"To: {first_header(request, 'To')}",
        f"Call-ID: {first_header(request, 'Call-ID')}",
        f"CSeq: {first_header(request, 'CSeq')}",
        "Content-Length: 0",
        "",
        "",
    ]
    return CRLF.join(headers).encode()


def run_mock_upstream(args: argparse.Namespace) -> int:
    bind = parse_addr(args.bind)
    statuses = [status.strip() for status in args.invite_responses.split(",") if status.strip()]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(bind)
    print(f"mock UDP SIP upstream listening on {bind[0]}:{bind[1]}", flush=True)

    while True:
        data, peer = sock.recvfrom(args.recv_bytes)
        request = data.decode(errors="replace")
        method = request.split(" ", 1)[0].upper() if request else ""
        if method == "INVITE":
            for status in statuses:
                sock.sendto(build_response(request, status), peer)
        else:
            sock.sendto(build_response(request, args.default_response), peer)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="UDP SIP benchmark helper")
    subcommands = parser.add_subparsers(dest="command", required=True)

    bench = subcommands.add_parser("udp", help="run UDP SIP benchmark")
    bench.add_argument("--target", default="127.0.0.1:5060", help="proxy target host:port")
    bench.add_argument(
        "--scenario",
        choices=("options", "register", "invite"),
        default="options",
        help="SIP scenario to benchmark",
    )
    bench.add_argument("--requests", type=int, default=1000)
    bench.add_argument("--concurrency", type=int, default=32)
    bench.add_argument("--timeout-ms", type=int, default=1000)
    bench.add_argument("--recv-bytes", type=int, default=65535)
    bench.add_argument("--domain", default="example.com")
    bench.add_argument("--from-user", default="100")
    bench.add_argument("--to-user", default="200")
    bench.add_argument("--json", action="store_true")
    bench.set_defaults(func=run_udp_bench)

    upstream = subcommands.add_parser("mock-upstream", help="run mock UDP SIP upstream")
    upstream.add_argument("--bind", default="127.0.0.1:5080")
    upstream.add_argument("--recv-bytes", type=int, default=65535)
    upstream.add_argument("--default-response", default="200 OK")
    upstream.add_argument("--invite-responses", default="100 Trying,180 Ringing,200 OK")
    upstream.set_defaults(func=run_mock_upstream)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(args, "requests") and args.requests <= 0:
        parser.error("--requests must be greater than 0")
    if hasattr(args, "concurrency") and args.concurrency <= 0:
        parser.error("--concurrency must be greater than 0")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
