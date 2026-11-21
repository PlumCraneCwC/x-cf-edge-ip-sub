#!/usr/bin/env python3
"""Measure which Cloudflare anycast IPv4 addresses are usable from this LAN.

The publish workflow runs on GitHub's runners, so an address that is fine from
there can still be blocked between the router and Cloudflare (that is exactly
what happened to the jsdelivr.com addresses on 2026-11-22). This helper probes
every affected host in ``targets.txt`` against a candidate address list and
writes the best addresses to ``preferred-ip.txt``; the workflow prefers those.

Usage:
    python3 scripts/client_verify.py                 # probe built-in candidates
    python3 scripts/client_verify.py --ip 104.17.0.1 # probe only this address
    python3 scripts/client_verify.py --write         # also rewrite preferred-ip.txt
"""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_filter  # noqa: E402

DEFAULT_TARGETS = ROOT / "targets.txt"
DEFAULT_OUTPUT = ROOT / "preferred-ip.txt"

# A spread of Cloudflare anycast addresses. Any of them serves any Cloudflare
# zone, so the only question is which ones this network can reach.
CANDIDATE_IPS = [
    "104.16.0.1", "104.17.0.1", "104.18.0.1", "104.19.0.1", "104.20.0.1",
    "104.21.0.1", "104.24.0.1", "104.25.0.1", "104.26.0.1", "104.27.0.1",
    "162.159.0.1", "188.114.96.1", "188.114.97.1", "188.114.98.1",
    "188.114.99.1", "103.21.244.1", "103.31.4.1", "108.162.192.1",
]
ATTEMPTS = 3
MIN_SUCCESSES = 2
TOP_N = 3


def measure(ip: str, hosts: list[str]) -> tuple[str, list[str]]:
    """Return (ip, hosts that passed) for one candidate address."""
    passed: list[str] = []
    for host in hosts:
        probes = [build_filter.probe_ipv4(ip, hostname=host) for _ in range(ATTEMPTS)]
        if sum(1 for probe in probes if probe.ok) >= MIN_SUCCESSES:
            passed.append(host)
    return ip, passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", action="append", default=None,
                        help="probe only these addresses (repeatable)")
    parser.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--write", action="store_true",
                        help="rewrite the preferred-ip.txt file")
    args = parser.parse_args()

    hosts = build_filter.read_targets(args.targets)
    candidates = args.ip or CANDIDATE_IPS
    print(f"Probing {len(hosts)} hosts against {len(candidates)} addresses", file=sys.stderr)

    results: list[tuple[str, list[str]]] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for ip, passed in pool.map(lambda ip: measure(ip, hosts), candidates):
            results.append((ip, passed))
            print(f"{ip:16s} {len(passed):2d}/{len(hosts)} hosts ok", file=sys.stderr)

    results.sort(key=lambda item: len(item[1]), reverse=True)
    best = [ip for ip, passed in results if len(passed) == len(hosts)][:TOP_N]
    if not best:
        print("error: no address served every host; refusing to write", file=sys.stderr)
        return 1

    print(f"Addresses that served every host: {', '.join(best)}", file=sys.stderr)
    if args.write:
        lines = [
            "# Cloudflare anycast IPv4 addresses that are reachable from the LAN.",
            "# Written by scripts/client_verify.py; the publish workflow prefers",
            "# these addresses, in order, and falls back to jsdelivr.com otherwise.",
            *best,
            "",
        ]
        build_filter.atomic_write(args.output, "\n".join(lines))
        print(f"Wrote {len(best)} addresses to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
