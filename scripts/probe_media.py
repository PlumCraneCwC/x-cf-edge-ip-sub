#!/usr/bin/env python3
"""Probe the X media hosts that live on Fastly and emit AdGuard Home rules.

These hosts cannot borrow a Cloudflare edge: they are CNAME'd to Fastly
(``twimg.twitter.map.fastly.net`` / ``video.twitter.map.fastly.net``), and the
address set Fastly hands out includes dead edges such as ``146.75.44.159``
where the TLS handshake never completes.  This script walks a candidate pool,
keeps the addresses that finish a TLS 1.3 handshake for the host name, and
writes one ``A`` rewrite per host pointing at the fastest one.

Candidate pool, in order:

* ``--ips FILE`` — lines of ``host ip`` or bare ``ip``; the router script in
  China writes this file so real reachability is what decides.
* the Fastly anycast prefixes below, sampled per network.  A GitHub runner
  cannot see the SNI blocking that happens in China, so this pool only proves
  an edge is alive and holds a matching certificate.

The output is a plain AdGuard Home filter list, same shape as ``xcom.txt``.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import socket
import ssl
import sys
import time
from pathlib import Path

FASTLY_CIDRS = (
    "23.235.32.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "140.248.64.0/18",
    "140.248.128.0/17",
    "146.75.0.0/17",
    "151.101.0.0/16",
    "157.52.64.0/18",
    "167.82.0.0/17",
    "167.82.128.0/20",
    "167.82.160.0/20",
    "167.82.224.0/20",
    "172.111.64.0/18",
    "185.31.16.0/22",
    "199.27.72.0/21",
    "199.232.0.0/16",
)


SAMPLES_PER_NETWORK = 4
ATTEMPTS = 1
IO_TIMEOUT = 5.0
WORKERS = 32
ACCEPT_STATUS = ("200", "204", "301", "302", "304", "400", "403", "404", "410", "421")


def read_hosts(path: Path) -> list[str]:
    hosts = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            hosts.append(line)
    return hosts


def read_pinned_ips(path: Path, hosts: list[str]) -> dict[str, list[str]]:
    """Return host -> candidate addresses from a `host ip` or bare `ip` file."""
    pinned: dict[str, list[str]] = {host: [] for host in hosts}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) == 1:
            for host in hosts:
                pinned[host].append(parts[0])
            continue
        host, address = parts[0], parts[1]
        if host in pinned:
            pinned[host].append(address)
    return pinned


def fastly_candidates() -> list[str]:
    """Fastly answers on the address ending in 159 inside each /24."""
    out: list[str] = []
    for cidr in FASTLY_CIDRS:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses < 512:
            out.append(str(ipaddress.IPv4Address(int(network.network_address) + 159)))
            continue
        for subnet in network.subnets(new_prefix=24):
            out.append(str(ipaddress.IPv4Address(int(subnet.network_address) + 159)))
    return out


def sample_fastly_ips() -> list[str]:
    out: list[str] = []
    for cidr in FASTLY_CIDRS:
        network = ipaddress.ip_network(cidr)
        step = max(1, network.num_addresses // SAMPLES_PER_NETWORK)
        for offset in range(1, network.num_addresses, step):
            out.append(str(network.network_address + offset))
    return out


def probe(ip: str, host: str) -> float | None:
    """Return the elapsed seconds when the handshake and a request both work."""
    context = ssl.create_default_context()
    request = (
        f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: probe\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode()
    started = time.monotonic()
    try:
        with socket.create_connection((ip, 443), timeout=IO_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(request)
                data = tls.recv(64)
    except (OSError, ssl.SSLError):
        return None
    if not data:
        return None
    status = data.split(b"\r\n", 1)[0].split()
    if len(status) < 2 or status[1].decode(errors="replace") not in ACCEPT_STATUS:
        return None
    return time.monotonic() - started


def resolve(host: str) -> list[str]:
    """The addresses Fastly hands this runner; usually the closest edges."""
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    return [info[4][0] for info in infos]


def pick(host: str, candidates: list[str]) -> tuple[str, float] | None:
    best: tuple[str, float] | None = None
    for ip in dict.fromkeys(candidates):
        elapsed = None
        for _ in range(ATTEMPTS):
            elapsed = probe(ip, host)
            if elapsed is not None:
                break
        if elapsed is None:
            continue
        if best is None or elapsed < best[1]:
            best = (ip, elapsed)
    return best


def find_edge(host: str, candidates: list[str], batch: int = WORKERS) -> tuple[str, float] | None:
    """Walk the sweep pool in batches and stop at the first batch that answers."""
    for start in range(0, len(candidates), batch):
        chunk = candidates[start : start + batch]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(chunk)) as pool:
            results = list(pool.map(lambda ip: (ip, probe(ip, host)), chunk))
        alive = [(ip, elapsed) for ip, elapsed in results if elapsed is not None]
        if alive:
            return min(alive, key=lambda item: item[1])
    return None


def probe_host(
    host: str, pinned: list[str], fallback: list[str]
) -> tuple[str, str, float] | None:
    """An address reported from China wins; the rest is a best-effort guess."""
    best = pick(host, pinned) if pinned else None
    if best is None:
        best = find_edge(host, fallback)
    if best is None:
        return None
    return host, best[0], best[1]


def split_target(host: str) -> str:
    """AGH rewrite on ||x.com^ does not cover subdomains, so always be explicit."""
    return f"|{host}|"


def render(pins: dict[str, str]) -> str:
    lines = [
        "! Title: X media hosts on Fastly",
        "! Description: A rewrites pin the X media hosts to a Fastly edge that",
        "!   completes a TLS handshake; AAAA is answered NXDOMAIN.",
        f"! Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
    ]
    for host in sorted(pins):
        prefix = split_target(host)
        lines.append(f"{prefix}$dnstype=A,dnsrewrite=NOERROR;A;{pins[host]}")
        lines.append(f"{prefix}$dnstype=AAAA,dnsrewrite=NXDOMAIN")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", type=Path, default=Path("media-hosts.txt"))
    parser.add_argument("--ips", type=Path, help="candidate addresses reported from China")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--only", action="append", help="probe just this host")
    args = parser.parse_args()

    hosts = read_hosts(args.hosts)
    if args.only:
        hosts = [h for h in hosts if h in set(args.only)]
    if not hosts:
        print("no hosts to probe", file=sys.stderr)
        return 1

    shared = fastly_candidates() + sample_fastly_ips()
    pinned = read_pinned_ips(args.ips, hosts) if args.ips else {h: [] for h in hosts}
    dns = {host: resolve(host) for host in hosts}

    pins: dict[str, str] = {}
    failures: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {
            pool.submit(
                probe_host,
                host,
                pinned[host],
                dns[host] + shared,
            ): host for host in hosts
        }
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - report and keep going
                print(f"{host}: probe crashed: {exc}", file=sys.stderr)
                failures.append(host)
                continue
            if result is None:
                print(f"{host}: no candidate finished a handshake", file=sys.stderr)
                failures.append(host)
                continue
            _, ip, elapsed = result
            pins[host] = ip
            print(f"{host} -> {ip} ({elapsed:.2f}s)")

    if failures:
        print(f"failed hosts: {' '.join(failures)}", file=sys.stderr)
    if not pins:
        print("nothing pinned, leaving the output untouched", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(pins), encoding="utf-8")
    print(f"wrote {len(pins)} hosts to {args.output}")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
