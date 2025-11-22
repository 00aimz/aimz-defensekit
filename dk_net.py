"""Lightweight TCP port scanner."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List

from dk_common import write_json

HIGH_RISK_PORTS = {23, 3389}


def scan_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def handle_net(args, logger) -> int:
    ports: List[int] = []
    if args.ports:
        ports.extend(int(p) for p in args.ports.split(",") if p)
    if args.port_range:
        start, end = args.port_range.split("-", 1)
        ports.extend(range(int(start), int(end) + 1))
    ports = sorted(set(ports))
    if not ports:
        logger.error("no ports specified")
        return 1

    open_ports: List[int] = []
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda p: (p, scan_port(args.host, p, args.timeout)), ports))
    for port, is_open in results:
        if is_open:
            open_ports.append(port)
            print(f"Port {port} open")
    duration = time.time() - start_time

    if not args.json_path:
        print(f"Scanned {len(ports)} ports in {duration:.2f}s")
        if not open_ports:
            print("No open ports detected")

    report = {
        "host": args.host,
        "ports_scanned": ports,
        "open_ports": open_ports,
        "closed_count": len(ports) - len(open_ports),
        "duration_seconds": round(duration, 3),
    }
    if args.json_path:
        write_json(args.json_path, report)

    if any(p in HIGH_RISK_PORTS for p in open_ports):
        return 3
    return 0
