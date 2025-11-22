"""TLS certificate inspector."""

from __future__ import annotations

import socket
import ssl
import datetime as dt
from typing import Dict

from dk_common import write_json



def handle_cert(args, logger) -> int:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((args.host, args.port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=args.host) as tls:
                cert = tls.getpeercert()
    except Exception as exc:
        logger.error("certificate fetch failed: %s", exc)
        return 2

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    days_until = None
    if not_after:
        expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_until = (expiry - dt.datetime.utcnow()).days
    issuer = cert.get("issuer", [])
    subject = cert.get("subject", [])
    san = cert.get("subjectAltName", [])

    if not args.json_path:
        print(f"Issuer: {issuer}")
        print(f"Subject: {subject}")
        print(f"Not after: {not_after}")
        print(f"Days until expiry: {days_until}")
        if san:
            print(f"SAN: {san}")

    report = {
        "host": args.host,
        "port": args.port,
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "days_until_expiry": days_until,
        "san": san,
    }
    if args.json_path:
        write_json(args.json_path, report)

    if days_until is not None and days_until < 30:
        return 3
    return 0
