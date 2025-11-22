"""HTTP security header checker."""

from __future__ import annotations

import json
import urllib.request
from typing import Dict, List

from dk_common import write_json, RiskLevel


REQUIRED_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


def score_headers(headers: Dict[str, str]) -> tuple[int, List[str]]:
    score = 0
    findings = []
    for key, display in REQUIRED_HEADERS.items():
        if key in headers:
            score += 20
            if key == "content-security-policy" and "default-src" not in headers[key].lower():
                findings.append("CSP present but missing default-src")
        else:
            findings.append(f"Missing {display}")
    return min(score, 100), findings


def handle_http(args, logger) -> int:
    try:
        with urllib.request.urlopen(args.url) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
            status = resp.status
    except Exception as exc:
        logger.error("request failed: %s", exc)
        return 2

    score, findings = score_headers(headers)
    if not args.json_path:
        print(f"Status: {status}")
        print(f"Hardening score: {score}/100")
        for key, display in REQUIRED_HEADERS.items():
            present = "yes" if key in headers else "no"
            print(f" - {display}: {present}")
        if findings:
            print("Findings:")
            for f in findings:
                print(f" * {f}")

    report = {
        "url": args.url,
        "status_code": status,
        "headers": headers,
        "score": score,
        "findings": findings,
    }
    if args.json_path:
        write_json(args.json_path, report)

    if score < 50:
        return 3
    return 0
