"""Auth log analyzer for brute-force detection."""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

from dk_common import write_json

LOG_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*?(?P<status>Failed|Accepted) password for (?P<user>[\w-]+) from (?P<ip>[\d\.]+)"
)

ATTEMPT_THRESHOLD = 10
WINDOW_MINUTES = 5
USER_THRESHOLD = 3


def parse_line(line: str):
    match = LOG_RE.search(line)
    if not match:
        return None
    ts = dt.datetime.fromisoformat(match.group("ts"))
    status = match.group("status")
    return {
        "timestamp": ts,
        "status": status,
        "user": match.group("user"),
        "ip": match.group("ip"),
    }


def detect_bruteforce(entries: List[Dict]) -> List[Dict]:
    flagged = []
    by_ip: Dict[str, List[Dict]] = defaultdict(list)
    for ent in entries:
        by_ip[ent["ip"]].append(ent)

    for ip, events in by_ip.items():
        events = sorted(events, key=lambda e: e["timestamp"])
        users = {e["user"] for e in events if e["status"] == "Failed"}
        if len(users) >= USER_THRESHOLD:
            flagged.append({"ip": ip, "reason": "multiple usernames"})
            continue
        for i in range(len(events)):
            window = [e for e in events if 0 <= (events[i]["timestamp"] - e["timestamp"]).total_seconds() <= WINDOW_MINUTES * 60]
            fails = [e for e in window if e["status"] == "Failed"]
            if len(fails) >= ATTEMPT_THRESHOLD:
                flagged.append({"ip": ip, "reason": f"{len(fails)} failures within {WINDOW_MINUTES} minutes"})
                break
    return flagged


def handle_logs(args, logger) -> int:
    path = Path(args.file)
    if not path.exists():
        logger.error("log file not found: %s", path)
        return 2

    entries = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            parsed = parse_line(line)
            if not parsed:
                continue
            if args.ip and not parsed["ip"].startswith(args.ip):
                continue
            if args.since:
                since_dt = dt.datetime.fromisoformat(args.since)
                if parsed["timestamp"] < since_dt:
                    continue
            entries.append(parsed)

    by_ip = Counter(e["ip"] for e in entries)
    by_user = Counter(e["user"] for e in entries)
    attackers = detect_bruteforce(entries)

    if not args.json_path:
        print("Top IPs:")
        for ip, count in by_ip.most_common(args.top):
            print(f" - {ip}: {count} attempts")
        print("Top users:")
        for user, count in by_user.most_common(args.top):
            print(f" - {user}: {count} attempts")
        if attackers:
            print("Suspected attackers:")
            for att in attackers:
                print(f" * {att['ip']}: {att['reason']}")
        print(f"Processed {len(entries)} relevant entries")

    report = {
        "summary": {"total": len(entries)},
        "by_ip": dict(by_ip),
        "by_user": dict(by_user),
        "suspected_attackers": attackers,
    }
    if args.json_path:
        write_json(args.json_path, report)

    return 3 if attackers else 0
