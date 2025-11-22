"""Process inventory and whitelist checker."""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from typing import List, Dict

from dk_common import write_json


@dataclass
class ProcessInfo:
    pid: int
    name: str
    cmdline: str


def enumerate_processes() -> List[ProcessInfo]:
    system = platform.system().lower()
    processes: List[ProcessInfo] = []
    if system == "windows":
        cmd = ["tasklist", "/fo", "csv", "/nh"]
        try:
            out = subprocess.check_output(cmd, text=True)
            for line in out.splitlines():
                parts = [p.strip('"') for p in line.split(',')]
                if len(parts) >= 2:
                    processes.append(ProcessInfo(int(parts[1]), parts[0], parts[0]))
        except Exception:
            pass
    else:
        cmd = ["ps", "-eo", "pid,comm,args"]
        try:
            out = subprocess.check_output(cmd, text=True)
            for line in out.splitlines()[1:]:
                parts = line.strip().split(None, 2)
                if len(parts) >= 2:
                    pid = int(parts[0])
                    name = parts[1]
                    cmdline = parts[2] if len(parts) > 2 else name
                    processes.append(ProcessInfo(pid, name, cmdline))
        except Exception:
            pass
    return processes


def load_whitelist(path: str) -> List[str]:
    names = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            names.append(line)
    return names


def handle_procs(args, logger) -> int:
    procs = enumerate_processes()
    unknown: List[Dict[str, object]] = []
    whitelist = []
    if args.whitelist:
        whitelist = load_whitelist(args.whitelist)
        whitelist_set = set(whitelist)
        for proc in procs:
            if proc.name not in whitelist_set:
                unknown.append(proc.__dict__)
    else:
        unknown = [p.__dict__ for p in procs]

    if not args.json_path:
        if args.whitelist:
            print(f"Unknown processes ({len(unknown)}):")
            for proc in unknown:
                print(f" - {proc['pid']}: {proc['name']} ({proc['cmdline']})")
        else:
            print(f"Found {len(procs)} processes")
            for proc in procs:
                print(f" - {proc.pid}: {proc.name}")

    report = {
        "summary": {"total": len(procs), "unknown_count": len(unknown)},
        "unknown_processes": unknown,
    }
    if args.json_path:
        write_json(args.json_path, report)

    if args.strict and args.whitelist and unknown:
        return 3
    return 0
