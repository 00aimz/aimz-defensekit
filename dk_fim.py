"""File integrity monitor."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, Tuple

from dk_common import write_json

STATE_FILENAME = ".defensekit_fim.json"


def hash_file(path: Path) -> Tuple[str, int, float]:
    h = hashlib.sha256()
    data = path.read_bytes()
    h.update(data)
    stat = path.stat()
    return h.hexdigest(), stat.st_size, stat.st_mtime


def build_state(root: Path) -> Dict[str, Dict[str, object]]:
    state = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest, size, mtime = hash_file(path)
            rel = path.relative_to(root).as_posix()
            state[rel] = {"hash": digest, "size": size, "mtime": mtime}
    return state


def state_path(base: Path, override: str | None) -> Path:
    return Path(override) if override else base / STATE_FILENAME


def handle_fim(args, logger) -> int:
    base = Path(args.path)
    if not base.exists():
        logger.error("path does not exist: %s", base)
        return 2

    if args.fim_command == "init":
        state = build_state(base)
        path = state_path(base, args.state_file)
        path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        logger.info("baseline written to %s", path)
        print(f"Baseline created with {len(state)} files")
        return 0

    if args.fim_command == "scan":
        path = state_path(base, args.state_file)
        if not path.exists():
            logger.error("state file missing: %s", path)
            return 2
        prev = json.loads(path.read_text(encoding="utf-8"))
        current = build_state(base)

        added = [p for p in current.keys() if p not in prev]
        deleted = [p for p in prev.keys() if p not in current]
        modified = [p for p in current.keys() if p in prev and current[p]["hash"] != prev[p]["hash"]]

        if not args.json_path:
            print(f"Added: {len(added)}")
            for p in added:
                print(f" + {p}")
            print(f"Modified: {len(modified)}")
            for p in modified:
                print(f" * {p}")
            print(f"Deleted: {len(deleted)}")
            for p in deleted:
                print(f" - {p}")

        report = {"added": added, "modified": modified, "deleted": deleted}
        if args.json_path:
            write_json(args.json_path, report)

        if modified or deleted:
            return 3
        return 0

    return 1
