"""Configuration drift detector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple

from dk_common import write_json

SENSITIVE_KEYS = ["SECRET", "TOKEN", "KEY", "PASS"]


def parse_config(path: Path) -> Dict[str, str]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("JSON config must be an object")
        return {str(k): str(v) for k, v in data.items()}
    result: Dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.strip().startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def mask_value(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "***" + value[-2:]


def classify(old: Dict[str, str], new: Dict[str, str], ignore: list[str]) -> Dict[str, Dict[str, str]]:
    added = {k: new[k] for k in new.keys() - old.keys() if k not in ignore}
    removed = {k: old[k] for k in old.keys() - new.keys() if k not in ignore}
    changed = {k: {"old": old[k], "new": new[k]} for k in old.keys() & new.keys() if old[k] != new[k] and k not in ignore}
    unchanged = {k: old[k] for k in old.keys() & new.keys() if old[k] == new[k] and k not in ignore}
    return {"added": added, "removed": removed, "changed": changed, "unchanged": unchanged}


def handle_config(args, logger) -> int:
    old_path = Path(args.old)
    new_path = Path(args.new)
    if not old_path.exists() or not new_path.exists():
        logger.error("config files must exist")
        return 2

    try:
        old = parse_config(old_path)
        new = parse_config(new_path)
    except Exception as exc:
        logger.error("parse error: %s", exc)
        return 2

    diff = classify(old, new, args.ignore)

    if not args.json_path:
        print(f"Added: {len(diff['added'])}")
        for k, v in diff["added"].items():
            display = mask_value(v) if args.mask else v
            print(f" + {k}={display}")
        print(f"Removed: {len(diff['removed'])}")
        for k, v in diff["removed"].items():
            display = mask_value(v) if args.mask else v
            print(f" - {k}={display}")
        print(f"Changed: {len(diff['changed'])}")
        for k, v in diff["changed"].items():
            old_v = mask_value(v["old"]) if args.mask else v["old"]
            new_v = mask_value(v["new"]) if args.mask else v["new"]
            print(f" * {k}: {old_v} -> {new_v}")

    report = diff
    if args.json_path:
        write_json(args.json_path, report)

    if diff["changed"]:
        return 3
    return 0
