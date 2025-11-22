"""Common utilities for defensekit CLI suite."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

__all__ = ["setup_logging", "write_json", "RiskLevel"]


class RiskLevel(str, Enum):
    """Simple risk levels used across tools."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def from_score(cls, score: int) -> "RiskLevel":
        if score >= 60:
            return cls.HIGH
        if score >= 30:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class LoggerConfig:
    verbose: bool = False


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure a module-level logger.

    Args:
        verbose: Whether to enable debug logging.

    Returns:
        Configured ``logging.Logger`` instance.
    """

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")
    logger = logging.getLogger("defensekit")
    logger.setLevel(level)
    return logger


def write_json(path: str, data: Any) -> None:
    """Write JSON data to ``path`` with safe directory creation."""

    target = Path(path)
    if target.parent:
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
