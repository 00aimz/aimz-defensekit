"""Password strength analyzer."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Dict, List

from dk_common import write_json

COMMON_PATTERNS = ["1234", "qwerty", "password", "letmein", "welcome", "admin", "abc123"]


def shannon_entropy(password: str) -> float:
    if not password:
        return 0.0
    freq = {ch: password.count(ch) for ch in set(password)}
    length = len(password)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy * length


def score_password(pw: str) -> Dict[str, object]:
    score = 0
    reasons: List[str] = []
    length = len(pw)
    if length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    else:
        score += 5
        reasons.append("very short password")

    sets = [any(c.islower() for c in pw), any(c.isupper() for c in pw), any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)]
    score += sum(sets) * 10
    if not all(sets[:3]):
        reasons.append("missing character variety")

    entropy = shannon_entropy(pw)
    score += min(int(entropy), 30)

    if re.fullmatch(r"(.)\1{3,}", pw):
        score -= 15
        reasons.append("repeated characters")
    for pattern in COMMON_PATTERNS:
        if pattern in pw.lower():
            score -= 20
            reasons.append(f"contains common pattern {pattern}")
            break

    score = max(0, min(100, score))
    if score >= 70:
        classification = "strong"
    elif score >= 40:
        classification = "medium"
    else:
        classification = "weak"
    return {"score": score, "classification": classification, "entropy_bits": round(entropy, 2), "reasons": reasons}


def handle_passwd(args, logger) -> int:
    path = Path(args.file)
    if not path.exists():
        logger.error("password file not found")
        return 2

    results = []
    weak_found = False
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        pw = line.strip()
        if not pw:
            continue
        info = score_password(pw)
        weak_found = weak_found or info["classification"] == "weak"
        if info["score"] < args.min_score:
            continue
        masked = pw[0] + "*" * (len(pw) - 2) + pw[-1] if len(pw) >= 2 else "*"
        results.append({
            "password_masked": masked,
            "score": info["score"],
            "classification": info["classification"],
            "entropy_bits": info["entropy_bits"],
            "reasons": info["reasons"],
        })
        print(f"{masked}: {info['classification']} ({info['score']})")

    if args.json_path:
        write_json(args.json_path, results)

    if weak_found:
        return 3
    return 0
