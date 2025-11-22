"""Phishing email analyzer."""

from __future__ import annotations

import re
import email
from email.message import Message
from pathlib import Path
from typing import Dict, List, Tuple

from dk_common import RiskLevel, write_json

URL_RE = re.compile(r"https?://[^\s>]+", re.IGNORECASE)
IP_HOST_RE = re.compile(r"https?://(\d+\.\d+\.\d+\.\d+)")
BRAND_WORDS = ["paypal", "microsoft", "google", "apple", "bank"]
URGENT_PHRASES = ["immediately", "suspended", "within 24 hours", "urgent"]
CRED_PHRASES = ["password", "login", "verify your account", "credentials"]
MONEY_PHRASES = ["gift card", "lottery", "payment pending", "wire transfer"]
BAD_EXT = [".exe", ".scr", ".js", ".vbs", ".docm", ".xlsm"]


Indicator = Dict[str, object]


class EmailAnalysis:
    def __init__(self, file: Path, msg: Message):
        self.file = file
        self.msg = msg
        self.indicators: List[Indicator] = []
        self.score: int = 0
        self.risk_level: RiskLevel = RiskLevel.LOW

    def add_indicator(self, points: int, ind_id: str, description: str) -> None:
        self.score += points
        self.indicators.append({"points": points, "id": ind_id, "description": description})

    def finalize(self) -> None:
        self.score = max(0, min(100, self.score))
        self.risk_level = RiskLevel.from_score(self.score)


def analyze_email(msg: Message, file_path: Path) -> EmailAnalysis:
    analysis = EmailAnalysis(file_path, msg)
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")
    lower_from = from_header.lower()

    # sender anomalies
    if "<" in from_header and ">" in from_header:
        display = from_header.split("<", 1)[0].strip('" ')
        domain = from_header.split("@")[-1].strip("<>")
        if display and domain and display.lower() not in domain.lower():
            analysis.add_indicator(15, "sender_mismatch", f"Display name '{display}' but domain '{domain}'")
    if reply_to and reply_to != from_header:
        analysis.add_indicator(10, "reply_to_diff", "Reply-To differs from From")
    if any(brand in lower_from and "gmail.com" in lower_from for brand in BRAND_WORDS):
        analysis.add_indicator(10, "freemail_brand", "Brand name using freemail domain")

    payload = get_email_body(msg).lower()

    # URL analysis
    urls = URL_RE.findall(payload)
    for url in urls:
        if IP_HOST_RE.search(url):
            analysis.add_indicator(10, "ip_url", f"URL uses raw IP {url}")
        host = url.split("//", 1)[-1].split("/", 1)[0]
        if host.count(".") >= 3 or len(host) > 40:
            analysis.add_indicator(8, "long_host", f"Suspicious hostname {host}")
        if url.startswith("http://"):
            analysis.add_indicator(5, "plaintext_http", "Non-HTTPS link")
        for brand in BRAND_WORDS:
            if brand in host and not host.endswith(f"{brand}.com"):
                analysis.add_indicator(8, "brand_domain_mismatch", f"Brand keyword {brand} not on official domain")
                break

    # content signals
    for phrase in URGENT_PHRASES:
        if phrase in payload:
            analysis.add_indicator(5, "urgency", f"Urgent phrase '{phrase}'")
            break
    for phrase in CRED_PHRASES:
        if phrase in payload:
            analysis.add_indicator(7, "credentials", f"Credential phrase '{phrase}'")
            break
    for phrase in MONEY_PHRASES:
        if phrase in payload:
            analysis.add_indicator(6, "money", f"Money-related phrase '{phrase}'")
            break

    # header anomalies / attachments
    lower_headers = "\n".join(f"{k}:{v}" for k, v in msg.items()).lower()
    if any(h in lower_headers for h in ["spf", "dkim", "dmarc"]):
        pass
    else:
        if "@" in from_header:
            analysis.add_indicator(8, "missing_auth", "Missing SPF/DKIM/DMARC headers")

    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            lower = filename.lower()
            if any(lower.endswith(ext) for ext in BAD_EXT):
                analysis.add_indicator(7, "dangerous_attachment", f"Attachment {filename}")

    analysis.finalize()
    return analysis


def get_email_body(msg: Message) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    continue
        return ""
    try:
        payload = msg.get_payload(decode=True)
        if payload is None:
            return str(msg.get_payload())
        return payload.decode(msg.get_content_charset() or "utf-8", errors="ignore")
    except Exception:
        return ""


def handle_phish(args, logger) -> int:
    files: List[Path] = []
    if args.file:
        files.append(Path(args.file))
    if args.dir:
        files.extend(sorted(Path(args.dir).glob("*.eml")))
    if not files:
        logger.error("phish requires --file or --dir")
        return 1

    results = []
    high_found = False
    for file_path in files:
        try:
            msg = email.message_from_file(open(file_path, "r", encoding="utf-8", errors="ignore"))
        except FileNotFoundError:
            logger.error("file not found: %s", file_path)
            return 2
        analysis = analyze_email(msg, file_path)
        if analysis.score < args.min_score:
            continue
        high_found = high_found or analysis.risk_level == RiskLevel.HIGH
        results.append(
            {
                "file": str(file_path),
                "score": analysis.score,
                "risk_level": analysis.risk_level.value,
                "from": msg.get("From", ""),
                "subject": msg.get("Subject", ""),
                "indicators": analysis.indicators,
            }
        )
        if not args.summary:
            print(f"Score {analysis.score}/100 [{analysis.risk_level.name}] From: {msg.get('From','')} Subject: {msg.get('Subject','')}")
            for ind in analysis.indicators:
                print(f" - ({ind['points']} pts) {ind['description']}")

    if args.json_path:
        write_json(args.json_path, results)
    if not args.summary:
        print(f"Analyzed {len(results)} email(s)")
    if high_found:
        return 3
    return 0
