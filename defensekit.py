"""defensekit main CLI entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dk_common import setup_logging
from dk_phish import handle_phish
from dk_logs import handle_logs
from dk_fim import handle_fim
from dk_procs import handle_procs
from dk_net import handle_net
from dk_http import handle_http
from dk_cert import handle_cert
from dk_config import handle_config
from dk_passwd import handle_passwd

__version__ = "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="defensekit", description="defensive security toolkit")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose logging")

    subparsers = parser.add_subparsers(dest="command")

    # phish
    phish_p = subparsers.add_parser("phish", help="analyze potential phishing emails")
    phish_p.add_argument("--file", help="path to email file")
    phish_p.add_argument("--dir", help="directory containing email files")
    phish_p.add_argument("--json", dest="json_path", help="write JSON report")
    phish_p.add_argument("--min-score", type=int, default=0, help="minimum score to display")
    phish_p.add_argument("--summary", action="store_true", help="summary only output")

    # logs
    logs_p = subparsers.add_parser("logs", help="analyze auth/system logs")
    logs_p.add_argument("--file", required=True, help="log file path")
    logs_p.add_argument("--since", help="filter logs since date YYYY-MM-DD")
    logs_p.add_argument("--ip", help="filter specific IP or prefix")
    logs_p.add_argument("--json", dest="json_path", help="write JSON report")
    logs_p.add_argument("--top", type=int, default=10, help="top entries to show")

    # fim
    fim_p = subparsers.add_parser("fim", help="file integrity monitor")
    fim_sub = fim_p.add_subparsers(dest="fim_command", required=True)
    fim_init = fim_sub.add_parser("init", help="initialize baseline")
    fim_init.add_argument("path")
    fim_init.add_argument("--state-file", dest="state_file", help="state file path")

    fim_scan = fim_sub.add_parser("scan", help="scan against baseline")
    fim_scan.add_argument("path")
    fim_scan.add_argument("--state-file", dest="state_file", help="state file path")
    fim_scan.add_argument("--json", dest="json_path", help="write JSON report")

    # procs
    procs_p = subparsers.add_parser("procs", help="process inventory")
    procs_p.add_argument("--list", action="store_true", help="list processes")
    procs_p.add_argument("--whitelist", help="whitelist file path")
    procs_p.add_argument("--strict", action="store_true", help="exit with alerts on unknown")
    procs_p.add_argument("--json", dest="json_path", help="write JSON report")

    # net
    net_p = subparsers.add_parser("net", help="tcp port scanner")
    net_p.add_argument("--host", required=True)
    net_p.add_argument("--ports", help="comma separated ports")
    net_p.add_argument("--range", dest="port_range", help="port range start-end")
    net_p.add_argument("--timeout", type=float, default=1.0)
    net_p.add_argument("--workers", type=int, default=10)
    net_p.add_argument("--json", dest="json_path")

    # http
    http_p = subparsers.add_parser("http", help="http security header checker")
    http_p.add_argument("--url", required=True)
    http_p.add_argument("--json", dest="json_path")

    # cert
    cert_p = subparsers.add_parser("cert", help="tls certificate inspector")
    cert_p.add_argument("--host", required=True)
    cert_p.add_argument("--port", required=True, type=int)
    cert_p.add_argument("--json", dest="json_path")

    # config
    cfg_p = subparsers.add_parser("config", help="config drift detector")
    cfg_p.add_argument("--old", required=True)
    cfg_p.add_argument("--new", required=True)
    cfg_p.add_argument("--json", dest="json_path")
    cfg_p.add_argument("--mask", dest="mask", action="store_true", default=True)
    cfg_p.add_argument("--no-mask", dest="mask", action="store_false")
    cfg_p.add_argument("--ignore", action="append", default=[])

    # passwd
    pw_p = subparsers.add_parser("passwd", help="password strength analyzer")
    pw_p.add_argument("--file", required=True)
    pw_p.add_argument("--json", dest="json_path")
    pw_p.add_argument("--min-score", type=int, default=0)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1

    logger = setup_logging(args.verbose)

    dispatch = {
        "phish": handle_phish,
        "logs": handle_logs,
        "fim": handle_fim,
        "procs": handle_procs,
        "net": handle_net,
        "http": handle_http,
        "cert": handle_cert,
        "config": handle_config,
        "passwd": handle_passwd,
    }

    handler = dispatch.get(args.command)
    if not handler:
        parser.print_help()
        return 1

    try:
        return handler(args, logger)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("runtime error: %s", exc)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
