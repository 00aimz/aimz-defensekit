# defensekit

`defensekit` is a defensive, education-focused security CLI suite built with the Python standard library. It bundles multiple blue-team utilities under a single entry point.

> **Use responsibly:** only run these tools against systems and data you own or are explicitly authorized to assess. The suite is strictly defensive and does not perform offensive exploitation.

## Requirements
- Python 3.10+

## Installation
```bash
git clone <repo>
cd aimz-defensekit
python -m unittest  # run test suite
```

## Usage
The main entry point is `defensekit` with subcommands:

- `phish` – analyze potential phishing emails (`--file` or `--dir`).
- `logs` – scan auth/system logs for brute-force attempts.
- `fim` – file integrity monitoring (`init` and `scan`).
- `procs` – process inventory and whitelist checking.
- `net` – simple TCP connect scanner (authorized hosts only).
- `http` – HTTP security header checker for URLs.
- `cert` – TLS certificate inspector.
- `config` – configuration drift detector.
- `passwd` – password strength batch analyzer.

Examples:
```bash
python defensekit.py phish --file suspicious.eml
python defensekit.py logs --file /var/log/auth.log --json report.json
python defensekit.py fim init /etc
python defensekit.py fim scan /etc --json fim-report.json
python defensekit.py procs --whitelist safe.txt --strict
python defensekit.py net --host 192.168.1.10 --ports 22,80,443
python defensekit.py http --url https://example.com
python defensekit.py cert --host example.com --port 443
python defensekit.py config --old prod.env --new staging.env
python defensekit.py passwd --file passwords.txt
```

### Exit codes
- `0` success
- `1` usage/argument error
- `2` runtime or environment error
- `3` security alerts or risky findings detected

### JSON output
Most subcommands accept `--json PATH` to write structured findings for automation.

## Testing
Run all unit tests with:
```bash
python -m unittest
```
