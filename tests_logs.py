import tempfile
import unittest
from pathlib import Path

from dk_logs import parse_line, detect_bruteforce

SAMPLE_LINES = [
    "2025-10-27T12:34:56 host sshd[1234]: Failed password for bob from 10.0.0.5 port 51123",
    "2025-10-27T12:35:10 host sshd[1234]: Failed password for alice from 10.0.0.5 port 51123",
    "2025-10-27T12:35:20 host sshd[1234]: Failed password for carol from 10.0.0.5 port 51123",
]


class TestLogs(unittest.TestCase):
    def test_parse_line(self):
        parsed = parse_line(SAMPLE_LINES[0])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["user"], "bob")

    def test_bruteforce_detection(self):
        entries = [parse_line(l) for l in SAMPLE_LINES]
        attackers = detect_bruteforce(entries)  # type: ignore
        self.assertTrue(any(att["ip"] == "10.0.0.5" for att in attackers))


if __name__ == "__main__":
    unittest.main()
