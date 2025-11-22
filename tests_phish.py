import tempfile
import unittest
from pathlib import Path

from dk_phish import analyze_email
import email


PHISH_SAMPLE = """From: PayPal <security@gmail.com>
Subject: Verify your account
Reply-To: fraud@bad.com

Please verify your account immediately at http://192.168.1.4/login
"""


class TestPhish(unittest.TestCase):
    def test_analysis_scores_high(self):
        msg = email.message_from_string(PHISH_SAMPLE)
        analysis = analyze_email(msg, Path("sample.eml"))
        self.assertGreaterEqual(analysis.score, 30)
        self.assertEqual(analysis.risk_level.value, "high" if analysis.score >= 60 else analysis.risk_level.value)
        self.assertTrue(any(ind["id"] == "reply_to_diff" for ind in analysis.indicators))


if __name__ == "__main__":
    unittest.main()
