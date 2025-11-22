import tempfile
import unittest
from pathlib import Path

from dk_passwd import score_password, handle_passwd


class DummyLogger:
    def error(self, *a, **k):
        pass


class TestPasswd(unittest.TestCase):
    def test_score(self):
        info = score_password("Password123!")
        self.assertGreaterEqual(info["score"], 40)
        self.assertIn(info["classification"], {"medium", "strong"})

    def test_handle_weak_exit(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as fh:
            fh.write("1234\nStrongPass!123")
            fh.flush()
            args = type("Args", (), {"file": fh.name, "json_path": None, "min_score": 0})
            code = handle_passwd(args, logger=DummyLogger())
            self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
