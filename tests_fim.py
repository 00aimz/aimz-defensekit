import tempfile
import unittest
from pathlib import Path

from dk_fim import build_state, handle_fim


class TestFIM(unittest.TestCase):
    def test_init_and_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            file1 = base / "a.txt"
            file1.write_text("hello", encoding="utf-8")
            state = build_state(base)
            self.assertIn("a.txt", state)

            class Args:
                fim_command = "init"
                path = str(base)
                state_file = None
            exit_code = handle_fim(Args(), logger=_DummyLogger())
            self.assertEqual(exit_code, 0)

            file1.write_text("changed", encoding="utf-8")
            class ScanArgs:
                fim_command = "scan"
                path = str(base)
                state_file = None
                json_path = None
            exit_code = handle_fim(ScanArgs(), logger=_DummyLogger())
            self.assertEqual(exit_code, 3)


class _DummyLogger:
    def error(self, *a, **k):
        pass
    def info(self, *a, **k):
        pass


if __name__ == "__main__":
    unittest.main()
