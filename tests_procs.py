import unittest
from types import SimpleNamespace

import dk_procs
from dk_procs import ProcessInfo


class DummyLogger:
    def error(self, *a, **k):
        pass


class TestProcs(unittest.TestCase):
    def test_whitelist_detection(self):
        original = dk_procs.enumerate_processes
        dk_procs.enumerate_processes = lambda: [ProcessInfo(1, "init", "init"), ProcessInfo(2, "badproc", "badproc")]
        try:
            args = SimpleNamespace(whitelist=None, json_path=None, strict=False, list=True)
            code = dk_procs.handle_procs(args, logger=DummyLogger())
            self.assertEqual(code, 0)

            args = SimpleNamespace(whitelist="/tmp/wl.txt", json_path=None, strict=True, list=True)
            with open(args.whitelist, "w", encoding="utf-8") as fh:
                fh.write("init\n")
            code = dk_procs.handle_procs(args, logger=DummyLogger())
            self.assertEqual(code, 3)
        finally:
            dk_procs.enumerate_processes = original


if __name__ == "__main__":
    unittest.main()
