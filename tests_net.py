import unittest
from types import SimpleNamespace

import dk_net


class DummyLogger:
    def error(self, *a, **k):
        pass


class TestNet(unittest.TestCase):
    def test_detects_high_risk_open(self):
        original = dk_net.scan_port
        dk_net.scan_port = lambda host, port, timeout: port == 23
        try:
            args = SimpleNamespace(host="localhost", ports="22,23", port_range=None, timeout=0.1, workers=2, json_path=None)
            code = dk_net.handle_net(args, logger=DummyLogger())
            self.assertEqual(code, 3)
        finally:
            dk_net.scan_port = original


if __name__ == "__main__":
    unittest.main()
