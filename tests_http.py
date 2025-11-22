import io
import unittest
from types import SimpleNamespace
from unittest import mock

import dk_http


class DummyResponse:
    def __init__(self, headers, status=200):
        self._headers = headers
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def getheaders(self):
        return list(self._headers.items())


class DummyLogger:
    def error(self, *a, **k):
        pass


class TestHTTP(unittest.TestCase):
    def test_score_headers(self):
        headers = {"strict-transport-security": "max-age=63072000", "content-security-policy": "default-src 'self'"}
        score, findings = dk_http.score_headers(headers)
        self.assertGreater(score, 0)
        self.assertTrue(findings)

    def test_handle_http_low_score_alert(self):
        resp = DummyResponse({})
        with mock.patch("urllib.request.urlopen", return_value=resp):
            args = SimpleNamespace(url="http://example.com", json_path=None)
            code = dk_http.handle_http(args, logger=DummyLogger())
            self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
