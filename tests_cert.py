import unittest
from types import SimpleNamespace
from unittest import mock

import dk_cert


class DummyLogger:
    def error(self, *a, **k):
        pass


class DummyTLS:
    def __init__(self, cert):
        self._cert = cert

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def getpeercert(self):
        return self._cert


class DummySock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestCert(unittest.TestCase):
    def test_expiring_certificate_triggers_alert(self):
        cert_dict = {
            "notAfter": "Jan 01 00:00:00 2024 GMT",
            "issuer": ((('commonName', 'Test CA'),),),
            "subject": ((('commonName', 'example.com'),),),
        }

        def fake_wrap(sock, server_hostname=None):
            return DummyTLS(cert_dict)

        with mock.patch("ssl.create_default_context") as ctx, mock.patch("socket.create_connection", return_value=DummySock()):
            ctx.return_value.wrap_socket = fake_wrap
            args = SimpleNamespace(host="example.com", port=443, json_path=None)
            code = dk_cert.handle_cert(args, logger=DummyLogger())
            self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
