import io
import unittest
from contextlib import redirect_stdout, suppress

import defensekit


class TestCLI(unittest.TestCase):
    def test_help_no_command(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = defensekit.main([])
        self.assertEqual(code, 1)
        self.assertIn("usage", buf.getvalue().lower())

    def test_version_flag(self):
        parser = defensekit.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--version"])

    def test_dispatch_known_command(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = defensekit.main(["phish", "--file", "missing.eml"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
