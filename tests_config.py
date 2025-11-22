import tempfile
import unittest
from pathlib import Path

from dk_config import parse_config, classify, mask_value


class TestConfig(unittest.TestCase):
    def test_parse_env_and_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / "old.env"
            env_path.write_text("API_KEY=secret\nNAME=test", encoding="utf-8")
            data = parse_config(env_path)
            self.assertEqual(data["API_KEY"], "secret")

            json_path = Path(tmpdir) / "new.json"
            json_path.write_text("{\"API_KEY\": \"secret2\", \"NAME\": \"test\"}", encoding="utf-8")
            data2 = parse_config(json_path)
            diff = classify(data, data2, ignore=[])
            self.assertIn("API_KEY", diff["changed"])

    def test_mask_value(self):
        self.assertEqual(mask_value("abcd"), "****")
        self.assertTrue(mask_value("secretvalue").startswith("se"))


if __name__ == "__main__":
    unittest.main()
