import tempfile
from pathlib import Path
import unittest
import vein


class DiffTests(unittest.TestCase):
    def test_anchors_and_undecoded_bytes(self):
        schema = vein.compile("endian be\nroot packet\ntype packet {\n level: u16\n}\n")
        with tempfile.TemporaryDirectory() as folder:
            a, b = (Path(folder)/n for n in ("a","b"))
            a.write_bytes(bytes([0,1,7]))
            b.write_bytes(bytes([0,2,7]))
            diff = vein.compare_files(schema, a, b)
            change, = diff["changes"]
            self.assertEqual(change["path"], ["level"])
            self.assertEqual(change["before"]["offset"], 0)
            self.assertEqual(change["after"]["size"], 2)
            self.assertEqual(change["after"]["value"], 2)
            b.write_bytes(bytes([0,1,8]))
            diff = vein.compare_files(schema, a, b)
            self.assertEqual(diff["changes"], [])
            self.assertNotEqual(diff["before"], diff["after"])
