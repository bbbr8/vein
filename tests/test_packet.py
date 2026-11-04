import unittest
import vein


class PacketTests(unittest.TestCase):
    def test_decode(self):
        schema = vein.compile("endian be\nroot packet\ntype packet {\n level: u16\n}\n")
        tree = schema.parse(bytes([1, 2]))
        self.assertIn("258", str(vein.to_json(tree)))

    def test_short(self):
        schema = vein.compile("endian be\nroot packet\ntype packet {\n level: u16\n}\n")
        with self.assertRaises(vein.ParseError):
            schema.parse(b"x")
