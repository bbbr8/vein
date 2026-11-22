import codecs
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PacketEncodingTests(unittest.TestCase):
    def test_bom_preserves_example_results(self):
        with tempfile.TemporaryDirectory() as scratch:
            examples = Path(scratch) / 'examples'
            shutil.copytree(ROOT / 'examples', examples)
            packet = examples / 'candidates.json'
            args = [str(packet)]
            command = [sys.executable, str(ROOT / 'vein_candidates.py'), *args]
            plain = subprocess.run(command, capture_output=True, check=True, cwd=ROOT)
            packet.write_bytes(codecs.BOM_UTF8 + packet.read_bytes())
            marked = subprocess.run(command, capture_output=True, check=True, cwd=ROOT)
            self.assertEqual(json.loads(marked.stdout), json.loads(plain.stdout))
