# Private - personal, financial, and mental-health data
import json
from pathlib import Path
import subprocess
import sys
import unittest


class MatrixCommandTests(unittest.TestCase):
    def run_packet(self, left, right):
        command = [sys.executable, str(Path(__file__).resolve().parents[1] / "vein.py"), "matmul", "-"]
        process = subprocess.run(command, input=json.dumps({"left": left, "right": right}),
                                 text=True, capture_output=True, timeout=15)
        return process.returncode, json.loads(process.stdout)

    def test_rectangular_complex_fraction(self):
        code, result = self.run_packet([[1, {"real": 0, "imag": "1/2"}]], [[2, 3], [4, 6]])
        self.assertEqual(code, 0)
        self.assertEqual(result["product"], [[{"real": 2, "imag": 2}, {"real": 3, "imag": 3}]])

    def test_real_and_empty(self):
        self.assertEqual(self.run_packet([[1, 2], [3, 4]], [[5], [6]])[1]["product"], [[17], [39]])
        self.assertEqual(self.run_packet([[0.1]], [[0.2]])[1]["product"], [["1/50"]])
        self.assertEqual(self.run_packet([[], []], [])[1]["product"], [[], []])

    def test_invalid_input(self):
        for a, b in [([[1], [2, 3]], [[1]]), ([[1]], [[1], [2]]), ([[True]], [[1]]),
                     ([[{"imag": 1}]], [[1]]), ([["1/0"]], [[0]])]:
            with self.subTest(a=a):
                code, result = self.run_packet(a, b)
                self.assertNotEqual(code, 0)
                self.assertFalse(result["ok"])
