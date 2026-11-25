# Private - personal, financial, and mental-health data
"""Row-by-column multiplication, with scalar arithmetic supplied by the language."""
from operator import add, mul, sub

_OPERATIONS = {"+": add, "-": sub, "*": mul}


def _identity(value):
    return value


def _child(parent, value):
    return value


def _arithmetic(op, left, right):
    return _OPERATIONS[op](left, right)


def matmul(left, right, *, scalar, zero, unwrap=_identity, child=_child,
           arithmetic=_arithmetic, tick=None):
    """Multiply rectangular row lists. A complex entry selects complex output."""
    complex_output = False

    def prepare(matrix, side):
        nonlocal complex_output
        raw = unwrap(matrix)
        if not isinstance(raw, list):
            raise ValueError(f"{side} operand must be a list of rows")
        rows, width = [], 0
        for i, raw_row in enumerate(raw):
            row = child(matrix, raw_row)
            items = unwrap(row)
            if not isinstance(items, list):
                raise ValueError(f"{side} row {i} must be a list")
            if i and len(items) != width:
                raise ValueError(f"{side} row {i} has {len(items)} entries, expected {width}")
            width = len(items)
            converted = []
            for raw_value in items:
                value = child(row, raw_value)
                entry = unwrap(value)
                if tick:
                    tick()
                if isinstance(entry, dict):
                    if set(entry) != {"real", "imag"}:
                        raise ValueError("complex entries require real and imag fields")
                    converted.append((scalar(child(value, entry["real"])),
                                      scalar(child(value, entry["imag"]))))
                    complex_output = True
                else:
                    converted.append((scalar(value), zero))
            rows.append(converted)
        return rows, width

    a, n = prepare(left, "left")
    b, p = prepare(right, "right")
    if n != len(b):
        raise ValueError(f"incompatible shapes {len(a)}x{n} and {len(b)}x{p}")
    columns = list(zip(*b))
    result = []
    for row in a:
        output = []
        for column in columns:
            real, imag = zero, zero
            for (x, y), (u, v) in zip(row, column):
                if tick:
                    tick()
                term = arithmetic("*", x, u)
                if complex_output:
                    term = arithmetic("-", term, arithmetic("*", y, v))
                    cross = arithmetic("+", arithmetic("*", x, v), arithmetic("*", y, u))
                    imag = arithmetic("+", imag, cross)
                real = arithmetic("+", real, term)
            output.append({"real": real, "imag": imag} if complex_output else real)
        result.append(output)
    return result


def run_packet(path):
    """Run an exact JSON matrix packet; - reads standard input."""
    import json
    import sys
    from decimal import Decimal
    from fractions import Fraction
    from pathlib import Path

    def number(value):
        if type(value) not in (int, Decimal, str):
            raise ValueError("entries must be numbers or exact fraction strings")
        try:
            return Fraction(value)
        except (ValueError, ArithmeticError) as exc:
            raise ValueError("invalid rational entry") from exc

    def encode(value):
        if isinstance(value, Fraction):
            return value.numerator if value.denominator == 1 else str(value)
        raise TypeError("unexpected matrix output")

    try:
        text = sys.stdin.read() if str(path) == "-" else Path(path).read_text(encoding="utf-8-sig")
        packet = json.loads(text, parse_float=Decimal)
        if not isinstance(packet, dict) or set(packet) != {"left", "right"}:
            raise ValueError("expected left and right matrices")
        result = matmul(packet["left"], packet["right"], scalar=number, zero=Fraction(0))
        print(json.dumps({"ok": True, "product": result}, default=encode, allow_nan=False))
    except (ValueError, ArithmeticError, OSError, RecursionError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    return 0
