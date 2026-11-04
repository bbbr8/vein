#!/usr/bin/env python3
"""Vein - a small declarative language for binary file structures.

Every decoded value carries its exact byte anchor (offset, size, type).
Standard library only; never writes to the input it parses.

    import vein
    schema = vein.compile(source_text)               # raises vein.VeinError(message, line, col)
    tree = schema.parse(data, root="file", base_offset=0)   # raises vein.ParseError(msg, offset, path)
    print(vein.to_json(tree))

See README.md for usage.
"""

import argparse
import base64
import binascii
import codecs
import datetime as _dt
import json
import math
import mmap
import operator
import os
import re
import struct
import sys
import uuid
import zlib

__version__ = "0.1.0"

HERE = os.path.dirname(os.path.abspath(__file__))
SPECS_DIR = os.path.join(HERE, "specs")
MAX_DEPTH = 1000                 # nested struct levels (guards recursive types)
DEFAULT_MAX_ITEMS = 10_000_000   # per array, guards runaway loops
_MISSING = object()

__all__ = [
    "VeinError", "ParseError", "AssertFailed", "Schema", "StructView", "ArrayView",
    "compile", "compile_file", "load_spec", "list_specs", "to_json", "format_tree",
    "thread_index", "main",
]


# --------------------------------------------------------------------------- errors

class VeinError(Exception):
    """Compile-time error in Vein source (message, line, col are 1-based)."""

    def __init__(self, message, line=0, col=0):
        self.message = message
        self.line = line
        self.col = col
        super().__init__(f"{line}:{col}: {message}")


class ParseError(Exception):
    """Data did not match the spec. offset is absolute (includes base_offset)."""

    def __init__(self, msg, offset, path):
        self.msg = msg
        self.offset = offset
        self.path = path
        self.partial = None   # root node as far as it got (set by Schema.parse)
        super().__init__(f"{msg} (offset {offset} / 0x{offset:x}, at {path})")


class AssertFailed(ParseError):
    """A field assertion (== / != / in) or an `assert` statement failed."""

    def __init__(self, msg, offset, path, field=None, expected=None, actual=None):
        super().__init__(msg, offset, path)
        self.field = field
        self.expected = expected
        self.actual = actual


class _EvalError(Exception):
    def __init__(self, msg, line, col):
        super().__init__(msg)
        self.msg = msg
        self.line = line
        self.col = col


# --------------------------------------------------------------------------- lexer

class _Tok:
    __slots__ = ("kind", "val", "line", "col", "pos", "end")

    def __init__(self, kind, val, line, col, pos, end):
        self.kind, self.val, self.line, self.col, self.pos, self.end = kind, val, line, col, pos, end

    def __repr__(self):
        return f"Tok({self.kind},{self.val!r},{self.line}:{self.col})"


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUM_RE = re.compile(
    r"0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*|0[bB][01](?:_?[01])*|0[oO][0-7](?:_?[0-7])*"
    r"|[0-9](?:_?[0-9])*(?:\.[0-9](?:_?[0-9])*)?(?:[eE][+-]?[0-9]+)?")
_TWO = ("<<", ">>", "<=", ">=", "==", "!=")
_ONE = "+-*/%&|^~<>()[]{},:.@=?;"
_ESC = {"n": 10, "r": 13, "t": 9, "0": 0, "\\": 92, '"': 34, "'": 39, "a": 7, "b": 8, "f": 12, "v": 11}
_HEX = set("0123456789abcdefABCDEF")


def _lex_string(src, i, line, lstart, is_bytes):
    n = len(src)
    j = i + 1
    out = bytearray() if is_bytes else []
    while True:
        if j >= n or src[j] == "\n":
            raise VeinError("unterminated string literal", line, i - lstart + 1)
        ch = src[j]
        if ch == '"':
            j += 1
            break
        if ch == "\\":
            e = src[j + 1] if j + 1 < n else ""
            if e == "x":
                h = src[j + 2:j + 4]
                if len(h) != 2 or not set(h) <= _HEX:
                    raise VeinError("\\x escape needs two hex digits", line, j - lstart + 1)
                code = int(h, 16)
                j += 4
            elif e == "u" and not is_bytes:
                h = src[j + 2:j + 6]
                if len(h) != 4 or not set(h) <= _HEX:
                    raise VeinError("\\u escape needs four hex digits", line, j - lstart + 1)
                code = int(h, 16)
                j += 6
            elif e in _ESC:
                code = _ESC[e]
                j += 2
            else:
                raise VeinError(f"unknown escape '\\{e}'", line, j - lstart + 1)
            if is_bytes:
                out.append(code)
            else:
                out.append(chr(code))
            continue
        if is_bytes:
            if ord(ch) > 127:
                raise VeinError("bytes literal may only contain ASCII; use \\xNN", line, j - lstart + 1)
            out.append(ord(ch))
        else:
            out.append(ch)
        j += 1
    return (bytes(out) if is_bytes else "".join(out)), j


def _tokenize(src):
    toks = []
    i, n, line, lstart, depth = 0, len(src), 1, 0, 0
    while i < n:
        c = src[i]
        if c == "\n":
            if depth == 0:
                toks.append(_Tok("NL", "\n", line, i - lstart + 1, i, i + 1))
            i += 1
            line += 1
            lstart = i
            continue
        if c in " \t\r\f":
            i += 1
            continue
        if c == "#":
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        col = i - lstart + 1
        if c == '"' or (c == "b" and i + 1 < n and src[i + 1] == '"'):
            is_b = c == "b"
            val, j = _lex_string(src, i + (1 if is_b else 0), line, lstart, is_b)
            toks.append(_Tok("BYTES" if is_b else "STR", val, line, col, i, j))
            i = j
            continue
        if c in "0123456789":
            m = _NUM_RE.match(src, i)
            j = m.end()
            if j < n and (src[j].isalnum() or src[j] == "_"):
                raise VeinError(f"invalid number literal '{src[i:j + 1]}'", line, col)
            t = m.group(0).replace("_", "")
            if t[:2].lower() in ("0x", "0b", "0o"):
                val = int(t, 0)
            elif any(ch in t for ch in ".eE"):
                val = float(t)
            else:
                val = int(t, 10)
            toks.append(_Tok("NUM", val, line, col, i, j))
            i = j
            continue
        if c == "_" or (c.isascii() and c.isalpha()):
            m = _IDENT_RE.match(src, i)
            j = m.end()
            toks.append(_Tok("NAME", m.group(0), line, col, i, j))
            i = j
            continue
        two = src[i:i + 2]
        if two in _TWO:
            toks.append(_Tok("OP", two, line, col, i, i + 2))
            i += 2
            continue
        if c in _ONE:
            if c in "([":
                depth += 1
            elif c in ")]":
                depth = max(0, depth - 1)
            toks.append(_Tok("OP", c, line, col, i, i + 1))
            i += 1
            continue
        raise VeinError(f"unexpected character {c!r}", line, col)
    toks.append(_Tok("EOF", None, line, i - lstart + 1, n, n))
    return toks


def _desc(t):
    if t.kind == "NL":
        return "end of line"
    if t.kind == "EOF":
        return "end of file"
    if t.kind in ("OP", "NAME"):
        return f"'{t.val}'"
    if t.kind == "NUM":
        return f"number {t.val}"
    return "string literal" if t.kind == "STR" else "bytes literal"


# --------------------------------------------------------------------------- parser
# AST: tuples. Expressions: (kind, line, col, ...). Statements likewise.

_RESERVED = {"pos", "size", "eof", "_parent", "_root", "_", "_index", "true", "false", "null",
             "and", "or", "not", "in"}
_BUILTIN_TYPES = {"bytes", "skip", "str", "strz", "cstr", "bits"}
_PRIM_RE = re.compile(r"^(?:(?P<s>[ui])(?P<w>8|16|24|32|40|48|56|64)|f(?P<fw>32|64))(?P<e>le|be)?$")
_LEVELS = [("|",), ("^",), ("&",), ("<<", ">>"), ("+", "-"), ("*", "/", "%")]
_MOD_WORDS = ("in", "enum", "if", "at", "size")


class _Module:
    def __init__(self):
        self.endian = "le"
        self.endian_tok = None
        self.root = None
        self.types = []     # (name, line, col, body)
        self.enums = []     # (name, line, col, items)
        self.consts = []    # (name, line, col, expr)


class _Parser:
    def __init__(self, src):
        self.src = src
        self.toks = _tokenize(src)
        self.i = 0

    # -- token helpers
    def peek(self, k=0):
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else self.toks[-1]

    def advance(self):
        t = self.toks[self.i]
        if t.kind != "EOF":
            self.i += 1
        return t

    def is_op(self, v, k=0):
        t = self.peek(k)
        return t.kind == "OP" and t.val == v

    def is_kw(self, v, k=0):
        t = self.peek(k)
        return t.kind == "NAME" and t.val == v

    def fail(self, msg, t=None):
        t = t or self.peek()
        raise VeinError(msg, t.line, t.col)

    def expect_op(self, v):
        t = self.peek()
        if not (t.kind == "OP" and t.val == v):
            self.fail(f"expected '{v}', found {_desc(t)}", t)
        return self.advance()

    def expect_name(self, what="a name"):
        t = self.peek()
        if t.kind != "NAME":
            self.fail(f"expected {what}, found {_desc(t)}", t)
        return self.advance()

    def skip_nl(self):
        while True:
            t = self.peek()
            if t.kind == "NL" or (t.kind == "OP" and t.val == ";"):
                self.i += 1
            else:
                return

    def end_stmt(self):
        t = self.peek()
        if t.kind in ("NL", "EOF") or (t.kind == "OP" and t.val in (";", "}")):
            return
        self.fail(f"unexpected {_desc(t)} (expected end of statement)", t)

    def text(self, a, b):
        if b <= a:
            return ""
        return self.src[self.toks[a].pos:self.toks[b - 1].end]

    # -- module
    def parse_module(self):
        mod = _Module()
        self.skip_nl()
        while self.peek().kind != "EOF":
            t = self.peek()
            if t.kind != "NAME" or t.val not in ("endian", "root", "type", "enum", "const"):
                self.fail(f"expected 'type', 'enum', 'endian', 'root' or 'const', found {_desc(t)}", t)
            kw = self.advance()
            if kw.val == "endian":
                if mod.endian_tok is not None:
                    self.fail("file endianness declared twice", kw)
                e = self.expect_name("'le' or 'be'")
                if e.val not in ("le", "be"):
                    self.fail(f"endian must be 'le' or 'be', found '{e.val}'", e)
                mod.endian, mod.endian_tok = e.val, kw
            elif kw.val == "root":
                n = self.expect_name("a type name")
                mod.root = (n.val, n.line, n.col)
            elif kw.val == "type":
                n = self.expect_name("a type name")
                self.expect_op("{")
                body = self.parse_body()
                mod.types.append((n.val, n.line, n.col, body))
            elif kw.val == "enum":
                mod.enums.append(self.parse_enum())
            else:
                n = self.expect_name("a constant name")
                self.expect_op("=")
                mod.consts.append((n.val, n.line, n.col, self.parse_expr()))
            self.end_stmt()
            self.skip_nl()
        return mod

    def parse_enum(self):
        n = self.expect_name("an enum name")
        self.expect_op("{")
        items = []
        while True:
            while self.peek().kind == "NL" or self.is_op(",") or self.is_op(";"):
                self.advance()
            if self.is_op("}"):
                self.advance()
                break
            t = self.peek()
            neg = False
            if self.is_op("-"):
                self.advance()
                neg = True
                t = self.peek()
            if t.kind != "NUM" or not isinstance(t.val, int):
                self.fail(f"expected an integer enum value, found {_desc(t)}", t)
            self.advance()
            self.expect_op(":")
            m = self.expect_name("an enum member name")
            items.append((-t.val if neg else t.val, m.val, m.line, m.col))
        return (n.val, n.line, n.col, items)

    # -- type bodies
    def parse_body(self):
        stmts = []
        self.skip_nl()
        while not self.is_op("}"):
            if self.peek().kind == "EOF":
                self.fail("unexpected end of file (missing '}')")
            stmts.append(self.parse_stmt())
            self.end_stmt()
            self.skip_nl()
        self.expect_op("}")
        return stmts

    def parse_block(self):
        self.expect_op("{")
        return self.parse_body()

    def parse_stmt(self):
        t = self.peek()
        if t.kind == "OP" and t.val == "@":
            self.advance()
            return ("seek", t.line, t.col, self.parse_expr())
        if t.kind != "NAME":
            self.fail(f"expected a field 'name: type' or a statement, found {_desc(t)}", t)
        if self.is_op(":", 1):
            return self.parse_field()
        kw = t.val
        self.advance()
        if kw == "let":
            n = self.expect_name("a name after 'let'")
            self.expect_op("=")
            return ("let", n.line, n.col, n.val, self.parse_expr())
        if kw == "if":
            return self.parse_if(t)
        if kw == "at":
            e = self.parse_expr()
            return ("at", t.line, t.col, e, self.parse_block())
        if kw == "restore":
            return ("at", t.line, t.col, None, self.parse_block())
        if kw == "bitfield":
            return self.parse_bitfield(t)
        if kw == "endian":
            e = self.expect_name("'le' or 'be'")
            if e.val not in ("le", "be"):
                self.fail(f"endian must be 'le' or 'be', found '{e.val}'", e)
            return ("endian", t.line, t.col, e.val)
        if kw == "assert":
            start = self.i
            e = self.parse_expr()
            src = self.text(start, self.i)
            msg = None
            if self.is_op(","):
                self.advance()
                m = self.peek()
                if m.kind != "STR":
                    self.fail("assert message must be a string literal", m)
                msg = self.advance().val
            return ("assert", t.line, t.col, e, src, msg)
        if kw == "else":
            self.fail("'else' without a matching 'if'", t)
        self.fail(f"expected a field 'name: type' or a statement, found '{kw}'", t)

    def parse_if(self, kwtok):
        branches = [(self.parse_expr(), self.parse_block())]
        while True:
            save = self.i
            while self.peek().kind == "NL":
                self.advance()
            if self.is_kw("else"):
                self.advance()
                if self.is_kw("if"):
                    self.advance()
                    branches.append((self.parse_expr(), self.parse_block()))
                    continue
                branches.append((None, self.parse_block()))
                break
            self.i = save
            break
        return ("if", kwtok.line, kwtok.col, branches)

    def parse_field(self):
        n = self.advance()
        self.expect_op(":")
        tref = self.parse_typeref()
        mods = self.parse_mods()
        return ("field", n.line, n.col, n.val, tref, mods)

    def parse_bitfield(self, kwtok):
        name = None
        if self.peek().kind == "NAME" and self.is_op("{", 1):
            name = self.advance()
        self.expect_op("{")
        items = []
        self.skip_nl()
        while not self.is_op("}"):
            if self.peek().kind == "EOF":
                self.fail("unexpected end of file inside bitfield (missing '}')")
            nt = self.expect_name("a bit field member name")
            self.expect_op(":")
            bt = self.expect_name("bits(n)")
            if bt.val != "bits":
                self.fail(f"bitfield members must be bits(n), found '{bt.val}'", bt)
            self.expect_op("(")
            wt = self.peek()
            if wt.kind != "NUM" or not isinstance(wt.val, int):
                self.fail("bits(n) needs an integer literal width", wt)
            self.advance()
            self.expect_op(")")
            if not 1 <= wt.val <= 64:
                self.fail("bits(n) width must be 1..64", wt)
            mods = self.parse_mods()
            for k in ("if", "at", "size"):
                if k in mods:
                    self.fail(f"'{k}' is not allowed on a bitfield member", nt)
            items.append((nt.val, nt.line, nt.col, wt.val, mods))
            self.end_stmt()
            self.skip_nl()
        self.expect_op("}")
        return ("bitfield", kwtok.line, kwtok.col, name.val if name else None, items,
                name.line if name else kwtok.line, name.col if name else kwtok.col)

    def parse_typeref(self):
        t = self.expect_name("a type")
        name, l, c = t.val, t.line, t.col
        if name in ("bytes", "skip"):
            self.expect_op("(")
            e = self.parse_expr()
            self.expect_op(")")
            base = (name, l, c, e)
        elif name in ("str", "strz"):
            self.expect_op("(")
            e = self.parse_expr()
            enc = ("lit", l, c, "utf-8")
            if self.is_op(","):
                self.advance()
                enc = self.parse_expr()
            self.expect_op(")")
            base = (name, l, c, e, enc)
        elif name == "cstr":
            enc = ("lit", l, c, "utf-8")
            if self.is_op("("):
                self.advance()
                enc = self.parse_expr()
                self.expect_op(")")
            base = ("cstr", l, c, enc)
        elif name == "bits":
            self.fail("bits(n) is only allowed inside a bitfield { } block", t)
        else:
            base = ("named", l, c, name)
        if self.is_op("["):
            lb = self.advance()
            if self.is_op("]"):
                self.advance()
                rep = self.parse_repeat()
            else:
                cnt = self.parse_expr()
                self.expect_op("]")
                rep = ("count", cnt)
            return ("array", lb.line, lb.col, base, rep)
        return base

    def _clause_end(self, k):
        t = self.peek(k)
        return (t.kind in ("NL", "EOF") or (t.kind == "OP" and t.val in (";", "}"))
                or (t.kind == "NAME" and t.val in _MOD_WORDS))

    def parse_repeat(self):
        t = self.peek()
        if self.is_kw("until"):
            self.advance()
            if self.is_kw("eof_or_fail"):
                self.advance()
                return ("eof_or_fail", None)
            if self.is_kw("eof") and self._clause_end(1):
                self.advance()
                return ("eof", None)
            if self._clause_end(0):
                self.fail("'until' needs 'eof', 'eof_or_fail' or an expression")
            return ("until", self.parse_expr())
        if self.is_kw("while"):
            self.advance()
            return ("while", self.parse_expr())
        self.fail("'T[]' needs a repeat clause: 'until eof', 'until eof_or_fail', 'until EXPR' or 'while EXPR'", t)

    def parse_mods(self):
        mods = {}
        while True:
            t = self.peek()
            if t.kind == "OP" and t.val in ("==", "!="):
                key = "eq" if t.val == "==" else "ne"
            elif t.kind == "NAME" and t.val in _MOD_WORDS:
                key = t.val
            else:
                return mods
            if key in mods:
                self.fail(f"duplicate '{t.val}' modifier", t)
            self.advance()
            if key == "enum":
                n = self.expect_name("an enum name")
                mods["enum"] = (n.val, n.line, n.col)
            else:
                start = self.i
                e = self.parse_expr()
                mods[key] = (e, self.text(start, self.i), t.line, t.col)

    # -- expressions
    def parse_expr(self):
        c = self.parse_or()
        if self.is_op("?"):
            t = self.advance()
            a = self.parse_expr()
            self.expect_op(":")
            b = self.parse_expr()
            return ("cond", t.line, t.col, c, a, b)
        return c

    def parse_or(self):
        e = self.parse_and()
        while self.is_kw("or"):
            t = self.advance()
            e = ("or", t.line, t.col, e, self.parse_and())
        return e

    def parse_and(self):
        e = self.parse_not()
        while self.is_kw("and"):
            t = self.advance()
            e = ("and", t.line, t.col, e, self.parse_not())
        return e

    def parse_not(self):
        if self.is_kw("not") and not self.is_kw("in", 1):
            t = self.advance()
            return ("not", t.line, t.col, self.parse_not())
        return self.parse_cmp()

    def parse_cmp(self):
        e = self.parse_level(0)
        t = self.peek()
        if t.kind == "OP" and t.val in ("==", "!=", "<", "<=", ">", ">="):
            self.advance()
            e = ("cmp", t.line, t.col, t.val, e, self.parse_level(0))
        elif self.is_kw("in"):
            self.advance()
            e = ("in", t.line, t.col, e, self.parse_level(0), False)
        elif self.is_kw("not") and self.is_kw("in", 1):
            self.advance()
            self.advance()
            e = ("in", t.line, t.col, e, self.parse_level(0), True)
        else:
            return e
        t2 = self.peek()
        if t2.kind == "OP" and t2.val in ("==", "!=", "<", "<=", ">", ">="):
            self.fail("chained comparisons are not supported; combine with 'and'", t2)
        return e

    def parse_level(self, lvl):
        if lvl == len(_LEVELS):
            return self.parse_unary()
        e = self.parse_level(lvl + 1)
        ops = _LEVELS[lvl]
        while self.peek().kind == "OP" and self.peek().val in ops:
            t = self.advance()
            e = ("bin", t.line, t.col, t.val, e, self.parse_level(lvl + 1))
        return e

    def parse_unary(self):
        t = self.peek()
        if t.kind == "OP" and t.val in ("-", "+", "~"):
            self.advance()
            return ("unary", t.line, t.col, t.val, self.parse_unary())
        return self.parse_postfix()

    def parse_postfix(self):
        e = self.parse_primary()
        while True:
            if self.is_op("."):
                self.advance()
                n = self.expect_name("a field name after '.'")
                e = ("attr", n.line, n.col, e, n.val)
            elif self.is_op("["):
                t = self.advance()
                idx = self.parse_expr()
                self.expect_op("]")
                e = ("index", t.line, t.col, e, idx)
            else:
                return e

    def parse_primary(self):
        t = self.peek()
        if t.kind in ("NUM", "STR", "BYTES"):
            self.advance()
            return ("lit", t.line, t.col, t.val)
        if t.kind == "NAME":
            if t.val in ("true", "false", "null"):
                self.advance()
                return ("lit", t.line, t.col, {"true": True, "false": False, "null": None}[t.val])
            if t.val in ("and", "or", "not", "in"):
                self.fail(f"unexpected '{t.val}' (expected an expression)", t)
            self.advance()
            if self.is_op("("):
                self.advance()
                args = []
                if not self.is_op(")"):
                    while True:
                        args.append(self.parse_expr())
                        if self.is_op(","):
                            self.advance()
                            continue
                        break
                self.expect_op(")")
                return ("call", t.line, t.col, t.val, args)
            return ("name", t.line, t.col, t.val)
        if t.kind == "OP" and t.val == "(":
            self.advance()
            e = self.parse_expr()
            self.expect_op(")")
            return e
        if t.kind == "OP" and t.val == "[":
            self.advance()
            items = []
            if not self.is_op("]"):
                while True:
                    items.append(self.parse_expr())
                    if self.is_op(","):
                        self.advance()
                        if self.is_op("]"):
                            break
                        continue
                    break
            self.expect_op("]")
            return ("list", t.line, t.col, items)
        self.fail(f"expected an expression, found {_desc(t)}", t)


# --------------------------------------------------------------------------- runtime objects

class StructView:
    """Expression-side view of a parsed struct (raw values, bytes as bytes)."""
    __slots__ = ("tdef", "vals", "fields")

    def __init__(self, tdef, vals, fields):
        self.tdef, self.vals, self.fields = tdef, vals, fields

    def get(self, name, line=0, col=0):
        v = self.vals.get(name, _MISSING)
        if v is not _MISSING:
            return v
        if name in self.tdef.declared:
            return None
        raise _EvalError(f"type '{self.tdef.name}' has no field '{name}'", line, col)

    def __repr__(self):
        return f"<struct {self.tdef.name}>"


class ArrayView:
    """Expression-side view of a parsed array."""
    __slots__ = ("vals", "node")

    def __init__(self, vals, node):
        self.vals, self.node = vals, node

    def __len__(self):
        return len(self.vals)

    def __repr__(self):
        return f"<array {self.node['type']} x{len(self.vals)}>"


class _TypeDef:
    __slots__ = ("name", "line", "col", "body", "declared", "ops")

    def __init__(self, name, line, col, body):
        self.name, self.line, self.col, self.body = name, line, col, body
        self.declared = {}
        self.ops = []


class _EnumDef:
    __slots__ = ("name", "names", "members")

    def __init__(self, name):
        self.name = name
        self.names = {}     # value -> member
        self.members = {}   # member -> value


class _Stream:
    __slots__ = ("data", "start", "end", "cur")

    def __init__(self, data, start, end, cur):
        self.data, self.start, self.end, self.cur = data, start, end, cur


class _Runtime:
    __slots__ = ("data", "base", "max_items", "depth", "root_node")

    def __init__(self, data, base, max_items):
        self.data, self.base, self.max_items = data, base, max_items
        self.depth = 0
        self.root_node = None


class _Ctx:
    __slots__ = ("rt", "s", "fields", "vals", "parent", "root", "index", "loop_index", "last", "path", "tdef")

    def __init__(self, rt, s, fields, parent, path, tdef, index):
        self.rt, self.s, self.fields, self.parent, self.path, self.tdef, self.index = rt, s, fields, parent, path, tdef, index
        self.vals = {}
        self.root = parent.root if parent is not None else self
        self.loop_index = None
        self.last = None


class _Scope:
    __slots__ = ("names", "endian", "const_mode")

    def __init__(self, names, endian, const_mode=False):
        self.names, self.endian, self.const_mode = names, endian, const_mode

    def copy(self):
        return _Scope(dict(self.names), self.endian, self.const_mode)


def _view(ctx):
    return None if ctx is None else StructView(ctx.tdef, ctx.vals, ctx.fields)


def _tn(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "str"
    if isinstance(v, (bytes, bytearray)):
        return "bytes"
    if isinstance(v, (list, tuple)):
        return "list"
    if type(v) is StructView:
        return f"struct {v.tdef.name}"
    if type(v) is ArrayView:
        return "array"
    return type(v).__name__


def _truth(v):
    if type(v) is ArrayView:
        return len(v.vals) > 0
    return bool(v)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _fmtv(v):
    if _is_int(v):
        return f"0x{v:x} ({v})" if v >= 0 else str(v)
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        r = repr(b[:24])
        return r + ("..." if len(b) > 24 else "")
    if isinstance(v, str):
        return json.dumps(v[:80], ensure_ascii=False)
    if v is None:
        return "null"
    return repr(v)


def _eq(a, b, line, col):
    if (isinstance(a, (bytes, bytearray)) and isinstance(b, str)) or (isinstance(a, str) and isinstance(b, (bytes, bytearray))):
        raise _EvalError("cannot compare bytes with str (use a b\"...\" literal or decode())", line, col)
    if type(a) is ArrayView:
        a = a.vals
    if type(b) is ArrayView:
        b = b.vals
    if type(a) is StructView or type(b) is StructView:
        raise _EvalError("cannot compare structs; compare their fields", line, col)
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return False
        return all(_eq(x, y, line, col) for x, y in zip(a, b))
    return a == b


def _in(a, b, line, col):
    if type(b) is ArrayView:
        b = b.vals
    if isinstance(b, (list, tuple)):
        return any(_eq(a, x, line, col) for x in b)
    if isinstance(b, (bytes, bytearray)):
        if _is_int(a):
            return a in b
        if isinstance(a, (bytes, bytearray)):
            return bytes(a) in b
    if isinstance(b, str) and isinstance(a, str):
        return a in b
    raise _EvalError(f"cannot test {_tn(a)} in {_tn(b)}", line, col)


def _export(v):
    """Runtime value -> (tree value, kind or None)."""
    if v is None or isinstance(v, (bool, int, float, str)):
        return v, None
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex(), "bytes"
    if isinstance(v, (list, tuple)):
        out = []
        for x in v:
            ev, k = _export(x)
            out.append(ev)
        return out, "list"
    return None, "ref"


# --------------------------------------------------------------------------- builtins

_FT_EPOCH = _dt.datetime(1601, 1, 1)
_UNIX_EPOCH = _dt.datetime(1970, 1, 1)


def _need_int(v, fname):
    if not _is_int(v):
        raise TypeError(f"{fname}() needs an integer, got {_tn(v)}")
    return v


def _need_bytes(v, fname):
    if not isinstance(v, (bytes, bytearray)):
        raise TypeError(f"{fname}() needs bytes, got {_tn(v)}")
    return bytes(v)


def _iso(d, frac=""):
    return f"{d.year:04d}-{d.month:02d}-{d.day:02d}T{d.hour:02d}:{d.minute:02d}:{d.second:02d}{frac}"


def iso_filetime(ticks):
    """FILETIME (100 ns ticks since 1601-01-01 UTC) -> 'YYYY-MM-DDTHH:MM:SS.fffffffZ' or None."""
    ticks = _need_int(ticks, "filetime")
    if ticks < 0:
        return None
    us, rem = divmod(ticks, 10)
    try:
        d = _FT_EPOCH + _dt.timedelta(microseconds=us)
    except OverflowError:
        return None
    return _iso(d, f".{d.microsecond:06d}{rem}Z")


def _bi_filetime(t):
    return iso_filetime(t)


def _bi_unix(n):
    if isinstance(n, bool) or not isinstance(n, (int, float)):
        raise TypeError(f"unix() needs a number, got {_tn(n)}")
    try:
        if isinstance(n, int):
            return _iso(_UNIX_EPOCH + _dt.timedelta(seconds=n), "Z")
        if not math.isfinite(n):
            return None
        d = _UNIX_EPOCH + _dt.timedelta(seconds=n)
        return _iso(d, f".{d.microsecond:06d}Z")
    except OverflowError:
        return None


def _bi_dosdatetime(date, time):
    date = _need_int(date, "dosdatetime")
    time = _need_int(time, "dosdatetime")
    y, mo, dd = (date >> 9) + 1980, (date >> 5) & 0xF, date & 0x1F
    h, mi, s = time >> 11, (time >> 5) & 0x3F, (time & 0x1F) * 2
    try:
        _dt.datetime(y, mo, dd, h, mi, s)
    except ValueError:
        return None
    return f"{y:04d}-{mo:02d}-{dd:02d}T{h:02d}:{mi:02d}:{s:02d}"


def _bi_dosdate(date):
    date = _need_int(date, "dosdate")
    y, mo, dd = (date >> 9) + 1980, (date >> 5) & 0xF, date & 0x1F
    try:
        _dt.date(y, mo, dd)
    except ValueError:
        return None
    return f"{y:04d}-{mo:02d}-{dd:02d}"


def _bi_len(x):
    if type(x) is ArrayView:
        return len(x.vals)
    if isinstance(x, (bytes, bytearray, str, list, tuple)):
        return len(x)
    raise TypeError(f"len() needs bytes, str or an array, got {_tn(x)}")


def _bi_hex(x):
    if _is_int(x):
        return hex(x)
    if isinstance(x, (bytes, bytearray)):
        return bytes(x).hex()
    raise TypeError(f"hex() needs an integer or bytes, got {_tn(x)}")


def _bi_guid(b):
    b = _need_bytes(b, "guid")
    if len(b) != 16:
        raise ValueError(f"guid() needs 16 bytes, got {len(b)}")
    return str(uuid.UUID(bytes_le=b))


def _bi_uuid(b):
    b = _need_bytes(b, "uuid")
    if len(b) != 16:
        raise ValueError(f"uuid() needs 16 bytes, got {len(b)}")
    return str(uuid.UUID(bytes=b))


def _bi_crc32(b):
    if b is None:
        return None
    return zlib.crc32(_need_bytes(b, "crc32")) & 0xFFFFFFFF


def _bi_adler32(b):
    if b is None:
        return None
    return zlib.adler32(_need_bytes(b, "adler32")) & 0xFFFFFFFF


def _bi_inflate(b):
    if b is None:
        return None
    try:
        return zlib.decompress(_need_bytes(b, "inflate"), -15)
    except zlib.error:
        return None


def _bi_zlib(b):
    if b is None:
        return None
    try:
        return zlib.decompress(_need_bytes(b, "zlib"))
    except zlib.error:
        return None


def _bi_decode(b, enc="utf-8"):
    if b is None:
        return None
    b = _need_bytes(b, "decode")
    if not isinstance(enc, str):
        raise TypeError("decode() encoding must be a string")
    try:
        return b.decode(enc)
    except UnicodeDecodeError:
        return None
    except LookupError:
        raise ValueError(f"unknown encoding {enc!r}")


def _bi_ascii(b):
    return _bi_decode(b, "ascii")


def _bi_unhex(s):
    if not isinstance(s, str):
        raise TypeError(f"unhex() needs a str, got {_tn(s)}")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError(f"unhex(): invalid hex string {s[:40]!r}")


def _bi_be(b):
    return int.from_bytes(_need_bytes(b, "be"), "big")


def _bi_le(b):
    return int.from_bytes(_need_bytes(b, "le"), "little")


def _bi_int(x):
    if isinstance(x, bool):
        return int(x)
    if isinstance(x, int):
        return x
    if isinstance(x, float):
        if not math.isfinite(x):
            raise ValueError("int() of a non-finite float")
        return int(x)
    if isinstance(x, str):
        try:
            return int(x.strip(), 0)
        except ValueError:
            raise ValueError(f"int(): not a number: {x[:40]!r}")
    raise TypeError(f"int() needs a number or str, got {_tn(x)}")


def _seq_args(args, fname):
    if len(args) == 1:
        a = args[0]
        if type(a) is ArrayView:
            return a.vals
        if isinstance(a, (list, tuple)):
            return list(a)
    return list(args)


def _bi_min(*args):
    seq = _seq_args(args, "min")
    if not seq:
        raise ValueError("min() of an empty sequence")
    return min(seq)


def _bi_max(*args):
    seq = _seq_args(args, "max")
    if not seq:
        raise ValueError("max() of an empty sequence")
    return max(seq)


def _bi_sum(x):
    seq = _seq_args((x,), "sum")
    return sum(seq)


def _bi_abs(x):
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        raise TypeError(f"abs() needs a number, got {_tn(x)}")
    return abs(x)


def _bi_search(ctx, pat):
    pat = _need_bytes(pat, "search")
    if not pat:
        raise ValueError("search() pattern is empty")
    s = ctx.s
    i = s.data.rfind(pat, s.start, s.end)
    return -1 if i < 0 else i - s.start


def _bi_find(ctx, pat, start=0):
    pat = _need_bytes(pat, "find")
    start = _need_int(start, "find")
    if not pat:
        raise ValueError("find() pattern is empty")
    s = ctx.s
    if start < 0:
        start = 0
    i = s.data.find(pat, s.start + start, s.end)
    return -1 if i < 0 else i - s.start


def _bi_bytes_at(ctx, off, n):
    off = _need_int(off, "bytes_at")
    n = _need_int(n, "bytes_at")
    s = ctx.s
    if off < 0 or n < 0 or s.start + off + n > s.end:
        raise ValueError(f"bytes_at({off}, {n}) is outside the buffer (size {s.end - s.start})")
    return bytes(s.data[s.start + off:s.start + off + n])


# name -> (function, min args, max args, needs ctx)
_BUILTINS = {
    "len": (_bi_len, 1, 1, False),
    "hex": (_bi_hex, 1, 1, False),
    "filetime": (_bi_filetime, 1, 1, False),
    "unix": (_bi_unix, 1, 1, False),
    "dosdatetime": (_bi_dosdatetime, 2, 2, False),
    "dosdate": (_bi_dosdate, 1, 1, False),
    "guid": (_bi_guid, 1, 1, False),
    "uuid": (_bi_uuid, 1, 1, False),
    "crc32": (_bi_crc32, 1, 1, False),
    "adler32": (_bi_adler32, 1, 1, False),
    "inflate": (_bi_inflate, 1, 1, False),
    "zlib": (_bi_zlib, 1, 1, False),
    "decode": (_bi_decode, 1, 2, False),
    "ascii": (_bi_ascii, 1, 1, False),
    "unhex": (_bi_unhex, 1, 1, False),
    "be": (_bi_be, 1, 1, False),
    "le": (_bi_le, 1, 1, False),
    "int": (_bi_int, 1, 1, False),
    "min": (_bi_min, 1, 64, False),
    "max": (_bi_max, 1, 64, False),
    "sum": (_bi_sum, 1, 1, False),
    "abs": (_bi_abs, 1, 1, False),
    "search": (_bi_search, 1, 1, True),
    "find": (_bi_find, 1, 2, True),
    "bytes_at": (_bi_bytes_at, 2, 2, True),
}
_SPECIAL_CALLS = ("offsetof", "sizeof")


def _prim_info(name, default_endian):
    m = _PRIM_RE.match(name)
    if not m:
        return None
    endian = m.group("e") or default_endian
    if m.group("fw"):
        w = int(m.group("fw")) // 8
        return ("float", w, True, endian, struct.Struct(("<" if endian == "le" else ">") + ("f" if w == 4 else "d")))
    w = int(m.group("w")) // 8
    signed = m.group("s") == "i"
    code = {1: "b", 2: "h", 4: "i", 8: "q"}.get(w)
    st = None
    if code:
        st = struct.Struct(("<" if endian == "le" else ">") + (code if signed else code.upper()))
    return ("int", w, signed, endian, st)


# --------------------------------------------------------------------------- schema / compiler

class Schema:
    """A compiled Vein module. Use parse()/parse_file()."""

    def __init__(self, mod, source_name="<spec>"):
        self.source_name = source_name
        self.endian = mod.endian
        self.types = {}
        self.enums = {}
        self.consts = {}
        self._bitfield_defs = {}
        for name, line, col, items in mod.enums:
            if name in self.enums:
                raise VeinError(f"enum '{name}' declared twice", line, col)
            en = _EnumDef(name)
            for value, member, ml, mc in items:
                if member in en.members:
                    raise VeinError(f"enum '{name}' has duplicate member '{member}'", ml, mc)
                if value in en.names:
                    raise VeinError(f"enum '{name}' value {value} declared twice", ml, mc)
                en.members[member] = value
                en.names[value] = member
            self.enums[name] = en
        for name, line, col, body in mod.types:
            if name in _BUILTIN_TYPES or _PRIM_RE.match(name):
                raise VeinError(f"'{name}' is a built-in type name", line, col)
            if name in self.types:
                t = self.types[name]
                raise VeinError(f"type '{name}' declared twice (first at {t.line}:{t.col})", line, col)
            self.types[name] = _TypeDef(name, line, col, body)
        for td in self.types.values():
            self._declared(td.body, td.declared)
        for name, line, col, expr in mod.consts:
            if name in self.consts or name in _RESERVED:
                raise VeinError(f"constant '{name}' is reserved or declared twice", line, col)
            fn = self._cx(expr, _Scope({}, self.endian, const_mode=True))
            try:
                self.consts[name] = fn(None)
            except _EvalError as e:
                raise VeinError(e.msg, e.line, e.col)
        for td in self.types.values():
            td.ops = self._c_body(td.body, _Scope({}, self.endian))
        if mod.root is not None:
            rname, rl, rc = mod.root
            if rname not in self.types:
                raise VeinError(f"root type '{rname}' is not declared", rl, rc)
            self.root = rname
        elif "file" in self.types:
            self.root = "file"
        elif mod.types:
            self.root = mod.types[0][0]
        else:
            self.root = None

    # -- public
    @property
    def type_names(self):
        return list(self.types)

    def parse(self, data, root=None, base_offset=0, max_items=None):
        """Parse bytes-like data. Returns the root node dict."""
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        if not isinstance(data, (bytes, mmap.mmap)):
            raise TypeError(f"parse() needs bytes, got {type(data).__name__}")
        name = root or self.root
        tdef = self.types.get(name) if name else None
        if tdef is None:
            raise VeinError(f"unknown root type {name!r}; declared types: {', '.join(self.types) or '(none)'}", 0, 0)
        rt = _Runtime(data, int(base_offset), int(max_items) if max_items else DEFAULT_MAX_ITEMS)
        s = _Stream(data, 0, len(data), 0)
        old = sys.getrecursionlimit()
        if old < 20000:
            sys.setrecursionlimit(20000)
        try:
            node, _ = _parse_struct(rt, tdef, s, None, name, None)
        except ParseError as e:
            e.partial = rt.root_node
            raise
        except RecursionError:
            err = ParseError("structure nests too deeply (Python recursion limit)", rt.base + s.cur, name)
            err.partial = rt.root_node
            raise err from None
        finally:
            sys.setrecursionlimit(old)
        return node

    def parse_file(self, path, root=None, base_offset=0, max_items=None):
        """Parse a file opened read-only (memory-mapped). The file is never written."""
        with open(path, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            if size == 0:
                return self.parse(b"", root=root, base_offset=base_offset, max_items=max_items)
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                return self.parse(mm, root=root, base_offset=base_offset, max_items=max_items)
            finally:
                mm.close()

    # -- static analysis
    def _typeinfo(self, tref):
        if tref[0] == "named" and tref[3] in self.types:
            return ("type", tref[3])
        if tref[0] == "array" and tref[3][0] == "named" and tref[3][3] in self.types:
            return ("array", tref[3][3])
        return None

    def _declared(self, stmts, out):
        for st in stmts:
            k = st[0]
            if k == "field":
                out.setdefault(st[3], self._typeinfo(st[4]))
            elif k == "let":
                out.setdefault(st[3], None)
            elif k == "bitfield":
                if st[3]:
                    bf = self._bitfield_defs.get(id(st))
                    if bf is None:
                        bf = _TypeDef("bitfield", st[1], st[2], [])
                        for it in st[4]:
                            if it[0] != "_":
                                bf.declared[it[0]] = None
                        self._bitfield_defs[id(st)] = bf
                    out.setdefault(st[3], ("bitfield", bf))
                else:
                    for it in st[4]:
                        if it[0] != "_":
                            out.setdefault(it[0], None)
            elif k == "if":
                for _, body in st[3]:
                    self._declared(body, out)
            elif k == "at":
                self._declared(st[4], out)

    def _member_check(self, obj, member, sc, line, col):
        info = None
        if obj[0] == "name" and obj[3] in sc.names:
            info = sc.names[obj[3]][0]
        elif obj[0] == "index" and obj[3][0] == "name" and obj[3][3] in sc.names:
            i2 = sc.names[obj[3][3]][0]
            if i2 and i2[0] == "array":
                info = ("type", i2[1])
        if not info:
            return
        if info[0] == "type":
            td = self.types.get(info[1])
            if td is not None and member not in td.declared:
                raise VeinError(f"type '{td.name}' has no field '{member}'", line, col)
        elif info[0] == "bitfield" and member not in info[1].declared:
            raise VeinError(f"bitfield has no member '{member}'", line, col)

    # -- statements
    def _declare(self, sc, name, info, line, col):
        if name in _RESERVED:
            raise VeinError(f"'{name}' is a reserved name and cannot be a field name", line, col)
        if name in sc.names:
            _, pl, pc = sc.names[name]
            raise VeinError(f"duplicate field '{name}' (first declared at {pl}:{pc})", line, col)
        sc.names[name] = (info, line, col)

    def _c_body(self, stmts, sc):
        ops = []
        for st in stmts:
            op = self._c_stmt(st, sc)
            if op is not None:
                ops.append(op)
        return ops

    def _c_stmt(self, st, sc):
        k = st[0]
        if k == "field":
            return self._c_field(st, sc)
        if k == "let":
            return self._c_let(st, sc)
        if k == "if":
            return self._c_if(st, sc)
        if k == "seek":
            return self._c_seek(st, sc)
        if k == "at":
            return self._c_at(st, sc)
        if k == "bitfield":
            return self._c_bitfield(st, sc)
        if k == "endian":
            sc.endian = st[3]
            return None
        if k == "assert":
            return self._c_assert(st, sc)
        raise VeinError(f"internal: unknown statement {k}", st[1], st[2])

    def _c_checks(self, mods, sc):
        checks = []
        for key, opname in (("eq", "=="), ("ne", "!="), ("in", "in")):
            if key in mods:
                e, src, l, c = mods[key]
                checks.append((key, opname, self._cx(e, sc), src, l, c))
        return checks

    def _c_field(self, st, sc):
        _, line, col, name, tref, mods = st
        if name in _RESERVED:
            raise VeinError(f"'{name}' is a reserved name and cannot be a field name", line, col)
        if name in sc.names:
            _, pl, pc = sc.names[name]
            raise VeinError(f"duplicate field '{name}' (first declared at {pl}:{pc})", line, col)
        cond = self._cx(mods["if"][0], sc) if "if" in mods else None
        at = self._cx(mods["at"][0], sc) if "at" in mods else None
        size = self._cx(mods["size"][0], sc) if "size" in mods else None
        enum = None
        if "enum" in mods:
            en, el, ec = mods["enum"]
            if en not in self.enums:
                raise VeinError(f"unknown enum '{en}'", el, ec)
            enum = self.enums[en]
        reader = self._reader(tref, sc, enum)
        checks = self._c_checks(mods, sc)
        if checks:
            base = tref[3] if tref[0] == "array" else tref
            if tref[0] == "array" or (base[0] == "named" and base[3] in self.types):
                raise VeinError("assertions (==, !=, in) are only allowed on scalar fields", checks[0][4], checks[0][5])
        self._declare(sc, name, self._typeinfo(tref), line, col)

        def op(ctx):
            if cond is not None and not _truth(cond(ctx)):
                return
            s = ctx.s
            rt = ctx.rt
            path = ctx.path + "." + name
            saved = -1
            if at is not None:
                t = at(ctx)
                if not _is_int(t):
                    raise _EvalError(f"'at' offset must be an integer, got {_tn(t)}", mods["at"][2], mods["at"][3])
                if t < 0 or t > s.end - s.start:
                    raise ParseError(f"'at' offset {t} is outside the buffer (size {s.end - s.start})", rt.base + s.cur, path)
                saved = s.cur
                s.cur = s.start + t
            try:
                if size is not None:
                    n = size(ctx)
                    if not _is_int(n):
                        raise _EvalError(f"'size' must be an integer, got {_tn(n)}", mods["size"][2], mods["size"][3])
                    if n < 0:
                        raise ParseError(f"negative size {n}", rt.base + s.cur, path)
                    if s.cur + n > s.end:
                        raise ParseError(f"unexpected end of data: field needs {n} bytes, {s.end - s.cur} available",
                                         rt.base + s.cur, path)
                    sub = _Stream(s.data, s.cur, s.cur + n, s.cur)
                    ctx.s = sub
                    try:
                        node, val = reader(ctx, path, name, None)
                    finally:
                        ctx.s = s
                    used = sub.cur - sub.start
                    s.cur += n
                    node["offset"] = rt.base + sub.start
                    node["size"] = n
                    if used < n:
                        node["tail"] = n - used
                else:
                    node, val = reader(ctx, path, name, None)
            finally:
                if saved >= 0:
                    s.cur = saved
            for key, opname, fn, src, l, c in checks:
                exp = fn(ctx)
                if key == "eq":
                    ok = _eq(val, exp, l, c)
                elif key == "ne":
                    ok = not _eq(val, exp, l, c)
                else:
                    ok = _in(val, exp, l, c)
                if not ok:
                    raise AssertFailed(f"assertion failed: {path} {opname} {src}; got {_fmtv(val)}",
                                       node["offset"], path, field=name, expected=exp, actual=val)
            ctx.fields[name] = node
            ctx.vals[name] = val
        return _guard(op, name)

    def _c_let(self, st, sc):
        _, line, col, name, expr = st
        fn = self._cx(expr, sc)
        self._declare(sc, name, None, line, col)

        def op(ctx):
            v = fn(ctx)
            ev, kind = _export(v)
            node = {"type": "let", "offset": None, "size": 0, "value": ev}
            if kind:
                node["kind"] = kind
            ctx.fields[name] = node
            ctx.vals[name] = v
        return _guard(op, name)

    def _c_if(self, st, sc):
        branches = []
        union = {}
        for cond, body in st[3]:
            fc = self._cx(cond, sc) if cond is not None else None
            bsc = sc.copy()
            ops = self._c_body(body, bsc)
            for k, v in bsc.names.items():
                if k not in sc.names and k not in union:
                    union[k] = v
            branches.append((fc, ops))
        sc.names.update(union)

        def op(ctx):
            for fc, ops in branches:
                if fc is None or _truth(fc(ctx)):
                    for o in ops:
                        o(ctx)
                    return
        return _guard(op, None)

    def _c_seek(self, st, sc):
        _, line, col, expr = st
        fn = self._cx(expr, sc)

        def op(ctx):
            t = fn(ctx)
            s = ctx.s
            if not _is_int(t):
                raise _EvalError(f"'@' offset must be an integer, got {_tn(t)}", line, col)
            if t < 0 or t > s.end - s.start:
                raise ParseError(f"'@' offset {t} is outside the buffer (size {s.end - s.start})",
                                 ctx.rt.base + s.cur, ctx.path)
            s.cur = s.start + t
        return _guard(op, None)

    def _c_at(self, st, sc):
        _, line, col, expr, body = st
        fn = self._cx(expr, sc) if expr is not None else None
        ops = self._c_body(body, sc)

        def op(ctx):
            s = ctx.s
            saved = s.cur
            if fn is not None:
                t = fn(ctx)
                if not _is_int(t):
                    raise _EvalError(f"'at' offset must be an integer, got {_tn(t)}", line, col)
                if t < 0 or t > s.end - s.start:
                    raise ParseError(f"'at' offset {t} is outside the buffer (size {s.end - s.start})",
                                     ctx.rt.base + s.cur, ctx.path)
                s.cur = s.start + t
            try:
                for o in ops:
                    o(ctx)
            finally:
                s.cur = saved
        return _guard(op, None)

    def _c_assert(self, st, sc):
        _, line, col, expr, src, msg = st
        fn = self._cx(expr, sc)
        text = msg or f"assertion failed: {src}"

        def op(ctx):
            if not _truth(fn(ctx)):
                raise AssertFailed(f"{text} [spec line {line}:{col}]", ctx.rt.base + ctx.s.cur, ctx.path)
        return _guard(op, None)

    def _c_bitfield(self, st, sc):
        _, line, col, bname, items, nl, nc = st
        total = sum(it[3] for it in items)
        if not items:
            raise VeinError("empty bitfield", line, col)
        if total % 8:
            raise VeinError(f"bitfield is {total} bits; the total must be a multiple of 8 (pad with '_: bits(n)')",
                            line, col)
        nbytes = total // 8
        compiled = []
        pos = 0
        member_scope = sc if bname is None else _Scope({}, sc.endian)
        for mname, ml, mc, width, mods in items:
            enum = None
            if "enum" in mods:
                en, el, ec = mods["enum"]
                if en not in self.enums:
                    raise VeinError(f"unknown enum '{en}'", el, ec)
                enum = self.enums[en]
            checks = self._c_checks(mods, sc)
            if mname != "_":
                self._declare(member_scope, mname, None, ml, mc)
            compiled.append((mname, pos, width, (1 << width) - 1, enum.names if enum else None, checks))
            pos += width
        bf = None
        if bname is not None:
            bf = self._bitfield_defs[id(st)]
            self._declare(sc, bname, ("bitfield", bf), nl, nc)

        def op(ctx):
            s = ctx.s
            rt = ctx.rt
            c = s.cur
            path0 = ctx.path + ("." + bname if bname else "")
            if c + nbytes > s.end:
                raise ParseError(f"unexpected end of data: bitfield needs {nbytes} bytes, {s.end - c} available",
                                 rt.base + c, path0)
            big = int.from_bytes(s.data[c:c + nbytes], "big")
            s.cur = c + nbytes
            if bname is None:
                fields, vals = ctx.fields, ctx.vals
            else:
                fields, vals = {}, {}
            for mname, bitpos, width, mask, names, checks in compiled:
                v = (big >> (total - bitpos - width)) & mask
                node = {"type": "bits", "offset": rt.base + c + bitpos // 8,
                        "size": ((bitpos % 8) + width + 7) // 8, "value": v, "bit": bitpos % 8, "bits": width}
                if names is not None:
                    node["name"] = names.get(v)
                mpath = path0 + "." + mname
                for key, opname, fn, src, l, cc in checks:
                    exp = fn(ctx)
                    ok = _eq(v, exp, l, cc) if key == "eq" else (not _eq(v, exp, l, cc) if key == "ne" else _in(v, exp, l, cc))
                    if not ok:
                        raise AssertFailed(f"assertion failed: {mpath} {opname} {src}; got {_fmtv(v)}",
                                           node["offset"], mpath, field=mname, expected=exp, actual=v)
                if mname != "_":
                    fields[mname] = node
                    vals[mname] = v
            if bname is not None:
                ctx.fields[bname] = {"type": "bitfield", "offset": rt.base + c, "size": nbytes, "fields": fields}
                ctx.vals[bname] = StructView(bf, vals, fields)
        return _guard(op, bname)

    # -- readers: fn(ctx, path, name, index) -> (node, runtime value)
    def _type_str(self, tref):
        k = tref[0]
        if k == "named":
            return tref[3]
        if k == "array":
            return self._type_str(tref[3]) + "[]"
        return k

    def _reader(self, tref, sc, enum):
        k = tref[0]
        line, col = tref[1], tref[2]
        if k == "array":
            return self._array_reader(tref, sc, enum)
        if enum is not None and not (k == "named" and _PRIM_RE.match(tref[3]) and not tref[3].startswith("f")):
            raise VeinError("'enum' can only be applied to integer fields", line, col)
        if k == "named":
            name = tref[3]
            pi = _prim_info(name, sc.endian)
            if pi is not None:
                return _prim_reader(name, pi, enum)
            if name in self.types:
                tdef = self.types[name]

                def rd_user(ctx, path, fname, index):
                    return _parse_struct(ctx.rt, tdef, ctx.s, ctx, path, index, fname)
                return rd_user
            raise VeinError(f"unknown type '{name}'", line, col)
        if k in ("bytes", "skip"):
            nfn = self._cx(tref[3], sc)
            skip = k == "skip"

            def rd_bytes(ctx, path, fname, index):
                n = _length(nfn(ctx), ctx, path, line, col)
                s = ctx.s
                c = s.cur
                if c + n > s.end:
                    raise _trunc(ctx, c, n, path, k)
                s.cur = c + n
                if skip:
                    return {"type": "skip", "offset": ctx.rt.base + c, "size": n, "value": None}, None
                b = bytes(s.data[c:c + n])
                return {"type": "bytes", "offset": ctx.rt.base + c, "size": n, "value": b.hex()}, b
            return rd_bytes
        if k in ("str", "strz"):
            nfn = self._cx(tref[3], sc)
            efn = self._encoding(tref[4], sc)
            strz = k == "strz"

            def rd_str(ctx, path, fname, index):
                n = _length(nfn(ctx), ctx, path, line, col)
                enc = efn(ctx)
                s = ctx.s
                c = s.cur
                if c + n > s.end:
                    raise _trunc(ctx, c, n, path, k)
                s.cur = c + n
                b = bytes(s.data[c:c + n])
                if strz:
                    z = b.find(b"\x00")
                    b = b if z < 0 else b[:z]
                node = {"type": k, "offset": ctx.rt.base + c, "size": n, "value": None, "encoding": enc}
                node["value"] = _decode_into(node, b, enc, line, col)
                return node, node["value"]
            return rd_str
        if k == "cstr":
            efn = self._encoding(tref[3], sc)

            def rd_cstr(ctx, path, fname, index):
                enc = efn(ctx)
                s = ctx.s
                c = s.cur
                wide = enc.lower().replace("_", "-") in ("utf-16", "utf-16le", "utf-16-le", "utf-16be", "utf-16-be")
                if wide:
                    j = c
                    while True:
                        j = s.data.find(b"\x00\x00", j, s.end)
                        if j < 0 or (j - c) % 2 == 0:
                            break
                        j += 1
                    term = 2
                else:
                    j = s.data.find(b"\x00", c, s.end)
                    term = 1
                if j < 0:
                    raise ParseError("cstr: no NUL terminator before the end of the buffer", ctx.rt.base + c, path)
                b = bytes(s.data[c:j])
                s.cur = j + term
                node = {"type": "cstr", "offset": ctx.rt.base + c, "size": j + term - c, "value": None, "encoding": enc}
                node["value"] = _decode_into(node, b, enc, line, col)
                return node, node["value"]
            return rd_cstr
        raise VeinError(f"internal: unknown type form {k}", line, col)

    def _encoding(self, e, sc):
        if e[0] == "lit":
            enc = e[3]
            if not isinstance(enc, str):
                raise VeinError("encoding must be a string", e[1], e[2])
            try:
                codecs.lookup(enc)
            except LookupError:
                raise VeinError(f"unknown encoding '{enc}'", e[1], e[2])
            return lambda ctx: enc
        fn = self._cx(e, sc)
        l, c = e[1], e[2]

        def f(ctx):
            enc = fn(ctx)
            if not isinstance(enc, str):
                raise _EvalError(f"encoding must be a string, got {_tn(enc)}", l, c)
            try:
                codecs.lookup(enc)
            except LookupError:
                raise _EvalError(f"unknown encoding '{enc}'", l, c)
            return enc
        return f

    def _array_reader(self, tref, sc, enum):
        _, line, col, base, rep = tref
        elem = self._reader(base, sc, enum)
        tstr = self._type_str(tref)
        rkind, rexpr = rep
        rf = self._cx(rexpr, sc) if rexpr is not None else None

        def rd_array(ctx, path, fname, index):
            rt = ctx.rt
            s = ctx.s
            start = s.cur
            items, vals = [], []
            node = {"type": tstr, "offset": rt.base + start, "size": 0, "items": items, "stopped": None}
            view = ArrayView(vals, node)
            if fname is not None:
                ctx.fields[fname] = node      # visible while in progress: _parent.arr[_index - 1]
                ctx.vals[fname] = view
            lim = rt.max_items
            try:
                if rkind == "count":
                    cnt = rf(ctx)
                    if not _is_int(cnt):
                        raise _EvalError(f"array count must be an integer, got {_tn(cnt)}", line, col)
                    if cnt < 0:
                        raise ParseError(f"negative array count {cnt}", rt.base + s.cur, path)
                    if cnt > lim:
                        raise ParseError(f"array count {cnt} exceeds max_items {lim}", rt.base + s.cur, path)
                    for i in range(cnt):
                        n, v = elem(ctx, f"{path}[{i}]", None, i)
                        items.append(n)
                        vals.append(v)
                elif rkind == "eof":
                    i = 0
                    while s.cur < s.end:
                        if i >= lim:
                            raise ParseError(f"array exceeds max_items {lim}", rt.base + s.cur, path)
                        at0 = s.cur
                        n, v = elem(ctx, f"{path}[{i}]", None, i)
                        if s.cur == at0:
                            raise ParseError("array item consumed no bytes; 'until eof' cannot make progress",
                                             rt.base + at0, f"{path}[{i}]")
                        items.append(n)
                        vals.append(v)
                        i += 1
                elif rkind == "eof_or_fail":
                    i = 0
                    while s.cur < s.end:
                        if i >= lim:
                            node["stopped"] = {"reason": f"max_items {lim} reached", "offset": rt.base + s.cur}
                            break
                        at0 = s.cur
                        try:
                            n, v = elem(ctx, f"{path}[{i}]", None, i)
                        except ParseError as ex:
                            s.cur = at0
                            node["stopped"] = {"reason": ex.msg, "offset": rt.base + at0,
                                               "error_offset": ex.offset, "error_path": ex.path}
                            break
                        if s.cur == at0:
                            node["stopped"] = {"reason": "array item consumed no bytes", "offset": rt.base + at0}
                            break
                        items.append(n)
                        vals.append(v)
                        i += 1
                else:
                    saved = (ctx.loop_index, ctx.last)
                    try:
                        i = 0
                        while True:
                            if i >= lim:
                                raise ParseError(f"array exceeds max_items {lim}", rt.base + s.cur, path)
                            if rkind == "while":
                                ctx.loop_index = i
                                ctx.last = vals[-1] if vals else None
                                if not _truth(rf(ctx)):
                                    break
                            n, v = elem(ctx, f"{path}[{i}]", None, i)
                            items.append(n)
                            vals.append(v)
                            if rkind == "until":
                                ctx.loop_index = i
                                ctx.last = v
                                if _truth(rf(ctx)):
                                    break
                            i += 1
                    finally:
                        ctx.loop_index, ctx.last = saved
            finally:
                node["size"] = s.cur - start if s.cur >= start else 0
            return node, view
        return rd_array

    # -- expressions -> closures fn(ctx)
    def _cx(self, e, sc):
        k, line, col = e[0], e[1], e[2]
        if k == "lit":
            v = e[3]
            return lambda ctx: v
        if k == "name":
            return self._cx_name(e, sc)
        if k == "attr":
            obj, member = e[3], e[4]
            if (obj[0] == "name" and obj[3] not in sc.names and obj[3] in self.enums
                    and obj[3] not in _RESERVED):
                en = self.enums[obj[3]]
                if member not in en.members:
                    raise VeinError(f"enum '{en.name}' has no member '{member}'", line, col)
                v = en.members[member]
                return lambda ctx: v
            if sc.const_mode:
                raise VeinError("constant expressions may only use literals, enums and other constants", line, col)
            self._member_check(obj, member, sc, line, col)
            fo = self._cx(obj, sc)

            def f_attr(ctx):
                o = fo(ctx)
                if type(o) is StructView:
                    return o.get(member, line, col)
                raise _EvalError(f"cannot read '.{member}' of {_tn(o)}", line, col)
            return f_attr
        if k == "index":
            fo = self._cx(e[3], sc)
            fi = self._cx(e[4], sc)

            def f_index(ctx):
                o = fo(ctx)
                i = fi(ctx)
                if not _is_int(i):
                    raise _EvalError(f"index must be an integer, got {_tn(i)}", line, col)
                if type(o) is ArrayView:
                    seq = o.vals
                elif isinstance(o, (bytes, bytearray, str, list, tuple)):
                    seq = o
                else:
                    raise _EvalError(f"cannot index {_tn(o)}", line, col)
                try:
                    return seq[i]
                except IndexError:
                    raise _EvalError(f"index {i} out of range (length {len(seq)})", line, col) from None
            return f_index
        if k == "call":
            return self._cx_call(e, sc)
        if k == "unary":
            op, fa = e[3], self._cx(e[4], sc)

            def f_unary(ctx):
                a = fa(ctx)
                if op == "~":
                    if not _is_int(a):
                        raise _EvalError(f"'~' needs an integer, got {_tn(a)}", line, col)
                    return ~a
                if isinstance(a, bool) or not isinstance(a, (int, float)):
                    raise _EvalError(f"unary '{op}' needs a number, got {_tn(a)}", line, col)
                return -a if op == "-" else a
            return f_unary
        if k == "not":
            fa = self._cx(e[3], sc)
            return lambda ctx: not _truth(fa(ctx))
        if k == "and":
            fa, fb = self._cx(e[3], sc), self._cx(e[4], sc)
            return lambda ctx: _truth(fa(ctx)) and _truth(fb(ctx))
        if k == "or":
            fa, fb = self._cx(e[3], sc), self._cx(e[4], sc)
            return lambda ctx: _truth(fa(ctx)) or _truth(fb(ctx))
        if k == "cond":
            fc, fa, fb = self._cx(e[3], sc), self._cx(e[4], sc), self._cx(e[5], sc)
            return lambda ctx: fa(ctx) if _truth(fc(ctx)) else fb(ctx)
        if k == "list":
            fs = [self._cx(x, sc) for x in e[3]]
            return lambda ctx: [f(ctx) for f in fs]
        if k == "cmp":
            return _cmp_closure(e[3], self._cx(e[4], sc), self._cx(e[5], sc), line, col)
        if k == "in":
            fa, fb, neg = self._cx(e[3], sc), self._cx(e[4], sc), e[5]
            if neg:
                return lambda ctx: not _in(fa(ctx), fb(ctx), line, col)
            return lambda ctx: _in(fa(ctx), fb(ctx), line, col)
        if k == "bin":
            return _bin_closure(e[3], self._cx(e[4], sc), self._cx(e[5], sc), line, col)
        raise VeinError(f"internal: unknown expression {k}", line, col)

    def _cx_name(self, e, sc):
        name, line, col = e[3], e[1], e[2]
        if sc.const_mode:
            if name in self.consts:
                v = self.consts[name]
                return lambda ctx: v
            raise VeinError(f"constant expressions may only use literals, enums and other constants ('{name}')", line, col)
        if name in sc.names:
            return lambda ctx: ctx.vals.get(name)
        if name == "pos":
            return lambda ctx: ctx.s.cur - ctx.s.start
        if name == "size":
            return lambda ctx: ctx.s.end - ctx.s.start
        if name == "eof":
            return lambda ctx: ctx.s.cur >= ctx.s.end
        if name == "_parent":
            return lambda ctx: _view(ctx.parent)
        if name == "_root":
            return lambda ctx: _view(ctx.root)
        if name == "_":
            return lambda ctx: ctx.last
        if name == "_index":
            return lambda ctx: ctx.loop_index if ctx.loop_index is not None else ctx.index
        if name in self.consts:
            v = self.consts[name]
            return lambda ctx: v
        if name in self.enums:
            raise VeinError(f"enum '{name}' is not a value; use {name}.member", line, col)
        raise VeinError(f"unknown name '{name}' (a field can only use fields declared before it; "
                        f"use _parent / _root for enclosing types)", line, col)

    def _cx_node(self, e, sc, fname):
        k, line, col = e[0], e[1], e[2]
        if k == "name":
            name = e[3]
            if name not in sc.names:
                raise VeinError(f"{fname}() needs a field declared earlier, got '{name}'", line, col)
            return lambda ctx: ctx.fields.get(name)
        if k == "attr":
            member = e[4]
            self._member_check(e[3], member, sc, line, col)
            fo = self._cx(e[3], sc)

            def f_attr(ctx):
                o = fo(ctx)
                if type(o) is StructView:
                    o.get(member, line, col)
                    return o.fields.get(member)
                raise _EvalError(f"{fname}(): cannot read '.{member}' of {_tn(o)}", line, col)
            return f_attr
        if k == "index":
            fo, fi = self._cx(e[3], sc), self._cx(e[4], sc)

            def f_index(ctx):
                o = fo(ctx)
                i = fi(ctx)
                if type(o) is not ArrayView or not _is_int(i):
                    raise _EvalError(f"{fname}(): expected array[int], got {_tn(o)}[{_tn(i)}]", line, col)
                try:
                    return o.node["items"][i]
                except IndexError:
                    raise _EvalError(f"{fname}(): index {i} out of range", line, col) from None
            return f_index
        raise VeinError(f"{fname}() takes a field reference such as a, a.b or a[i]", line, col)

    def _cx_call(self, e, sc):
        _, line, col, fname, args = e
        if sc.const_mode and (fname in _SPECIAL_CALLS or _PRIM_RE.match(fname)
                              or (fname in _BUILTINS and _BUILTINS[fname][3])):
            raise VeinError(f"{fname}() reads the buffer and cannot be used in a constant", line, col)
        if fname in _SPECIAL_CALLS:
            if len(args) != 1:
                raise VeinError(f"{fname}() takes exactly 1 argument", line, col)
            fn = self._cx_node(args[0], sc, fname)
            key = "offset" if fname == "offsetof" else "size"

            def f_special(ctx):
                n = fn(ctx)
                if n is None:
                    raise _EvalError(f"{fname}(): field is not present", line, col)
                v = n.get(key)
                if v is None:
                    raise _EvalError(f"{fname}(): computed field has no {key}", line, col)
                return v - ctx.rt.base - ctx.s.start if key == "offset" else v
            return f_special
        pi = _prim_info(fname, sc.endian)
        if pi is not None:
            if len(args) != 1:
                raise VeinError(f"{fname}(offset) takes exactly 1 argument", line, col)
            fa = self._cx(args[0], sc)
            kind, w, signed, endian, st = pi
            order = "little" if endian == "le" else "big"

            def f_peek(ctx):
                off = fa(ctx)
                if not _is_int(off):
                    raise _EvalError(f"{fname}() offset must be an integer, got {_tn(off)}", line, col)
                s = ctx.s
                if off < 0 or s.start + off + w > s.end:
                    raise _EvalError(f"{fname}({off}) reads outside the buffer (size {s.end - s.start})", line, col)
                a = s.start + off
                if st is not None:
                    return st.unpack_from(s.data, a)[0]
                return int.from_bytes(s.data[a:a + w], order, signed=signed)
            return f_peek
        if fname not in _BUILTINS:
            raise VeinError(f"unknown function '{fname}'", line, col)
        fn, nmin, nmax, needs_ctx = _BUILTINS[fname]
        if not nmin <= len(args) <= nmax:
            want = str(nmin) if nmin == nmax else f"{nmin}..{nmax}"
            raise VeinError(f"{fname}() takes {want} argument(s), got {len(args)}", line, col)
        fargs = [self._cx(a, sc) for a in args]

        def f_call(ctx):
            av = [g(ctx) for g in fargs]
            try:
                return fn(ctx, *av) if needs_ctx else fn(*av)
            except (TypeError, ValueError, OverflowError) as ex:
                raise _EvalError(f"{fname}(): {ex}", line, col) from None
        return f_call


def _length(v, ctx, path, line, col):
    if not _is_int(v):
        raise _EvalError(f"length must be an integer, got {_tn(v)}", line, col)
    if v < 0:
        raise ParseError(f"negative length {v}", ctx.rt.base + ctx.s.cur, path)
    return v


def _trunc(ctx, c, n, path, tname):
    s = ctx.s
    return ParseError(f"unexpected end of data: {tname} needs {n} bytes, {max(0, s.end - c)} available "
                      f"(buffer ends at 0x{ctx.rt.base + s.end:x})", ctx.rt.base + c, path)


def _decode_into(node, b, enc, line, col):
    try:
        return b.decode(enc)
    except UnicodeDecodeError as ex:
        node["decode_error"] = str(ex)
        node["raw"] = b.hex()
        return b.decode(enc, "backslashreplace")
    except LookupError:
        raise _EvalError(f"unknown encoding '{enc}'", line, col)


def _prim_reader(tname, pi, enum):
    kind, w, signed, endian, st = pi
    order = "little" if endian == "le" else "big"
    names = enum.names if enum is not None else None
    unpack = st.unpack_from if st is not None else None

    def rd_prim(ctx, path, fname, index):
        s = ctx.s
        c = s.cur
        if c + w > s.end:
            raise _trunc(ctx, c, w, path, tname)
        if unpack is not None:
            v = unpack(s.data, c)[0]
        else:
            v = int.from_bytes(s.data[c:c + w], order, signed=signed)
        s.cur = c + w
        node = {"type": tname, "offset": ctx.rt.base + c, "size": w, "value": v}
        if names is not None:
            node["name"] = names.get(v)
        return node, v
    return rd_prim


def _guard(op, name):
    def guarded(ctx):
        try:
            op(ctx)
        except _EvalError as e:
            p = ctx.path + ("." + name if name else "")
            raise ParseError(f"{e.msg} [spec line {e.line}:{e.col}]", ctx.rt.base + ctx.s.cur, p) from None
    return guarded


def _parse_struct(rt, tdef, s, parent, path, index, fname=None):
    if rt.depth >= MAX_DEPTH:
        raise ParseError(f"nesting deeper than {MAX_DEPTH} levels (recursive type '{tdef.name}'?)",
                         rt.base + s.cur, path)
    rt.depth += 1
    start = s.cur
    fields = {}
    node = {"type": tdef.name, "offset": rt.base + start, "size": 0, "fields": fields}
    ctx = _Ctx(rt, s, fields, parent, path, tdef, index)
    if parent is None:
        rt.root_node = node
    elif fname is not None:
        parent.fields[fname] = node      # visible early so a partial tree shows where parsing stopped
    try:
        for op in tdef.ops:
            op(ctx)
    finally:
        rt.depth -= 1
        node["size"] = s.cur - start if s.cur >= start else 0
    return node, StructView(tdef, ctx.vals, fields)


def _div(a, b):
    if _is_int(a) and _is_int(b):
        return a // b
    return a / b


def _shl(a, b):
    if not (_is_int(a) and _is_int(b)):
        raise TypeError("shift needs integers")
    if b < 0 or b > 4096:
        raise ValueError(f"shift count {b} out of range 0..4096")
    return a << b


def _shr(a, b):
    if not (_is_int(a) and _is_int(b)):
        raise TypeError("shift needs integers")
    if b < 0:
        raise ValueError(f"negative shift count {b}")
    return a >> b


_BINFN = {"+": operator.add, "-": operator.sub, "*": operator.mul, "/": _div, "%": operator.mod,
          "&": operator.and_, "|": operator.or_, "^": operator.xor, "<<": _shl, ">>": _shr}


def _bin_closure(op, fa, fb, line, col):
    fn = _BINFN[op]

    def f_bin(ctx):
        a = fa(ctx)
        b = fb(ctx)
        if op in "&|^" and not (_is_int(a) and _is_int(b)) and not (isinstance(a, bool) and isinstance(b, bool)):
            raise _EvalError(f"'{op}' needs integers, got {_tn(a)} and {_tn(b)}", line, col)
        try:
            return fn(a, b)
        except ZeroDivisionError:
            raise _EvalError(f"division by zero in '{op}'", line, col) from None
        except (TypeError, ValueError, OverflowError) as ex:
            detail = str(ex) if op in ("<<", ">>") else f"cannot apply '{op}' to {_tn(a)} and {_tn(b)}"
            raise _EvalError(detail, line, col) from None
    return f_bin


def _cmp_closure(op, fa, fb, line, col):
    if op == "==":
        return lambda ctx: _eq(fa(ctx), fb(ctx), line, col)
    if op == "!=":
        return lambda ctx: not _eq(fa(ctx), fb(ctx), line, col)
    fn = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge}[op]

    def f_cmp(ctx):
        a = fa(ctx)
        b = fb(ctx)
        try:
            return fn(a, b)
        except TypeError:
            raise _EvalError(f"cannot compare {_tn(a)} {op} {_tn(b)}", line, col) from None
    return f_cmp


# --------------------------------------------------------------------------- public helpers

def compile(source_text, name="<spec>"):  # noqa: A001 - public API name by contract
    """Compile Vein source text into a Schema. Raises VeinError(message, line, col)."""
    if not isinstance(source_text, str):
        raise TypeError("vein.compile() needs source text (str)")
    return Schema(_Parser(source_text).parse_module(), name)


def compile_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return compile(f.read(), os.path.basename(path))


_SPEC_CACHE = {}


def load_spec(name):
    """Compile a bundled spec from specs/ by name ('zip' or 'zip.vein')."""
    base = name[:-5] if name.endswith(".vein") else name
    if base not in _SPEC_CACHE:
        _SPEC_CACHE[base] = compile_file(os.path.join(SPECS_DIR, base + ".vein"))
    return _SPEC_CACHE[base]


def list_specs():
    """[(name, path, description)] for bundled specs."""
    out = []
    if not os.path.isdir(SPECS_DIR):
        return out
    for fn in sorted(os.listdir(SPECS_DIR)):
        if not fn.endswith(".vein"):
            continue
        path = os.path.join(SPECS_DIR, fn)
        desc = ""
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    desc = line.lstrip("#").strip()
                    if " - " in desc and desc.split(" - ", 1)[0].strip() == fn:
                        desc = desc.split(" - ", 1)[1].strip()
                    break
        out.append((fn[:-5], path, desc))
    return out


def _jsonify(obj):
    if isinstance(obj, dict):
        is_bytes = obj.get("type") == "bytes" or obj.get("kind") == "bytes"
        out = {}
        for k, v in obj.items():
            if k == "value" and is_bytes and isinstance(v, str):
                out[k] = {"hex": v, "len": len(v) // 2}
            else:
                out[k] = _jsonify(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [_jsonify(x) for x in obj]
    if isinstance(obj, (bytes, bytearray)):
        return {"hex": bytes(obj).hex(), "len": len(obj)}
    if isinstance(obj, float) and not math.isfinite(obj):
        return "NaN" if math.isnan(obj) else ("Infinity" if obj > 0 else "-Infinity")
    return obj


def to_json(tree, indent=None):
    """JSON text for a parse tree; bytes become {"hex": "...", "len": n}."""
    return json.dumps(_jsonify(tree), indent=indent, ensure_ascii=False, allow_nan=False)


def _leaf_text(n, max_bytes=32):
    t = n.get("type")
    v = n.get("value")
    if t == "bytes" or n.get("kind") == "bytes":
        h = v or ""
        shown = h[:max_bytes * 2]
        return f"[{len(h) // 2} bytes] {shown}{'...' if len(h) > len(shown) else ''}".rstrip()
    if t == "skip":
        return f"[{n.get('size')} bytes skipped]"
    if isinstance(v, bool):
        s = "true" if v else "false"
    elif isinstance(v, int):
        s = f"{v} (0x{v:x})" if v >= 0 else str(v)
    elif isinstance(v, str):
        s = json.dumps(v if len(v) <= 120 else v[:120] + "...", ensure_ascii=False)
    elif v is None:
        s = "null"
    else:
        s = json.dumps(_jsonify(v), ensure_ascii=False) if isinstance(v, list) else repr(v)
    if "name" in n:
        s += f" [{n['name'] if n['name'] is not None else '?'}]"
    if n.get("decode_error"):
        s += "  (decode error; raw kept)"
    return s


def format_tree(tree, max_items=None, max_bytes=32):
    """Human-readable tree: absolute hex offset, size, name, type, value."""
    lines = []

    def loc(n):
        off = n.get("offset")
        return (f"0x{off:08x}" if isinstance(off, int) else "-").rjust(10)

    def walk(label, n, depth):
        pad = "  " * depth
        size = n.get("size", 0)
        sz = f"+0x{size:x}".rjust(9)
        if "fields" in n:
            extra = f"  (tail 0x{n['tail']:x} unparsed)" if n.get("tail") else ""
            lines.append(f"{loc(n)} {sz}  {pad}{label}: {n['type']}{extra}")
            for k, ch in n["fields"].items():
                walk(k, ch, depth + 1)
        elif "items" in n:
            items = n["items"]
            line = f"{loc(n)} {sz}  {pad}{label}: {n['type']} ({len(items)} items)"
            st = n.get("stopped")
            if st:
                line += f"  STOPPED at 0x{st['offset']:x}: {st['reason']}"
            lines.append(line)
            lim = len(items) if max_items is None else min(len(items), max_items)
            for i in range(lim):
                walk(f"[{i}]", items[i], depth + 1)
            if lim < len(items):
                lines.append(f"{'':>10} {'':>9}  {pad}  ... {len(items) - lim} more items")
        elif n.get("type") == "let":
            lines.append(f"{'-':>10} {'':>9}  {pad}{label} = {_leaf_text(n, max_bytes)}")
        elif n.get("type") == "bits":
            lines.append(f"{loc(n)} {sz}  {pad}{label}: bits({n['bits']})@bit{n['bit']} = {_leaf_text(n, max_bytes)}")
        else:
            lines.append(f"{loc(n)} {sz}  {pad}{label}: {n['type']} = {_leaf_text(n, max_bytes)}")

    walk(tree.get("type", "?"), tree, 0)
    return "\n".join(lines)


def _truncate_items(node, n):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "items" and isinstance(v, list):
                out[k] = [_truncate_items(x, n) for x in v[:n]]
                if len(v) > n:
                    out["items_total"] = len(v)
            else:
                out[k] = _truncate_items(v, n)
        return out
    if isinstance(node, list):
        return [_truncate_items(x, n) for x in node]
    return node


# --------------------------------------------------------------------------- Outlook Thread-Index helper

THREAD_INDEX_RESOLUTION_TICKS = {"header_6byte": 1 << 16, "header_reserved5": 1 << 24, "code0": 1 << 18, "code1": 1 << 23}


def _coerce_thread_index(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if not isinstance(value, str):
        raise TypeError("thread_index() needs bytes or a base64/hex string")
    s = "".join(value.split())
    if s.lower().startswith("thread-index:"):
        s = s.split(":", 1)[1]
    if s[:2].lower() == "0x":
        s = s[2:]
    if s and len(s) % 2 == 0 and set(s) <= _HEX:
        return bytes.fromhex(s)          # all-hex text is hex (hex digits are also valid base64)
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        pass
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError("thread_index(): value is neither base64 nor hex")


def thread_index(value):
    """Decode an Outlook Thread-Index / PidTagConversationIndex (bytes, base64 or hex).

    Uses specs/outlook_thread_index.vein. Two header forms: "6-byte" (bytes[0:6] << 16) and
    "reserved+5" (bytes start 01 01; bytes[1:6] << 24). For "6-byte", child times are cumulative:
    t1 = header + d1, t2 = t1 + d2, ...  (also returned: time_from_header = header + d_i).
    For "reserved+5", child time fields are None and child_times == "unverified" (raw fields kept).
    """
    data = _coerce_thread_index(value)
    tree = load_spec("outlook_thread_index").parse(data)
    f = tree["fields"]
    children = []
    for i, item in enumerate(f["children"]["items"]):
        cf = item["fields"]
        children.append({
            "index": i,
            "offset": item["offset"],
            "code": cf["code"]["value"],
            "delta": cf["delta"]["value"],
            "delta_ticks": cf["delta_ticks"]["value"],
            "ticks": cf["ticks"]["value"],
            "time": cf["time"]["value"],
            "time_from_header": cf["time_from_header"]["value"],
            "random": cf["random"]["value"],
            "sequence": cf["sequence"]["value"],
        })
    return {
        "form": f["form"]["value"],
        "child_times": f["child_times"]["value"],
        "header_ticks": f["header_ticks"]["value"],
        "header_time": f["header_time"]["value"],
        "guid": f["guid"]["value"],
        "guid_hex": f["guid_raw"]["value"],
        "child_count": len(children),
        "children": children,
        "tree": tree,
    }


# --------------------------------------------------------------------------- CLI

def _resolve_spec(name):
    if os.path.isfile(name):
        return name
    for cand in (os.path.join(SPECS_DIR, name), os.path.join(SPECS_DIR, name + ".vein")):
        if os.path.isfile(cand):
            return cand
    raise FileNotFoundError(f"spec not found: {name} (not a file, not a bundled spec; see 'vein specs')")


def _out(text):
    sys.stdout.buffer.write((text + "\n").encode("utf-8", "backslashreplace"))
    sys.stdout.flush()


def _selftest():
    import io
    import unittest
    tests_dir = os.path.join(HERE, "tests")
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    suite = unittest.TestLoader().discover(tests_dir, pattern="test_*.py", top_level_dir=tests_dir)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    total = result.testsRun
    bad = len(result.failures) + len(result.errors) + len(result.unexpectedSuccesses)
    passed = total - bad - len(result.skipped)
    if bad or result.skipped:
        sys.stderr.write(stream.getvalue())
    _out(f"selftest: {passed}/{total}")
    return 0 if passed == total and total > 0 else 1


def compare_files(schema, before, after):
    """Compare decoded leaves at matching schema paths and retain both byte anchors."""
    import hashlib

    def leaves(node, path, output):
        if not isinstance(node, dict):
            return
        for name, child in node.get("fields", {}).items():
            leaves(child, path + (name,), output)
        for i, child in enumerate(node.get("items", [])):
            leaves(child, path + (i,), output)
        if "value" in node:
            output[path] = {k: node[k] for k in ("type", "value", "offset", "size") if k in node}

    sides = []
    identities = []
    for filename in (before, after):
        with open(filename, "rb") as stream:
            data = stream.read()
        fields = {}
        leaves(schema.parse(data), (), fields)
        sides.append(fields)
        identities.append(dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    left, right = sides
    changes = []
    for path in dict.fromkeys((*left, *right)):
        a, b = left.get(path), right.get(path)
        if a == b:
            continue
        kind = ("added" if a is None else "removed" if b is None else
                "relocated" if all(a.get(k) == b.get(k) for k in ("type", "value", "size"))
                else "modified")
        changes.append(dict(path=list(path), kind=kind, before=a, after=b))
    return dict(before=identities[0], after=identities[1], changes=changes)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--selftest"]:
        return _selftest()
    ap = argparse.ArgumentParser(prog="vein", description="Vein: declarative binary structure decoder (exact byte anchors).")
    ap.add_argument("--selftest", action="store_true", help="run the test suite and print passed/total")
    ap.add_argument("--version", action="version", version=f"vein {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("parse", help="parse FILE with SPEC (a path or a bundled spec name)")
    p.add_argument("spec")
    p.add_argument("file")
    p.add_argument("--root", default=None, help="root type (default: spec 'root', else 'file')")
    p.add_argument("--json", action="store_true", help="emit JSON instead of the pretty tree")
    p.add_argument("--max-items", type=int, default=None, help="show at most N items per array")
    p.add_argument("--base-offset", type=lambda x: int(x, 0), default=0, help="add to every reported offset")
    c = sub.add_parser("check", help="compile SPEC(s) and report errors as file:line:col")
    c.add_argument("spec", nargs="+")
    sub.add_parser("specs", help="list bundled specs")
    t = sub.add_parser("thread-index", help="decode an Outlook Thread-Index (base64 or hex)")
    t.add_argument("value")
    t.add_argument("--json", action="store_true")
    diff = sub.add_parser("diff", help="compare decoded fields and their byte anchors")
    for arg in ("spec", "before", "after"):
        diff.add_argument(arg)
    args = ap.parse_args(argv)

    if args.cmd == "diff":
        try:
            result = compare_files(compile_file(_resolve_spec(args.spec)), args.before, args.after)
            _out(to_json(result, indent=2))
            return 0
        except (VeinError, ParseError, OSError) as error:
            print(f"diff error: {error}", file=sys.stderr)
            return 2
    if args.cmd == "specs":
        for name, path, desc in list_specs():
            _out(f"{name:<22} {desc}")
        return 0
    if args.cmd == "check":
        rc = 0
        for sp in args.spec:
            try:
                path = _resolve_spec(sp)
                sch = compile_file(path)
            except FileNotFoundError as e:
                print(f"{sp}: error: {e}", file=sys.stderr)
                rc = 2
                continue
            except VeinError as e:
                print(f"{path}:{e.line}:{e.col}: error: {e.message}", file=sys.stderr)
                rc = 1
                continue
            _out(f"OK  {path}  types={len(sch.types)} enums={len(sch.enums)} root={sch.root}")
        return rc
    if args.cmd == "thread-index":
        try:
            r = thread_index(args.value)
        except (ValueError, TypeError, ParseError) as e:
            print(f"thread-index error: {e}", file=sys.stderr)
            return 1
        if args.json:
            r = dict(r)
            r.pop("tree")
            _out(json.dumps(r, indent=2))
        else:
            _out(f"form         {r['form']}  (child times: {r['child_times']})")
            _out(f"header_time  {r['header_time']}  (ticks {r['header_ticks']})")
            _out(f"guid         {r['guid']}")
            _out(f"children     {r['child_count']}")
            for ch in r["children"]:
                when = ch['time'] if ch['time'] is not None else "unverified"
                _out(f"  [{ch['index']}] @0x{ch['offset']:x} code={ch['code']} delta={ch['delta']} "
                     f"delta_ticks={ch['delta_ticks']} time={when} random={ch['random']} seq={ch['sequence']}")
        return 0
    if args.cmd == "parse":
        try:
            path = _resolve_spec(args.spec)
            sch = compile_file(path)
        except FileNotFoundError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        except VeinError as e:
            print(f"{path}:{e.line}:{e.col}: error: {e.message}", file=sys.stderr)
            return 2
        try:
            tree = sch.parse_file(args.file, root=args.root, base_offset=args.base_offset)
        except VeinError as e:
            print(f"error: {e.message}", file=sys.stderr)
            return 2
        except OSError as e:
            print(f"error: cannot read {args.file}: {e}", file=sys.stderr)
            return 2
        except ParseError as e:
            if e.partial is not None:
                part = e.partial if args.max_items is None else _truncate_items(e.partial, args.max_items)
                if args.json:
                    _out(json.dumps({"error": {"message": e.msg, "offset": e.offset, "path": e.path},
                                     "partial": _jsonify(part)}, ensure_ascii=False))
                else:
                    _out(format_tree(part, args.max_items))
            print(f"parse error: {e}", file=sys.stderr)
            return 1
        if args.json:
            _out(to_json(tree if args.max_items is None else _truncate_items(tree, args.max_items)))
        else:
            _out(format_tree(tree, args.max_items))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
