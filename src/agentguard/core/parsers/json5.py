"""A bounded JSON5 / JSONC reader (OpenClaw's ``openclaw.json``, VS Code and
dev-container files): comments, trailing commas, single-quoted strings,
unquoted keys, hex and signed numbers. Strict JSON is a subset.

Untrusted input: depth and node count are capped and nothing is evaluated.
"""

from __future__ import annotations

from typing import Any

from .structured import Parsed

_WS = " \t\r\n﻿   "
_ESC = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "0": "\0", "\n": "", "\r": ""}
_IDENT_START = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$"
_IDENT = _IDENT_START + "0123456789"
_WORDS = {"true": True, "false": False, "null": None, "Infinity": None, "NaN": None}


class _Error(ValueError):
    pass


class _Reader:
    def __init__(self, text: str, max_depth: int, max_nodes: int) -> None:
        self.t, self.i, self.n = text, 0, len(text)
        self.max_depth, self.max_nodes, self.nodes = max_depth, max_nodes, 0

    def fail(self, what: str) -> _Error:
        line = self.t.count("\n", 0, self.i) + 1
        return _Error(f"{what} at line {line}")

    def skip(self) -> None:
        t, n = self.t, self.n
        while self.i < n:
            ch = t[self.i]
            if ch in _WS:
                self.i += 1
            elif ch == "/" and t.startswith("//", self.i):
                end = t.find("\n", self.i)
                self.i = n if end < 0 else end
            elif ch == "/" and t.startswith("/*", self.i):
                end = t.find("*/", self.i + 2)
                if end < 0:
                    raise self.fail("unterminated comment")
                self.i = end + 2
            else:
                return

    def value(self, depth: int) -> Any:
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise self.fail("too many values")
        if depth > self.max_depth:
            raise self.fail("nesting exceeds depth limit")
        self.skip()
        if self.i >= self.n:
            raise self.fail("unexpected end of input")
        ch = self.t[self.i]
        if ch == "{":
            return self.obj(depth)
        if ch == "[":
            return self.arr(depth)
        if ch in "\"'":
            return self.string()
        if ch in "+-.0123456789":
            return self.number()
        if ch in _IDENT_START:
            word = self.ident()
            if word in _WORDS:
                return _WORDS[word]
            raise self.fail(f"unexpected word {word[:20]!r}")
        raise self.fail(f"unexpected character {ch!r}")

    def obj(self, depth: int) -> dict[str, Any]:
        self.i += 1
        out: dict[str, Any] = {}
        while True:
            self.skip()
            if self.i >= self.n:
                raise self.fail("unterminated object")
            ch = self.t[self.i]
            if ch == "}":
                self.i += 1
                return out
            key = self.string() if ch in "\"'" else self.ident() if ch in _IDENT_START else None
            if key is None:
                raise self.fail("expected a key")
            self.skip()
            if self.i >= self.n or self.t[self.i] != ":":
                raise self.fail("expected ':'")
            self.i += 1
            out[key] = self.value(depth + 1)
            self.skip()
            if self.i < self.n and self.t[self.i] == ",":
                self.i += 1
            elif self.i < self.n and self.t[self.i] != "}":
                raise self.fail("expected ',' or '}'")

    def arr(self, depth: int) -> list[Any]:
        self.i += 1
        out: list[Any] = []
        while True:
            self.skip()
            if self.i >= self.n:
                raise self.fail("unterminated array")
            if self.t[self.i] == "]":
                self.i += 1
                return out
            out.append(self.value(depth + 1))
            self.skip()
            if self.i < self.n and self.t[self.i] == ",":
                self.i += 1
            elif self.i < self.n and self.t[self.i] != "]":
                raise self.fail("expected ',' or ']'")

    def ident(self) -> str:
        start = self.i
        while self.i < self.n and self.t[self.i] in _IDENT:
            self.i += 1
        return self.t[start:self.i]

    def string(self) -> str:
        quote = self.t[self.i]
        self.i += 1
        out: list[str] = []
        t = self.t
        while self.i < self.n:
            ch = t[self.i]
            if ch == quote:
                self.i += 1
                return "".join(out)
            if ch == "\\":
                self.i += 1
                if self.i >= self.n:
                    break
                e = t[self.i]
                if e == "u" and self.i + 4 < self.n:
                    try:
                        out.append(chr(int(t[self.i + 1:self.i + 5], 16)))
                    except ValueError as exc:
                        raise self.fail("bad \\u escape") from exc
                    self.i += 5
                    continue
                if e == "x" and self.i + 2 < self.n:
                    try:
                        out.append(chr(int(t[self.i + 1:self.i + 3], 16)))
                    except ValueError as exc:
                        raise self.fail("bad \\x escape") from exc
                    self.i += 3
                    continue
                out.append(_ESC.get(e, e))
                self.i += 1
                continue
            if ch == "\n" and quote == '"':
                raise self.fail("newline in string")
            out.append(ch)
            self.i += 1
        raise self.fail("unterminated string")

    def number(self) -> int | float | None:
        start = self.i
        while self.i < self.n and self.t[self.i] in "+-.0123456789abcdefABCDEFxXInfityNa":
            self.i += 1
        raw = self.t[start:self.i]
        body = raw.lstrip("+-")
        sign = -1 if raw.startswith("-") else 1
        try:
            if body.lower().startswith("0x"):
                return sign * int(body, 16)
            if body in ("Infinity", "NaN"):
                return None
            if any(c in body for c in ".eE"):
                return sign * float(body)
            return sign * int(body)
        except ValueError as exc:
            raise self.fail(f"bad number {raw[:20]!r}") from exc


def parse_json5(text: str, *, max_depth: int = 64, max_nodes: int = 200_000) -> Parsed:
    reader = _Reader(text, max_depth, max_nodes)
    try:
        value = reader.value(0)
        reader.skip()
        if reader.i < reader.n:
            raise reader.fail("unexpected content after the document")
        return Parsed(value=value, fmt="json5")
    except _Error as exc:
        return Parsed(error=f"JSON5 error: {exc}", fmt="json5")
    except RecursionError:
        return Parsed(error="JSON5 error: nesting exceeds depth limit", fmt="json5")
