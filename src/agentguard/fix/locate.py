"""Find where a key lives in a configuration file, by character offset, so a fix
can edit exactly that member and leave the rest of the file as the author wrote it.

Three small readers, each tolerant of what agents accept in practice:

* JSON and JSON5 (comments, trailing commas, single quotes, bare keys);
* TOML (tables, arrays of tables, dotted and quoted keys, inline tables);
* YAML frontmatter and plain YAML mappings, line-based.

They only locate; they never evaluate anything. A fix is verified by a
re-scan afterwards, so a location these readers get wrong costs a rolled-back
fix, never a wrong file.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class LocateError(ValueError):
    pass


@dataclass
class Node:
    kind: str                      # object | array | scalar
    start: int                     # offset of the value
    end: int                       # exclusive
    key: str | int | None = None
    key_start: int | None = None   # offset of the key token (None for array elements and the root)
    children: list[Node] = field(default_factory=list)
    parent: Node | None = field(default=None, repr=False)

    @property
    def member_start(self) -> int:
        return self.key_start if self.key_start is not None else self.start

    def child(self, key: str | int) -> Node | None:
        return next((c for c in self.children if c.key == key), None)


# ------------------------------------------------------------------ JSON --
class _Json:
    def __init__(self, text: str) -> None:
        self.t, self.i, self.n = text, 0, len(text)

    def ws(self) -> None:
        t, n = self.t, self.n
        while self.i < n:
            c = t[self.i]
            if c in " \t\r\n\ufeff\xa0":
                self.i += 1
            elif t.startswith("//", self.i):
                nl = t.find("\n", self.i)
                self.i = n if nl < 0 else nl
            elif t.startswith("/*", self.i):
                end = t.find("*/", self.i + 2)
                self.i = n if end < 0 else end + 2
            else:
                return

    def string(self) -> str:
        quote = self.t[self.i]
        j, out = self.i + 1, []
        while j < self.n:
            c = self.t[j]
            if c == "\\" and j + 1 < self.n:
                out.append(self.t[j:j + 2])
                j += 2
                continue
            if c == quote:
                self.i = j + 1
                raw = "".join(out)
                try:
                    import json

                    return json.loads('"' + raw.replace('"', '\\"') + '"') if quote == "'" else json.loads('"' + raw + '"')
                except ValueError:
                    return raw
            out.append(c)
            j += 1
        raise LocateError("unterminated string")

    def value(self, depth: int = 0) -> Node:
        if depth > 200:
            raise LocateError("nesting too deep")
        self.ws()
        if self.i >= self.n:
            raise LocateError("unexpected end")
        c, start = self.t[self.i], self.i
        if c == "{":
            node = Node("object", start, start)
            self.i += 1
            while True:
                self.ws()
                if self.i >= self.n:
                    raise LocateError("unterminated object")
                if self.t[self.i] == "}":
                    self.i += 1
                    break
                if self.t[self.i] == ",":
                    self.i += 1
                    continue
                key_start = self.i
                if self.t[self.i] in "\"'":
                    key = self.string()
                else:
                    j = self.i
                    while j < self.n and (self.t[j].isalnum() or self.t[j] in "_$-."):
                        j += 1
                    if j == self.i:
                        raise LocateError(f"unexpected character {self.t[self.i]!r}")
                    key, self.i = self.t[self.i:j], j
                self.ws()
                if self.i >= self.n or self.t[self.i] != ":":
                    raise LocateError("expected ':'")
                self.i += 1
                child = self.value(depth + 1)
                child.key, child.key_start, child.parent = key, key_start, node
                node.children.append(child)
            node.end = self.i
            return node
        if c == "[":
            node = Node("array", start, start)
            self.i += 1
            while True:
                self.ws()
                if self.i >= self.n:
                    raise LocateError("unterminated array")
                if self.t[self.i] == "]":
                    self.i += 1
                    break
                if self.t[self.i] == ",":
                    self.i += 1
                    continue
                child = self.value(depth + 1)
                child.key, child.parent = len(node.children), node
                node.children.append(child)
            node.end = self.i
            return node
        if c in "\"'":
            self.string()
            return Node("scalar", start, self.i)
        j = self.i
        while j < self.n and self.t[j] not in ",}]\r\n" and not self.t.startswith("//", j) and not self.t.startswith("/*", j):
            j += 1
        while j > self.i and self.t[j - 1] in " \t":
            j -= 1
        if j == self.i:
            raise LocateError(f"unexpected character {c!r}")
        self.i = j
        return Node("scalar", start, j)


def parse_json(text: str) -> Node:
    """The member tree of a JSON or JSON5 document. Raises LocateError when it cannot be read."""
    p = _Json(text)
    try:
        root = p.value()
    except RecursionError as exc:  # pragma: no cover - guarded by the depth check
        raise LocateError("nesting too deep") from exc
    p.ws()
    if p.i < p.n:
        raise LocateError("trailing content")
    return root


def find_path(root: Node, dotted: str) -> Node | None:
    """The node at a dotted key path. Keys may themselves contain dots (``chat.tools.autoApprove``,
    ``projects./home/dev/x.trust_level``), so at each level the longest matching key wins."""
    if dotted == "":
        return root
    if root.kind == "array":
        head, _, rest = dotted.partition(".")
        if not head.isdigit():
            return None
        child = root.child(int(head))
        return find_path(child, rest) if child is not None else None
    if root.kind != "object":
        return None
    for child in sorted(root.children, key=lambda c: -len(str(c.key))):
        key = str(child.key)
        if dotted == key:
            return child
        if dotted.startswith(key + "."):
            found = find_path(child, dotted[len(key) + 1:])
            if found is not None:
                return found
    return None


def innermost(root: Node, offset: int) -> Node | None:
    """The deepest member whose extent (key through value) contains the offset."""
    best: Node | None = None
    stack = [root]
    while stack:
        node = stack.pop()
        if node.member_start <= offset < max(node.end, node.member_start + 1):
            if node.parent is not None:
                best = node
            stack.extend(node.children)
    return best


# ------------------------------------------------------------------ TOML --
def _split_key(text: str) -> list[str]:
    """Split a dotted TOML key, honouring quoted segments."""
    out, cur, i, n = [], [], 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            end = text.find(c, i + 1)
            if end < 0:
                raise LocateError("unterminated key")
            cur.append(text[i + 1:end])
            i = end + 1
        elif c == ".":
            out.append("".join(cur).strip())
            cur = []
            i += 1
        else:
            cur.append(c)
            i += 1
    out.append("".join(cur).strip())
    return [s for s in out if s != ""]


def _toml_value_end(t: str, i: int) -> int:
    """Offset just past the TOML value that starts at ``i``."""
    n = len(t)
    if t.startswith('"""', i) or t.startswith("'''", i):
        end = t.find(t[i:i + 3], i + 3)
        return n if end < 0 else end + 3
    c = t[i] if i < n else ""
    if c in "\"'":
        j = i + 1
        while j < n and t[j] != "\n":
            if t[j] == "\\" and c == '"':
                j += 2
                continue
            if t[j] == c:
                return j + 1
            j += 1
        return j
    if c in "[{":
        depth, j = 0, i
        while j < n:
            ch = t[j]
            if ch in "\"'":
                j = _toml_value_end(t, j)
                continue
            if ch == "#":
                nl = t.find("\n", j)
                j = n if nl < 0 else nl
                continue
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return n
    j = i
    while j < n and t[j] not in "\n#,}":
        j += 1
    while j > i and t[j - 1] in " \t\r":
        j -= 1
    return j


def _toml_inline(t: str, node: Node) -> None:
    """Members of an inline table ``{ a = 1, b = "x" }``."""
    i, end = node.start + 1, node.end - 1
    while i < end:
        while i < end and t[i] in " \t\r\n,":
            i += 1
        if i >= end:
            break
        eq = i
        while eq < end and t[eq] != "=":
            if t[eq] in "\"'":
                close = t.find(t[eq], eq + 1)
                eq = end if close < 0 else close
            eq += 1
        if eq >= end:
            break
        key = ".".join(_split_key(t[i:eq]))
        vs = eq + 1
        while vs < end and t[vs] in " \t":
            vs += 1
        ve = min(_toml_value_end(t, vs), end)
        child = Node("object" if t[vs:vs + 1] == "{" else ("array" if t[vs:vs + 1] == "[" else "scalar"), vs, ve, key=key,
                     key_start=i, parent=node)
        node.children.append(child)
        if child.kind == "object":
            _toml_inline(t, child)
        i = max(ve, vs + 1)


def parse_toml(text: str) -> Node:
    """The member tree of a TOML document: tables become objects, ``[[x]]`` arrays of tables."""
    root = Node("object", 0, len(text))
    current = root
    i, n = 0, len(text)

    def descend(base: Node, parts: list[str], header_start: int, array: bool) -> Node:
        node = base
        for k, part in enumerate(parts):
            last = k == len(parts) - 1
            child = node.child(part)
            if child is not None and child.kind == "array" and child.children and not (last and array):
                node = child.children[-1]
                continue
            if child is None:
                child = Node("array" if (last and array) else "object", header_start, header_start, key=part,
                             key_start=header_start, parent=node)
                node.children.append(child)
            if last and array:
                item = Node("object", header_start, header_start, key=len(child.children), parent=child)
                child.children.append(item)
                return item
            node = child
        return node

    while i < n:
        nl = text.find("\n", i)
        line_end = n if nl < 0 else nl
        line = text[i:line_end]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i = line_end + 1
            continue
        lead = len(line) - len(line.lstrip())
        if stripped.startswith("[["):
            close = stripped.find("]]")
            current = descend(root, _split_key(stripped[2:close if close > 0 else None]), i + lead, True)
            i = line_end + 1
            continue
        if stripped.startswith("["):
            close = stripped.find("]")
            current = descend(root, _split_key(stripped[1:close if close > 0 else None]), i + lead, False)
            i = line_end + 1
            continue
        eq = line.find("=")
        if eq < 0:
            i = line_end + 1
            continue
        parts = _split_key(line[:eq])
        vs = i + eq + 1
        while vs < n and text[vs] in " \t":
            vs += 1
        ve = _toml_value_end(text, vs)
        holder = current
        for part in parts[:-1]:
            nxt = holder.child(part)
            if nxt is None:
                nxt = Node("object", i + lead, ve, key=part, key_start=i + lead, parent=holder)
                holder.children.append(nxt)
            holder = nxt
        kind = "object" if text[vs:vs + 1] == "{" else ("array" if text[vs:vs + 1] == "[" else "scalar")
        child = Node(kind, vs, ve, key=parts[-1] if parts else "", key_start=i + lead, parent=holder)
        holder.children.append(child)
        if kind == "object":
            _toml_inline(text, child)
        nl2 = text.find("\n", ve)
        i = n if nl2 < 0 else nl2 + 1
    return root


# ------------------------------------------------------------- lines, YAML --
def line_starts(text: str) -> list[int]:
    out, i = [0], text.find("\n")
    while i >= 0:
        out.append(i + 1)
        i = text.find("\n", i + 1)
    return out


def offset_of(text: str, line: int, col: int = 1, starts: list[int] | None = None) -> int:
    """Character offset of a 1-based line and column (clamped to the text)."""
    starts = starts or line_starts(text)
    if line < 1:
        return 0
    if line > len(starts):
        return len(text)
    return min(starts[line - 1] + max(col - 1, 0), len(text))


def line_span(text: str, line: int, starts: list[int] | None = None) -> tuple[int, int]:
    """(start, end) of a 1-based line; ``end`` is past its newline."""
    starts = starts or line_starts(text)
    if line < 1 or line > len(starts):
        raise LocateError(f"no line {line}")
    start = starts[line - 1]
    end = starts[line] if line < len(starts) else len(text)
    return start, end


def frontmatter_lines(text: str) -> tuple[int, int] | None:
    """1-based (first, last) line numbers of the frontmatter body, between the ``---`` fences."""
    lines = text.split("\n")
    if not lines or lines[0].lstrip("\ufeff").rstrip() != "---":
        return None
    for i in range(1, len(lines)):
        if lines[i].rstrip() in ("---", "..."):
            return (2, i) if i >= 1 else None
    return None


def yaml_block(text: str, line: int) -> tuple[int, int]:
    """(start, end) offsets of the YAML mapping entry that begins on ``line``: the key line and
    everything nested under it."""
    starts = line_starts(text)
    start, end = line_span(text, line, starts)
    head = text[start:end]
    indent = len(head) - len(head.lstrip(" "))
    n = line
    while n < len(starts):
        s, e = line_span(text, n + 1, starts)
        nxt = text[s:e]
        body = nxt.strip()
        if body == "---" or body == "...":
            break
        nxt_indent = len(nxt) - len(nxt.lstrip(" "))
        if body == "" or nxt_indent > indent or (nxt_indent == indent and body.startswith("- ") and not head.strip().startswith("- ")):
            end = e
            n += 1
            continue
        break
    # Do not swallow trailing blank lines.
    while end > start and text[start:end].endswith("\n\n"):
        end -= 1
    return start, end
