"""Hardened YAML loading.

* Only core-schema types (SafeLoader); custom and python tags are rejected.
* Anchors and aliases are rejected by default (skill frontmatter has no
  legitimate use for them). Configuration files (compose files, CI workflows)
  use them routinely, so ``aliases=True`` reads them as any loader would, with
  each alias counted as the nodes it stands for (no billion laughs) and an
  alias to its own ancestor refused.
* Duplicate mapping keys are recorded (later-wins is how most loaders behave,
  which lets an attacker hide a value from a human reviewer).
* Node count and nesting depth are bounded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, SequenceNode


class YamlRejected(ValueError):
    pass


@dataclass
class YamlResult:
    value: Any = None
    duplicate_keys: list[tuple[str, int]] = field(default_factory=list)  # (key, line)
    error: str | None = None
    anchors_used: bool = False


def _make_loader(max_nodes: int, max_depth: int, dups: list[tuple[str, int]], aliases: bool):
    class _Loader(yaml.SafeLoader):
        def __init__(self, stream: str) -> None:
            super().__init__(stream)
            self._count = 0                      # nodes so far, an alias counting as the nodes it stands for
            self._sizes: dict[str, int] = {}     # anchor -> the nodes under it, once its node is complete
            self._depth = 0
            self.anchored = False

        def compose_node(self, parent: Node | None, index: Any) -> Node:  # type: ignore[override]
            if self.check_event(AliasEvent):
                if not aliases:
                    raise YamlRejected("YAML aliases are not allowed")
                self.anchored = True
                name = self.peek_event().anchor
                if name in self.anchors and name not in self._sizes:
                    raise YamlRejected("YAML alias refers to a node that contains it")
                self._count += self._sizes.get(name, 1)
                if self._count > max_nodes:
                    raise YamlRejected("YAML aliases expand past the node limit")
                return super().compose_node(parent, index)
            event = self.peek_event()
            anchor = getattr(event, "anchor", None)
            if anchor:
                if not aliases:
                    raise YamlRejected("YAML anchors are not allowed")
                self.anchored = True
            start = self._count
            self._count += 1
            if self._count > max_nodes:
                raise YamlRejected("YAML document exceeds node limit")
            depth = self._depth
            if depth > max_depth:
                raise YamlRejected("YAML document exceeds depth limit")
            self._depth = depth + 1
            try:
                node = super().compose_node(parent, index)
            finally:
                self._depth = depth
            if anchor:
                self._sizes[anchor] = self._count - start
            return node

        def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict:  # type: ignore[override]
            # Duplicates among the keys written in this mapping. A merge key (`<<: *defaults`) is not one: the keys it
            # brings in are meant to be overridden by the ones written here.
            seen: set[Any] = set()
            for key_node, _ in node.value:
                if key_node.tag == _MERGE:
                    continue
                key = self.construct_object(key_node, deep=True)
                try:
                    hashable = key in seen
                except TypeError:
                    raise YamlRejected("unhashable mapping key") from None
                if hashable:
                    dups.append((str(key), key_node.start_mark.line + 1))
                seen.add(key)
            return super().construct_mapping(node, deep=deep)

    return _Loader


_MERGE = "tag:yaml.org,2002:merge"


def safe_load(text: str, *, max_nodes: int = 50_000, max_depth: int = 64, aliases: bool = False) -> YamlResult:
    """Parse one YAML document. ``aliases``: read anchors and aliases (configuration files) instead of rejecting
    them (skill frontmatter)."""
    result = YamlResult()
    loader_cls = _make_loader(max_nodes, max_depth, result.duplicate_keys, aliases)
    loader = None
    try:
        loader = loader_cls(text)
        result.value = loader.get_single_data()
        result.anchors_used = loader.anchored
    except YamlRejected as exc:
        result.error = str(exc)
        result.anchors_used = "alias" in str(exc) or "anchor" in str(exc)
    except yaml.YAMLError as exc:
        result.error = f"YAML error: {str(exc).splitlines()[0][:200]}"
    except (RecursionError, ValueError, TypeError) as exc:
        result.error = f"YAML error: {type(exc).__name__}"
    finally:
        if loader is not None:
            loader.dispose()
    return result
