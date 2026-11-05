"""Manifests are untrusted: a field of the wrong type must not end the scan, and
what it held must not pass unread."""

import copy
import json

import pytest

from agentguard import ArtifactTree, ScanOptions, scan
from agentguard.core.inventory import build_inventory

WRONG = ["not an object", 5, True, ["x"], [1], [[1]], {"a": 1}]

TOOL = {
    "name": "x", "title": "t", "description": "d", "annotations": {"readOnlyHint": True},
    "inputSchema": {"type": "object", "properties": {"a": {"type": "string"}}},
    "input_schema": {"type": "object"}, "outputSchema": {"type": "object"},
}
PROMPT = {"name": "p", "title": "t", "description": "d", "arguments": [{"name": "a"}],
          "messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}]}
RESOURCE = {"uri": "ui://x", "name": "n", "title": "t", "description": "d", "mimeType": "text/html",
            "text": "<p>hi</p>", "blob": "aGk=", "_meta": {"ui": {"csp": {}}}}
MANIFESTS = {
    "server/tools.json": {"serverInfo": {"name": "s", "version": "1"}, "instructions": "hi",
                          "tools": [TOOL], "prompts": [PROMPT], "resources": [RESOURCE]},
    "pkg/server.json": {"name": "a/b", "version_detail": {"version": "1"}, "repository": {"url": "https://example.com"}},
    "pkg/package.json": {"name": "x", "dependencies": {"a": "1"}, "devDependencies": {"a": "1"}, "peerDependencies": {"a": "1"}},
}


def field_paths(value, prefix=()):
    """Every position in a JSON value, itself included."""
    yield prefix
    children = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, list) else ()
    for key, child in children:
        yield from field_paths(child, (*prefix, key))


def replaced(doc, path, value):
    out = copy.deepcopy(doc)
    node = out
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return out


def run(files):
    return scan(ArtifactTree.from_mapping({p: v if isinstance(v, str) else json.dumps(v) for p, v in files.items()}), ScanOptions())


def manifest(**tool):
    return {"server/tools.json": {"tools": [{"name": "x", "description": "d", **tool}]}}


def coverage_messages(report):
    return [f.message for f in report.findings if f.rule_id == "AG-SYS-001"]


CASES = [(file, path) for file, doc in MANIFESTS.items() for path in field_paths(doc) if path]


@pytest.mark.parametrize(("file", "path"), CASES, ids=lambda c: ".".join(map(str, c)) if isinstance(c, tuple) else c)
def test_a_wrong_type_never_ends_the_scan(file, path):
    for wrong in WRONG:
        report = run({file: replaced(MANIFESTS[file], path, wrong)})
        assert [a.id for a in report.analyzers if a.status == "errored"] == []


@pytest.mark.parametrize("key", ["tools", "resources"])
def test_a_wrong_type_at_the_top_of_a_prompts_manifest(key):
    # The manifest is recognised by its prompts alone, so `tools` here has had no check at all.
    for wrong in WRONG:
        run({"server/tools.json": {"prompts": [PROMPT], key: wrong}})


@pytest.mark.parametrize("toml", [
    'project = "x"\n',
    "[project]\ndependencies = 5\n",
    '[project]\ndependencies = "mcp"\n',
    "[project]\nname = 5\nversion = 5\n",
])
def test_pyproject_with_wrong_types(toml):
    run({"pkg/pyproject.toml": toml})


def test_non_object_schema_is_reported_at_the_tool():
    report = run({"server/tools.json": '{"tools": [\n  {"name": "a", "description": "d"},\n'
                                       '  {"name": "x", "description": "d", "outputSchema": "not an object"}\n]}'})
    found = next(f for f in report.findings if f.rule_id == "AG-SYS-001")
    assert found.message == "Tool 'x' field 'outputSchema' is a string, not an object; it was not analyzed."
    assert (found.primary.path, found.primary.start_line) == ("server/tools.json", 3)


@pytest.mark.parametrize(("key", "value", "words"), [
    ("inputSchema", ["x"], "Tool 'x' field 'inputSchema' is an array, not an object"),
    ("input_schema", 5, "Tool 'x' field 'input_schema' is a number, not an object"),
    ("outputSchema", True, "Tool 'x' field 'outputSchema' is a boolean, not an object"),
    ("title", ["x"], "Tool 'x' field 'title' is an array, not a string"),
])
def test_each_dropped_tool_field_is_reported(key, value, words):
    assert any(words in m for m in coverage_messages(run(manifest(**{key: value}))))


@pytest.mark.parametrize(("entry", "key", "words"), [
    ({"prompts": [{"name": "p", "description": ["hidden"]}]}, "description", "Prompt 'p' field 'description'"),
    ({"prompts": [{"name": "p", "messages": "hidden"}]}, "messages", "Prompt 'p' field 'messages'"),
    ({"resources": [{"uri": "ui://x", "text": ["hidden"]}], "tools": [TOOL]}, "text", "Resource 'ui://x' field 'text'"),
    ({"resources": [{"uri": "ui://x", "description": ["hidden"]}], "tools": [TOOL]}, "description", "Resource 'ui://x' field 'description'"),
    ({"prompts": [PROMPT], "tools": "hidden"}, "tools", "Manifest field 'tools'"),
    ({"tools": [TOOL], "instructions": ["hidden"]}, "instructions", "Manifest field 'instructions'"),
])
def test_text_in_a_dropped_field_is_not_a_silent_pass(entry, key, words):
    # These used to crash the scan; dropping them with no finding would turn that into a clean result.
    messages = coverage_messages(run({"server/tools.json": entry}))
    assert any(words in m for m in messages), messages


@pytest.mark.parametrize("empty", [None, "", [], 0, False])
def test_empty_values_hold_nothing_to_report(empty):
    report = run(manifest(inputSchema={"type": "object"}, outputSchema=empty, annotations=empty))
    assert coverage_messages(report) == []


def test_snake_case_schema_is_used_when_the_camel_case_one_is_malformed():
    tree = ArtifactTree.from_mapping({"server/tools.json": json.dumps(
        {"tools": [{"name": "x", "description": "d", "inputSchema": "bad", "input_schema": {"type": "object"}}]})})
    tool = next(t for c in build_inventory(tree).components.values() for t in c.tools)
    assert tool.input_schema == {"type": "object"}


def test_the_snippet_is_redacted_and_capped():
    secret = "ghp_" + "a1B2" * 9
    report = run(manifest(outputSchema=f"token {secret} " + "x" * 500))
    found = next(f for f in report.findings if f.rule_id == "AG-SYS-001")
    snippet = str(found.evidence[0].snippet)
    assert secret not in snippet
    assert len(snippet) < 300
