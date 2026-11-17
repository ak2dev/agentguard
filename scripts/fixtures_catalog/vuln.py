"""VULN: implementation flaws in honest code. Every sample is a few inert lines."""

from . import N, P, add, py_server, script, skill

_PLAIN = "Read the CSV file the user names and summarize each column."
_HEAD = 'from mcp.server.fastmcp import FastMCP\nfrom pathlib import Path\n\nmcp = FastMCP("demo")\n\n\n'

add("AG-VULN-006",
    P("py-open-for-writing", py_server(
        _HEAD + '@mcp.tool()\ndef save_note(path: str, text: str):\n    """Save a note."""\n'
                '    with open(path, "w", encoding="utf-8") as fh:\n        fh.write(text)\n    return "saved"')),
    P("py-write-text", py_server(
        _HEAD + '@mcp.tool()\ndef save_note(name: str, text: str):\n    """Save a note."""\n'
                '    Path(name).write_text(text)\n    return "saved"')),
    N("py-contained-write", py_server(
        _HEAD + '@mcp.tool()\ndef save_note(name: str, text: str):\n    """Save a note."""\n'
                "    root = Path('notes').resolve()\n    p = (root / name).resolve()\n"
                "    if not p.is_relative_to(root):\n        raise ValueError('outside notes')\n"
                '    p.write_text(text)\n    return "saved"')),
    N("py-fixed-path", py_server(
        _HEAD + '@mcp.tool()\ndef save_note(text: str):\n    """Save the note."""\n'
                '    Path("notes/latest.txt").write_text(text)\n    return "saved"')))

add("AG-VULN-008",
    P("lxml-default-parser", script("import sys\nfrom lxml import etree\ntree = etree.parse(sys.argv[1])\nprint(len(tree.getroot()))")),
    P("sax-parser", script("import sys\nimport xml.sax\nxml.sax.parse(sys.argv[1], xml.sax.ContentHandler())")),
    N("defusedxml", script("import sys\nfrom defusedxml import ElementTree as ET\nprint(len(ET.parse(sys.argv[1]).getroot()))")),
    N("entities-off", script("import sys\nfrom lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
                             "print(len(etree.parse(sys.argv[1], parser).getroot()))")))

add("AG-VULN-009",
    P("mktemp", script("import tempfile\nname = tempfile.mktemp(suffix='.csv')\nprint(name)")),
    P("fixed-tmp-path", script('rows = ["a,b"]\nwith open("/tmp/csv-tool-cache.json", "w") as fh:\n    fh.write(str(rows))')),
    N("mkstemp", script("import os, tempfile\nfd, name = tempfile.mkstemp(suffix='.csv')\nos.close(fd)\nprint(name)")),
    N("named-temporary-file", script("import tempfile\nwith tempfile.NamedTemporaryFile('w', suffix='.csv') as fh:\n    fh.write('a,b')")))

add("AG-VULN-010",
    P("requests-verify-false", script('import requests\nprint(requests.get("https://files.example.invalid/data.csv", verify=False).status_code)')),
    P("curl-insecure", skill("Download the sample with `curl -k https://files.example.invalid/data.csv -o data.csv`.")),
    N("default-verification", script('import requests\nprint(requests.get("https://files.example.invalid/data.csv", timeout=10).status_code)')),
    N("warns-against-it", skill("Never pass `verify=False`; add the company CA bundle to the trust store.")))

add("AG-VULN-012",
    P("recursive-copy-loop", script("export function merge(target, source) {\n  for (const key in source) {\n    target[key] = source[key];\n  }\n  return target;\n}",
                                    path="scripts/merge.js")),
    P("lodash-merge-of-parsed-input", script("import _ from 'lodash';\nexport function apply(config, body) {\n  return _.merge(config, JSON.parse(body));\n}",
                                             path="scripts/merge.js")),
    N("skips-dangerous-keys", script("export function merge(target, source) {\n  for (const key in source) {\n"
                                     '    if (["__proto__", "constructor", "prototype"].includes(key)) continue;\n'
                                     "    target[key] = source[key];\n  }\n  return target;\n}", path="scripts/merge.js")),
    N("spread-of-defaults", script("export function withDefaults(options) {\n  return { delimiter: ',', ...options };\n}",
                                   path="scripts/merge.js")))

add("AG-VULN-013",
    P("nested-quantifier-python", script('import re, sys\nPATTERN = re.compile(r"^(\\d+)*$")\nprint(bool(PATTERN.match(sys.argv[1])))')),
    P("nested-quantifier-js", script('const pattern = new RegExp("^(a+)+$");\nconsole.log(pattern.test(process.argv[2]));',
                                     path="scripts/check.js")),
    N("character-class", script('import re, sys\nPATTERN = re.compile(r"^[a-z0-9_-]+$")\nprint(bool(PATTERN.match(sys.argv[1])))')),
    N("alternation", script('import re, sys\nPATTERN = re.compile(r"^(csv|tsv)$")\nprint(bool(PATTERN.match(sys.argv[1])))')))

add("AG-VULN-015",
    P("tar-extractall", script("import sys, tarfile\ntar = tarfile.open(sys.argv[1])\ntar.extractall('data')")),
    P("unpack-archive", script("import shutil, sys\nshutil.unpack_archive(sys.argv[1], 'data')")),
    N("data-filter", script("import sys, tarfile\ntar = tarfile.open(sys.argv[1])\ntar.extractall('data', filter='data')")),
    N("lists-members-only", script("import sys, zipfile\nwith zipfile.ZipFile(sys.argv[1]) as zf:\n    print(len(zf.namelist()))")))

add("AG-VULN-016",
    P("flask-redirect-from-query", script('from flask import Flask, redirect, request\napp = Flask(__name__)\n\n\n@app.route("/done")\n'
                                          'def done():\n    return redirect(request.args.get("next"))')),
    P("express-redirect-from-query", script('import express from "express";\nconst app = express();\n'
                                            'app.get("/done", (req, res) => res.redirect(req.query.url));', path="scripts/app.js")),
    N("fixed-target", script('from flask import Flask, redirect, url_for\napp = Flask(__name__)\n\n\n@app.route("/done")\n'
                             'def done():\n    return redirect(url_for("index"))')),
    N("host-allow-list", script('from urllib.parse import urlparse\nfrom flask import Flask, abort, redirect, request\napp = Flask(__name__)\n'
                                'ALLOWED_HOSTS = {"reports.example.invalid"}\n\n\n@app.route("/done")\ndef done():\n'
                                '    if urlparse(request.args.get("next", "")).netloc not in ALLOWED_HOSTS:\n        abort(400)\n'
                                '    return redirect(request.args.get("next"))')))

add("AG-VULN-017",
    P("prints-token-fstring", script('import os\napi_token = os.environ["CSV_TOOL_TOKEN"]\nprint(f"using token {api_token}")')),
    P("console-log-api-key", script("const apiKey = process.env.CSV_TOOL_KEY;\nconsole.log(`key=${apiKey}`);", path="scripts/app.js")),
    N("logs-presence-only", script('import os\napi_token = os.environ.get("CSV_TOOL_TOKEN")\nprint(f"token present: {bool(api_token)}")')),
    N("plain-log-line", script('import logging\nlogging.getLogger("csv").info("request sent")')))

add("AG-VULN-018",
    P("exists-then-remove", script("import os, sys\npath = sys.argv[1]\nif os.path.exists(path):\n    os.remove(path)")),
    P("exists-sync-then-write", script('import fs from "node:fs";\nconst target = process.argv[2];\nif (!fs.existsSync(target)) {\n'
                                       '  fs.writeFileSync(target, "");\n}', path="scripts/touch.js")),
    N("try-except", script("import os, sys\ntry:\n    os.remove(sys.argv[1])\nexcept FileNotFoundError:\n    pass")),
    N("plain-skill", skill(_PLAIN)))

add("AG-VULN-019",
    P("debug-on", script('from flask import Flask\napp = Flask(__name__)\napp.run(host="127.0.0.1", debug=True)')),
    P("auth-off-by-default", script('AUTH_REQUIRED = False\nPORT = 8080\nprint("listening on", PORT)')),
    N("debug-from-environment", script('import os\nfrom flask import Flask\napp = Flask(__name__)\napp.run(host="127.0.0.1", debug=os.environ.get("CSV_DEBUG") == "1")')),
    N("auth-on", script('AUTH_REQUIRED = True\nPORT = 8080\nprint("listening on", PORT)')))
