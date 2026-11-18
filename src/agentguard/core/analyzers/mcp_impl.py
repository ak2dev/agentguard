"""How an MCP server is implemented: authentication, token handling, what its tools return and what they touch.

Static checks on server source (Python, JavaScript, TypeScript). They are heuristics over the code's text and the
tool handlers found by ``McpUnitsBuilder``; each says in its message what it saw.

* AG-MCP-040: an HTTP transport and no sign of authentication anywhere in the server.
* AG-MCP-043: a JWT is decoded without checking its audience.
* AG-MCP-045: a token read from the query string, built into a URL, or written to a log.
* AG-MCP-046: a tool returns fetched external content as it came.
* AG-MCP-047: write or admin OAuth scopes requested by a server whose tools only read.
* AG-MCP-049: a file tool that opens whatever path it is given, in a server with no path confinement at all.
* AG-MCP-050: per-user state kept in module-level variables of an HTTP server.
* AG-MCP-051: a destructive tool whose handler checks nothing.
* AG-VULN-014: the low-level tool handler uses its arguments without validating them against the declared schema.
* AG-MCP-031: a tool result or error message that gives orders to the model: recorded results
  (``options.facts["tool_results"]``) and literals in handler code.
"""

from __future__ import annotations

from typing import ClassVar

import regex

from ..artifacts import ArtifactText
from ..models import Span
from ..models.enums import EvidenceKind, Severity
from ..textutil import TIMEOUT
from .base import Context
from .code import _block, _call_args, _is_comment, _line_of
from .connectors import _DESTRUCTIVE, _READ_ONLY_NAME, DIRECTIVE
from .instructions import CORE
from .mcp import _SERVER_SOURCE_KINDS, ToolHandler

_F = regex.IGNORECASE
_TEST_PATH = regex.compile(r"(^|/)(?:tests?|__tests__|spec|fixtures?|testdata|examples?|samples?|docs?|mocks?|node_modules|vendor)/|\.(?:test|spec)\.[a-z]+$", _F)
_HTTP_TRANSPORT = regex.compile(
    r"""transport\s*[=:]\s*["'](?:streamable-http|streamable_http|http|sse)["']|\bStreamableHTTPServerTransport\b|\bSSEServerTransport\b"""
    r"""|\bstreamable_http_app\s*\(|\bsse_app\s*\(|\.http_app\s*\(|\bStreamableHTTPSessionManager\b|\bWebStandardStreamableHTTPServerTransport\b"""
    r"""|\bcreateMcpExpressApp\b|\brun_streamable_http_async\b|\brun_sse_async\b""")
_AUTH_MARK = regex.compile(
    r"authorization|bearer|\bauth\s*=|token_verifier|TokenVerifier|requireBearerAuth|mcpAuthRouter|mcpAuthMetadataRouter|OAuthProvider|"
    r"AuthSettings|verify_?token|\bjwt\b|jsonwebtoken|\bjose\b|oauth|api[_-]?key|authenticat|passport|basicAuth|HTTPBearer|HTTPBasic|"
    r"WWW-Authenticate|\b401\b|Unauthorized|client_cert|verify_client|\bhmac\b|signature", _F)
_LOOPBACK = regex.compile(r"""["'](?:127\.0\.0\.1|localhost|::1)["']""")
_ALL_INTERFACES = regex.compile(r"""["'](?:0\.0\.0\.0|::)["']""")
_JWT_DECODE = regex.compile(r"\b(?:jwt\.decode|jwt\.verify|jose\.jwtVerify|jwtVerify|jws\.verify)\s*\(")
_AUD_OFF = regex.compile(r"""verify_aud["']?\s*[:=]\s*False|ignoreAudience\s*:\s*true""", _F)
_AUD = regex.compile(r"\baud(?:ience)?\b", _F)
_QUERY_TOKEN = regex.compile(
    r"""(?:query_params|request\.args|req\.query|request\.query|searchParams|ctx\.query|url\.query)\s*(?:\.get\(\s*|\[\s*|\.)["']?"""
    r"""(?:access_token|auth_token|id_token|token|api_?key|apikey|secret)\b"""
    r"""|[?&](?:access_token|auth_token|token|api_?key|apikey|secret)=(?:\$\{|\{|["']\s*\+|%s)""", _F)
_LOG_CALL = regex.compile(
    r"\b(?:print|console\.(?:log|info|debug|warn|error)|(?:logger|logging|log)\.(?:info|debug|warning|warn|error|exception|critical|log))\s*\(")
_STRING = regex.compile(r"""(?<![A-Za-z0-9_])[rbu]?(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')""")
_INTERPOLATION = regex.compile(r"\$\{([^}]*)\}|(?<!\{)\{([A-Za-z_][^{}:!]*)[^{}]*\}(?!\})")
_SECRET_IDENT = regex.compile(
    r"\b(?!(?:max|num|n|total|input|output|prompt|completion|used|remaining)_?tokens?\b)[A-Za-z_]*(?:access_?token|auth_?token|id_?token|"
    r"refresh_?token|bearer|api_?key|apikey|secret|passw(?:or)?d|authorization|credentials?)(?!_?(?:count|len|length|limit|usage|budget|"
    r"type|url|uri|path|file|name|id|endpoint|expir\w*|ttl|header_name))[A-Za-z_]*\b", _F)
_BARE_TOKEN = regex.compile(r"(?<![\w.])(?:token|jwt)(?![\w(])")
_HEADERS_DUMP = regex.compile(r"\b(?:request|req|ctx\.request|event)\.headers\b(?!\s*(?:\[|\.get\())")
_FETCH = regex.compile(
    r"\b(?:requests|httpx|aiohttp|urllib\.request|session|client|http)\.(?:get|post|request|urlopen|fetch)\s*\(|\burlopen\s*\(|\bfetch\s*\(|"
    r"\baxios(?:\.(?:get|post|request))?\s*\(|\bgot(?:\.get)?\s*\(|\bpage\.(?:content|goto|inner_text|evaluate)\s*\(", _F)
_RETURNS_RAW = regex.compile(
    r"\breturn\b[^\n]{0,240}?(?:\.text\b|\.json\s*\(|\.content\b|\.body\b|\.read\s*\(|\b(?:html|response|resp|res|data|result|body|page|text|"
    r"markdown|content)\b)", _F)
_CONTENT_TOOL = regex.compile(r"(?:fetch|browse|scrape|crawl|read_?url|web|search|email|mail|inbox|issue|comment|page|message|feed|rss|download)", _F)
_URL_PARAM = regex.compile(r"^(?:url|uri|link|href|page|site|query|q|address|endpoint)$|_(?:url|uri|link)$", _F)
_UNTRUSTED_MARK = regex.compile(
    r"untrusted|external[ _-]content|do\s+not\s+follow|not\s+instructions|<\s*/?\s*(?:external|untrusted|data|document|web)[\w-]*\s*>|"
    r"BEGIN[ _](?:EXTERNAL|UNTRUSTED|DATA)|sanitiz|strip_(?:instructions|html|tags)|spotlight|quarantine|wrap_untrusted|escape_for_model", _F)
_SCOPE_LINE = regex.compile(r"scopes?\b", _F)
_BROAD_SCOPE = regex.compile(
    r"""["'\s,](?P<scope>repo|admin:org|admin:enterprise|delete_repo|admin:repo_hook|write:packages|admin:public_key|workflow"""
    r"""|https://www\.googleapis\.com/auth/(?:drive|cloud-platform|gmail\.modify|calendar|spreadsheets|documents|admin\.directory\.user)"""
    r"""|https://mail\.google\.com/|(?:Mail|Files|Sites|Directory|User|Group|Calendars)\.ReadWrite(?:\.All)?|Directory\.AccessAsUser\.All"""
    r"""|channels:manage|chat:write|files:write|users:write|admin|full_access)["'\s,\]]""")
_PATH_PARAM = regex.compile(r"^(?:path|file|filename|file_?path|dir|directory|folder|target|dest|destination|src|source)$|_(?:path|file|dir)$", _F)
_FILE_API = regex.compile(
    r"\bopen\s*\(|\bPath\s*\(|\.read_text\s*\(|\.write_text\s*\(|\.read_bytes\s*\(|\.write_bytes\s*\(|\bos\.(?:listdir|remove|unlink|scandir|walk)\s*\(|"
    r"\bshutil\.\w+\s*\(|\bfs(?:Promises|\.promises)?\.\w+\s*\(|\b(?:readFile|writeFile|readdir|unlink|appendFile|createReadStream|createWriteStream)"
    r"(?:Sync)?\s*\(")
_CONFINE = regex.compile(
    r"is_relative_to|commonpath|\.startswith\s*\(|\.startsWith\s*\(|path\.relative\s*\(|realpath|\.resolve\s*\(|allowed_?(?:dirs|roots|paths|directories)|"
    r"ALLOWED_|BASE_DIR|ROOT_DIR|WORKSPACE|sandbox|safe_join|secure_filename|validate_?path|is_?sub_?path|is_?within|chroot|"
    r"""["']\.\.["']""", _F)
_STATE_NAME = regex.compile(r"(?:current|active|last|session|user|token|auth|cred|history|conversation|context|state|pending|cart|profile|memory)", _F)
_PY_GLOBAL = regex.compile(
    r"^(?P<name>[A-Za-z_]\w*)\s*(?::\s*[^=\n]+)?=\s*(?:\{\}|\[\]|dict\(\)|list\(\)|set\(\)|None\b|defaultdict\(|\"\"|'')", regex.MULTILINE)
_JS_GLOBAL = regex.compile(
    r"^(?:let|var|const)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[^=\n]+)?=\s*(?:new\s+(?:Map|Set)\s*\(|\{\s*\}|\[\s*\]|null\b|undefined\b|\"\"|'')",
    regex.MULTILINE)
_DESTRUCTIVE_API = regex.compile(
    r"\bos\.(?:remove|unlink|rmdir)\s*\(|\bshutil\.rmtree\s*\(|\.unlink\s*\(|\brm(?:dir)?Sync\s*\(|\bfs\.rm\s*\(|\brm\s+-[a-z]*r|"
    r"\bDELETE\s+FROM\b|\bDROP\s+(?:TABLE|DATABASE)\b|\bTRUNCATE\b|\.delete(?:_many|_one|One|Many)?\s*\(|\.destroy\s*\(|\.drop\s*\(")
_VALIDATION = regex.compile(
    r"\bif\b|\braise\b|\bassert\b|\bthrow\b|confirm|elicit|validat|dry_?run|rate_?limit|throttle|allow(?:ed|list)|permission|authoriz|"
    r"\.parse\s*\(|safeParse", _F)
_JS_CALL_TOOL = regex.compile(r"setRequestHandler\s*\(\s*CallToolRequestSchema\b")
_PY_NO_VALIDATE = regex.compile(r"\.call_tool\s*\(\s*validate_input\s*=\s*False")
_ARG_USE = regex.compile(r"\.params\.arguments\b|\barguments\s*[\[.]|\bargs\s*[\[.]")
_ARG_CHECK = regex.compile(r"\.parse\s*\(|safeParse|validat|\bajv\b|\bzod\b|typeof\s|instanceof\b|Array\.isArray|\bassert|isinstance\s*\(|schema\.", _F)
_RESULT_LINE = regex.compile(r"\b(?:return|raise|throw)\b|isError|\btext\s*[:=]|Error\s*\(", _F)


def _search(rx: regex.Pattern[str], text: str) -> regex.Match[str] | None:
    try:
        return rx.search(text, timeout=TIMEOUT)
    except TimeoutError:
        return None


def _finditer(rx: regex.Pattern[str], text: str) -> list[regex.Match[str]]:
    try:
        return list(rx.finditer(text, timeout=TIMEOUT))
    except TimeoutError:
        return []


def logged_secret(args: str) -> str:
    """The name of a secret-bearing value among the arguments of a logging call, or ""."""
    outside = _STRING.sub(" ", args)
    inside = " ".join((m.group(1) or m.group(2) or "") for s in _STRING.finditer(args) for m in _INTERPOLATION.finditer(s.group(0)))
    for part in (outside, inside):
        m = _search(_SECRET_IDENT, part) or _search(_BARE_TOKEN, part) or _search(_HEADERS_DUMP, part)
        if m:
            return m.group(0)
    return ""


class McpImplAnalyzer:
    id: ClassVar[str] = "mcp.impl"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-MCP-031", "AG-MCP-040", "AG-MCP-043", "AG-MCP-045", "AG-MCP-046", "AG-MCP-047", "AG-MCP-049",
                                        "AG-MCP-050", "AG-MCP-051", "AG-VULN-014")

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        inv = ctx.inventory
        handlers: list[ToolHandler] = ctx.data.get("tool_handlers", [])  # type: ignore[assignment]
        by_comp: dict[str, list[ArtifactText]] = {}
        for at in ctx.texts("source_code", "script"):
            comp = inv.components.get(at.artifact.component_id)
            if comp is None or comp.kind not in _SERVER_SOURCE_KINDS or _search(_TEST_PATH, at.path):
                continue
            if at.artifact.language not in ("python", "javascript", "typescript"):
                continue
            by_comp.setdefault(comp.id, []).append(at)
        for cid in sorted(by_comp):
            texts = by_comp[cid]
            hs = [h for h in handlers if h.component_id == cid]
            if not hs and not any(_search(_HTTP_TRANSPORT, at.text) or "mcp" in at.text.lower() for at in texts):
                continue                                   # not server code: a plugin's helper scripts
            http = self._transport(cid, texts)
            self._tokens(cid, texts)
            self._scopes(cid, texts)
            self._schema(cid, texts)
            self._handlers(cid, texts, hs, http)
        self._recorded_results()

    # -- AG-MCP-040 -----------------------------------------------------------------------------------------
    def _transport(self, cid: str, texts: list[ArtifactText]) -> bool:
        hit: tuple[ArtifactText, regex.Match[str]] | None = None
        for at in texts:
            for m in _finditer(_HTTP_TRANSPORT, at.text):
                if not _is_comment(_line_of(at.text, m.start())):
                    hit = hit or (at, m)
                    break
        if hit is None:
            return False
        if any(_search(_AUTH_MARK, at.text) for at in texts):
            return True
        at, m = hit
        whole = "\n".join(t.text for t in texts)
        local_only = bool(_search(_LOOPBACK, whole)) and not _search(_ALL_INTERFACES, whole)
        self.ctx.emit("AG-MCP-040", component_ids=cid, span=at.span(m.start(), m.end()), snippet=_line_of(at.text, m.start()).strip()[:240],
                      match=f"http-no-auth:{at.path}", kind=EvidenceKind.ast, severity=Severity.medium if local_only else None,
                      message="The server is reachable over HTTP (" + m.group(0).strip()[:60] + ") and nothing in its source checks who is "
                              "calling: no Authorization header, token verifier, API key or OAuth setup."
                              + (" It binds to the loopback address, which still lets any local process and any web page that can "
                                 "reach localhost call its tools." if local_only else " Anyone who can reach the port can call its tools."))
        return True

    # -- AG-MCP-043, AG-MCP-045 -----------------------------------------------------------------------------
    def _tokens(self, cid: str, texts: list[ArtifactText]) -> None:
        emitted_aud = emitted_45 = 0
        for at in texts:
            text = at.text
            for m in _finditer(_JWT_DECODE, text):
                if emitted_aud >= 2 or _is_comment(_line_of(text, m.start())):
                    continue
                args = _call_args(text, m.end() - 1)
                after = text[m.end(): m.end() + len(args) + 900]
                if _search(_AUD_OFF, args):
                    why = "with the audience check switched off"
                elif not _search(_AUD, args) and not _search(_AUD, after):
                    why = "and neither the call nor the code after it looks at the token's audience"
                else:
                    continue
                emitted_aud += 1
                self.ctx.emit("AG-MCP-043", component_ids=cid, span=at.span(m.start(), m.end()), snippet=_line_of(text, m.start()).strip()[:240],
                              match=f"aud:{at.path}:{m.group(0)}", kind=EvidenceKind.ast,
                              message=f"`{m.group(0).rstrip('( ')}` verifies a token {why}. A token issued for another service by the same "
                                      "authorization server is then accepted here, which the MCP authorization specification forbids.")
            for m in _finditer(_QUERY_TOKEN, text):
                if emitted_45 >= 3 or _is_comment(_line_of(text, m.start())):
                    continue
                emitted_45 += 1
                self.ctx.emit("AG-MCP-045", component_ids=cid, span=at.span(m.start(), m.end()), snippet=_line_of(text, m.start()).strip()[:240],
                              match=f"query-token:{at.path}:{m.group(0)[:60]}", kind=EvidenceKind.ast,
                              message="A token travels in a URL query string here. URLs are written to server logs, proxy logs and "
                                      "browser history, so the token is exposed in each of them.")
                break
            for m in _finditer(_LOG_CALL, text):
                if emitted_45 >= 3 or _is_comment(_line_of(text, m.start())):
                    continue
                name = logged_secret(_call_args(text, m.end() - 1, 600))
                if not name:
                    continue
                emitted_45 += 1
                self.ctx.emit("AG-MCP-045", component_ids=cid, span=at.span(m.start(), m.end()), snippet=_line_of(text, m.start()).strip()[:240],
                              match=f"log-token:{at.path}:{name}", kind=EvidenceKind.ast,
                              message=f"The logging call writes `{name}` to the log. Logs are kept longer and read by more people than "
                                      "the secret they now contain.")
                break

    # -- AG-MCP-047 -----------------------------------------------------------------------------------------
    def _scopes(self, cid: str, texts: list[ArtifactText]) -> None:
        comp = self.ctx.inventory.components.get(cid)
        names = [t.name for t in comp.tools] if comp is not None else []
        if not names or not all(_search(_READ_ONLY_NAME, n.lower()) for n in names):
            return
        for at in texts:
            lines = at.text.split("\n")
            offset = 0
            for i, line in enumerate(lines):
                start = offset
                offset += len(line) + 1
                if _is_comment(line):
                    continue
                m = _search(_BROAD_SCOPE, " " + line + " ")
                if not m or not _search(_SCOPE_LINE, "\n".join(lines[max(0, i - 3): i + 1])):
                    continue
                scope = m.group("scope")
                col = line.find(scope)
                self.ctx.emit("AG-MCP-047", component_ids=cid, span=at.span(start + max(col, 0), start + max(col, 0) + len(scope)),
                              snippet=line.strip()[:240], match=f"scope:{at.path}:{scope}", kind=EvidenceKind.ast,
                              message=f"The server asks the upstream service for the scope `{scope}`, which allows writing or "
                                      f"administration, and every tool it offers only reads ({', '.join(names[:5])}). The token it "
                                      "holds can do far more than the server needs, which is what an attacker who reaches it gains.")
                return

    # -- AG-VULN-014 ----------------------------------------------------------------------------------------
    def _schema(self, cid: str, texts: list[ArtifactText]) -> None:
        for at in texts:
            text = at.text
            m = _search(_PY_NO_VALIDATE, text) if at.artifact.language == "python" else None
            if m:
                self.ctx.emit("AG-VULN-014", component_ids=cid, span=at.span(m.start(), m.end()), snippet=_line_of(text, m.start()).strip()[:240],
                              match=f"schema-off:{at.path}", kind=EvidenceKind.ast,
                              message="`call_tool(validate_input=False)` turns off the SDK's check of tool arguments against the "
                                      "declared input schema, so the handler receives whatever the caller sends.")
                continue
            if at.artifact.language == "python":
                continue
            m = _search(_JS_CALL_TOOL, text)
            if not m:
                continue
            brace = text.find("{", text.find("=>", m.end()) if text.find("=>", m.end()) >= 0 else m.end())
            body = _block(text, brace) if brace >= 0 else text[m.end(): m.end() + 4000]
            if _search(_ARG_USE, body) and not _search(_ARG_CHECK, body):
                self.ctx.emit("AG-VULN-014", component_ids=cid, span=at.span(m.start(), m.end()), snippet=_line_of(text, m.start()).strip()[:240],
                              match=f"schema-unchecked:{at.path}", kind=EvidenceKind.ast,
                              message="The `CallToolRequestSchema` handler reads `request.params.arguments` and never validates them. "
                                      "The low-level server does not enforce the `inputSchema` it advertises: types, required fields "
                                      "and limits in the schema are documentation only.")

    # -- per handler: AG-MCP-031 (literals), 046, 049, 050, 051 ---------------------------------------------
    def _handlers(self, cid: str, texts: list[ArtifactText], hs: list[ToolHandler], http: bool) -> None:
        by_path = {at.path: at for at in texts}
        package_confines = any(_search(_CONFINE, at.text) for at in texts)
        package_marks = any(_search(_UNTRUSTED_MARK, at.text) for at in texts)
        unconfined: list[tuple[ToolHandler, ArtifactText, str]] = []
        n46 = n51 = n31 = 0
        for h in sorted(hs, key=lambda x: (x.path, x.start)):
            at = by_path.get(h.path)
            if at is None:
                continue
            body = at.text[h.start:h.end]
            tool = h.tool
            # 046: fetched content returned as it came
            fetch = _search(_FETCH, body)
            if fetch and n46 < 3 and not package_marks and _search(_RETURNS_RAW, body):
                dynamic = any(_search(_URL_PARAM, p) and regex.search(r"\b" + regex.escape(p) + r"\b", _call_args(body, body.find("(", fetch.start())))
                              for p in h.params)
                if dynamic or _search(_CONTENT_TOOL, tool):
                    n46 += 1
                    self.ctx.emit("AG-MCP-046", component_ids=cid, span=at.span(h.start + fetch.start(), h.start + fetch.end()),
                                  snippet=_line_of(body, fetch.start()).strip()[:240], match=f"untrusted:{h.path}:{tool}", kind=EvidenceKind.ast,
                                  message=f"The tool `{tool}` fetches content from outside and returns it to the model as it came. Nothing "
                                          "marks it as data, so instructions planted in a page, an issue or a message are read by "
                                          "the model as if the server had said them.")
            # 049: file tool without confinement
            path_params = [p for p in h.params if _search(_PATH_PARAM, p)]
            if path_params and not package_confines:
                api = _search(_FILE_API, body)
                if api and any(regex.search(r"\b" + regex.escape(p) + r"\b", body[api.start(): api.start() + 400]) for p in path_params):
                    unconfined.append((h, at, path_params[0]))
            # 051: destructive tool with no checks
            destructive = _search(_DESTRUCTIVE, tool.lower()) or _search(_DESTRUCTIVE_API, body)
            if destructive and n51 < 3 and not _search(_VALIDATION, body):
                n51 += 1
                self.ctx.emit("AG-MCP-051", component_ids=cid, span=at.span(h.start, min(h.end, h.start + 80)),
                              snippet=_line_of(at.text, h.start).strip()[:240], match=f"destructive:{h.path}:{tool}", kind=EvidenceKind.ast,
                              message=f"The tool `{tool}` deletes or destroys data, and its handler checks nothing first: no validation "
                                      "of what it was asked to remove, no confirmation, no limit on how often it runs.")
            # 031: a literal the handler returns or raises that gives orders to the model
            if n31 < 2:
                for s in _finditer(_STRING, body):
                    lit = s.group(0)
                    if len(lit) < 24:
                        continue
                    d = _search(DIRECTIVE, lit) or _search(CORE, lit)
                    if d and _search(_RESULT_LINE, _line_of(body, s.start())):
                        n31 += 1
                        self.ctx.emit("AG-MCP-031", component_ids=cid, span=at.span(h.start + s.start(), h.start + s.end()),
                                      snippet=lit[:240], match=f"literal:{h.path}:{tool}:{d.group(0).lower()}", kind=EvidenceKind.ast,
                                      message=f"The tool `{tool}` returns or raises text that gives the model orders (\"{d.group(0)[:80]}\"). "
                                              "Tool results and error messages are read by the model with the same trust as the "
                                              "tool's description, and reviewers rarely read them.")
                        break
        if unconfined:
            h, at, param = unconfined[0]
            tools = ", ".join(f"`{u[0].tool}`" for u in unconfined[:5])
            self.ctx.emit("AG-MCP-049", component_ids=cid, span=at.span(h.start, min(h.end, h.start + 80)),
                          snippet=_line_of(at.text, h.start).strip()[:240], match=f"unconfined:{[u[0].tool for u in unconfined]}",
                          kind=EvidenceKind.ast, related=[Span(path=u[1].path, start_line=u[1].index.line_col(u[0].start)[0]) for u in unconfined[1:5]],
                          message=f"{tools} open{'s' if len(unconfined) == 1 else ''} the path given in `{param}`, and the server has no "
                                  "notion of an allowed directory anywhere in its source: no root, no resolve-and-compare. Whoever "
                                  "steers the model can read or write any file the server's account can.")
        if http:
            self._shared_state(cid, texts, hs)

    def _shared_state(self, cid: str, texts: list[ArtifactText], hs: list[ToolHandler]) -> None:
        done = 0
        for at in texts:
            mine = [h for h in hs if h.path == at.path]
            if not mine:
                continue
            rx = _PY_GLOBAL if at.artifact.language == "python" else _JS_GLOBAL
            for g in _finditer(rx, at.text):
                name = g.group("name")
                if not _search(_STATE_NAME, name) or name.isupper():
                    continue
                esc = regex.escape(name)
                mutate = regex.compile(rf"\bglobal\s+[^\n]*\b{esc}\b|(?<![\w.]){esc}\s*\[[^\]\n]+\]\s*=(?!=)|(?<![\w.]){esc}\."
                                       rf"(?:append|add|update|setdefault|pop|clear|extend|set|push|delete)\s*\(|(?<![\w.]){esc}\s*=(?!=)")
                for h in mine:
                    if h.start <= g.start() < h.end:
                        continue
                    m = _search(mutate, at.text[h.start:h.end])
                    if not m:
                        continue
                    if at.artifact.language == "python" and m.group(0).rstrip().endswith("=") and "[" not in m.group(0) \
                            and not regex.search(rf"\bglobal\s+[^\n]*\b{esc}\b", at.text[h.start:h.end]):
                        continue                    # a local variable of the same name
                    self.ctx.emit("AG-MCP-050", component_ids=cid, span=at.span(g.start(), g.end()),
                                  snippet=_line_of(at.text, g.start()).strip()[:240], match=f"shared:{at.path}:{name}", kind=EvidenceKind.ast,
                                  related=[Span(path=at.path, start_line=at.index.line_col(h.start + m.start())[0])],
                                  message=f"`{name}` is a module-level variable that the tool `{h.tool}` changes, and the server is served "
                                          "over HTTP, where one process answers every client. What one user's call stores, the next "
                                          "user's call reads.")
                    done += 1
                    break
                if done >= 3:
                    return

    # -- AG-MCP-031 from recorded results ---------------------------------------------------------------------
    def _recorded_results(self) -> None:
        facts = self.ctx.options.facts if isinstance(self.ctx.options.facts, dict) else {}
        results = facts.get("tool_results") if isinstance(facts.get("tool_results"), dict) else {}
        inv = self.ctx.inventory
        for server, items in sorted(results.items()):
            comp = next((c for c in sorted(inv.components.values(), key=lambda c: c.id) if server in (c.name, c.root, c.id)), None)
            span: Span | None = None
            if comp is not None:
                span = comp.server.config_span if comp.server is not None and comp.server.config_span is not None else Span(path=comp.root or server)
            for item in items if isinstance(items, list) else []:
                text = item.get("text") if isinstance(item, dict) else None
                if not isinstance(text, str):
                    continue
                d = _search(DIRECTIVE, text) or _search(CORE, text)
                if not d:
                    continue
                tool = str(item.get("tool") or "?")
                what = "error message" if item.get("error") else "result"
                self.ctx.emit("AG-MCP-031", component_ids=comp.id if comp is not None else [], span=span or Span(path=server),
                              snippet=text[max(0, d.start() - 80): d.end() + 80], match=f"recorded:{server}:{tool}:{d.group(0).lower()}",
                              kind=EvidenceKind.metadata, detail=f"{tool} {what}",
                              message=f"When `{tool}` on `{server}` was called, its {what} gave the model orders (\"{d.group(0)[:80]}\"). "
                                      "This text is not in the tool's definition, so no review of the definition sees it.")


__all__ = ["McpImplAnalyzer", "logged_secret"]
