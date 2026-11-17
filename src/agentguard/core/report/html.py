"""Single-file HTML report. No scripts at all; strict CSP; every scanned
string HTML-escaped. Works offline and with JavaScript disabled.

It uses the Agent Guard website's look and lays out like the report on its
/scan page: a block with corner markers (the target, the verdict and a board of
severity counts), cells divided by hairlines, findings with evidence in
terminal windows and the fix in an orange-tinted cell. Findings are listed by
category (malice, vulnerabilities, hygiene; never mixed), can be filtered
without scripts, and carry an expandable trace. Inter and JetBrains Mono
(Latin subsets, SIL OFL 1.1, see ``fonts/``) are embedded so the file needs
nothing else; the CSP allows them only as data: URIs.
"""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache
from pathlib import Path

from .. import verdict as verdicts
from ..models import Finding, ImmutableRef, Report
from ..models.enums import Category, FixKind, Severity, Verdict
from .render import ALLOW_NOTE, CATEGORY_TITLE, FIX_LABEL, FRAMEWORK_LABEL
from .render import html_escape as e

_FONTS = Path(__file__).with_name("fonts")
_LATIN = (
    "U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,"
    "U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD"
)

_CSS = """
:root{--bg:#0e0d0c;--dots:#2f2c29;--surface:#161412;--bar:#1c1b19;--fg:#f4efe9;--fg-2:#d8d1c8;--muted:#a69e94;--line:#2a2724;--line-2:#3b3733;
--accent:#ff7a33;--code:#1f1c19;--term:#000;--hot-bg:#26140c;--hot-line:#6e3215;--hot-fg:#eaa682;--fix-bg:#1f110a;--fix-fg:#f2d5c4;
--crit:#ff8a80;--high:#ffb266;--med:#f5d565;--low:#7fdcf0;--info:#b5b0a8;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(var(--dots) 1px,transparent 1.2px) 6px 6px/13px 13px var(--bg);color:var(--fg);font:15px/1.55 "AG Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased;font-feature-settings:"cv11"}
a{color:var(--accent);text-underline-offset:3px}
a:hover{color:#ffa06b}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.page{max-width:1120px;min-height:100vh;margin:0 auto;background:var(--bg);border-left:1px dashed var(--line-2);border-right:1px dashed var(--line-2)}
.bar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:18px 28px;border-bottom:1px dashed var(--line)}
.brand{display:inline-flex;align-items:center;gap:10px;font-weight:650;font-size:1.2rem;letter-spacing:-.02em}
.brand svg{width:28px;height:28px;color:var(--accent)}
.bar .muted{font-size:.88rem}
main{padding:36px 28px 64px}
h1,h2,h3{font-weight:500;letter-spacing:-.025em;line-height:1.1;text-wrap:balance}
h2{font-size:1.6rem;margin:56px 0 16px;display:flex;align-items:baseline;gap:12px}
h2 .n{font-size:.95rem;font-weight:400;color:var(--muted);letter-spacing:0}
h3{font-size:1.02rem;font-weight:600;letter-spacing:-.01em;margin:0}
.muted{color:var(--muted)}
.corners{position:relative}
.corners::after{content:"";position:absolute;inset:-5px;pointer-events:none;background:
linear-gradient(var(--bg),var(--bg)) left 1px top 1px/7px 7px no-repeat,linear-gradient(var(--bg),var(--bg)) right 1px top 1px/7px 7px no-repeat,
linear-gradient(var(--bg),var(--bg)) left 1px bottom 1px/7px 7px no-repeat,linear-gradient(var(--bg),var(--bg)) right 1px bottom 1px/7px 7px no-repeat,
linear-gradient(var(--line-2),var(--line-2)) left top/9px 9px no-repeat,linear-gradient(var(--line-2),var(--line-2)) right top/9px 9px no-repeat,
linear-gradient(var(--line-2),var(--line-2)) left bottom/9px 9px no-repeat,linear-gradient(var(--line-2),var(--line-2)) right bottom/9px 9px no-repeat}
.report{border:1px solid var(--line)}
.top{display:grid;grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr);gap:28px 40px;align-items:center;padding:36px 32px 32px}
.top h1{font-size:2.2rem;letter-spacing:-.032em;margin:0 0 10px}
.target{margin:0;color:var(--muted);font-size:1rem;overflow-wrap:anywhere}
.target a{color:var(--fg)}.target a:hover{color:var(--accent)}
.verdict{margin:22px 0 0;padding:13px 15px;border:1px solid var(--line-2);background:var(--surface);color:var(--muted);font-size:.93rem;line-height:1.4;max-width:34em}
.verdict strong{display:block;margin-bottom:2px;color:var(--fg);font-weight:600;font-size:.98rem}
.verdict.hot{background:var(--hot-bg);border-color:var(--hot-line);color:var(--hot-fg)}.verdict.hot strong{color:var(--accent)}
.board{border:1px solid var(--line);padding:18px 20px 16px}
.board-head{display:flex;flex-wrap:wrap;justify-content:space-between;gap:4px 16px;margin:0 0 12px;font-size:.92rem;color:var(--fg-2)}
.board-head .hi{color:var(--accent)}
.counts{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin:0;padding:0;list-style:none}
.count{--sev:var(--info);margin:0;display:grid;justify-items:center;gap:9px;padding:16px 4px 13px;border:1px dashed var(--line-2);text-align:center}
.count.critical{--sev:var(--crit)}.count.high{--sev:var(--high)}.count.medium{--sev:var(--med)}.count.low{--sev:var(--low)}
.count b{font-size:1.7rem;font-weight:500;letter-spacing:-.03em;line-height:1;color:var(--sev);font-variant-numeric:tabular-nums}
.count:not(.zero){border-style:solid;border-color:color-mix(in srgb,var(--sev) 36%,transparent);background:color-mix(in srgb,var(--sev) 6%,transparent)}
.count .sev{padding:0 6px;letter-spacing:.05em}.count.zero b{color:var(--muted)}.count.zero .sev{opacity:.5}
.board-note{margin:12px 0 0;text-align:center;color:var(--muted);font-size:.88rem}
.stats{display:flex;flex-wrap:wrap;gap:1px;margin:0;background:var(--line);border-top:1px solid var(--line)}
.stats>div{flex:1 1 180px;min-width:0;padding:20px 22px 22px;background:var(--bg)}
.stats dt{color:var(--muted);font-size:.88rem}
.stats dd{margin:0}
.stats .v{display:block;margin:8px 0 2px;font-size:1.45rem;font-weight:500;letter-spacing:-.03em;line-height:1.15;overflow-wrap:anywhere}
.stats .sub{display:block;color:var(--muted);font-size:.85rem;line-height:1.35;overflow-wrap:anywhere}
.note{margin:0;padding:15px 22px;border-top:1px solid var(--line);color:var(--muted);font-size:.9rem}
.hatch{height:32px;border-top:1px solid var(--line);background:repeating-linear-gradient(-45deg,transparent 0 7px,rgba(255,255,255,.025) 7px 8px)}
.sev{--sev:var(--info);display:inline-flex;align-items:center;gap:6px;height:22px;padding:0 9px 0 8px;border-radius:4px;font-size:.68rem;font-weight:600;line-height:1;text-transform:uppercase;letter-spacing:.08em;white-space:nowrap;vertical-align:middle;color:var(--sev);background:color-mix(in srgb,var(--sev) 11%,transparent);border:1px solid color-mix(in srgb,var(--sev) 32%,transparent)}
.sev::before{content:"";width:6px;height:6px;border-radius:50%;flex:none;background:var(--sev);box-shadow:0 0 0 2.5px color-mix(in srgb,var(--sev) 22%,transparent)}
.critical .sev,.sev.critical{--sev:var(--crit);background:color-mix(in srgb,var(--sev) 15%,transparent);border-color:color-mix(in srgb,var(--sev) 45%,transparent)}.high .sev,.sev.high{--sev:var(--high)}.medium .sev,.sev.medium{--sev:var(--med)}.low .sev,.sev.low{--sev:var(--low)}.info .sev,.sev.info{--sev:var(--info)}
.rule{color:var(--muted);font-family:"AG Mono",ui-monospace,monospace;font-size:.8rem;white-space:nowrap}
code,pre{font:13px/1.55 "AG Mono",ui-monospace,SFMono-Regular,Consolas,monospace}
code{background:var(--code);border:1px solid var(--line);border-radius:4px;padding:.1em .4em;overflow-wrap:anywhere}
a code{color:inherit}
pre{white-space:pre-wrap;word-break:break-word;margin:0;overflow-x:auto}
pre code{background:none;border:0;padding:0}
.table{border:1px solid var(--line);border-radius:4px;overflow-x:auto;background:var(--bg)}
table{border-collapse:collapse;width:100%;font-size:.92rem}
th,td{border-bottom:1px solid var(--line);padding:12px 16px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:500;font-size:.84rem;background:var(--surface)}
tr:last-child td{border-bottom:0}
td code{background:none;border:0;padding:0;font-size:.82rem;color:var(--fg-2)}
td a{color:var(--fg);text-decoration:none}td a:hover{color:var(--accent);text-decoration:underline}
.index td{vertical-align:middle}.index td:first-child{width:1%}.list{margin-bottom:28px}
.f{border:1px solid var(--line);border-radius:4px;background:var(--bg);margin:12px 0;overflow:hidden;scroll-margin-top:16px}
.f:target{box-shadow:0 0 0 2px var(--accent)}
.f>header{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;padding:14px 18px;background:var(--surface);border-bottom:1px solid var(--line)}
.f>header .rule{margin-left:auto}
.f>div{padding:22px 20px}
.msg{margin:0 0 20px;max-width:80ch;color:var(--fg-2);font-size:1.02rem}
.facts{display:flex;flex-wrap:wrap;gap:1px;margin:0;background:var(--line);border:1px solid var(--line)}
.facts>div{flex:1 1 140px;display:flex;flex-direction:column;gap:5px;min-width:0;padding:12px 14px 13px;background:var(--bg)}
.facts>div.wide{flex:3 1 240px}
.facts dt{font-size:.82rem;color:var(--muted)}
.facts dd{margin:0;font-size:.95rem;overflow-wrap:anywhere}
.facts code{background:none;border:0;padding:0;font-size:.82rem}
.f h4{font-size:.88rem;font-weight:500;color:var(--muted);margin:22px 0 10px}
.ev{margin:0 0 10px;border:1px solid var(--line-2);border-radius:6px;overflow:hidden;background:var(--term)}
.ev figcaption{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:center;padding:8px 13px;background:var(--bar);border-bottom:1px solid var(--line);font-size:.82rem;color:var(--muted)}
.dots{display:inline-flex;gap:5px}.dots i{width:10px;height:10px;border-radius:50%;border:1.5px solid var(--line-2)}
.ev figcaption code{background:none;border:0;padding:0;color:var(--fg-2);font-size:.78rem}
.ev pre{padding:12px 14px;font-size:12.5px}
.flow{margin:0;padding:12px 14px;border:1px dashed var(--line-2);color:var(--fg-2)}
.advice{display:grid;grid-template-columns:1fr 1fr;gap:1px;margin-top:22px;background:var(--line);border:1px solid var(--line)}
.advice section{padding:15px 17px 17px;background:var(--bg)}
.advice section.fix{background:var(--fix-bg);box-shadow:inset 0 0 0 1px rgba(255,122,51,.32)}
.advice h4{margin:0 0 8px}.advice section.fix h4{color:var(--accent)}
.advice p{margin:0;color:var(--fg-2)}.advice .fix p{color:var(--fix-fg)}
.pills{margin:16px 0 0;display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.pills .label{color:var(--muted);font-size:.85rem;margin-right:4px}
.pill{display:inline-block;border:1px solid var(--line-2);border-radius:4px;padding:2px 8px;font-size:.78rem;color:var(--fg-2)}
.empty{margin:0;border:1px dashed var(--line-2);padding:20px;color:var(--fg-2)}
details.panel{border:1px solid var(--line);border-radius:4px;overflow:hidden}
details.panel summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:12px;padding:14px 18px;font-weight:600;background:var(--surface)}
details.panel summary::-webkit-details-marker{display:none}
details.panel summary::before{content:"";width:7px;height:7px;border-right:1.5px solid var(--muted);border-bottom:1.5px solid var(--muted);transform:rotate(-45deg);flex:none}
details.panel[open] summary::before{transform:rotate(45deg)}
details.panel[open] summary{border-bottom:1px solid var(--line)}
details.panel summary .muted{font-weight:400}
details.panel ul{margin:14px 18px 16px;padding-left:20px;color:var(--fg-2)}
li{margin:5px 0}
footer{padding:20px 28px 28px;border-top:1px dashed var(--line);color:var(--muted);font-size:.85rem;display:flex;flex-wrap:wrap;gap:4px 16px;justify-content:space-between}
.verdict .vd{display:inline-block;margin:0 0 8px;padding:3px 10px;border:1px solid var(--line-2);border-radius:4px;font:600 .78rem/1.4 "AG Mono",ui-monospace,monospace;letter-spacing:.1em;color:var(--fg)}
.verdict.hot .vd{border-color:var(--hot-line);color:var(--accent)}
.verdict.warn{background:color-mix(in srgb,var(--med) 7%,transparent);border-color:color-mix(in srgb,var(--med) 34%,transparent);color:var(--fg-2)}.verdict.warn .vd{border-color:color-mix(in srgb,var(--med) 45%,transparent);color:var(--med)}
.verdict ul{margin:8px 0 0;padding-left:18px}.verdict li{margin:2px 0}
.filters{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 16px}
.filters input{position:absolute;opacity:0;pointer-events:none}
.filters label{cursor:pointer;border:1px solid var(--line-2);border-radius:4px;padding:4px 11px;font-size:.84rem;color:var(--fg-2);background:var(--bg)}
.filters label:hover{border-color:var(--muted)}
.filters input:checked+label{border-color:var(--accent);color:var(--accent);background:var(--hot-bg)}
.filters input:focus-visible+label{outline:2px solid var(--accent);outline-offset:2px}
main:has(#flt-block:checked) :is(.f,tr.row,h2.cat):not(.eff-block),main:has(#flt-review:checked) :is(.f,tr.row,h2.cat):not(.eff-review),main:has(#flt-info:checked) :is(.f,tr.row,h2.cat):not(.eff-info),main:has(#flt-auto:checked) :is(.f,tr.row,h2.cat):not(.fix-auto){display:none}
details.trace{margin:18px 0 0;border:1px dashed var(--line-2)}
details.trace summary{cursor:pointer;padding:10px 14px;color:var(--muted);font-size:.88rem;list-style:none}
details.trace summary::-webkit-details-marker{display:none}
details.trace summary::before{content:"+";display:inline-block;width:1.1em;color:var(--accent)}details.trace[open] summary::before{content:"-"}
details.trace ol{margin:0;padding:4px 14px 12px 38px;color:var(--fg-2)}details.trace li span{color:var(--muted)}
.uncounted{color:var(--muted);font-size:.8rem;border:1px dashed var(--line-2);border-radius:4px;padding:1px 7px}
.tier{font-family:"AG Mono",ui-monospace,monospace;font-size:.82rem}
@media (max-width:1150px){.page{border-left:0;border-right:0}}
@media (max-width:1000px){.top{grid-template-columns:minmax(0,1fr)}}
@media (max-width:720px){.advice{grid-template-columns:1fr}.f>header .rule{margin-left:0}}
@media (max-width:640px){.index th:nth-child(n+3),.index td:nth-child(n+3){display:none}.counts{grid-template-columns:repeat(3,minmax(0,1fr))}
.bar,main,footer{padding-left:16px;padding-right:16px}.top{padding:24px 16px}.top h1{font-size:1.8rem}.board{padding:14px 12px}
.stats>div{flex-basis:140px;padding:16px}.note{padding:14px 16px}.f>div{padding:18px 14px}}
@media print{
:root{--bg:#fff;--surface:#f7f5f2;--bar:#f7f5f2;--fg:#1d1a17;--fg-2:#3b3733;--muted:#5f5c55;--line:#ddd8d0;--line-2:#cfc9c0;--accent:#b33a0a;--code:#f5f2ee;--term:#faf8f5;
--hot-bg:#fff4ee;--hot-line:#e5b39a;--hot-fg:#7a2c0a;--fix-bg:#fff;--fix-fg:#3b3733;--crit:#b3261e;--high:#b45309;--med:#8a6d00;--low:#0e7490;--info:#6b7280;color-scheme:light}
body{background:#fff}.page{border:0}.hatch{display:none}.f:target{box-shadow:none}
.f,.ev,.advice section{break-inside:avoid}}
"""

_SHIELD = (
    '<svg viewBox="0 0 32 32" aria-hidden="true" focusable="false">'
    '<path d="M16 2 4 7v8c0 7.5 5.1 13.3 12 15 6.9-1.7 12-7.5 12-15V7L16 2z" fill="currentColor" opacity=".14"></path>'
    '<path d="M16 2 4 7v8c0 7.5 5.1 13.3 12 15 6.9-1.7 12-7.5 12-15V7L16 2z" fill="none" stroke="currentColor" stroke-width="2"></path>'
    '<path d="m10.5 16.2 3.6 3.6 7.4-7.6" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"></path>'
    "</svg>"
)

@lru_cache(maxsize=1)
def _style() -> tuple[str, str]:
    """The stylesheet (with embedded fonts, when available) and its CSP hash."""
    faces = []
    for family, name in (("AG Inter", "inter-latin-wght-normal.woff2"), ("AG Mono", "jetbrains-mono-latin-wght-normal.woff2")):
        try:
            data = base64.b64encode((_FONTS / name).read_bytes()).decode("ascii")
        except OSError:
            continue  # fall back to system fonts
        faces.append(
            f"@font-face{{font-family:\"{family}\";font-style:normal;font-weight:100 900;font-display:swap;"
            f"src:url(data:font/woff2;base64,{data}) format(\"woff2\");unicode-range:{_LATIN}}}"
        )
    css = "\n".join(faces) + _CSS
    return css, "sha256-" + base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()


def _target(report: Report) -> str:
    t = report.target.ref
    if t is None:
        return e(report.target.source.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]) if report.target.source else ""
    if isinstance(t, ImmutableRef):
        label = f"{t.locator} @ {t.resolved[:12]}"
        if t.kind.value == "github":
            owner_repo = "/".join(t.locator.split("/")[:2])
            return f'<a href="{e("https://github.com/" + owner_repo + "/tree/" + t.resolved)}">{e(label)}</a>'
        return e(label)
    if t.kind.value == "local":
        # Only the folder or file name: a shared report should not reveal local paths.
        return e(t.locator.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1])
    return e(t.locator)


def _loc_link(report: Report, path: str, line: int, col: int | None = None) -> str:
    text = e(f"{path}:{line}" + (f":{col}" if col and col > 1 else ""))
    t = report.target.ref
    if isinstance(t, ImmutableRef):
        url = t.url_for(path, line)
        if url and url.startswith("https://"):
            return f'<a href="{e(url)}"><code>{text}</code></a>'
    return f"<code>{text}</code>"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _same(a: str, b: str) -> bool:
    return a.strip().rstrip(".").casefold() == b.strip().rstrip(".").casefold()


def _classes(report: Report, f: Finding) -> str:
    return f"eff-{verdicts.effect(f, report.chains)} cat-{f.category.value}" + (" fix-auto" if f.fix.kind == FixKind.auto else "")


def _finding(report: Report, f: Finding) -> list[str]:
    out = [f'<section class="f {f.severity.value} {_classes(report, f)}" id="{e(f.fingerprint)}">',
           f'<header><span class="sev">{f.severity.value}</span><h3>{e(f.title)}</h3>'
           + ("" if f.corroborated else '<span class="uncounted">not corroborated</span>')
           + f'<span class="rule">{e(f.id)}</span></header><div>']
    if f.risk and not _same(f.risk, f.title):
        out.append(f'<p class="msg">{e(f.risk)}</p>')
    facts = []
    loc = f.location
    if loc:
        where = _loc_link(report, loc.file, loc.start.line, loc.start.column)
        if loc.container:
            where = f"<code>{e(loc.container)}</code> » {where}"
        facts.append(("Location", where, "wide"))
        if loc.artifact:
            facts.append(("Artifact", e(loc.artifact), ""))
    facts.append(("Confidence", e(f.confidence.value), ""))
    facts.append(("Lane", e(f.lane.value), ""))
    if f.engines:
        facts.append(("Engines", e(", ".join(f.engines)), ""))
    if f.chain:
        facts.append(("Chain", f'<a href="#{e(f.chain)}">{e(f.chain)}</a>', ""))
    if f.aivss:
        facts.append(("AIVSS", f'{f.aivss.value} <span class="muted">{e(f.aivss.scorer)} {e(f.aivss.scorer_version)}</span>', ""))
    if f.adjudication and f.adjudication.status != "not_run":
        facts.append(("Model review", e(f.adjudication.status), ""))
    if f.tags:
        facts.append(("Tags", e(", ".join(f.tags)), ""))
    cells = []
    for k, v, cls in facts:
        attr = f' class="{cls}"' if cls else ""
        cells.append(f"<div{attr}><dt>{k}</dt><dd>{v}</dd></div>")
    out.append('<dl class="facts">' + "".join(cells) + "</dl>")
    narrative = f.flow.narrative if f.flow else ""
    shown = [ev for ev in f.evidence.items[:3] if str(ev.snippet) and not (narrative and _same(str(ev.snippet), narrative))]
    decoded = str(f.evidence.decoded)
    if shown or decoded:
        out.append("<h4>Evidence</h4>")
    dots = '<span class="dots" aria-hidden="true"><i></i><i></i><i></i></span>'
    if decoded:
        via = e(" → ".join(f.evidence.derivation)) if f.evidence.derivation else "hidden content"
        source = str(f.evidence.snippet)
        if source and not _same(source, decoded):
            out.append(f'<figure class="ev"><figcaption>{dots}<span>source line</span></figcaption><pre><code>{e(source)}</code></pre></figure>')
        out.append(f'<figure class="ev"><figcaption>{dots}<span>decoded ({via})</span></figcaption><pre><code>{e(decoded)}</code></pre></figure>')
    else:
        for ev in shown:
            # a terminal window: three hollow dots, the file and the detail in its title bar
            where = f"<code>{e(ev.location.path)}:{ev.location.start_line}</code>" if ev.location else ""
            caption = " ".join(x for x in (dots, where, f"<span>{e(ev.detail)}</span>" if ev.detail else "") if x)
            out.append(f'<figure class="ev"><figcaption>{caption}</figcaption><pre><code>{e(str(ev.snippet))}</code></pre></figure>')
    if narrative and not _same(narrative, f.risk or ""):
        out.append(f'<h4>Flow</h4><p class="flow">{e(narrative)}</p>')
    if f.trace:
        steps = "".join(f"<li>{_loc_link(report, t.file, t.line)}" + (f" <span>{e(t.role)}</span>" if t.role and t.role != "step" else "")
                        + (f" {e(t.note)}" if t.note else "") + "</li>" for t in f.trace)
        out.append(f'<details class="trace"><summary>Trace: {_plural(len(f.trace), "step")}</summary><ol>{steps}</ol></details>')
    fix = e(f.fix.summary) if f.fix.summary else ""
    if f.fix.kind == FixKind.auto:
        fix += f' <span class="muted">Run <code>agentguard fix --finding {e(f.fingerprint[:12])}</code>.</span>'
    out.append(f'<div class="advice"><section><h4>Why it matters</h4><p>{e(f.explanation)}</p></section>'
               f'<section class="fix"><h4>{e(FIX_LABEL[f.fix.kind])}</h4><p>{fix}</p></section></div>')
    pills = [(FRAMEWORK_LABEL.get(k, k), i) for k, ids in f.mappings.items() for i in ids]
    if pills:
        out.append('<p class="pills"><span class="label">Standards</span>' + "".join(
            f'<span class="pill">{e(label)} {e(i)}</span>' for label, i in pills) + "</p>")
    out.append("</div></section>")
    return out


def _stat(label: str, value: str, sub: str = "") -> str:
    """One cell of the row of figures under the report's top: a label, a large value and a note."""
    note = f'<span class="sub">{sub}</span>' if sub else ""
    return f'<div><dt>{label}</dt><dd><span class="v">{value}</span>{note}</dd></div>'


_VERDICT_TEXT = {
    Verdict.block: ("hot", "Do not install or enable this.", "At least one finding is enough on its own to block it."),
    Verdict.review: ("warn", "Review before installing or enabling this.", "Nothing blocks it outright, but something needs a person to look."),
    Verdict.allow: ("", "No rule that counts towards the verdict matched.",
                    "That does not mean safe: static rules miss paraphrased or novel attacks, and behavior that only appears at run time."),
}


def _verdict(report: Report) -> str:
    cls, head, body = _VERDICT_TEXT[report.verdict]
    reasons = "".join(f"<li>{e(r)}</li>" for r in report.verdict_reasons[:5])
    return (f'<div class="verdict{" " + cls if cls else ""}"><span class="vd">{report.verdict.value}</span>'
            f"<strong>{head}</strong>{body}" + (f"<ul>{reasons}</ul>" if reasons else "") + "</div>")


def render_html(report: Report) -> str:
    css, css_hash = _style()
    sev = report.stats.findings_by_severity
    target = _target(report)
    stats = report.stats
    cov = report.coverage
    head = (f"{_plural(len(report.findings), 'finding')}: " + ", ".join(f"{sev[s.value]} {s.value}" for s in Severity if sev.get(s.value))
            if report.findings else "No findings")
    network = report.network_features_used
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src '{css_hash}'; font-src data:; img-src 'none'; base-uri 'none'; form-action 'none'\">",
        '<meta name="referrer" content="no-referrer"><meta name="color-scheme" content="dark">',
        '<meta name="description" content="Agent Guard scan report: verdict, findings, evidence, fixes and standards mappings.">',
        "<title>Agent Guard report</title>",
        f"<style>{css}</style></head><body><div class=\"page\">",
        f'<header><div class="bar"><span class="brand">{_SHIELD}Agent Guard</span><span class="muted">Scan report</span></div></header><main>',
        '<section class="report corners"><div class="top"><div><h1>Scan report</h1>',
        f'<p class="target">Scanned {target}</p>' if target else "",
        _verdict(report),
        f'</div><div class="board corners"><p class="board-head"><span>{head}</span>'
        f'<span class="hi">Score {report.score} · tier {report.risk_tier.value}</span></p><ul class="counts" aria-label="Findings by severity">',
    ]
    for s in Severity:
        n = sev.get(s.value, 0)
        parts.append(f'<li class="count {s.value}{"" if n else " zero"}"><b>{n}</b><span class="sev">{s.value}</span></li>')
    parts.append(f'</ul><p class="board-note">{_plural(stats.files_scanned, "file")} and {_plural(stats.components, "component")} scanned</p></div></div>')
    parts.append('<dl class="stats">' + "".join((
        _stat("Coverage", f"{round(cov.analyzability * 100)}%",
              f"{cov.files_analysed} of {_plural(cov.files_total, 'file')} analysed · {_plural(stats.components, 'component')}"),
        _stat("Rule pack", f"v{e(report.tool.rule_pack)}",
              f"{stats.rules_evaluated} of {_plural(report.tool.rule_count, 'rule')} applied · digest {e(report.tool.rule_pack_digest[:12])}"),
        _stat("Engine", e(report.engine_version), f"profile {e(report.profile)} · policy {e(report.policy)}"),
        _stat("Network", "Used" if network else "Offline", e(", ".join(network)) if network else "No network features used"),
    )) + "</dl>")
    parts.append(f'<p class="note">{e(ALLOW_NOTE)} Each finding names the risk, the file and line that cause it, and the fix.</p>'
                 '<div class="hatch" aria-hidden="true"></div></section>')
    parts.append(f'<h2>Findings <span class="n">{len(report.findings)}</span></h2>')
    if not report.findings:
        parts.append(f'<p class="empty">{e(report.summary)}</p>')
    else:
        parts.append('<div class="filters" role="radiogroup" aria-label="Filter findings">'
                     + "".join(f'<input type="radio" name="flt" id="flt-{key}"{" checked" if key == "all" else ""}><label for="flt-{key}">{label}</label>'
                               for key, label in (("all", "All"), ("block", "Blocking"), ("review", "Needs review"),
                                                  ("info", "No effect on the verdict"), ("auto", "Auto-fixable")))
                     + "</div>")
        parts.append('<div class="corners list"><div class="table index"><table><thead><tr><th scope="col">Severity</th><th scope="col">Finding</th>'
                     '<th scope="col">Rule</th><th scope="col">Location</th></tr></thead><tbody>')
        for f in report.findings:
            loc = f"<code>{e(f.primary.path)}:{f.primary.start_line}</code>" if f.primary else ""
            parts.append(f'<tr class="row {f.severity.value} {_classes(report, f)}"><td><span class="sev">{f.severity.value}</span></td>'
                         f'<td><a href="#{e(f.fingerprint)}">{e(f.title)}</a></td><td class="rule">{e(f.id)}</td><td>{loc}</td></tr>')
        parts.append("</tbody></table></div></div>")
        # Malice, vulnerabilities and hygiene are never mixed into one list.
        for cat in Category:
            group = [f for f in report.findings if f.category == cat]
            if not group:
                continue
            effects = " ".join(sorted({c for f in group for c in _classes(report, f).split()}))
            parts.append(f'<h2 class="cat {effects}">{CATEGORY_TITLE[cat]} <span class="n">{len(group)}</span></h2>')
            for f in group:
                parts += _finding(report, f)
    if report.chains:
        by_fp = {f.fingerprint: f for f in report.findings}
        parts.append(f'<h2>Attack chains <span class="n">{len(report.chains)}</span></h2><div class="corners"><div class="table"><table><thead><tr>'
                     '<th scope="col">Chain</th><th scope="col">Severity</th><th scope="col">Path</th><th scope="col">Ends in</th></tr></thead><tbody>')
        for ch in report.chains:
            path = " → ".join(f'<a href="#{e(s)}">{e(by_fp[s].id)}</a>' for s in ch.steps if s in by_fp)
            parts.append(f'<tr id="{e(ch.id)}" class="{ch.severity.value}"><td><code>{e(ch.id)}</code></td>'
                         f'<td><span class="sev">{ch.severity.value}</span></td><td>{path}<br><span class="muted">{e(ch.narrative)}</span></td>'
                         f"<td>{e(ch.sink or 'not confirmed')}</td></tr>")
        parts.append("</tbody></table></div></div>")
    notes = [a for a in report.analyzers if a.status != "ran" and a.reason != "not selected"]
    if notes or cov.unanalysed:
        parts.append('<h2>Coverage</h2>')
        if cov.unanalysed:
            missing = cov.files_total - cov.files_analysed
            parts.append(f'<details class="panel" open><summary>Not analysed <span class="muted">({_plural(missing, "file")})</span></summary><ul>')
            parts += [f"<li><code>{e(u.path)}</code> — {e(u.reason)}</li>" for u in cov.unanalysed[:50]]
            if missing > 50:
                parts.append(f"<li>…and {missing - 50} more</li>")
            parts.append("</ul></details>")
        if notes:
            parts.append(f'<details class="panel" open><summary>What was not run '
                         f'<span class="muted">({_plural(len(notes), "analyzer")})</span></summary><ul>')
            parts += [f"<li><code>{e(a.id)}</code> {e(a.status)} — {e(a.reason)}</li>" for a in notes]
            parts.append("</ul></details>")
    parts.append(f'<h2>Artifacts <span class="n">{len(report.artifacts)}</span></h2><div class="corners"><div class="table"><table><thead><tr>'
                 '<th scope="col">Artifact</th><th scope="col">Type</th><th scope="col">Can do</th><th scope="col">Tier</th>'
                 '<th scope="col">Verdict</th><th scope="col">Location</th></tr></thead><tbody>')
    for a in report.artifacts:
        caps = e(", ".join(a.capabilities)) if a.capabilities else '<span class="muted">instructions only</span>'
        parts.append(f"<tr><td>{e(a.id)}</td><td>{e(a.type)} <span class=\"muted\">{e(a.ecosystem)}</span></td><td>{caps}</td>"
                     f'<td class="tier">{a.risk_tier.value}</td><td>{a.verdict.value}</td><td><code>{e(a.root)}</code></td></tr>')
    parts.append("</tbody></table></div></div>")
    plans = [a for a in report.artifacts if a.least_privilege and a.least_privilege.allowed_tools]
    if plans:
        parts.append(f'<details class="panel"><summary>Least privilege <span class="muted">(the smallest grant that covers what '
                     f'{_plural(len(plans), "artifact")} was seen to do)</span></summary><ul>')
        for a in plans:
            lp = a.least_privilege
            assert lp is not None
            domains = (lp.sandbox.get("network") or {}).get("allowedDomains") or []
            net = "network to " + ", ".join(f"<code>{e(d)}</code>" for d in domains[:8]) if domains else "no network"
            parts.append(f"<li>{e(a.id)}: " + ", ".join(f"<code>{e(t)}</code>" for t in lp.allowed_tools[:12])
                         + f' <span class="muted">· sandbox with {net}</span></li>')
        parts.append("</ul></details>")
    parts.append("</main>")
    parts.append(f"<footer><span>Generated by Agent Guard {e(report.engine_version)} · rule pack {e(report.tool.rule_pack)}</span>"
                 "<span>Fonts: Inter and JetBrains Mono, SIL Open Font License 1.1</span></footer></div></body></html>\n")
    return "".join(parts)
