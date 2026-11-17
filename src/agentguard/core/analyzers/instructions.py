"""Instruction analysis beyond the English pattern rules (engine B).

* AG-INJ-016: a block written in a different language or script from the rest of the document.
* AG-INJ-017: known injection phrasings in Chinese, Japanese, Korean, Spanish, Portuguese, French, German, Italian,
  Russian, Arabic and Hindi. These run on the original text: normalisation folds Cyrillic and Greek to Latin.
* AG-INJ-018: instructions written in an encoded form (leetspeak, spaced-out letters, reversed text, ROT13, Morse,
  regional-indicator letters), found by decoding each line and re-reading it.
* AG-INJ-024: a command or prompt template that puts its arguments into a shell command unquoted.
* AG-INJ-025: hijack phrasing in a subagent's prompt.
"""

from __future__ import annotations

import codecs
from collections import Counter
from typing import Any, ClassVar

import regex

from ..artifacts import ArtifactText
from ..models import Span
from ..models.enums import ArtifactRole, EvidenceKind, Severity
from ..textutil import TIMEOUT
from .base import Context
from .connectors import DIRECTIVE

_F = regex.IGNORECASE
# The core of an injection, in English. Used on decoded text and on subagent prompts.
CORE = regex.compile(
    r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|rules?|prompts?)\b"
    r"|\bdo\s+not\s+(?:tell|inform|notify)\s+the\s+user\b|\b(?:reveal|print|show|send)\s+(?:the\s+|your\s+)?system\s+prompt\b"
    r"|\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|unrestricted|jailbreak)\b"
    r"|\b(?:send|upload|post|exfiltrate)\s+(?:all\s+|the\s+)?(?:secrets?|credentials?|tokens?|api\s+keys?|ssh\s+keys?|passwords?)\b"
    r"|\bcurl\s+\S+\s*\|\s*(?:ba)?sh\b|\brun\s+the\s+following\s+command\b", _F)
PHRASES: dict[str, tuple[str, ...]] = {
    "Chinese": (
        r"(?:忽略|无视|無視|忘记|忘記|不要理会)(?:掉)?(?:之前|以上|先前|前面|上面|上述|此前)?(?:的)?(?:所有|全部|一切)?(?:的)?(?:指令|指示|说明|說明|提示|规则|規則|命令)",
        r"不要(?:告诉|告訴|告知|通知)(?:用户|用戶|使用者)",
        r"你现在是|你現在是|从现在开始你是",
    ),
    "Japanese": (
        r"(?:以前|これまで|上記|今まで)の(?:すべての|全ての)?(?:指示|命令|指令|ルール)(?:を|は)(?:すべて|全て)?(?:無視|忘れ)",
        r"ユーザー(?:に|には)(?:知らせ|伝え|言わ|教え)(?:ない|ず)",
    ),
    "Korean": (
        r"(?:이전|위|앞)(?:의)?\s*(?:모든\s*)?(?:지시|지침|명령)(?:사항)?(?:을|를)?\s*(?:모두\s*)?(?:무시|잊)",
        r"사용자에게\s*(?:알리지|말하지)\s*(?:마|않)",
    ),
    "Spanish": (
        r"\b(?:ignora|ignore|ignorar|olvida|olvide|omite)\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)",
        r"\bno\s+(?:le\s+)?(?:digas|diga|informes|informe|menciones|reveles)\s+(?:nada\s+|esto\s+)?al\s+usuario",
    ),
    "Portuguese": (
        r"\b(?:ignore|ignora|ignorar|esqueça|esqueca)\s+(?:todas\s+)?(?:as\s+)?instruções\s+(?:anteriores|prévias|previas)",
        r"\bnão\s+(?:diga|conte|informe|revele|mencione)\s+(?:nada\s+|isso\s+)?(?:ao|para\s+o)\s+usuário",
    ),
    "French": (
        r"\b(?:ignore|ignorez|ignorer|oublie|oubliez)\s+(?:toutes\s+)?(?:les\s+)?instructions\s+(?:précédentes|precedentes|antérieures|ci-dessus)",
        r"\bne\s+(?:le\s+)?(?:dis|dites|révèle|révélez|mentionne|mentionnez)\s+(?:rien\s+|pas\s+)(?:cela\s+)?à\s+l['’]utilisateur",
    ),
    "German": (
        r"\b(?:ignoriere|ignorieren\s+sie|ignorier|vergiss|vergessen\s+sie)\s+(?:alle\s+)?(?:vorherigen|bisherigen|obigen|früheren)\s+(?:anweisungen|instruktionen|regeln)",
        r"\b(?:sag|sage|sagen\s+sie|teile|informiere|informieren\s+sie)\s+(?:es\s+)?(?:dem|den)\s+(?:benutzer|nutzer|anwender)\s+(?:nichts|nicht)",
    ),
    "Italian": (
        r"\b(?:ignora|ignorare|dimentica)\s+(?:tutte\s+)?(?:le\s+)?istruzioni\s+precedenti",
        r"\bnon\s+(?:dire|rivelare)\s+(?:nulla\s+|niente\s+)?all['’]utente",
    ),
    "Russian": (
        r"(?:игнорируй|игнорируйте|забудь|забудьте|не\s+обращай\s+внимания\s+на)\s+(?:все\s+)?(?:предыдущие|прежние|вышеуказанные|прошлые)\s+(?:инструкции|указания|правила)",
        r"не\s+(?:говори|говорите|сообщай|сообщайте|рассказывай)\s+(?:об\s+этом\s+)?пользователю",
    ),
    "Arabic": (
        r"تجاهل\s+(?:جميع\s+|كل\s+)?(?:التعليمات|الإرشادات|الأوامر)\s+السابقة",
        r"لا\s+تخبر\s+المستخدم",
    ),
    "Hindi": (
        r"(?:पिछले|पहले\s+के|पूर्व)\s+(?:सभी\s+)?(?:निर्देशों|निर्देश|आदेशों)\s+(?:को\s+)?(?:अनदेखा|नज़रअंदाज़|अनदेखी)\s+(?:करें|करो|कर\s+दें)",
        r"उपयोगकर्ता\s+को\s+(?:मत|न)\s+बताएं",
    ),
}
_COMPILED = {lang: tuple(regex.compile(p, _F) for p in pats) for lang, pats in PHRASES.items()}
# Languages whose injection phrasings can be written in ASCII alone (accents are often dropped).
_LATIN_LANGS = frozenset({"Spanish", "Portuguese", "French", "German", "Italian"})
_SCRIPTS: tuple[tuple[str, int, int], ...] = (
    ("Latin", 0x41, 0x24F), ("Greek", 0x370, 0x3FF), ("Cyrillic", 0x400, 0x4FF), ("Hebrew", 0x590, 0x5FF), ("Arabic", 0x600, 0x6FF),
    ("Devanagari", 0x900, 0x97F), ("Thai", 0xE00, 0xE7F), ("Japanese", 0x3040, 0x30FF), ("Chinese", 0x3400, 0x9FFF),
    ("Korean", 0xAC00, 0xD7AF),
)
_STOPWORDS: dict[str, frozenset[str]] = {
    "English": frozenset("the and you with for this that are from not your will when use file each then all it is of to in".split()),
    "Spanish": frozenset("el la los las que para con una por del usuario todas instrucciones es en al lo se su como este".split()),
    "French": frozenset("le les des une pour avec vous est dans que ne pas toutes et au du ce cette sur votre".split()),
    "German": frozenset("der die das und nicht mit für ist sie ein eine alle dem den zu auf von dieser diese wird".split()),
    "Portuguese": frozenset("o os as uma para com não você que do da em todas é ao dos das seu este isso".split()),
    "Italian": frozenset("il gli che per con non una del della tutte sono di al lo questo questa nel alla".split()),
}
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})
_SPACED = regex.compile(r"(?<!\w)(?:\w[ \t._\-]){4,}\w(?!\w)")
_MORSE_RUN = regex.compile(r"(?:[.\-]{1,5}(?:[ ]{1,3}|[ ]?/[ ]?)){5,}[.\-]{1,5}")
_MORSE = {".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g", "....": "h", "..": "i", ".---": "j",
          "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t",
          "..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y", "--..": "z"}
_ARG = regex.compile(r"\$ARGUMENTS\b|\$\{ARGUMENTS\}|\$[1-9]\b|\$\{[1-9]\}|\$@|\$\*")
_SHELL_START = regex.compile(
    r"^\s*(?:\$\s+)?(?:sudo\s+)?(?:git|gh|npm|npx|pnpm|yarn|python3?|node|bash|sh|curl|wget|docker|kubectl|make|cargo|go|pip3?|uv|rm|cp|mv|cat|"
    r"grep|find|sed|awk|echo|ssh|scp|terraform|aws|gcloud|az|open|xargs|chmod)\b")
_INLINE_CODE = regex.compile(r"`([^`\n]{3,300})`")
_PROSE = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.command_md, ArtifactRole.reference)
_HIJACK_IDS = frozenset({"AG-INJ-001", "AG-INJ-002", "AG-INJ-003", "AG-INJ-004", "AG-INJ-008", "AG-INJ-011", "AG-INJ-019", "AG-INJ-021"})
MIN_BLOCK_LETTERS = 20


def _search(rx: regex.Pattern[str], text: str) -> regex.Match[str] | None:
    try:
        return rx.search(text, timeout=TIMEOUT)
    except TimeoutError:
        return None


def script_of(ch: str) -> str | None:
    cp = ord(ch)
    if cp < 0x41 or not ch.isalpha():
        return None
    for name, lo, hi in _SCRIPTS:
        if lo <= cp <= hi:
            return name
    return None


def language_of(text: str) -> tuple[str, int, int]:
    """(language or script, letters counted, confidence hits) of a block of prose."""
    scripts = Counter(s for s in map(script_of, text) if s)
    letters = sum(scripts.values())
    if not letters:
        return "", 0, 0
    top, n = scripts.most_common(1)[0]
    if top == "Chinese" and scripts.get("Japanese", 0) >= 3:
        top, n = "Japanese", n + scripts["Japanese"]
    if top != "Latin":
        return top, letters, n
    words = regex.findall(r"[^\W\d_]+", text.lower())
    hits = {lang: sum(1 for w in words if w in sw) for lang, sw in _STOPWORDS.items()}
    lang, best = max(hits.items(), key=lambda kv: (kv[1], kv[0] == "English"))
    second = max((v for k, v in hits.items() if k != lang), default=0)
    if best >= 3 and best >= second + 2:
        return lang, letters, best
    return "Latin", letters, 0


def decodings(line: str) -> list[tuple[str, str]]:
    """Readings of a line under the common encoded-language tricks: (technique, decoded text)."""
    out: list[tuple[str, str]] = []
    if any(c in line for c in "013457@$") and regex.search(r"[A-Za-z]", line):
        folded = " ".join(tok.translate(_LEET) if regex.search(r"[A-Za-z]", tok) and regex.search(r"[013457@$!|]", tok) else tok
                          for tok in line.split(" "))
        if folded != line:
            out.append(("leetspeak", folded))
    spaced = _SPACED.sub(lambda m: regex.sub(r"[ \t._\-]", "", m.group(0)), line)
    if spaced != line:
        out.append(("spaced-out letters", spaced))
    if len(line.strip()) >= 12:
        out.append(("reversed text", line[::-1]))
        out.append(("ROT13", codecs.decode(line, "rot13")))
    for m in _MORSE_RUN.finditer(line):
        words = []
        for word in regex.split(r"\s*/\s*|\s{2,}", m.group(0).strip()):
            words.append("".join(_MORSE.get(sym, "?") for sym in word.split()))
        text = " ".join(words)
        if text.count("?") <= len(text) // 6:
            out.append(("Morse code", line[:m.start()] + text + line[m.end():]))
    if any(0x1F1E6 <= ord(c) <= 0x1F1FF for c in line):
        out.append(("regional-indicator letters", "".join(chr(ord(c) - 0x1F1E6 + ord("a")) if 0x1F1E6 <= ord(c) <= 0x1F1FF else c
                                                          for c in line)))
    return out


def unquoted_argument(command: str) -> regex.Match[str] | None:
    """The first argument placeholder of a command that sits outside quotes."""
    for m in _ARG.finditer(command):
        before = command[:m.start()]
        if before.count('"') % 2 == 0 and before.count("'") % 2 == 0:
            return m
    return None


class InstructionAnalyzer:
    id: ClassVar[str] = "instruction"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-INJ-016", "AG-INJ-017", "AG-INJ-018", "AG-INJ-024", "AG-INJ-025")

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        for at in ctx.texts():
            role = at.artifact.role
            if role in _PROSE:
                if not at.text.isascii():
                    self._foreign_block(at)
                self._phrases_text(at)
                self._encoded(at)
            surface = ctx.inventory.surfaces.get(at.path)
            if role in (ArtifactRole.skill_md, ArtifactRole.command_md) or (surface is not None and surface.group == "command"):
                self._templates(at)
        for unit in ctx.data.get("extra_units", []):  # type: ignore[union-attr]
            if unit.scope in ("tool_text", "server_instructions") or unit.role == "config_prompt":
                self._phrases_unit(unit)
        self._subagents()

    # -- AG-INJ-016 ---------------------------------------------------------------------------------
    def _foreign_block(self, at: ArtifactText) -> None:
        body = at.fm.body if at.fm is not None else at.text
        base = at.fm.body_offset if at.fm is not None else 0
        blocks: list[tuple[int, str, str, int]] = []           # offset, language, text, letters
        pos = 0
        for para in regex.split(r"\n[ \t]*\n", body):
            start = body.find(para, pos)
            pos = start + len(para)
            if not para.strip() or at.in_code(base + start):
                continue
            lang, letters, _ = language_of(para)
            if letters >= MIN_BLOCK_LETTERS and lang:
                blocks.append((base + start, lang, para, letters))
        total = sum(b[3] for b in blocks)
        if total < 120 or len(blocks) < 2:
            return
        weight: Counter[str] = Counter()
        for _, lang, _, letters in blocks:
            weight[lang] += letters
        main, n = weight.most_common(1)[0]
        if main == "Latin" or n / total < 0.7:
            return
        for start, lang, para, _letters in blocks:
            if lang in (main, "Latin"):
                continue
            self.ctx.emit("AG-INJ-016", component_ids=at.artifact.component_id, span=at.span(start, start + len(para)),
                          snippet=para.strip()[:240], match=f"foreign:{lang}:{para.strip()[:80]}", kind=EvidenceKind.regex,
                          message=f"This block is in {lang}; the rest of the document is in {main}. A reviewer who reads {main} does "
                                  "not read this part, and the model reads both.")
            return

    # -- AG-INJ-017 ---------------------------------------------------------------------------------
    def _phrases_text(self, at: ArtifactText) -> None:
        ascii_only = at.text.isascii()
        for lang, patterns in _COMPILED.items():
            if ascii_only and lang not in _LATIN_LANGS:
                continue
            for rx in patterns:
                m = _search(rx, at.text)
                if m:
                    self.ctx.emit("AG-INJ-017", component_ids=at.artifact.component_id, span=at.span(m.start(), m.end()),
                                  snippet=at.line_text(m.start())[:240], match=f"{lang}:{m.group(0).lower()}", kind=EvidenceKind.regex,
                                  message=f"A known injection phrasing in {lang} (\"{m.group(0)[:80]}\"): it tells the agent to drop "
                                          "its earlier instructions or to keep something from the user.")
                    return

    def _phrases_unit(self, unit: Any) -> None:
        ascii_only = unit.text.isascii()
        for lang, patterns in _COMPILED.items():
            if ascii_only and lang not in _LATIN_LANGS:
                continue
            for rx in patterns:
                m = _search(rx, unit.text)
                if m:
                    self.ctx.emit("AG-INJ-017", component_ids=unit.component_id, span=unit.anchor_span or Span(path=unit.path),
                                  snippet=unit.text[max(0, m.start() - 60): m.end() + 60], match=f"{unit.label}:{lang}:{m.group(0).lower()}",
                                  kind=EvidenceKind.metadata, detail=unit.label,
                                  message=f"A known injection phrasing in {lang} in {unit.label or 'this value'} (\"{m.group(0)[:80]}\").")
                    return

    # -- AG-INJ-018 ---------------------------------------------------------------------------------
    def _encoded(self, at: ArtifactText) -> None:
        offset = 0
        for line in at.text.split("\n"):
            start = offset
            offset += len(line) + 1
            if len(line.strip()) < 8 or len(line) > 2000 or _search(CORE, line):
                continue
            for technique, decoded in decodings(line):
                m = _search(CORE, decoded)
                if m:
                    self.ctx.emit("AG-INJ-018", component_ids=at.artifact.component_id, span=at.span(start, start + len(line)),
                                  snippet=line.strip()[:240], match=f"encoded:{technique}:{m.group(0).lower()}", kind=EvidenceKind.regex,
                                  decoded=decoded.strip()[:300], decode_path=(technique,),
                                  message=f"Read as {technique}, this line says \"{decoded.strip()[:100]}\". The instruction is written so "
                                          "that keyword filters and a quick read miss it, while a model decodes it without effort.")
                    return

    # -- AG-INJ-024 ---------------------------------------------------------------------------------
    def _templates(self, at: ArtifactText) -> None:
        cid = at.artifact.component_id
        seen: set[int] = set()
        for b in at.bang:
            m = unquoted_argument(b.command)
            if m:
                line = at.index.line_col(b.command_start)[0]
                seen.add(line)
                self.ctx.emit("AG-INJ-024", component_ids=cid, span=at.span(b.command_start + m.start(), b.command_start + m.end()),
                              snippet=b.command[:240], match=f"bang:{b.command[:120]}", kind=EvidenceKind.regex,
                              message=f"The load-time command `{b.command[:80]}` inserts `{m.group(0)}` into a shell command without "
                                      "quotes. Whatever follows the command name when it is used is parsed by the shell, so `; other "
                                      "command` runs too.")
        candidates: list[tuple[int, str]] = []
        for f in at.fence_list:
            info = (f.info or "").strip().lower()
            if info.startswith("!") or info not in ("", "bash", "sh", "shell", "zsh", "console"):
                continue
            pos = f.body_start
            for line in at.text[f.body_start:f.body_end].split("\n"):
                candidates.append((pos, line))
                pos += len(line) + 1
        for m in _INLINE_CODE.finditer(at.text):
            if not at.in_code(m.start()) and (m.start() == 0 or at.text[m.start() - 1] != "!"):
                candidates.append((m.start(1), m.group(1)))
        for pos, cmd in candidates:
            line = at.index.line_col(pos)[0]
            if line in seen or not _search(_SHELL_START, cmd):
                continue
            m = unquoted_argument(cmd)
            if m:
                seen.add(line)
                self.ctx.emit("AG-INJ-024", component_ids=cid, span=at.span(pos + m.start(), pos + m.end()), snippet=cmd.strip()[:240],
                              match=f"template:{cmd.strip()[:120]}", kind=EvidenceKind.regex, severity=Severity.medium,
                              message=f"The command template `{cmd.strip()[:80]}` places `{m.group(0)}` into a shell command without "
                                      "quotes. The agent fills it in with whatever it was given, and the shell parses the result.")
                if len(seen) >= 5:
                    return

    # -- AG-INJ-025 ---------------------------------------------------------------------------------
    def _subagents(self) -> None:
        inv = self.ctx.inventory
        paths = sorted(p for p, s in inv.surfaces.items() if s.group == "agent")
        if not paths:
            return
        by_path: dict[str, Any] = {}
        for r in self.ctx.raw:
            if r.rid in _HIJACK_IDS and r.primary is not None:
                by_path.setdefault(r.primary.path, r)
        for path in paths:
            art = inv.artifacts.get(path)
            cid = art.component_id if art else ""
            prompts: list[tuple[str, str]] = []
            at = inv.texts.get(path)
            doc = inv.docs.get(path)
            if at is not None and at.fm is not None and isinstance(at.fm.data, dict):
                for key in ("initialPrompt", "initial_prompt", "prompt", "instructions"):
                    if isinstance(at.fm.data.get(key), str):
                        prompts.append((key, at.fm.data[key]))
                prompts.append(("prompt body", at.fm.body))
            if doc is not None and isinstance(doc.value, dict):
                for key in ("developer_instructions", "instructions", "prompt", "system_prompt"):
                    if isinstance(doc.data.get(key), str):
                        prompts.append((key, doc.data[key]))
            hit: tuple[str, str] | None = None
            for key, text in prompts:
                m = _search(CORE, text) or _search(DIRECTIVE, text)
                if m is None and not text.isascii():
                    m = next((mm for pats in _COMPILED.values() for rx in pats if (mm := _search(rx, text))), None)
                if m:
                    hit = (key, m.group(0))
                    break
            raw = by_path.get(path)
            if hit is None and raw is None:
                continue
            if hit is not None:
                text = at.text if at is not None else (doc.text if doc is not None else "")
                off = text.find(hit[1])
                line = text.count("\n", 0, off) + 1 if off >= 0 else 1
                span, where, what = Span(path=path, start_line=line), hit[0], hit[1]
            else:
                span, where, what = raw.primary, "prompt", raw.rid
            self.ctx.emit("AG-INJ-025", component_ids=[cid] if cid else [], span=span, snippet=what[:200], match=f"subagent:{path}:{what[:80]}",
                          kind=EvidenceKind.regex,
                          message=f"The subagent defined in `{path}` carries hijack phrasing in its {where} (\"{what[:80]}\"). A "
                                  "subagent's prompt is its system prompt: the parent agent hands it work and trusts what comes back.")


__all__ = ["CORE", "InstructionAnalyzer", "PHRASES", "decodings", "language_of", "unquoted_argument"]
