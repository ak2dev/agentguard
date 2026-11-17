"""The program that runs as PID 1 inside the detonation container (spec/sandbox.md). Standard library only.

    stdin:  one JSON line (the job), then an uncompressed tar of the target
    stdout: one line  "AGRESULT <nonce> <json>"  (everything else on stdout is ignored by the host)

It runs as root with a handful of capabilities so that it can route every address to the sinkhole, lay
out the honey environment and then drop to an unprivileged user. Everything from the target runs as that
user, under `strace -f`, with the decoy environment and no way to reach a real network.

The functions that parse traces and compare file listings are pure and are unit-tested on any platform.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import select
import shutil
import subprocess
import sys
import tarfile
import time
from typing import Any

TRACE_CALLS = "execve,openat,open,connect,unlink,unlinkat,rename,renameat,renameat2,ptrace,listen,clone,clone3,fork,vfork"
MAX_OUTPUT = 32 * 1024
MAX_EVENTS = 1500
MAX_LIFT = 5
WATCHED_ROOTS = ("/home", "/work", "/tmp", "/root", "/var/tmp", "/var/spool/cron", "/etc/cron", "/etc/systemd", "/etc/profile",
                 "/etc/ssh", "/etc/sudoers", "/etc/shadow", "/etc/passwd")
PROBE_PATHS = ("/.dockerenv", "/proc/1/cgroup", "/proc/self/cgroup", "/sys/class/dmi", "/proc/scsi/scsi", "/sys/hypervisor",
               "/proc/sys/kernel/osrelease", "/run/.containerenv")
_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')
_LINE = re.compile(r"^(\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(?:\s+(\w+))?")
_RESUMED = re.compile(r"^(\d+)\s+<\.\.\. (\w+) resumed>(.*)\)\s+=\s+(-?\d+|\?)")
_ADDR = re.compile(r'sin_port=htons\((\d+)\).*?inet_addr\("([^"]+)"\)|sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"')


def _unescape(s: str) -> str:
    try:
        return s.encode("latin-1", "replace").decode("unicode_escape").encode("latin-1", "replace").decode("utf-8", "replace")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return s


def parse_trace(text: str, limit: int = MAX_EVENTS) -> dict[str, Any]:
    """Events from `strace -f` output: programs started, watched files opened, addresses connected to, files
    removed or renamed, and whether the target asked to be traced or opened a listening socket."""
    comm: dict[str, str] = {}
    out: dict[str, Any] = {"exec": [], "open": [], "connect": [], "unlink": [], "rename": [], "ptrace": False, "listen": 0,
                           "probes": [], "truncated": False}
    total = 0
    for line in text.splitlines():
        m = _LINE.match(line)
        if m is None:
            r = _RESUMED.match(line)
            if r is not None and r.group(2) in ("clone", "clone3", "fork", "vfork") and r.group(4).isdigit():
                comm[r.group(4)] = comm.get(r.group(1), "")
            continue
        pid, call, args, ret = m.group(1), m.group(2), m.group(3), m.group(4)
        ok = ret not in ("?",) and not ret.startswith("-")
        if call in ("clone", "clone3", "fork", "vfork"):
            if ok:
                comm[ret] = comm.get(pid, "")
            continue
        if total >= limit:
            out["truncated"] = True
            break
        if call == "execve" and ok:
            strings = [_unescape(s) for s in _STR.findall(args.split("], ", 1)[0])]
            if strings:
                comm[pid] = os.path.basename(strings[0])
                out["exec"].append(strings[1:][:24] or [strings[0]])
                total += 1
        elif call in ("openat", "open"):
            s = _STR.search(args)
            if s is None:
                continue
            path = _unescape(s.group(1))
            if path.startswith(PROBE_PATHS):
                if path not in out["probes"]:
                    out["probes"].append(path)
                continue
            if not path.startswith(WATCHED_ROOTS):
                continue
            mode = "w" if re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND", args) else "r"
            rec = [path, mode, comm.get(pid, ""), ok]
            if rec not in out["open"]:
                out["open"].append(rec)
                total += 1
        elif call == "connect":
            a = _ADDR.search(args)
            if a is not None:
                rec = [a.group(2) or a.group(4), int(a.group(1) or a.group(3)), comm.get(pid, "")]
                if rec not in out["connect"]:
                    out["connect"].append(rec)
                    total += 1
        elif call in ("unlink", "unlinkat") and ok:
            s = _STR.search(args)
            if s is not None:
                out["unlink"].append(_unescape(s.group(1)))
                total += 1
        elif call in ("rename", "renameat", "renameat2") and ok:
            names = [_unescape(x) for x in _STR.findall(args)]
            if len(names) >= 2:
                out["rename"].append(names[:2])
                total += 1
        elif call == "ptrace":
            out["ptrace"] = out["ptrace"] or "PTRACE_TRACEME" in args or "PTRACE_ATTACH" in args
        elif call == "listen" and ok:
            out["listen"] += 1
    return out


def manifest(roots: list[str], skip: tuple[str, ...] = ()) -> dict[str, list[Any]]:
    """path -> [size, sha256 of the first megabyte] for every regular file under the roots."""
    out: dict[str, list[Any]] = {}
    for root in roots:
        for base, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not os.path.join(base, d).startswith(skip)]
            for name in files:
                path = os.path.join(base, name)
                if path.startswith(skip) or len(out) >= 20000:
                    continue
                try:
                    if os.path.islink(path) or not os.path.isfile(path):
                        out[path] = [0, "link"]
                        continue
                    with open(path, "rb") as fh:
                        out[path] = [os.path.getsize(path), hashlib.sha256(fh.read(1 << 20)).hexdigest()]
                except OSError:
                    continue
    return out


def diff_manifests(before: dict[str, list[Any]], after: dict[str, list[Any]], read: Any = None) -> dict[str, list[Any]]:
    """What a run changed. Created and modified files up to 64 KB carry their text, for the static rules."""
    def entry(path: str) -> dict[str, Any]:
        rec: dict[str, Any] = {"path": path, "size": after[path][0]}
        if read is not None and after[path][0] <= 65536 and after[path][1] != "link":
            data = read(path)
            if data is not None:
                try:
                    rec["text"] = data.decode("utf-8")
                except UnicodeDecodeError:
                    rec["binary"] = True
        return rec

    return {"created": [entry(p) for p in sorted(set(after) - set(before))][:300],
            "modified": [entry(p) for p in sorted(set(after) & set(before)) if after[p] != before[p]][:300],
            "deleted": sorted(set(before) - set(after))[:1000]}


def sample_args(schema: Any) -> dict[str, Any]:
    """Harmless arguments that satisfy a tool's input schema well enough for the call to run."""
    props = schema.get("properties") if isinstance(schema, dict) and isinstance(schema.get("properties"), dict) else {}
    required = schema.get("required") if isinstance(schema, dict) and isinstance(schema.get("required"), list) else list(props)
    out: dict[str, Any] = {}
    for name in required:
        spec = props.get(name) if isinstance(props.get(name), dict) else {}
        kind = spec.get("type")
        if isinstance(spec.get("enum"), list) and spec["enum"]:
            out[name] = spec["enum"][0]
        elif "default" in spec:
            out[name] = spec["default"]
        elif kind in ("integer", "number"):
            out[name] = 1
        elif kind == "boolean":
            out[name] = False
        elif kind == "array":
            out[name] = []
        elif kind == "object":
            out[name] = {}
        else:
            out[name] = "test"
    return out


def fuzz_payloads(marker: str, canary_path: str, token: str) -> list[tuple[str, str]]:
    """(kind, payload) pairs. Each is proven by an effect, not by an error message: a marker file, the decoy
    file's content in the output, or a request arriving at the sinkhole."""
    return [
        ("cmdi", f"x; touch /tmp/.{marker}-fz #"),
        ("cmdi", f"$(touch /tmp/.{marker}-fz)"),
        ("cmdi", f"x' ; touch /tmp/.{marker}-fz ; '"),
        ("traversal", "../" * 8 + canary_path.lstrip("/")),
        ("traversal", canary_path),
        ("ssrf", f"http://{token}.ssrf.test/latest/meta-data/"),
        ("sqli", "x' OR '1'='1' --"),
    ]


SQL_ERRORS = re.compile(r"(?i)sqlite3?\.\w*Error|syntax error at or near|SQLSTATE|unterminated quoted string|near \"[^\"]*\": syntax error|"
                        r"You have an error in your SQL syntax|ORA-\d{5}")


# ----------------------------------------------------------- inside Linux --
def _demote(uid: int, gid: int) -> Any:
    def apply() -> None:
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    return apply


def _write(path: str, content: str, uid: int, gid: int, mode: int = 0o600) -> None:
    parent = os.path.dirname(path)
    made = []
    while parent and not os.path.isdir(parent):
        made.append(parent)
        parent = os.path.dirname(parent)
    for d in reversed(made):
        os.mkdir(d, 0o755)
        os.chown(d, uid, gid)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    os.chmod(path, mode)
    os.chown(path, uid, gid)


def _read(path: str) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read(65536)
    except OSError:
        return None


class Guest:
    def __init__(self, job: dict[str, Any]) -> None:
        self.job = job
        self.uid, self.gid = int(job.get("uid", 1000)), int(job.get("gid", 1000))
        self.home, self.target = job.get("home", "/home/dev"), job.get("target_dir", "/work/target")
        self.marker = job["marker"]
        self.run_dir = "/run/ag"
        self.errors: list[str] = []
        self.strace = shutil.which("strace") is not None
        self.faketime = next((p for p in ("/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
                                          "/usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1") if os.path.exists(p)), None)
        self.deadline = time.time() + float(job.get("total_timeout", 900))
        self.env: dict[str, str] = {}

    # -- environment ----------------------------------------------------------------------------------
    def lay_out(self, tar_bytes: bytes) -> None:
        os.makedirs(self.target, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
            for member in tf.getmembers():
                name = os.path.normpath(member.name)
                if not member.isfile() or name.startswith(("..", "/")):
                    continue
                dest = os.path.join(self.target, name)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as fh:
                    fh.write(tf.extractfile(member).read())            # type: ignore[union-attr]
                os.chmod(dest, 0o755 if name.endswith((".sh", ".py", ".js", ".bash")) or member.mode & 0o111 else 0o644)
        for base, dirs, files in os.walk(os.path.dirname(self.target)):
            for name in dirs + files:
                os.chown(os.path.join(base, name), self.uid, self.gid)
        os.chown(os.path.dirname(self.target), self.uid, self.gid)
        self.honey()

    def honey(self) -> None:
        for path, content in sorted(self.job.get("honey_files", {}).items()):
            try:
                _write(path, content, self.uid, self.gid, 0o644 if "/project/" in path else 0o600)
            except OSError as exc:
                self.errors.append(f"honey {path}: {type(exc).__name__}")
        os.chown(self.home, self.uid, self.gid)

    def network(self) -> dict[str, Any]:
        import sinkhole

        anyip = False
        try:
            subprocess.run(["ip", "link", "set", "lo", "up"], check=False, timeout=10, capture_output=True)
            anyip = subprocess.run(["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo"], check=False, timeout=10,
                                   capture_output=True).returncode == 0
        except (OSError, subprocess.SubprocessError):
            pass
        self.log = sinkhole.Log(os.path.join(self.run_dir, "net.jsonl"))
        state = sinkhole.start(self.log, self.marker, cert_dir=os.path.join(self.run_dir, "ca"),
                               answer_ip=sinkhole.ANSWER_IP if anyip else "127.0.0.1")
        try:
            with open("/etc/resolv.conf", "w", encoding="ascii") as fh:
                fh.write("nameserver 127.0.0.1\noptions timeout:2 attempts:1\n")
            resolv = True
        except OSError:
            resolv = False
        bundle = ""
        if state.get("ca"):
            bundle = "/etc/ssl/certs/ca-certificates.crt"
            try:
                shutil.copyfile(state["ca"], bundle)
                os.chmod(bundle, 0o644)
            except OSError:
                bundle = os.path.join(self.home, ".sandbox-ca.crt")
                shutil.copyfile(state["ca"], bundle)
                os.chown(bundle, self.uid, self.gid)
        self.env = {
            "HOME": self.home, "USER": self.job.get("user", "dev"), "LOGNAME": self.job.get("user", "dev"), "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": self.job.get("lang", "en_US.UTF-8"),
            "TZ": self.job.get("tz", "UTC"), "TERM": "xterm-256color", "PWD": self.target, **self.job.get("env", {}),
        }
        if bundle:
            for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "PIP_CERT"):
                self.env[var] = bundle
        return {"anyip": anyip, "dns": state["dns"], "resolv": resolv, "http": state["http"], "tls": state["tls"], "raw": state["raw"]}

    # -- running --------------------------------------------------------------------------------------
    def command(self, entry: dict[str, Any], trace: str | None) -> list[str]:
        argv = ["/bin/sh", "-c", entry["shell"]] if entry.get("shell") else [str(a) for a in entry["argv"]]
        return ["strace", "-f", "-qq", "-s", "256", "-e", f"trace={TRACE_CALLS}", "-o", trace, "--", *argv] if trace else argv

    def environment(self, variant: dict[str, Any]) -> dict[str, str]:
        env = {**self.env, **{str(k): str(v) for k, v in (variant.get("env") or {}).items()}}
        for name in variant.get("unset") or []:
            env.pop(name, None)
        if variant.get("faketime") and self.faketime:
            env.update({"LD_PRELOAD": self.faketime, "FAKETIME": str(variant["faketime"]), "FAKETIME_DONT_RESET": "1"})
        return env

    def run_entry(self, entry: dict[str, Any], variant: dict[str, Any]) -> dict[str, Any]:
        rec: dict[str, Any] = {"id": entry["id"], "variant": variant.get("name", "base"), "status": "not_run", "start": time.time()}
        if variant.get("faketime") and not self.faketime:
            rec["reason"] = "the clock could not be moved (libfaketime is not in the image)"
            return rec
        budget = min(float(entry.get("timeout", 60)), self.deadline - time.time())
        if budget <= 1:
            rec["reason"] = "the run's time budget was used up before this entry"
            return rec
        self.honey()
        roots = [self.home, os.path.dirname(self.target), "/tmp", "/var/tmp"]
        before = manifest(roots, skip=(self.run_dir,))
        trace = os.path.join(self.run_dir, f"trace.{entry['id']}.{rec['variant']}") if self.strace else None
        if trace:
            open(trace, "w").close()
            os.chown(trace, self.uid, self.gid)
        cwd = os.path.join(self.target, entry.get("cwd", "")) if not os.path.isabs(entry.get("cwd", "")) else entry["cwd"]
        cwd = cwd if os.path.isdir(cwd) else self.target
        try:
            env = {**self.environment(variant), **{str(k): str(v) for k, v in (entry.get("env") or {}).items()}}
            proc = subprocess.Popen(self.command(entry, trace), cwd=cwd, env=env,
                                    stdin=subprocess.PIPE if entry.get("kind") == "mcp" or entry.get("stdin") is not None else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                    preexec_fn=_demote(self.uid, self.gid))
        except OSError as exc:
            rec.update(status="error", reason=f"could not start: {type(exc).__name__}")
            return rec
        out = err = b""
        try:
            if entry.get("kind") == "mcp":
                rec["mcp"] = self.drive_mcp(proc, entry, budget)
                try:
                    proc.stdin.close()                           # type: ignore[union-attr]
                except OSError:
                    pass
                out, err = b"", (proc.stderr.read(MAX_OUTPUT) if self._wait(proc, 3) else b"")   # type: ignore[union-attr]
                rec["status"] = "ok"
            else:
                data = entry["stdin"].encode() if isinstance(entry.get("stdin"), str) else None
                out, err = proc.communicate(data, timeout=budget)
                rec["status"] = "ok"
        except subprocess.TimeoutExpired:
            rec.update(status="timeout", reason=f"still running after {int(budget)} s")
        finally:
            self._kill(proc)
        rec.update(exit=proc.returncode, seconds=round(time.time() - rec["start"], 2), end=time.time(),
                   stdout=out[:MAX_OUTPUT].decode("utf-8", "replace"), stderr=err[:MAX_OUTPUT].decode("utf-8", "replace"))
        if rec["status"] == "ok" and proc.returncode in (126, 127) and entry.get("kind") != "mcp":
            rec.update(status="error", reason="the interpreter or a program it needs is not in the sandbox image")
        if trace:
            try:
                with open(trace, encoding="utf-8", errors="replace") as fh:
                    text = fh.read(8 << 20)
                rec["events"] = parse_trace(text)
                if "ptrace(PTRACE_TRACEME" in text and "Operation not permitted" in text and not rec["events"]["exec"]:
                    rec["events"]["untraced"] = True
                os.unlink(trace)
            except OSError:
                pass
        ran = []
        for kind in ("sh", "py", "js", "md", "fz"):
            flag = f"/tmp/.{self.marker}-{kind}"
            if os.path.exists(flag):
                ran.append(kind)
                os.unlink(flag)
        rec["marker_ran"] = ran
        rec["files"] = diff_manifests(before, manifest(roots, skip=(self.run_dir,)), _read)
        return rec

    @staticmethod
    def _wait(proc: subprocess.Popen, seconds: float) -> bool:
        try:
            proc.wait(timeout=seconds)
            return True
        except subprocess.TimeoutExpired:
            return False

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, 9)
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    # -- MCP over stdio -------------------------------------------------------------------------------
    def drive_mcp(self, proc: subprocess.Popen, entry: dict[str, Any], budget: float) -> dict[str, Any]:
        end = time.time() + budget
        buf = {"data": b""}
        ident = {"n": 0}
        out: dict[str, Any] = {"tools": [], "prompts": [], "resources": [], "tool_results": [], "confirmed": [], "error": ""}

        def rpc(method: str, params: dict[str, Any] | None = None, notify: bool = False, wait: float = 10) -> dict[str, Any] | None:
            msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                msg["params"] = params
            if not notify:
                ident["n"] += 1
                msg["id"] = ident["n"]
            try:
                proc.stdin.write((json.dumps(msg) + "\n").encode())       # type: ignore[union-attr]
                proc.stdin.flush()                                        # type: ignore[union-attr]
            except OSError:
                return None
            if notify:
                return None
            stop = min(end, time.time() + wait)
            while time.time() < stop:
                while b"\n" in buf["data"]:
                    line, _, buf["data"] = buf["data"].partition(b"\n")
                    try:
                        got = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(got, dict) and got.get("id") == ident["n"]:
                        return got
                ready, _, _ = select.select([proc.stdout], [], [], 0.25)
                if ready:
                    chunk = os.read(proc.stdout.fileno(), 65536)          # type: ignore[union-attr]
                    if not chunk:
                        return None
                    buf["data"] += chunk
                    if len(buf["data"]) > (8 << 20):
                        return None
            return None

        client = {"name": "claude-code", "version": "2.1.0"}
        init = rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": client}, wait=20)
        if not init or "result" not in init:
            found = rpc("server/discover", {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                                      "io.modelcontextprotocol/clientInfo": client}}, wait=10)
            if not found or "result" not in found:
                out["error"] = "the server did not answer `initialize` or `server/discover`"
                return out
            init = found
        else:
            rpc("notifications/initialized", notify=True)
        result = init["result"] if isinstance(init.get("result"), dict) else {}
        out["protocol_version"] = result.get("protocolVersion") or "2026-07-28"
        out["server_info"] = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else None
        out["instructions"] = result.get("instructions") if isinstance(result.get("instructions"), str) else None
        for method, key in (("tools/list", "tools"), ("prompts/list", "prompts"), ("resources/list", "resources")):
            got = rpc(method, {})
            items = (got or {}).get("result", {}).get(key) if isinstance((got or {}).get("result"), dict) else None
            out[key] = [x for x in items if isinstance(x, dict)][:200] if isinstance(items, list) else []

        def call(tool: str, args: dict[str, Any]) -> tuple[str, bool]:
            got = rpc("tools/call", {"name": tool, "arguments": args}, wait=15)
            if not got:
                return "", True
            if "error" in got:
                return json.dumps(got["error"])[:4000], True
            res = got.get("result") if isinstance(got.get("result"), dict) else {}
            texts = [c.get("text", "") for c in res.get("content") or [] if isinstance(c, dict) and isinstance(c.get("text"), str)]
            if isinstance(res.get("structuredContent"), (dict, list)):
                texts.append(json.dumps(res["structuredContent"]))
            return "\n".join(texts)[:4000], bool(res.get("isError"))

        canary_path, canary = entry.get("canary_path", ""), entry.get("canary", "")
        for i, tool in enumerate(out["tools"][: int(entry.get("max_tools", 12))]):
            name = tool.get("name")
            if not isinstance(name, str) or time.time() > end - 5:
                break
            schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
            base = sample_args(schema)
            if entry.get("call_tools", True):
                text, is_error = call(name, base)
                if text:
                    out["tool_results"].append({"tool": name, "text": text, "error": is_error})
            if not entry.get("fuzz", True):
                continue
            props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
            strings = [p for p, s in props.items() if not isinstance(s, dict) or s.get("type") in (None, "string")][:4]
            for param in strings:
                token = f"t{i}{strings.index(param)}{self.marker[-6:]}"
                for kind, payload in fuzz_payloads(self.marker, canary_path, token):
                    if time.time() > end - 5:
                        break
                    seen = self.log.count
                    text, _ = call(name, {**base, param: payload})
                    flag = f"/tmp/.{self.marker}-fz"
                    proof = ""
                    if kind == "cmdi" and os.path.exists(flag):
                        os.unlink(flag)
                        proof = "the injected command ran (it created the marker file)"
                    elif kind == "traversal" and canary and canary in text:
                        proof = "the reply contained the decoy file outside the server's directory"
                    elif kind == "ssrf":
                        time.sleep(0.3)
                        if any(token in json.dumps(r) for r in self.log.records[max(0, seen - 1):]):
                            proof = "the server requested the address it was given"
                    elif kind == "sqli" and SQL_ERRORS.search(text):
                        proof = "the reply was a database error caused by the quote"
                    if proof:
                        out["confirmed"].append({"tool": name, "param": param, "kind": kind, "payload": payload[:120], "proof": proof})
                        break
        return out

    # -- the whole run --------------------------------------------------------------------------------
    def run(self, tar_bytes: bytes) -> dict[str, Any]:
        os.makedirs(self.run_dir, exist_ok=True)
        os.chmod(self.run_dir, 0o711)
        self.lay_out(tar_bytes)
        net = self.network()
        result: dict[str, Any] = {"level": "baseline", "strace": self.strace, "faketime": bool(self.faketime), "network_setup": net,
                                  "entries": [], "started": time.time()}
        variants = self.job.get("variants") or [{"name": "base"}]
        lifted = 0
        queue = list(self.job.get("entries", []))
        seen_paths = {e.get("source", {}).get("path") for e in queue}
        while queue:
            entry = queue.pop(0)
            for variant in (variants if entry.get("kind") == "script" and entry.get("vary", True) else variants[:1]):
                rec = self.run_entry(entry, variant)
                result["entries"].append(rec)
                if rec.get("events", {}).get("untraced") and self.strace:
                    self.strace = False                       # tracing is refused here: run the rest untraced, and say so
                    result["strace"] = False
                # Closure lift: a script the run wrote into the target's own directory is run as well.
                for made in rec.get("files", {}).get("created", []) if variant.get("name", "base") == "base" else []:
                    path = made["path"]
                    rel = os.path.relpath(path, self.target)
                    if lifted >= MAX_LIFT or rel.startswith("..") or rel in seen_paths:
                        continue
                    runner = {".sh": ["/bin/sh"], ".bash": ["/bin/bash"], ".py": ["python3"], ".js": ["node"], ".mjs": ["node"]}.get(
                        os.path.splitext(path)[1].lower())
                    if runner:
                        lifted += 1
                        seen_paths.add(rel)
                        queue.append({"id": f"lift{lifted}", "kind": "script", "argv": [*runner, path], "cwd": os.path.dirname(rel),
                                      "timeout": entry.get("timeout", 60), "source": {"path": rel, "line": 1}, "lifted_from": entry["id"],
                                      "vary": False})
                        result.setdefault("lifted", []).append({"id": f"lift{lifted}", "path": rel, "from": entry["id"]})
        time.sleep(0.5)
        result["network"] = list(self.log.records)
        result["network_dropped"] = max(0, self.log.count - len(self.log.records))
        result["errors"] = self.errors
        result["finished"] = time.time()
        return result


def main() -> int:
    line = sys.stdin.buffer.readline(4 << 20)
    try:
        job = json.loads(line)
        nonce = str(job["nonce"])
    except (ValueError, KeyError, TypeError):
        sys.stdout.write("AGRESULT - {\"error\": \"bad job\"}\n")
        return 2
    tar_bytes = sys.stdin.buffer.read()
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        result = Guest(job).run(tar_bytes)
    except Exception as exc:                                  # the host must always get one result line
        result = {"error": f"{type(exc).__name__}: {exc}"[:500], "entries": []}
    sys.stdout.write(f"AGRESULT {nonce} {json.dumps(result, ensure_ascii=True)}\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
