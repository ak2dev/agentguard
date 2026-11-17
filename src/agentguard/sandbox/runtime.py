"""The container side of the dynamic tier (spec/sandbox.md §3).

One disposable container per run, with:

* no network interface but loopback (`--network none`), so there is no route to the internet at all;
  every address the target tries is routed to the sinkhole inside the same container;
* nothing from the host mounted: no home directory, no environment, no Docker socket. The target and
  the job travel in over stdin and the result comes back over stdout;
* a read-only root filesystem with small in-memory work directories, every capability dropped except
  the few the harness needs to set up routing and then drop to an unprivileged user, no new privileges,
  and CPU, memory and process limits.

Docker is the only program Agent Guard ever starts, and only through `guard.allow_exact` with the
exact argument list built here. If Docker is not available the tier refuses to run; it never falls back
to the host.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..io import guard

IMAGE_REPO = "agentguard-sandbox"
HERE = Path(__file__).parent
GUEST_FILES = ("guest/harness.py", "guest/sinkhole.py")
CAPABILITIES = ("SETUID", "SETGID", "CHOWN", "DAC_OVERRIDE", "FOWNER", "KILL", "NET_ADMIN", "NET_BIND_SERVICE")
MAX_RESULT = 64 * 1024 * 1024


class SandboxUnavailable(RuntimeError):
    """The sandbox cannot run here. Nothing was executed."""


def _exec(argv: list[str], *, data: bytes | None = None, timeout: float = 120) -> subprocess.CompletedProcess[bytes]:
    """Start exactly this command. The no-execution guard refuses everything else."""
    with guard.allow_exact(argv):
        return subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)


def image_tag() -> str:
    """The image is named after the content it is built from, so a changed harness is never run from a stale image."""
    h = hashlib.sha256()
    for rel in ("image/Dockerfile", *GUEST_FILES):
        h.update(rel.encode() + b"\0" + (HERE / rel).read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return f"{IMAGE_REPO}:{h.hexdigest()[:16]}"


def docker_status(docker: str | None = None) -> dict[str, Any]:
    """Whether the dynamic tier can run here and at which level (used by `agentguard doctor`)."""
    exe = docker or shutil.which("docker")
    enhanced = ("the enhanced level (eBPF tracing and FUSE secret markers on a Linux host that allows privileged containers) "
                "is not part of this build; runs use the baseline level and are labelled as such")
    if not exe:
        return {"available": False, "level": "none", "detail": "docker was not found on PATH", "level_detail": enhanced, "image": ""}
    try:
        proc = _exec([exe, "version", "--format", "{{json .}}"], timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "level": "none", "detail": f"docker could not be started ({type(exc).__name__})",
                "level_detail": enhanced, "image": ""}
    try:
        info = json.loads(proc.stdout.decode("utf-8", "replace") or "{}")
    except ValueError:
        info = {}
    server = info.get("Server") if isinstance(info, dict) else None
    if proc.returncode != 0 or not isinstance(server, dict):
        return {"available": False, "level": "none", "level_detail": enhanced, "image": "",
                "detail": f"docker is installed ({exe}) but its daemon is not running; start Docker Desktop or the docker service"}
    tag = image_tag()
    try:
        built = _exec([exe, "image", "inspect", "--format", "{{.Id}}", tag], timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        built = False
    return {"available": True, "level": "baseline", "image": tag, "image_built": built,
            "detail": f"Docker {server.get('Version', '?')} ({server.get('Os', '?')}/{server.get('Arch', '?')}); sandbox image "
                      + (f"{tag} is built" if built else f"{tag} will be built on first use (needs the network once)"),
            "level_detail": "baseline: strace, file-change comparison and an in-container sinkhole. " + enhanced[0].upper() + enhanced[1:]}


class DockerRuntime:
    level = "baseline"

    def __init__(self, docker: str | None = None, *, memory: str = "1g", cpus: str = "2", pids: int = 256) -> None:
        exe = docker or shutil.which("docker")
        if not exe:
            raise SandboxUnavailable("docker was not found on PATH")
        self.docker, self.memory, self.cpus, self.pids = exe, memory, cpus, pids
        self.tag = image_tag()

    # -- image ----------------------------------------------------------------------------------------
    def ensure_image(self) -> None:
        try:
            if _exec([self.docker, "image", "inspect", "--format", "{{.Id}}", self.tag], timeout=30).returncode == 0:
                return
            proc = _exec([self.docker, "build", "--quiet", "--tag", self.tag, "--file", str(HERE / "image" / "Dockerfile"), str(HERE)],
                         timeout=1800)
        except subprocess.TimeoutExpired as exc:
            raise SandboxUnavailable("building the sandbox image timed out") from exc
        except OSError as exc:
            raise SandboxUnavailable(f"docker could not be started ({type(exc).__name__})") from exc
        if proc.returncode != 0:
            tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
            raise SandboxUnavailable("the sandbox image could not be built (the first build needs the network): " + " | ".join(tail)[:400])

    def run_args(self, name: str, hostname: str) -> list[str]:
        """The exact `docker run` command. Nothing from the host is mounted and no host environment is passed."""
        args = [self.docker, "run", "--rm", "--interactive", "--name", name, "--hostname", hostname,
                "--network", "none", "--read-only", "--cap-drop", "ALL"]
        for cap in CAPABILITIES:
            args += ["--cap-add", cap]
        args += ["--security-opt", "no-new-privileges", "--pids-limit", str(self.pids), "--memory", self.memory,
                 "--memory-swap", self.memory, "--cpus", self.cpus, "--ulimit", "nofile=4096:4096", "--ulimit", "core=0",
                 "--tmpfs", "/work:rw,exec,nosuid,size=384m,mode=0755", "--tmpfs", "/home:rw,exec,nosuid,size=96m,mode=0755",
                 "--tmpfs", "/tmp:rw,exec,nosuid,size=192m,mode=1777", "--tmpfs", "/var/tmp:rw,nosuid,size=32m,mode=1777",
                 "--tmpfs", "/run/ag:rw,nosuid,size=96m,mode=0700", "--tmpfs", "/etc/ssl/certs:rw,nosuid,size=4m,mode=0755",
                 "--workdir", "/work", self.tag, "python3", "/opt/agentguard/harness.py"]
        return args

    # -- runs -----------------------------------------------------------------------------------------
    def run(self, job: dict[str, Any], tar: bytes) -> dict[str, Any]:
        """Run one job in a fresh container and return what the harness reported."""
        self.ensure_image()
        nonce = str(job["nonce"])
        name = f"agentguard-sbx-{nonce[:16]}"
        frame = json.dumps(job, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n" + tar
        budget = float(job.get("total_timeout", 900)) + 60
        try:
            proc = _exec(self.run_args(name, str(job.get("hostname") or "devbox")), data=frame, timeout=budget)
        except subprocess.TimeoutExpired:
            try:
                _exec([self.docker, "kill", name], timeout=30)
            except (OSError, subprocess.SubprocessError):
                pass
            return {"error": f"the container was still running after {int(budget)} s and was killed", "entries": []}
        except OSError as exc:
            raise SandboxUnavailable(f"docker could not be started ({type(exc).__name__})") from exc
        return parse_result(proc.stdout, nonce, proc.returncode, proc.stderr)

    def enumerate_server(self, argv: list[str], cwd: Path | None = None) -> dict[str, Any]:
        """Start a local MCP server given by its command inside the sandbox and record what it serves. Files the
        command names under `cwd` are copied in; nothing else from the host is."""
        from ..core.models import ScanOptions
        from ..core.tree import ArtifactTree
        from ..io.fs_loader import load_path
        from . import new_ids
        from .honey import make_honey
        from .plan import TARGET_DIR, tar_of

        tree = ArtifactTree()
        mapped = list(argv)
        base = (cwd or Path.cwd()).resolve()
        for i, arg in enumerate(argv[1:], start=1):
            if arg.startswith("-"):
                continue
            candidate = (base / arg).resolve() if not os.path.isabs(arg) else Path(arg)
            if candidate.is_file() and candidate.is_relative_to(base):
                limits = ScanOptions().limits
                loaded = load_path(candidate.parent, limits)
                rel_dir = candidate.parent.relative_to(base).as_posix()
                for path, blob in loaded.files.items():
                    tree.add(f"{rel_dir}/{path}".lstrip("./"), blob.data, limits)
                mapped[i] = f"{TARGET_DIR}/{candidate.relative_to(base).as_posix()}"
        if os.path.basename(mapped[0]).lower() in ("python", "py", "python.exe"):
            mapped[0] = "python3"
        honey = make_honey()
        nonce, marker = new_ids()
        canary = next((c for c, label in honey.canaries.items() if label.startswith("SSH private key")), "")
        job = {"nonce": nonce, "marker": marker, "target_dir": TARGET_DIR, "home": honey.home, "user": honey.user, "hostname": honey.hostname,
               "lang": honey.lang, "tz": honey.tz, "uid": 1000, "gid": 1000, "honey_files": honey.files, "env": honey.env,
               "variants": [{"name": "base"}], "total_timeout": 240,
               "entries": [{"id": "e1", "kind": "mcp", "argv": mapped, "cwd": "", "timeout": 180, "call_tools": True, "fuzz": False,
                            "canary_path": f"{honey.home}/.ssh/id_ed25519", "canary": canary[:70], "source": {"path": "", "line": 1}}]}
        result = self.run(job, tar_of(tree))
        entry = next((e for e in result.get("entries", []) if isinstance(e, dict) and isinstance(e.get("mcp"), dict)), None)
        if entry is None:
            reason = result.get("error") or next((e.get("reason") for e in result.get("entries", []) if isinstance(e, dict)), "") or "no answer"
            return {"error": str(reason)[:300], "level": self.level}
        return {**entry["mcp"], "level": self.level}


def parse_result(stdout: bytes, nonce: str, returncode: int = 0, stderr: bytes = b"") -> dict[str, Any]:
    """The harness's one result line. Everything else the container printed is ignored: it is untrusted."""
    if len(stdout) > MAX_RESULT:
        return {"error": "the container produced more output than the limit allows", "entries": []}
    prefix = f"AGRESULT {nonce} ".encode("ascii")
    for line in reversed(stdout.splitlines()):
        if line.startswith(prefix):
            try:
                doc = json.loads(line[len(prefix):])
            except ValueError:
                break
            if isinstance(doc, dict):
                return doc
            break
    tail = stderr.decode("utf-8", "replace").strip().splitlines()[-2:]
    return {"error": f"the container ended without a result (exit code {returncode})" + (": " + " | ".join(tail)[:300] if tail else ""),
            "entries": []}


def default_runtime() -> DockerRuntime:
    status = docker_status()
    if not status["available"]:
        raise SandboxUnavailable(status["detail"])
    return DockerRuntime()


__all__ = ["CAPABILITIES", "DockerRuntime", "SandboxUnavailable", "default_runtime", "docker_status", "image_tag", "parse_result"]
