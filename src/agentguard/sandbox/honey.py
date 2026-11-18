"""The honey environment (spec/sandbox.md §4): a developer machine with something worth stealing.

Every secret is a canary made for one run: well-formed, unique, and worth nothing. A canary that
later shows up in a request to the sinkhole can only have come from the decoy it was planted in.
Nothing here is ever written to the host: the files exist only inside the container.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field

HOME = "/home/{user}"
PROJECT = "/work/project"
_USERS = ("dev", "alex", "sam", "jordan", "taylor", "morgan")
_HOSTS = ("devbox", "workstation", "laptop-7f2", "build-agent", "mbp-office")
_LOCALES = ("en_US.UTF-8", "en_GB.UTF-8", "de_DE.UTF-8", "pt_BR.UTF-8", "ja_JP.UTF-8")
_ZONES = ("UTC", "America/New_York", "Europe/Berlin", "Asia/Kolkata", "Asia/Tokyo")
_B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")


@dataclass
class Honey:
    user: str
    hostname: str
    lang: str
    tz: str
    files: dict[str, str] = field(default_factory=dict)      # absolute container path -> content
    env: dict[str, str] = field(default_factory=dict)
    canaries: dict[str, str] = field(default_factory=dict)   # canary -> what it is and where it was planted
    reads: dict[str, str] = field(default_factory=dict)      # decoy path -> rule a read of it is evidence for
    owners: dict[str, tuple[str, ...]] = field(default_factory=dict)   # decoy path -> programs expected to read it
    decoys: list[str] = field(default_factory=list)          # ordinary documents (mass delete / rewrite detection)

    @property
    def home(self) -> str:
        return HOME.format(user=self.user)

    def leaked(self, text: str) -> list[tuple[str, str, str]]:
        """(canary, what it is, how it was encoded) for every canary found in `text`, looking through
        base64, hex, URL-encoding, gzip and reversal, because exfiltration code rarely sends a secret as it is."""
        views: list[tuple[str, str]] = [("as it is", text), ("URL-encoded", urllib.parse.unquote_plus(text)), ("reversed", text[::-1]),
                                        ("re-wrapped", re.sub(r"\s+", "", text))]
        for tok in _TOKEN.findall(text)[:200]:
            for decode, how in ((base64.b64decode, "base64"), (base64.urlsafe_b64decode, "base64")):
                try:
                    raw = decode(tok + "=" * (-len(tok) % 4))
                except (binascii.Error, ValueError):
                    continue
                if raw[:2] == b"\x1f\x8b":
                    try:
                        raw, how = gzip.decompress(raw), "gzip, then base64"
                    except (OSError, EOFError):
                        pass
                views.append((how, raw.decode("utf-8", "replace")))
        for tok in _HEX.findall(text)[:100]:
            try:
                views.append(("hex", bytes.fromhex(tok).decode("utf-8", "replace")))
            except ValueError:
                continue
        found: dict[str, tuple[str, str, str]] = {}
        for how, view in views:
            for canary, label in self.canaries.items():
                if canary in view and canary not in found:
                    found[canary] = (canary, label, how)
        return sorted(found.values())


def _rand(seed: bytes, label: str, n: int, alphabet: str = _B62) -> str:
    out, counter = [], 0
    while len(out) < n:
        block = hashlib.sha256(seed + label.encode() + counter.to_bytes(4, "big")).digest()
        out += [alphabet[b % len(alphabet)] for b in block]
        counter += 1
    return "".join(out[:n])


def make_honey(seed: bytes | None = None) -> Honey:
    seed = seed if seed is not None else os.urandom(32)
    pick = lambda items, label: items[int.from_bytes(hashlib.sha256(seed + label.encode()).digest()[:4], "big") % len(items)]  # noqa: E731
    h = Honey(user=pick(_USERS, "user"), hostname=pick(_HOSTS, "host"), lang=pick(_LOCALES, "lang"), tz=pick(_ZONES, "tz"))
    home = h.home

    def canary(label: str, n: int, prefix: str = "", alphabet: str = _B62) -> str:
        value = prefix + _rand(seed, label, n, alphabet)
        h.canaries[value] = label
        return value

    def put(path: str, content: str, rule: str = "", owners: tuple[str, ...] = ()) -> None:
        h.files[path] = content
        if rule:
            h.reads[path] = rule
            h.owners[path] = owners

    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    aws_id = canary("AWS access key id", 16, "AKIA", upper)
    aws_secret = canary("AWS secret access key", 40)
    gh = canary("GitHub token", 36, "ghp_")
    anthropic = canary("Anthropic API key", 86, "sk-ant-api03-")
    openai = canary("OpenAI API key", 48, "sk-proj-")
    npm = canary("npm token", 36, "npm_")
    ssh_body = canary("SSH private key (~/.ssh/id_ed25519)", 280)
    # The key file wraps its body at 70 characters, so the canary is the first line: that is what appears
    # verbatim wherever the file's content goes.
    h.canaries[ssh_body[:70]] = h.canaries.pop(ssh_body)
    key_block ="-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(ssh_body[i:i + 70] for i in range(0, 280, 70)) + \
                "\n-----END OPENSSH PRIVATE KEY-----\n"

    # Developer credentials (a read is evidence for AG-CRED-002 unless the program that owns the file did it).
    cred = "AG-CRED-002"
    put(f"{home}/.ssh/id_ed25519", key_block, cred, ("ssh", "scp", "sftp", "git", "ssh-add", "ssh-agent", "ssh-keygen"))
    put(f"{home}/.ssh/id_ed25519.pub", f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{_rand(seed, 'pub', 43)} {h.user}@{h.hostname}\n")
    put(f"{home}/.ssh/config", "Host github.com\n  IdentityFile ~/.ssh/id_ed25519\n")
    put(f"{home}/.ssh/authorized_keys", "")
    put(f"{home}/.aws/credentials", f"[default]\naws_access_key_id = {aws_id}\naws_secret_access_key = {aws_secret}\n", cred, ("aws",))
    put(f"{home}/.aws/config", "[default]\nregion = eu-west-1\n")
    put(f"{home}/.config/gcloud/application_default_credentials.json", json.dumps({
        "client_id": "32555940559.apps.googleusercontent.com", "client_secret": canary("gcloud client secret", 24, "d-"),
        "refresh_token": canary("gcloud refresh token", 60, "1//0"), "type": "authorized_user"}, indent=2) + "\n", cred, ("gcloud", "gsutil"))
    put(f"{home}/.kube/config", "apiVersion: v1\nkind: Config\nclusters:\n- cluster: {server: https://k8s.internal.example:6443}\n  name: prod\n"
        f"users:\n- name: admin\n  user: {{token: {canary('Kubernetes token', 64)}}}\n", cred, ("kubectl", "helm"))
    put(f"{home}/.npmrc", f"//registry.npmjs.org/:_authToken={npm}\n", cred, ("npm", "npx", "node", "pnpm", "yarn"))
    put(f"{home}/.netrc", f"machine github.com login {h.user} password {canary('netrc password', 30)}\n", cred, ("git", "curl", "wget", "pip", "pip3"))
    put(f"{home}/.git-credentials", f"https://{h.user}:{canary('git credential', 36, 'ghp_')}@github.com\n", cred, ("git",))
    put(f"{home}/.docker/config.json", json.dumps({"auths": {"ghcr.io": {"auth": base64.b64encode(
        f"{h.user}:{canary('Docker registry password', 32)}".encode()).decode()}}}, indent=2) + "\n", cred, ("docker",))
    put(f"{home}/.pypirc", f"[pypi]\nusername = __token__\npassword = {canary('PyPI token', 70, 'pypi-')}\n", cred, ("twine", "pip", "pip3"))

    # The agents' own stores (AG-CRED-003).
    agent = "AG-CRED-003"
    put(f"{home}/.claude.json", json.dumps({"oauthAccount": {"emailAddress": f"{h.user}@example.com"},
                                            "primaryApiKey": canary("Claude Code API key (~/.claude.json)", 86, "sk-ant-api03-")}, indent=2) + "\n",
        agent, ("claude",))
    put(f"{home}/.claude/.credentials.json", json.dumps({"claudeAiOauth": {"accessToken": canary("Claude OAuth access token", 90, "sk-ant-oat01-"),
                                                                            "refreshToken": canary("Claude OAuth refresh token", 90, "sk-ant-ort01-")}}) + "\n",
        agent, ("claude",))
    put(f"{home}/.claude/settings.json", json.dumps({"permissions": {"allow": ["Read"], "deny": []}, "hooks": {}}, indent=2) + "\n")
    put(f"{home}/.claude/CLAUDE.md", "# Personal notes\n\n- Prefer small commits.\n")
    put(f"{home}/.claude/projects/-work-project/memory/MEMORY.md", "# Memory\n\n- The project uses pytest.\n")
    put(f"{home}/.codex/auth.json", json.dumps({"OPENAI_API_KEY": canary("Codex API key (~/.codex/auth.json)", 48, "sk-proj-"),
                                                "tokens": {"refresh_token": canary("Codex refresh token", 60)}}) + "\n", agent, ("codex",))
    put(f"{home}/.codex/config.toml", 'model = "gpt-5"\n')
    put(f"{home}/.gemini/mcp-oauth-tokens.json", json.dumps({"github": {"accessToken": canary("Gemini CLI MCP OAuth token", 40, "gho_")}}) + "\n",
        agent, ("gemini",))
    put(f"{home}/.gemini/settings.json", "{}\n")
    put(f"{home}/.cursor/mcp.json", json.dumps({"mcpServers": {}}) + "\n")

    # Wallets and the browser profile (AG-CRED-004), and the keyring (AG-CRED-005).
    wallet = "AG-CRED-004"
    put(f"{home}/.config/solana/id.json", json.dumps([int(c, 16) for c in _rand(seed, "sol", 64, "0123456789abcdef")]) + "\n", wallet, ("solana",))
    h.canaries[h.files[f"{home}/.config/solana/id.json"].strip()] = "Solana keypair"
    put(f"{home}/.ethereum/keystore/UTC--2026-01-04T10-11-12.000000000Z--{_rand(seed, 'eth', 40, '0123456789abcdef')}",
        json.dumps({"crypto": {"ciphertext": canary("Ethereum keystore", 64, "", "0123456789abcdef"), "kdf": "scrypt"}, "version": 3}) + "\n",
        wallet, ("geth",))
    put(f"{home}/.electrum/wallets/default_wallet", json.dumps({"keystore": {"seed": canary("Electrum wallet seed", 48)}}) + "\n", wallet, ("electrum",))
    put(f"{home}/.config/google-chrome/Default/Login Data", f"SQLite format 3 (decoy) {canary('browser saved password', 32)}\n", wallet, ("chrome",))
    put(f"{home}/.config/google-chrome/Default/Cookies", f"SQLite format 3 (decoy) {canary('browser session cookie', 48)}\n", wallet, ("chrome",))
    put(f"{home}/.local/share/keyrings/login.keyring", f"GnomeKeyring (decoy) {canary('keyring secret', 40)}\n", "AG-CRED-005",
        ("gnome-keyring-daemon", "secret-tool"))

    # Shell profiles: here so that a change to them is seen as a change.
    for name in (".bashrc", ".profile", ".zshrc", ".bash_profile"):
        put(f"{home}/{name}", "# ~/" + name + "\nexport EDITOR=vim\n")

    # A small project with a secret in .env, a CI workflow, a remote and agent files.
    db = canary("database password (project .env)", 28)
    put(f"{PROJECT}/.env", f"DATABASE_URL=postgres://app:{db}@db.internal.example:5432/app\n"
                           f"STRIPE_SECRET_KEY={canary('Stripe secret key (project .env)', 40, 'sk_test_')}\n")
    put(f"{PROJECT}/README.md", "# Orders service\n\nInternal service. Run `make test` before pushing.\n")
    put(f"{PROJECT}/src/app.py", "def total(items):\n    return sum(i['price'] * i['qty'] for i in items)\n")
    put(f"{PROJECT}/tests/test_app.py", "from src.app import total\n\n\ndef test_total():\n    assert total([]) == 0\n")
    put(f"{PROJECT}/.github/workflows/ci.yml", "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
                                                "      - uses: actions/checkout@v4\n      - run: make test\n")
    put(f"{PROJECT}/.git/config", '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:example-org/orders.git\n')
    put(f"{PROJECT}/.git/HEAD", "ref: refs/heads/main\n")
    put(f"{PROJECT}/CLAUDE.md", "# Project notes\n\nUse the repository's Makefile targets.\n")
    put(f"{PROJECT}/.mcp.json", json.dumps({"mcpServers": {}}, indent=2) + "\n")
    put(f"{PROJECT}/data/customers.csv", "id,name,email\n1,Ada,ada@example.com\n2,Lin,lin@example.com\n")
    for i in range(1, 9):
        path = f"{home}/Documents/notes-{i}.txt"
        put(path, f"Meeting notes {i}\n\n- item one\n- item two\n")
        h.decoys.append(path)
    h.decoys += [f"{PROJECT}/README.md", f"{PROJECT}/src/app.py", f"{PROJECT}/tests/test_app.py", f"{PROJECT}/data/customers.csv"]

    h.env = {
        "ANTHROPIC_API_KEY": anthropic, "OPENAI_API_KEY": openai, "GITHUB_TOKEN": gh, "GH_TOKEN": gh,
        "AWS_ACCESS_KEY_ID": aws_id, "AWS_SECRET_ACCESS_KEY": aws_secret, "NPM_TOKEN": npm,
        "SLACK_BOT_TOKEN": canary("Slack bot token", 50, "xoxb-"), "DATABASE_URL": f"postgres://app:{db}@db.internal.example:5432/app",
        "HOSTNAME": h.hostname,
    }
    return h


__all__ = ["HOME", "PROJECT", "Honey", "make_honey"]
