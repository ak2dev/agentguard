"""Test isolation: the suite never reads the developer's own agent files,
configuration or installed rule packs, and never calls a model."""

import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent))

_ISOLATED = pathlib.Path(tempfile.mkdtemp(prefix="agentguard-tests-"))
for _name in ("data", "config", "home"):
    (_ISOLATED / _name).mkdir(parents=True, exist_ok=True)
os.environ["AGENTGUARD_HOME"] = str(_ISOLATED / "data")            # packs, caches, last report, intel
os.environ["AGENTGUARD_CONFIG_HOME"] = str(_ISOLATED / "config")   # user-level config.yml
os.environ["AGENTGUARD_USER_HOME"] = str(_ISOLATED / "home")       # where installed agent components are looked up
os.environ["AGENTGUARD_LLM"] = "off"                               # no model calls from tests
os.environ["AGENTGUARD_CONTEXT"] = "none"                          # no installed context unless a test asks
for _var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "AGENTGUARD_JUDGE_API_KEY"):
    os.environ.pop(_var, None)


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _run_from_an_empty_directory(tmp_path_factory, monkeypatch):
    """Configuration is read from the directory the user runs from. Tests run from
    an empty one, so the repository's own .agentguard.yaml never configures them."""
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))
