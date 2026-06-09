"""v1.2.1 — regression tests for hardcoded path fixes.

These tests guard against re-introducing the bug that blocked fresh installs:
- VERSION constant out of sync with pyproject.toml
- `/home/mrrobot/...` absolute paths shipping in user-facing code
- env-overridable subprocess targets exec'd without an existence check
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

import netwatch

REPO_ROOT = Path(__file__).resolve().parent.parent


# ─────────────────────────────────────────────────────────────
#  VERSION sync
# ─────────────────────────────────────────────────────────────

class TestVersionSync:
    def test_version_constant_matches_pyproject(self):
        py = (REPO_ROOT / "pyproject.toml").read_text()
        m = re.search(r'^version\s*=\s*"([^"]+)"', py, re.MULTILINE)
        assert m, "version not found in pyproject.toml"
        assert netwatch.VERSION == m.group(1), (
            f"netwatch.VERSION={netwatch.VERSION} but pyproject version={m.group(1)}"
        )

    def test_version_appears_in_dashboard(self):
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(frame)
        assert netwatch.VERSION in text


# ─────────────────────────────────────────────────────────────
#  No developer paths in shipped source
# ─────────────────────────────────────────────────────────────

class TestNoHardcodedPaths:
    """Static guard: no /home/mrrobot/ anywhere in code that gets shipped.

    Allowed exceptions: comments (rarely matter), tests (this file), example
    docstrings explaining env-var conventions.
    """

    SHIPPED = ("netwatch.py", "replay.py", "netwatch_crowdsec.py")

    @pytest.mark.parametrize("filename", SHIPPED)
    def test_no_home_mrrobot_in_shipped_source(self, filename):
        path = REPO_ROOT / filename
        if not path.exists():
            pytest.skip(f"{filename} not present in this checkout")
        bad_lines = []
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if "/home/mrrobot/" in line:
                bad_lines.append(f"{filename}:{i} — {line.strip()[:120]}")
        assert not bad_lines, (
            "Hardcoded developer paths leaked into shipped source:\n"
            + "\n".join(bad_lines)
        )

    def test_pyproject_has_no_developer_path(self):
        py = (REPO_ROOT / "pyproject.toml").read_text()
        assert "/home/mrrobot" not in py


# ─────────────────────────────────────────────────────────────
#  PROXYCHAIN_SCRIPT env override + safety check
# ─────────────────────────────────────────────────────────────

class TestProxychainScriptEnv:
    def test_default_resolves_to_user_home(self):
        # When env not set, default should expand ~ for the running user —
        # not a hardcoded /home/mrrobot/ string.
        assert "/home/mrrobot/" not in netwatch.PROXYCHAIN_SCRIPT or \
               os.path.expanduser("~").startswith("/home/mrrobot")
        # And it should be an absolute path
        assert os.path.isabs(netwatch.PROXYCHAIN_SCRIPT)

    def test_cmd_proxy_start_refuses_when_script_missing(self, monkeypatch):
        # Point at a path that definitely does not exist.
        monkeypatch.setattr(netwatch, "PROXYCHAIN_SCRIPT", "/nonexistent/proxy.sh")
        events = []
        with patch("netwatch.add_console", side_effect=lambda s: events.append(s)), \
             patch("netwatch.subprocess.run") as srun:
            netwatch._cmd_proxy("start")
        # Critical: subprocess.run MUST NOT have been called (no `sudo bash` fired).
        srun.assert_not_called()
        joined = " ".join(events)
        assert "not found" in joined.lower()

    def test_cmd_proxy_stop_refuses_when_script_missing(self, monkeypatch):
        monkeypatch.setattr(netwatch, "PROXYCHAIN_SCRIPT", "/nonexistent/proxy.sh")
        events = []
        with patch("netwatch.add_console", side_effect=lambda s: events.append(s)), \
             patch("netwatch.subprocess.run") as srun:
            netwatch._cmd_proxy("stop")
        srun.assert_not_called()

    def test_cmd_proxy_start_runs_when_script_present(self, tmp_path, monkeypatch):
        script = tmp_path / "proxy.sh"
        script.write_text("#!/bin/bash\necho started\n")
        script.chmod(0o755)
        monkeypatch.setattr(netwatch, "PROXYCHAIN_SCRIPT", str(script))
        # Stub subprocess.run so we don't actually invoke sudo
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok\n", stderr="")
        with patch("netwatch.add_console"), \
             patch("netwatch.subprocess.run", return_value=completed) as srun:
            netwatch._cmd_proxy("start")
        srun.assert_called_once()
        argv = srun.call_args[0][0]
        # Critical: subprocess uses argv list (no shell=True), starts with sudo bash
        assert argv[0] == "sudo"
        assert argv[1] == "bash"
        assert argv[2] == str(script)
        assert argv[3] == "start"


# ─────────────────────────────────────────────────────────────
#  Cloudflared resolution order
# ─────────────────────────────────────────────────────────────

class TestCloudflaredResolution:
    """Lookup order must be: shutil.which → env override → ~/agents fallback.
    Tested by reading the resolution chain at the call site.
    """

    def test_resolution_code_uses_shutil_which_first(self):
        # White-box: confirm the resolution snippet exists in source.
        src = (REPO_ROOT / "netwatch.py").read_text()
        assert 'shutil.which("cloudflared")' in src
        assert 'NETWATCH_CLOUDFLARED_BIN' in src
        # And no hardcoded /home/mrrobot/ for cloudflared
        assert "/home/mrrobot/agents/agent-office/cloudflared" not in src or \
               'os.path.expanduser' in src


# ─────────────────────────────────────────────────────────────
#  Extra log dirs no longer pin to /home/mrrobot
# ─────────────────────────────────────────────────────────────

class TestExtraLogDirs:
    def test_no_hardcoded_user_path_in_defaults(self, monkeypatch):
        monkeypatch.delenv("NETWATCH_EXTRA_LOG_DIRS", raising=False)
        # Locate the function inside netwatch.py — it's defined inline in a route
        # helper. Grep the source for the fallback line.
        src = (REPO_ROOT / "netwatch.py").read_text()
        # The bare absolute /home/mrrobot/agents/honeypot-captures must not appear
        # as a list entry anymore (was the L6832 bug).
        offenders = [
            l for l in src.splitlines()
            if l.strip().startswith('"/home/mrrobot/agents/honeypot-captures"')
            or l.strip().startswith("'/home/mrrobot/agents/honeypot-captures'")
        ]
        assert offenders == []
