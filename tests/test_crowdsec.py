"""Tests for netwatch_crowdsec.py — the cscli bridge.

Subprocess and shutil.which are stubbed via monkeypatch. No real cscli call
is ever made, no IP is ever banned. The module-level _RECENT dedupe dict is
reset between tests so order-of-execution can't leak state.
"""

import subprocess

import pytest

import netwatch_crowdsec


# ─────────────────────────────────────────────────────────────
#  Shared fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_dedupe(monkeypatch):
    """Wipe the module-level dedupe cache before every test."""
    monkeypatch.setattr(netwatch_crowdsec, "_RECENT", {})


class _RunRecorder:
    """Captures subprocess.run argv and returns a configurable result."""

    def __init__(self, returncode=0, stderr="", raises=None):
        self.calls = []
        self.returncode = returncode
        self.stderr = stderr
        self.raises = raises

    def __call__(self, argv, *args, **kwargs):
        self.calls.append({"argv": argv, "kwargs": kwargs})
        if self.raises is not None:
            raise self.raises
        class _R:
            pass
        r = _R()
        r.returncode = self.returncode
        r.stderr = self.stderr
        r.stdout = ""
        return r


@pytest.fixture
def fake_run(monkeypatch):
    rec = _RunRecorder()
    monkeypatch.setattr(netwatch_crowdsec.subprocess, "run", rec)
    return rec


@pytest.fixture
def cscli_present(monkeypatch):
    monkeypatch.setattr(netwatch_crowdsec.shutil, "which",
                        lambda name: "/usr/bin/cscli" if name == "cscli" else None)


@pytest.fixture
def cscli_absent(monkeypatch):
    monkeypatch.setattr(netwatch_crowdsec.shutil, "which", lambda name: None)


# ─────────────────────────────────────────────────────────────
#  cscli_available
# ─────────────────────────────────────────────────────────────

class TestCscliAvailable:
    def test_true_when_which_returns_path(self, cscli_present):
        assert netwatch_crowdsec.cscli_available() is True

    def test_false_when_which_returns_none(self, cscli_absent):
        assert netwatch_crowdsec.cscli_available() is False


# ─────────────────────────────────────────────────────────────
#  _is_bannable
# ─────────────────────────────────────────────────────────────

class TestIsBannable:
    @pytest.mark.parametrize("ip", [
        "127.0.0.1",         # loopback
        "127.0.0.5",         # loopback range
        "10.0.0.1",          # RFC1918
        "10.255.255.255",    # RFC1918 edge
        "172.16.0.1",        # RFC1918
        "172.31.255.254",    # RFC1918 edge
        "192.168.1.1",       # RFC1918
        "224.0.0.1",         # multicast
        "239.255.255.255",   # multicast edge
        "0.0.0.0",           # unspecified
    ])
    def test_rejects_reserved(self, ip):
        assert netwatch_crowdsec._is_bannable(ip) is False

    @pytest.mark.parametrize("garbage", [
        "",
        "not-an-ip",
        "999.999.999.999",
        "1.2.3",
        None,
        "; rm -rf /",
        "8.8.8.8\n",
    ])
    def test_rejects_garbage(self, garbage):
        assert netwatch_crowdsec._is_bannable(garbage) is False

    @pytest.mark.parametrize("ip", [
        "8.8.8.8",
        "1.1.1.1",
        "203.0.113.42",
    ])
    def test_accepts_public_ipv4(self, ip):
        assert netwatch_crowdsec._is_bannable(ip) is True


# ─────────────────────────────────────────────────────────────
#  _should_dedupe
# ─────────────────────────────────────────────────────────────

class TestShouldDedupe:
    def test_first_call_not_deduped(self):
        assert netwatch_crowdsec._should_dedupe("8.8.8.8") is False

    def test_second_call_within_window_deduped(self):
        netwatch_crowdsec._should_dedupe("8.8.8.8")
        assert netwatch_crowdsec._should_dedupe("8.8.8.8") is True

    def test_different_ips_not_deduped(self):
        netwatch_crowdsec._should_dedupe("8.8.8.8")
        assert netwatch_crowdsec._should_dedupe("1.1.1.1") is False

    def test_call_after_window_not_deduped(self, monkeypatch):
        netwatch_crowdsec._should_dedupe("8.8.8.8")
        # Jump time forward past the window
        real_monotonic = netwatch_crowdsec.time.monotonic
        future = real_monotonic() + netwatch_crowdsec._DEDUPE_WINDOW + 1.0
        monkeypatch.setattr(netwatch_crowdsec.time, "monotonic", lambda: future)
        assert netwatch_crowdsec._should_dedupe("8.8.8.8") is False


# ─────────────────────────────────────────────────────────────
#  cscli_block — argv construction & guard rails
# ─────────────────────────────────────────────────────────────

class TestCscliBlock:
    def test_constructs_correct_argv(self, cscli_present, fake_run):
        ok = netwatch_crowdsec.cscli_block("8.8.8.8", "credential")
        assert ok is True
        assert len(fake_run.calls) == 1
        argv = fake_run.calls[0]["argv"]
        assert argv == [
            "cscli", "decisions", "add",
            "--ip", "8.8.8.8",
            "--duration", "4h",
            "--reason", "netwatch:credential",
            "--type", "ban",
        ]

    def test_no_shell_true(self, cscli_present, fake_run):
        netwatch_crowdsec.cscli_block("8.8.8.8", "credential")
        kwargs = fake_run.calls[0]["kwargs"]
        assert kwargs.get("shell", False) is False
        assert kwargs.get("timeout") == 5

    def test_returns_false_when_cscli_absent(self, cscli_absent, fake_run):
        assert netwatch_crowdsec.cscli_block("8.8.8.8", "credential") is False
        assert fake_run.calls == []

    @pytest.mark.parametrize("ip", [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "224.0.0.1",
        "0.0.0.0",
        "garbage",
    ])
    def test_returns_false_for_unbannable_ip(self, cscli_present, fake_run, ip):
        assert netwatch_crowdsec.cscli_block(ip, "credential") is False
        assert fake_run.calls == []

    def test_sanitizes_malicious_reason(self, cscli_present, fake_run):
        ok = netwatch_crowdsec.cscli_block("8.8.8.8", "x; rm -rf /")
        assert ok is True
        argv = fake_run.calls[0]["argv"]
        # Bad reason was replaced with the fallback before reaching argv
        assert "netwatch:netwatch" in argv
        assert "x; rm -rf /" not in " ".join(argv)
        assert "rm" not in argv

    def test_sanitizes_empty_reason(self, cscli_present, fake_run):
        ok = netwatch_crowdsec.cscli_block("8.8.8.8", "")
        assert ok is True
        argv = fake_run.calls[0]["argv"]
        assert "netwatch:netwatch" in argv

    def test_sanitizes_bad_duration(self, cscli_present, fake_run):
        ok = netwatch_crowdsec.cscli_block("8.8.8.8", "credential", duration="forever")
        assert ok is True
        argv = fake_run.calls[0]["argv"]
        i = argv.index("--duration")
        assert argv[i + 1] == "4h"

    def test_accepts_valid_duration(self, cscli_present, fake_run):
        ok = netwatch_crowdsec.cscli_block("8.8.8.8", "credential", duration="30m")
        assert ok is True
        argv = fake_run.calls[0]["argv"]
        i = argv.index("--duration")
        assert argv[i + 1] == "30m"

    def test_dedupe_blocks_second_call_in_window(self, cscli_present, fake_run):
        a = netwatch_crowdsec.cscli_block("8.8.8.8", "credential")
        b = netwatch_crowdsec.cscli_block("8.8.8.8", "credential")
        assert a is True
        assert b is False
        # Subprocess only invoked once
        assert len(fake_run.calls) == 1

    def test_dedupe_allows_call_after_window(self, cscli_present, fake_run, monkeypatch):
        netwatch_crowdsec.cscli_block("8.8.8.8", "credential")
        real_monotonic = netwatch_crowdsec.time.monotonic
        future = real_monotonic() + netwatch_crowdsec._DEDUPE_WINDOW + 1.0
        monkeypatch.setattr(netwatch_crowdsec.time, "monotonic", lambda: future)
        netwatch_crowdsec.cscli_block("8.8.8.8", "credential")
        assert len(fake_run.calls) == 2

    def test_swallows_timeout(self, cscli_present, monkeypatch):
        rec = _RunRecorder(raises=subprocess.TimeoutExpired(cmd="cscli", timeout=5))
        monkeypatch.setattr(netwatch_crowdsec.subprocess, "run", rec)
        assert netwatch_crowdsec.cscli_block("8.8.8.8", "credential") is False

    def test_swallows_oserror(self, cscli_present, monkeypatch):
        rec = _RunRecorder(raises=OSError("boom"))
        monkeypatch.setattr(netwatch_crowdsec.subprocess, "run", rec)
        assert netwatch_crowdsec.cscli_block("8.8.8.8", "credential") is False

    def test_returns_false_on_nonzero_exit(self, cscli_present, monkeypatch):
        rec = _RunRecorder(returncode=1, stderr="already banned")
        monkeypatch.setattr(netwatch_crowdsec.subprocess, "run", rec)
        assert netwatch_crowdsec.cscli_block("8.8.8.8", "credential") is False


# ─────────────────────────────────────────────────────────────
#  cscli_unblock
# ─────────────────────────────────────────────────────────────

class TestCscliUnblock:
    def test_constructs_correct_argv(self, cscli_present, fake_run):
        ok = netwatch_crowdsec.cscli_unblock("8.8.8.8")
        assert ok is True
        assert fake_run.calls[0]["argv"] == [
            "cscli", "decisions", "delete", "--ip", "8.8.8.8",
        ]

    def test_returns_false_when_cscli_absent(self, cscli_absent, fake_run):
        assert netwatch_crowdsec.cscli_unblock("8.8.8.8") is False
        assert fake_run.calls == []

    def test_returns_false_for_private_ip(self, cscli_present, fake_run):
        assert netwatch_crowdsec.cscli_unblock("192.168.1.1") is False
        assert fake_run.calls == []

    def test_swallows_timeout(self, cscli_present, monkeypatch):
        rec = _RunRecorder(raises=subprocess.TimeoutExpired(cmd="cscli", timeout=5))
        monkeypatch.setattr(netwatch_crowdsec.subprocess, "run", rec)
        assert netwatch_crowdsec.cscli_unblock("8.8.8.8") is False

    def test_swallows_oserror(self, cscli_present, monkeypatch):
        rec = _RunRecorder(raises=OSError("boom"))
        monkeypatch.setattr(netwatch_crowdsec.subprocess, "run", rec)
        assert netwatch_crowdsec.cscli_unblock("8.8.8.8") is False


# ─────────────────────────────────────────────────────────────
#  maybe_defend — service gating
# ─────────────────────────────────────────────────────────────

class TestMaybeDefend:
    def test_noop_for_http(self, cscli_present, fake_run):
        netwatch_crowdsec.maybe_defend("http", "8.8.8.8")
        assert fake_run.calls == []

    @pytest.mark.parametrize("service", [
        "credential", "malware_attempt", "ftp_upload",
        "telnet", "telnet_cmd", "rtsp", "ftp",
    ])
    def test_fires_for_hot_services(self, cscli_present, fake_run, service):
        netwatch_crowdsec.maybe_defend(service, "8.8.8.8")
        assert len(fake_run.calls) == 1
        argv = fake_run.calls[0]["argv"]
        assert f"netwatch:{service}" in argv

    def test_noop_for_unknown_service(self, cscli_present, fake_run):
        netwatch_crowdsec.maybe_defend("unknown_thing", "8.8.8.8")
        assert fake_run.calls == []

    def test_no_action_on_private_even_for_hot_service(self, cscli_present, fake_run):
        netwatch_crowdsec.maybe_defend("credential", "192.168.1.1")
        assert fake_run.calls == []
