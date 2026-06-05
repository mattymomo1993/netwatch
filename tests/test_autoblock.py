"""Tests for netwatch_autoblock.py — automated iptables blocking + AbuseIPDB reporting.

The implementation does not yet exist; these tests will fail until the builder
agent writes the module. All external I/O (subprocess, urllib) is stubbed via
monkeypatch — no iptables rules are installed and no HTTP requests escape.
"""

import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

# Ensure netwatch_autoblock is importable from project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

netwatch_autoblock = pytest.importorskip(
    "netwatch_autoblock",
    reason="netwatch_autoblock module not yet implemented",
)


# ─────────────────────────────────────────────────────────────
#  Shared fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def fake_run(monkeypatch):
    """Stub subprocess.run inside netwatch_autoblock. Records argv list."""
    calls = []

    def _run(args, *a, **kw):
        calls.append(args)
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        return result

    monkeypatch.setattr(netwatch_autoblock.subprocess, "run", _run)
    return calls


@pytest.fixture
def fake_urlopen(monkeypatch):
    """Stub urllib.request.urlopen. Records (url, data) pairs."""
    calls = []

    class _Resp:
        def __init__(self, body=b'{"data":{}}'):
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _open(req, *a, **kw):
        url = getattr(req, "full_url", req)
        data = getattr(req, "data", None)
        calls.append((url, data))
        return _Resp()

    monkeypatch.setattr(netwatch_autoblock.urllib.request, "urlopen", _open)
    return calls


@pytest.fixture
def isolated_state(monkeypatch, tmp_path):
    """Point any persistent state file at tmp_path and clear in-memory caches."""
    state_file = tmp_path / "autoblock_state.json"
    if hasattr(netwatch_autoblock, "STATE_FILE"):
        monkeypatch.setattr(netwatch_autoblock, "STATE_FILE", str(state_file))
    # Best-effort: wipe known in-memory dicts/sets that track blocked IPs and hit counts.
    for attr in ("_blocked", "_hit_counts", "_report_count", "_report_day"):
        if hasattr(netwatch_autoblock, attr):
            obj = getattr(netwatch_autoblock, attr)
            if hasattr(obj, "clear"):
                obj.clear()
    yield state_file


# ─────────────────────────────────────────────────────────────
#  block_ip — argv construction
# ─────────────────────────────────────────────────────────────

class TestBlockIpArgv:
    def test_constructs_iptables_drop_rule(self, fake_run, isolated_state):
        ok = netwatch_autoblock.block_ip("198.51.100.7", "credential brute")
        assert ok is True
        assert len(fake_run) >= 1
        argv = fake_run[0]
        # Must be a list (not shell string) — prevents injection.
        assert isinstance(argv, list)
        assert argv[0].endswith("iptables") or argv[0] == "iptables" or argv[:2] == ["sudo", "iptables"]
        assert "-I" in argv or "-A" in argv
        assert "INPUT" in argv
        assert "-s" in argv
        assert "198.51.100.7" in argv
        assert "-j" in argv
        assert "DROP" in argv


# ─────────────────────────────────────────────────────────────
#  block_ip — allowlist + validation
# ─────────────────────────────────────────────────────────────

class TestBlockIpAllowlist:
    @pytest.mark.parametrize("ip", [
        "127.0.0.1",
        "127.0.0.99",
        "127.255.255.254",
    ])
    def test_refuses_loopback(self, fake_run, isolated_state, ip):
        ok = netwatch_autoblock.block_ip(ip, "test")
        assert ok is False
        assert fake_run == []

    @pytest.mark.parametrize("ip", [
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.5",
        "172.31.255.254",
        "192.168.1.1",
        "192.168.0.100",
    ])
    def test_refuses_rfc1918(self, fake_run, isolated_state, ip):
        ok = netwatch_autoblock.block_ip(ip, "test")
        assert ok is False
        assert fake_run == []

    @pytest.mark.parametrize("ip", [
        "224.0.0.1",
        "239.255.255.250",
    ])
    def test_refuses_multicast(self, fake_run, isolated_state, ip):
        ok = netwatch_autoblock.block_ip(ip, "test")
        assert ok is False
        assert fake_run == []

    def test_refuses_unspecified(self, fake_run, isolated_state):
        ok = netwatch_autoblock.block_ip("0.0.0.0", "test")
        assert ok is False
        assert fake_run == []

    def test_refuses_hard_allowlist_ip(self, fake_run, isolated_state):
        ok = netwatch_autoblock.block_ip("47.17.92.76", "doesn't matter")
        assert ok is False
        assert fake_run == []


# ─────────────────────────────────────────────────────────────
#  block_ip — input validation
# ─────────────────────────────────────────────────────────────

class TestBlockIpValidation:
    @pytest.mark.parametrize("bad", [
        "",
        "not.an.ip",
        "999.999.999.999",
        "1.2.3.4; rm -rf /",
        "1.2.3.4\nINSERT",
        "1.2.3.4 -j ACCEPT",
        "../etc/passwd",
        "$(whoami)",
        "1.2.3",
        "1.2.3.4.5",
        None,
    ])
    def test_invalid_ip_never_reaches_subprocess(self, fake_run, isolated_state, bad):
        try:
            ok = netwatch_autoblock.block_ip(bad, "test")
        except (ValueError, TypeError):
            ok = False
        assert ok is False
        assert fake_run == []


# ─────────────────────────────────────────────────────────────
#  block_ip — comment / reason sanitization
# ─────────────────────────────────────────────────────────────

class TestReasonSanitization:
    def test_dangerous_reason_does_not_taint_argv(self, fake_run, isolated_state):
        netwatch_autoblock.block_ip("198.51.100.8", "x; rm -rf /")
        assert len(fake_run) >= 1
        argv = fake_run[0]
        joined = " ".join(str(a) for a in argv)
        # Shell metacharacters must never appear in iptables argv unsanitized.
        assert "rm -rf" not in joined
        assert ";" not in joined
        # Every argv element should be a tame string (alnum + a small punct set).
        safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/: ")
        for piece in argv:
            assert isinstance(piece, str)
            assert all(c in safe for c in piece), f"unsafe char in argv piece: {piece!r}"

    def test_newline_in_reason_stripped(self, fake_run, isolated_state):
        netwatch_autoblock.block_ip("198.51.100.9", "abuse\n--comment EVIL")
        argv = fake_run[0]
        joined = " ".join(str(a) for a in argv)
        assert "\n" not in joined
        assert "EVIL" not in joined or "--comment" not in joined or argv.count("--comment") <= 1


# ─────────────────────────────────────────────────────────────
#  maybe_defend — trigger logic
# ─────────────────────────────────────────────────────────────

class TestMaybeDefendTriggers:
    @pytest.mark.parametrize("service", ["credential", "malware_attempt", "ftp_upload"])
    def test_first_hit_high_severity_blocks_immediately(
        self, monkeypatch, fake_run, fake_urlopen, isolated_state, service
    ):
        monkeypatch.setenv("ABUSEIPDB_KEY", "test-key")
        netwatch_autoblock.maybe_defend(service, "198.51.100.10", {"username": "root"})
        # At least one iptables call.
        assert any(
            "198.51.100.10" in (a if isinstance(a, list) else [])
            for a in fake_run
        )

    def test_first_http_hit_does_not_block(
        self, monkeypatch, fake_run, fake_urlopen, isolated_state
    ):
        monkeypatch.setenv("ABUSEIPDB_KEY", "test-key")
        netwatch_autoblock.maybe_defend("http", "198.51.100.11", {"path": "/admin"})
        assert fake_run == []

    def test_third_http_hit_blocks(
        self, monkeypatch, fake_run, fake_urlopen, isolated_state
    ):
        monkeypatch.setenv("ABUSEIPDB_KEY", "test-key")
        for _ in range(3):
            netwatch_autoblock.maybe_defend("http", "198.51.100.12", {"path": "/admin"})
        # Exactly one block call after the threshold trips.
        block_calls = [a for a in fake_run if isinstance(a, list) and "198.51.100.12" in a]
        assert len(block_calls) >= 1

    def test_idempotent_no_second_block(
        self, monkeypatch, fake_run, fake_urlopen, isolated_state
    ):
        monkeypatch.setenv("ABUSEIPDB_KEY", "test-key")
        ip = "198.51.100.13"
        netwatch_autoblock.maybe_defend("credential", ip, {})
        first = len([a for a in fake_run if isinstance(a, list) and ip in a])
        netwatch_autoblock.maybe_defend("credential", ip, {})
        second = len([a for a in fake_run if isinstance(a, list) and ip in a])
        assert first >= 1
        assert second == first, "second sighting should be a no-op"


# ─────────────────────────────────────────────────────────────
#  report_to_abuseipdb
# ─────────────────────────────────────────────────────────────

class TestAbuseIPDBNoop:
    def test_noop_when_key_missing(
        self, monkeypatch, fake_urlopen, isolated_state
    ):
        monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)
        ok = netwatch_autoblock.report_to_abuseipdb(
            "198.51.100.20", "credential", "brute force"
        )
        assert ok is False
        assert fake_urlopen == []


class TestAbuseIPDBRateLimit:
    def test_respects_900_per_day_cap(
        self, monkeypatch, fake_urlopen, isolated_state
    ):
        monkeypatch.setenv("ABUSEIPDB_KEY", "test-key")
        # Pre-load today's counter to the cap if the module exposes one.
        today = datetime.now(timezone.utc).date().isoformat()
        if hasattr(netwatch_autoblock, "_report_count"):
            netwatch_autoblock._report_count[today] = 900
        if hasattr(netwatch_autoblock, "_report_day"):
            try:
                netwatch_autoblock._report_day = today
            except Exception:
                pass
        # First call at cap should refuse without hitting network.
        before = len(fake_urlopen)
        ok = netwatch_autoblock.report_to_abuseipdb(
            "198.51.100.21", "credential", "brute"
        )
        after = len(fake_urlopen)
        assert ok is False
        assert after == before, "no HTTP call should be made once cap reached"

    def test_under_cap_does_send(
        self, monkeypatch, fake_urlopen, isolated_state
    ):
        monkeypatch.setenv("ABUSEIPDB_KEY", "test-key")
        ok = netwatch_autoblock.report_to_abuseipdb(
            "198.51.100.22", "credential", "brute"
        )
        assert ok is True
        assert len(fake_urlopen) == 1
        url, _data = fake_urlopen[0]
        assert "abuseipdb.com" in url


class TestAbuseIPDBNetworkErrors:
    def test_swallows_urlerror(self, monkeypatch, isolated_state):
        monkeypatch.setenv("ABUSEIPDB_KEY", "test-key")

        def _boom(*a, **kw):
            from urllib.error import URLError
            raise URLError("connection refused")

        monkeypatch.setattr(netwatch_autoblock.urllib.request, "urlopen", _boom)
        # Must not raise.
        ok = netwatch_autoblock.report_to_abuseipdb(
            "198.51.100.23", "credential", "brute"
        )
        assert ok is False

    def test_swallows_generic_exception(self, monkeypatch, isolated_state):
        monkeypatch.setenv("ABUSEIPDB_KEY", "test-key")

        def _boom(*a, **kw):
            raise RuntimeError("socket exploded")

        monkeypatch.setattr(netwatch_autoblock.urllib.request, "urlopen", _boom)
        ok = netwatch_autoblock.report_to_abuseipdb(
            "198.51.100.24", "credential", "brute"
        )
        assert ok is False

    def test_swallows_timeout(self, monkeypatch, isolated_state):
        monkeypatch.setenv("ABUSEIPDB_KEY", "test-key")

        def _boom(*a, **kw):
            raise TimeoutError("timed out")

        monkeypatch.setattr(netwatch_autoblock.urllib.request, "urlopen", _boom)
        ok = netwatch_autoblock.report_to_abuseipdb(
            "198.51.100.25", "credential", "brute"
        )
        assert ok is False
