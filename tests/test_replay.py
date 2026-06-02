"""Tests for replay.py — the session-replay data layer."""

import json
import os
import time
from datetime import datetime, timezone

import pytest

import replay


# ─────────────────────────────────────────────────────────────
#  session_id validation
# ─────────────────────────────────────────────────────────────

class TestSessionIdValidation:
    @pytest.mark.parametrize("sid", [
        "127.0.0.1_093945",
        "192.0.2.4_120000",
        "2001:db8::1_235959",
        "abc:def::1_000000",
    ])
    def test_accepts_valid_ids(self, sid):
        replay._validate_session_id(sid)  # no raise

    @pytest.mark.parametrize("sid", [
        "",
        None,
        "../etc/passwd_093945",
        "127.0.0.1",            # missing suffix
        "127.0.0.1_9394",       # too few digits
        "127.0.0.1_0939455",    # too many digits
        "; rm -rf /_093945",
        "127.0.0.1_093945\n",   # newline
    ])
    def test_rejects_invalid_ids(self, sid):
        with pytest.raises(ValueError):
            replay._validate_session_id(sid)


# ─────────────────────────────────────────────────────────────
#  log-line parser (modern + legacy)
# ─────────────────────────────────────────────────────────────

class TestParseLogLine:
    def test_modern_json_line(self):
        line = '{"ts": "01:46:38.413", "dir": "SERVER", "data": "220 ready"}'
        ts, d, data = replay._parse_log_line(line)
        assert ts == "01:46:38.413"
        assert d == "SERVER"
        assert data == "220 ready"

    def test_legacy_bracket_line(self):
        line = "[09:39:45.601] SERVER: 220 banner sent"
        ts, d, data = replay._parse_log_line(line)
        assert ts == "09:39:45.601"
        assert d == "SERVER"
        assert data == "220 banner sent"

    def test_empty_line(self):
        assert replay._parse_log_line("") is None
        assert replay._parse_log_line("\n") is None
        assert replay._parse_log_line("   ") is None

    def test_malformed_json(self):
        assert replay._parse_log_line('{"ts": invalid}') is None

    def test_garbage_line(self):
        assert replay._parse_log_line("not a real log entry") is None


# ─────────────────────────────────────────────────────────────
#  replay_loader — end-to-end timeline assembly
# ─────────────────────────────────────────────────────────────

class TestReplayLoader:
    @pytest.fixture
    def session_log(self, tmp_path):
        sid = "192.0.2.4_120000"
        path = tmp_path / f"ftp_session_{sid}.log"
        # Patched ftp_log() output: monotonic times, CLIENT + SERVER alternation
        lines = [
            '{"ts": "12:00:00.000", "dir": "SERVER", "data": "220 NVR-4200 ready"}',
            '{"ts": "12:00:00.500", "dir": "CLIENT", "data": "USER admin"}',
            '{"ts": "12:00:00.510", "dir": "SERVER", "data": "331 Password required"}',
            '{"ts": "12:00:02.100", "dir": "CLIENT", "data": "PASS hunter2"}',
            '{"ts": "12:00:02.111", "dir": "CRED",   "data": "USER=admin PASS=hunter2"}',
            '{"ts": "12:00:02.115", "dir": "SERVER", "data": "230 Login successful"}',
        ]
        path.write_text("\n".join(lines) + "\n")
        return sid, str(tmp_path), path

    def test_unified_timeline_shape(self, session_log):
        sid, log_dir, _ = session_log
        result = replay.replay_loader(sid, log_dir=log_dir)
        assert result["session_id"] == sid
        assert result["ip"] == "192.0.2.4"
        assert result["duration_ms"] == 2115  # last - first
        assert len(result["events"]) == 6
        assert result["events"][0]["t_ms"] == 0
        assert result["events"][0]["kind"] == "server"  # lowercased
        assert result["events"][-1]["t_ms"] == 2115
        assert result["started_at"].endswith("+00:00")
        assert result["ended_at"].endswith("+00:00")

    def test_events_are_chronologically_ordered(self, session_log):
        sid, log_dir, _ = session_log
        result = replay.replay_loader(sid, log_dir=log_dir)
        ts_list = [e["t_ms"] for e in result["events"]]
        assert ts_list == sorted(ts_list)

    def test_missing_session_log_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            replay.replay_loader("10.0.0.1_120000", log_dir=str(tmp_path))

    def test_invalid_session_id_raises(self, tmp_path):
        with pytest.raises(ValueError):
            replay.replay_loader("../etc/passwd_120000", log_dir=str(tmp_path))

    def test_legacy_format_log_still_parses(self, tmp_path):
        sid = "127.0.0.1_093945"
        path = tmp_path / f"ftp_session_{sid}.log"
        path.write_text(
            "[09:39:45.601] SERVER: 220 banner sent\n"
            "[09:39:45.601] CLIENT: LIST\n"
            "[09:39:45.602] SESSION_END: total session logged to /tmp/foo\n"
        )
        result = replay.replay_loader(sid, log_dir=str(tmp_path))
        assert len(result["events"]) == 3
        assert result["events"][0]["kind"] == "server"
        assert result["events"][1]["kind"] == "client"


# ─────────────────────────────────────────────────────────────
#  replay_index — directory scan + cache
# ─────────────────────────────────────────────────────────────

class TestReplayIndex:
    def test_scan_finds_sessions(self, tmp_path):
        for sid in ("192.0.2.4_120000", "10.0.0.1_113000"):
            (tmp_path / f"ftp_session_{sid}.log").write_text(
                '{"ts": "12:00:00.000", "dir": "SERVER", "data": "x"}\n')
        # Decoy non-matching files should be ignored
        (tmp_path / "ftp_session_garbage.log").write_text("nope")
        (tmp_path / "random.json").write_text("{}")

        # bypass cache: pass distinct log_dir
        idx = replay.replay_index(log_dir=str(tmp_path))
        sids = sorted(r["session_id"] for r in idx)
        assert sids == ["10.0.0.1_113000", "192.0.2.4_120000"]
        assert all("size_bytes" in r for r in idx)

    def test_empty_dir_returns_empty(self, tmp_path):
        # A fresh tmp_path => empty list, no crash
        assert replay.replay_index(log_dir=str(tmp_path)) == []

    def test_cache_hit_returns_same_object(self, tmp_path):
        (tmp_path / "ftp_session_192.0.2.4_120000.log").write_text("x")
        a = replay.replay_index(log_dir=str(tmp_path))
        b = replay.replay_index(log_dir=str(tmp_path))
        assert a is b  # same cached object, no re-walk


# ─────────────────────────────────────────────────────────────
#  load_intel — passive OSINT lookup
# ─────────────────────────────────────────────────────────────

class TestLoadIntel:
    def test_missing_recon_returns_empty(self, tmp_path):
        assert replay.load_intel("198.51.100.7", log_dir=str(tmp_path)) == {}

    def test_reads_recon_file(self, tmp_path):
        ip = "203.0.113.42"
        (tmp_path / "recon_203_0_113_42.json").write_text(json.dumps({
            "country": "RU",
            "city": "Moscow",
            "asn": "AS12345",
            "org": "Example Telecom",
            "abuse_score": 87,
            "tags": ["bruteforce", "scanner"],
            "hostname": "scanner.example.ru",
            "notes": "seen 14 times",
            "secret_field": "should NOT be exposed",
        }))
        intel = replay.load_intel(ip, log_dir=str(tmp_path))
        assert intel["ip"] == ip
        assert intel["country"] == "RU"
        assert intel["abuse_score"] == 87
        assert intel["tags"] == ["bruteforce", "scanner"]
        # Whitelist guard — undocumented fields stay invisible
        assert "secret_field" not in intel

    def test_corrupt_json_returns_empty(self, tmp_path):
        ip = "203.0.113.99"
        (tmp_path / "recon_203_0_113_99.json").write_text("not json at all")
        assert replay.load_intel(ip, log_dir=str(tmp_path)) == {}

    def test_non_dict_top_level_returns_empty(self, tmp_path):
        ip = "203.0.113.100"
        (tmp_path / "recon_203_0_113_100.json").write_text("[1,2,3]")
        assert replay.load_intel(ip, log_dir=str(tmp_path)) == {}
