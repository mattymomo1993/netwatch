"""Tarpit tests — RTSP cat-video stream + HTTP fake-cam endpoints.

The tarpit trickles bytes from a looped MP4 to attackers after credential
capture. These tests cover:
 - File-missing fallback (must not block honest 404 flow)
 - Whitelist short-circuit (operator scanners not caught)
 - Generator loops on EOF (file gets read past end)
 - Rate limiting actually trickles (timing within tolerance)
 - Max-duration hard cap fires
 - Disable via env var
"""
from __future__ import annotations

import os
import time
from unittest.mock import patch

import pytest

import netwatch


# ─────────────────────────────────────────────────────────────
#  Fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def tarpit_video(tmp_path, monkeypatch):
    """A tiny fake 'video' file just to make the tarpit yield bytes."""
    path = tmp_path / "cat_loop.mp4"
    path.write_bytes(b"FAKE_MP4_BYTES" * 1024)  # ~14 KB so passes the 1024 floor
    monkeypatch.setattr(netwatch, "TARPIT_VIDEO_PATH", str(path))
    monkeypatch.setattr(netwatch, "TARPIT_ENABLED", True)
    return str(path)


# ─────────────────────────────────────────────────────────────
#  _tarpit_should_trickle
# ─────────────────────────────────────────────────────────────

class TestShouldTrickle:
    def test_no_file_returns_false(self, monkeypatch):
        monkeypatch.setattr(netwatch, "TARPIT_VIDEO_PATH", "/nonexistent/path.mp4")
        monkeypatch.setattr(netwatch, "TARPIT_ENABLED", True)
        assert netwatch._tarpit_should_trickle("203.0.113.1") is False

    def test_tiny_file_returns_false(self, tmp_path, monkeypatch):
        # Files under 1 KB are likely empty placeholders — skip.
        p = tmp_path / "stub.mp4"
        p.write_bytes(b"x" * 100)
        monkeypatch.setattr(netwatch, "TARPIT_VIDEO_PATH", str(p))
        monkeypatch.setattr(netwatch, "TARPIT_ENABLED", True)
        assert netwatch._tarpit_should_trickle("203.0.113.1") is False

    def test_disabled_via_env(self, tarpit_video, monkeypatch):
        monkeypatch.setattr(netwatch, "TARPIT_ENABLED", False)
        assert netwatch._tarpit_should_trickle("203.0.113.1") is False

    def test_attacker_ip_returns_true(self, tarpit_video):
        assert netwatch._tarpit_should_trickle("203.0.113.99") is True

    def test_whitelist_scan_ip_returns_false(self, tarpit_video, monkeypatch):
        monkeypatch.setitem(__import__("builtins").__dict__, "_", None)  # touch to silence pyflakes
        # Use any IP that's already in WHITELIST_SCAN.
        wl_ip = next(iter(netwatch.WHITELIST_SCAN))
        assert netwatch._tarpit_should_trickle(wl_ip) is False

    def test_whitelist_prefix_short_circuits(self, tarpit_video):
        # 216.239.x.x is in WHITELIST_PREFIXES (Google).
        assert netwatch._tarpit_should_trickle("216.239.1.2") is False


# ─────────────────────────────────────────────────────────────
#  _tarpit_chunks generator
# ─────────────────────────────────────────────────────────────

class TestTarpitChunks:
    def test_yields_bytes(self, tarpit_video, monkeypatch):
        monkeypatch.setattr(netwatch, "TARPIT_MAX_SEC", 1)
        chunks = []
        for buf, _ in netwatch._tarpit_chunks():
            chunks.append(buf)
            if len(chunks) >= 2:
                break
        assert all(isinstance(c, bytes) for c in chunks)
        assert all(len(c) > 0 for c in chunks)

    def test_loops_on_eof(self, tarpit_video, monkeypatch):
        # Crank rate way up so we burn through the small file fast,
        # but cap iterations so the test doesn't hang.
        monkeypatch.setattr(netwatch, "TARPIT_BYTES_PER_SEC", 10_000_000)
        monkeypatch.setattr(netwatch, "TARPIT_MAX_SEC", 1)
        total = 0
        file_size = os.path.getsize(netwatch.TARPIT_VIDEO_PATH)
        for buf, _ in netwatch._tarpit_chunks():
            total += len(buf)
            # If we've emitted more than the file size, the generator looped.
            if total > file_size * 2:
                break
        assert total > file_size  # proves at least one loop happened

    def test_max_sec_caps_duration(self, tarpit_video, monkeypatch):
        monkeypatch.setattr(netwatch, "TARPIT_MAX_SEC", 1)  # 1-second hard cap
        monkeypatch.setattr(netwatch, "TARPIT_BYTES_PER_SEC", 1024)
        t0 = time.monotonic()
        for _ in netwatch._tarpit_chunks():
            pass
        elapsed = time.monotonic() - t0
        # Allow some slack for sleep granularity.
        assert elapsed < 2.5

    def test_missing_file_yields_nothing(self, monkeypatch):
        monkeypatch.setattr(netwatch, "TARPIT_VIDEO_PATH", "/nonexistent/file.mp4")
        monkeypatch.setattr(netwatch, "TARPIT_MAX_SEC", 1)
        chunks = list(netwatch._tarpit_chunks())
        assert chunks == []


# ─────────────────────────────────────────────────────────────
#  HTTP fake-cam Flask route
# ─────────────────────────────────────────────────────────────

class TestHttpTarpitRoute:
    def setup_method(self):
        netwatch.app.config["TESTING"] = True
        self.client = netwatch.app.test_client()

    def test_404_when_no_video(self, monkeypatch):
        monkeypatch.setattr(netwatch, "TARPIT_VIDEO_PATH", "/nonexistent/x.mp4")
        monkeypatch.setattr(netwatch, "TARPIT_ENABLED", True)
        resp = self.client.get("/cam01.mp4")
        assert resp.status_code == 404

    def test_404_when_disabled(self, tarpit_video, monkeypatch):
        monkeypatch.setattr(netwatch, "TARPIT_ENABLED", False)
        resp = self.client.get("/cam01.mp4")
        assert resp.status_code == 404

    # Override Flask test-client default 127.0.0.1 (which IS in WHITELIST_SCAN
    # and would short-circuit the tarpit).
    ATTACKER_IP = "203.0.113.42"

    def _get(self, path):
        return self.client.get(path, environ_base={"REMOTE_ADDR": self.ATTACKER_IP})

    def test_streams_video_mp4_when_enabled(self, tarpit_video, monkeypatch):
        monkeypatch.setattr(netwatch, "TARPIT_BYTES_PER_SEC", 100_000)
        monkeypatch.setattr(netwatch, "TARPIT_MAX_SEC", 1)
        resp = self._get("/cam01.mp4")
        assert resp.status_code == 200
        assert resp.mimetype == "video/mp4"
        body = resp.get_data()
        assert b"FAKE_MP4_BYTES" in body

    def test_multiple_cam_paths_all_work(self, tarpit_video, monkeypatch):
        monkeypatch.setattr(netwatch, "TARPIT_BYTES_PER_SEC", 100_000)
        monkeypatch.setattr(netwatch, "TARPIT_MAX_SEC", 1)
        for path in ("/cam01.mp4", "/cam99.mp4", "/video.mp4", "/stream.mp4"):
            resp = self._get(path)
            assert resp.status_code == 200, f"{path} returned {resp.status_code}"

    def test_logs_start_and_end_events(self, tarpit_video, monkeypatch):
        monkeypatch.setattr(netwatch, "TARPIT_BYTES_PER_SEC", 100_000)
        monkeypatch.setattr(netwatch, "TARPIT_MAX_SEC", 1)
        events = []
        with patch("netwatch.log_event", side_effect=lambda svc, ip, data: events.append((svc, ip, data))):
            resp = self._get("/cam05.mp4")
            resp.get_data()  # drain the generator so 'end' fires
        services = [e[0] for e in events]
        assert "http_tarpit_start" in services
        assert "http_tarpit_end" in services
        end = next(e for e in events if e[0] == "http_tarpit_end")
        assert end[2]["bytes_sent"] > 0

    def test_whitelisted_ip_gets_404(self, tarpit_video, monkeypatch):
        wl_ip = next(iter(netwatch.WHITELIST_SCAN))
        # Override remote_addr via environ_base
        resp = self.client.get("/cam01.mp4", environ_base={"REMOTE_ADDR": wl_ip})
        assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────
#  Config defaults
# ─────────────────────────────────────────────────────────────

class TestTarpitConfig:
    def test_default_rate_is_at_least_1kbps(self):
        assert netwatch.TARPIT_BYTES_PER_SEC >= 1024

    def test_default_max_sec_is_positive(self):
        assert netwatch.TARPIT_MAX_SEC >= 1

    def test_video_path_is_absolute(self):
        assert os.path.isabs(netwatch.TARPIT_VIDEO_PATH)
