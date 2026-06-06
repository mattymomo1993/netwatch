"""TUI replay screen — formatters, cursor advance, dispatcher.

Covers Drop #4 Steps 2-4 (replay command + paint + key bindings):
- _replay_fmt_ms formatting + edge cases
- _replay_event_color color mapping
- _replay_advance_cursor playback math + auto-pause at end
- _disp_replay: list, load by sid, load by index, error paths
"""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

import netwatch
from netwatch import (
    AppState,
    SCREEN_DASHBOARD,
    SCREEN_REPLAY,
    _REPLAY_SPEED_STEPS,
    _disp_replay,
    _paint_replay,
    _replay_advance_cursor,
    _replay_event_color,
    _replay_fmt_ms,
)


class TestReplayFmtMs:
    def test_zero(self):
        assert _replay_fmt_ms(0) == "00:00.000"

    def test_under_one_second(self):
        assert _replay_fmt_ms(123) == "00:00.123"

    def test_minute_boundary(self):
        assert _replay_fmt_ms(60_000) == "01:00.000"

    def test_compound(self):
        assert _replay_fmt_ms(65_432) == "01:05.432"

    def test_none_treated_as_zero(self):
        assert _replay_fmt_ms(None) == "00:00.000"

    def test_negative_treated_as_zero(self):
        assert _replay_fmt_ms(-9999) == "00:00.000"

    def test_long_session(self):
        assert _replay_fmt_ms(10 * 60_000 + 5_500) == "10:05.500"


class TestReplayEventColor:
    @pytest.mark.parametrize("kind", ["client", "cmd", "login", "CLIENT", "Cmd"])
    def test_client_family_cyan(self, kind):
        assert _replay_event_color(kind) == netwatch.CYAN

    def test_server_green(self):
        assert _replay_event_color("server") == netwatch.GREEN

    @pytest.mark.parametrize("kind", ["cred", "credential"])
    def test_cred_red(self, kind):
        assert _replay_event_color(kind) == netwatch.RED

    def test_malware_yellow(self):
        assert _replay_event_color("malware") == netwatch.YELLOW

    def test_connect_blue(self):
        assert _replay_event_color("connect") == netwatch.BLUE

    def test_unknown_empty(self):
        assert _replay_event_color("data") == ""

    def test_none_safe(self):
        assert _replay_event_color(None) == ""


class TestAdvanceCursor:
    def setup_method(self):
        netwatch.app_state = AppState()

    def test_paused_does_not_advance(self):
        st = netwatch.app_state
        st.replay_timeline = {"duration_ms": 10_000}
        st.replay_cursor_ms = 1234
        st.replay_playing = False
        st.replay_last_tick = time.monotonic() - 1.0
        _replay_advance_cursor()
        assert st.replay_cursor_ms == 1234

    def test_no_timeline_no_advance(self):
        st = netwatch.app_state
        st.replay_timeline = None
        st.replay_playing = True
        _replay_advance_cursor()  # must not raise
        assert st.replay_cursor_ms == 0

    def test_advance_with_delta(self):
        st = netwatch.app_state
        st.replay_timeline = {"duration_ms": 10_000}
        st.replay_playing = True
        st.replay_cursor_ms = 0
        st.replay_speed = 1.0
        now = time.monotonic()
        st.replay_last_tick = now - 0.5  # 500ms ago
        with patch("netwatch.time.monotonic", return_value=now):
            _replay_advance_cursor()
        # 500ms * 1.0x ≈ 500ms; allow tiny scheduler jitter.
        assert 400 <= st.replay_cursor_ms <= 600

    def test_speed_multiplies(self):
        st = netwatch.app_state
        st.replay_timeline = {"duration_ms": 100_000}
        st.replay_playing = True
        st.replay_cursor_ms = 0
        st.replay_speed = 4.0
        now = time.monotonic()
        st.replay_last_tick = now - 1.0
        with patch("netwatch.time.monotonic", return_value=now):
            _replay_advance_cursor()
        # 1s * 4x ≈ 4000ms
        assert 3800 <= st.replay_cursor_ms <= 4200

    def test_auto_pause_at_end(self):
        st = netwatch.app_state
        st.replay_timeline = {"duration_ms": 1000}
        st.replay_playing = True
        st.replay_cursor_ms = 950
        st.replay_speed = 1.0
        now = time.monotonic()
        st.replay_last_tick = now - 1.0
        with patch("netwatch.time.monotonic", return_value=now):
            _replay_advance_cursor()
        assert st.replay_cursor_ms == 1000
        assert st.replay_playing is False

    def test_zero_duration_pauses(self):
        st = netwatch.app_state
        st.replay_timeline = {"duration_ms": 0}
        st.replay_playing = True
        _replay_advance_cursor()
        assert st.replay_playing is False


class TestPaintReplayEmpty:
    """Empty-state render must not crash and must not write SCREEN_REPLAY footer rows."""

    def setup_method(self):
        netwatch.app_state = AppState()

    def test_empty_state_renders(self):
        netwatch.app_state.replay_timeline = None
        with patch("netwatch._write_frame") as wf, \
             patch("netwatch._get_terminal_dims", return_value=(80, 24)):
            _paint_replay()
        assert wf.called
        out = wf.call_args[0][0]
        assert "NETWATCH — REPLAY" in out
        assert "no session loaded" in out

    def test_loaded_state_renders_footer(self):
        netwatch.app_state.replay_timeline = {
            "session_id": "ftp_192.168.1.1_120000",
            "protocol": "ftp",
            "ip": "192.168.1.1",
            "duration_ms": 5000,
            "events": [
                {"t_ms": 0, "kind": "connect", "text": "client connected"},
                {"t_ms": 1000, "kind": "client", "text": "USER admin"},
                {"t_ms": 2000, "kind": "server", "text": "331 password"},
            ],
            "intel": {"country": "RU", "asn": "AS1234", "org": "evilcorp"},
        }
        netwatch.app_state.replay_cursor_ms = 1000
        with patch("netwatch._write_frame") as wf, \
             patch("netwatch._get_terminal_dims", return_value=(120, 30)):
            _paint_replay()
        out = wf.call_args[0][0]
        assert "ftp_192.168.1.1_120000" in out
        assert "192.168.1.1" in out
        assert "[SPACE] play" in out


class TestDispReplay:
    def setup_method(self):
        netwatch.app_state = AppState()
        netwatch._replay_last_index = []

    def test_list_empty(self):
        with patch("netwatch.replay.replay_index", return_value=[]), \
             patch("netwatch.add_console") as ac:
            _disp_replay(["replay", "list"])
        msgs = " ".join(c.args[0] for c in ac.call_args_list)
        assert "No captured sessions" in msgs

    def test_list_renders_rows(self):
        rows = [{
            "session_id": "ftp_1.2.3.4_120000",
            "protocol": "ftp",
            "ip": "1.2.3.4",
            "event_count": 7,
            "started_at_mtime": "2026-06-05T12:00:00",
        }]
        with patch("netwatch.replay.replay_index", return_value=rows), \
             patch("netwatch.add_console") as ac:
            _disp_replay(["replay", "list"])
        msgs = " ".join(c.args[0] for c in ac.call_args_list)
        assert "CAPTURED SESSIONS" in msgs
        assert "ftp_1.2.3.4_120000" in msgs
        assert netwatch._replay_last_index == rows

    def test_load_by_index_after_list(self):
        rows = [{"session_id": "ftp_a_1", "protocol": "ftp", "ip": "1.2.3.4", "event_count": 1, "started_at_mtime": ""}]
        netwatch._replay_last_index = rows
        timeline = {"session_id": "ftp_a_1", "ip": "1.2.3.4", "events": [], "duration_ms": 100, "protocol": "ftp"}
        with patch("netwatch.replay.replay_loader", return_value=timeline), \
             patch("netwatch.replay.load_intel", return_value={}), \
             patch("netwatch.add_console"), \
             patch("netwatch._redraw_event"):
            _disp_replay(["replay", "1"])
        assert netwatch.app_state.replay_session_id == "ftp_a_1"
        assert netwatch.app_state.current_screen == SCREEN_REPLAY

    def test_load_by_sid(self):
        timeline = {"session_id": "ftp_a_1", "ip": "1.2.3.4", "events": [], "duration_ms": 100, "protocol": "ftp"}
        with patch("netwatch.replay.replay_loader", return_value=timeline), \
             patch("netwatch.replay.load_intel", return_value={}), \
             patch("netwatch.add_console"), \
             patch("netwatch._redraw_event"):
            _disp_replay(["replay", "ftp_a_1", "ftp"])
        assert netwatch.app_state.replay_session_id == "ftp_a_1"
        assert netwatch.app_state.replay_protocol == "ftp"

    def test_index_out_of_range(self):
        netwatch._replay_last_index = []
        with patch("netwatch.add_console") as ac:
            _disp_replay(["replay", "5"])
        msgs = " ".join(c.args[0] for c in ac.call_args_list)
        assert "out of range" in msgs

    def test_load_handles_not_found(self):
        with patch("netwatch.replay.replay_loader", side_effect=FileNotFoundError("nope")), \
             patch("netwatch.add_console") as ac:
            _disp_replay(["replay", "missing_sid"])
        msgs = " ".join(c.args[0] for c in ac.call_args_list)
        assert "session not found" in msgs

    def test_load_handles_value_error(self):
        with patch("netwatch.replay.replay_loader", side_effect=ValueError("bad proto")), \
             patch("netwatch.add_console") as ac:
            _disp_replay(["replay", "sid"])
        msgs = " ".join(c.args[0] for c in ac.call_args_list)
        assert "bad proto" in msgs


class TestReplaySpeedSteps:
    def test_speeds_are_strictly_increasing(self):
        steps = list(_REPLAY_SPEED_STEPS)
        assert steps == sorted(steps)
        assert 1.0 in steps
        assert steps[0] < 1.0 < steps[-1]
