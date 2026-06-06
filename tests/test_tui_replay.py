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


class TestSafeText:
    """ANSI/control-char stripper — defense vs operator terminal hijack.

    All attacker-controlled strings (intel sidebar fields, event text, IPs,
    session_ids) flow through _safe_text before reaching the terminal.
    """

    def test_passes_plain_text(self):
        assert netwatch._safe_text("hello world") == "hello world"

    def test_strips_csi_color(self):
        assert netwatch._safe_text("\x1b[31mRED\x1b[0m") == "RED"

    def test_strips_csi_cursor_move(self):
        assert netwatch._safe_text("a\x1b[2Jb\x1b[Hc") == "abc"

    def test_strips_osc_52_clipboard_hijack(self):
        # OSC 52 = write to clipboard. Critical attack — recon JSON could exfil.
        payload = "before\x1b]52;c;cGF5bG9hZA==\x07after"
        assert netwatch._safe_text(payload) == "beforeafter"

    def test_strips_osc_terminated_by_st(self):
        payload = "x\x1b]0;FAKE TITLE\x1b\\y"
        assert netwatch._safe_text(payload) == "xy"

    def test_strips_c0_controls(self):
        # \x07 BEL, \x08 BS, \x1f US, \x7f DEL
        assert netwatch._safe_text("a\x07b\x08c\x1fd\x7fe") == "abcde"

    def test_preserves_tab(self):
        assert netwatch._safe_text("a\tb") == "a\tb"

    def test_newlines_collapsed_to_space_by_default(self):
        assert netwatch._safe_text("a\nb\rc") == "a bc"

    def test_newlines_kept_when_allowed(self):
        assert netwatch._safe_text("a\nb", allow_newlines=True) == "a\nb"

    def test_none_returns_empty(self):
        assert netwatch._safe_text(None) == ""

    def test_int_safely_stringified(self):
        assert netwatch._safe_text(42) == "42"

    def test_no_lone_esc_left_behind(self):
        # Solo ESC followed by non-ANSI gets stripped — closes a gap where
        # an attacker could break out of a partial sequence.
        assert "\x1b" not in netwatch._safe_text("a\x1bMb")

    def test_paint_replay_sanitizes_intel(self):
        # Full integration: an attacker-poisoned intel JSON cannot inject ANSI
        # through the sidebar render.
        from unittest.mock import patch
        from netwatch import AppState
        netwatch.app_state = AppState()
        netwatch.app_state.replay_timeline = {
            "session_id": "all_1.2.3.4",
            "protocol": "telnet",
            "ip": "1.2.3.4",
            "duration_ms": 1000,
            "events": [{"t_ms": 0, "kind": "connect", "text": "ok"}],
            "intel": {
                "country": "RU\x1b[2J",
                "org": "\x1b]52;c;cGF5\x07evilcorp",
                "hostname": "host\x1b[31m.bad",
                "notes": "line1\x1b[Hline2",
                "tags": ["clean", "ev\x1b[mil"],
            },
        }
        with patch("netwatch._write_frame") as wf, \
             patch("netwatch._get_terminal_dims", return_value=(120, 30)):
            netwatch._paint_replay()
        out = wf.call_args[0][0]
        # No raw ESC byte from the attacker fields should reach the frame.
        # The renderer's own ANSI for color is fine — we only check that no
        # injected ANSI snuck through (cursor move \x1b[2J, OSC 52, etc.).
        assert "\x1b[2J" not in out
        assert "\x1b]52" not in out
        assert "\x1b]52;c;cGF5\x07" not in out
        # Sanitized contents still present (text minus the escapes).
        assert "evilcorp" in out
        assert "RU" in out

    def test_paint_replay_sanitizes_event_text(self):
        from unittest.mock import patch
        from netwatch import AppState
        netwatch.app_state = AppState()
        netwatch.app_state.replay_timeline = {
            "session_id": "all_1.2.3.4",
            "protocol": "telnet",
            "ip": "1.2.3.4",
            "duration_ms": 1000,
            "events": [
                {"t_ms": 0, "kind": "client", "text": "USER \x1b]52;c;cGF5\x07root"},
            ],
            "intel": {},
        }
        with patch("netwatch._write_frame") as wf, \
             patch("netwatch._get_terminal_dims", return_value=(120, 30)):
            netwatch._paint_replay()
        out = wf.call_args[0][0]
        assert "\x1b]52" not in out
        assert "USER root" in out
