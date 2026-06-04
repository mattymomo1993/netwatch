"""Tests for AppState dataclass and 3-screen toggle behavior.

Covers item 1 (SCREEN STATE) from the refactor spec:
- AppState dataclass centralizes UI state
- Screens mounted once; switch toggles current_screen
- Dashboard restores exact prior state on return (tab, scroll, focus)
- F1/F2/F3 hotkeys + `dashboard`/`cli`/`console` commands
"""
from __future__ import annotations

import pytest

import netwatch
from netwatch import (
    AppState,
    SCREEN_DASHBOARD,
    SCREEN_CLI,
    SCREEN_CONSOLE,
    SCREEN_REPLAY,
    SCREENS,
    app_state,
)


class TestAppStateDataclass:

    def test_appstate_class_exists(self):
        assert hasattr(netwatch, "AppState")
        from dataclasses import is_dataclass
        assert is_dataclass(AppState)

    def test_default_screen_is_dashboard(self):
        s = AppState()
        assert s.current_screen == SCREEN_DASHBOARD

    def test_default_tab_is_all(self):
        s = AppState()
        assert s.current_tab == "all"

    def test_default_scrolls_are_zero(self):
        s = AppState()
        assert s.dash_scroll == 0
        assert s.cli_scroll == 0
        assert s.console_scroll == 0

    def test_needs_clear_default_off(self):
        s = AppState()
        assert s.needs_clear is False

    def test_switch_sets_needs_clear(self):
        s = AppState()
        s.switch(SCREEN_CLI)
        assert s.needs_clear is True

    def test_screens_constant(self):
        assert SCREENS == (SCREEN_DASHBOARD, SCREEN_CLI, SCREEN_CONSOLE, SCREEN_REPLAY)

    def test_module_has_singleton_app_state(self):
        assert isinstance(netwatch.app_state, AppState)


class TestScreenSwitch:

    def setup_method(self):
        self.s = AppState()

    def test_switch_to_cli_updates_current(self):
        self.s.switch(SCREEN_CLI)
        assert self.s.current_screen == SCREEN_CLI

    def test_switch_records_last_screen(self):
        self.s.switch(SCREEN_CLI)
        assert self.s.last_screen == SCREEN_DASHBOARD

    def test_switch_to_same_is_noop(self):
        self.s.switch(SCREEN_DASHBOARD)
        assert self.s.current_screen == SCREEN_DASHBOARD
        assert self.s.last_screen == SCREEN_DASHBOARD

    def test_switch_to_invalid_is_rejected(self):
        self.s.switch("not-a-screen")
        assert self.s.current_screen == SCREEN_DASHBOARD

    def test_round_trip_preserves_dashboard_state(self):
        """Core requirement: returning to dashboard restores tab + scroll."""
        self.s.current_tab = "nmap"
        self.s.dash_scroll = 42
        self.s.dash_focus = 7
        self.s.switch(SCREEN_CONSOLE)
        self.s.switch(SCREEN_CLI)
        self.s.switch(SCREEN_DASHBOARD)
        assert self.s.current_tab == "nmap"
        assert self.s.dash_scroll == 42
        assert self.s.dash_focus == 7

    def test_per_screen_scroll_persists_independently(self):
        self.s.dash_scroll = 10
        self.s.switch(SCREEN_CLI)
        self.s.cli_scroll = 25
        self.s.switch(SCREEN_CONSOLE)
        self.s.console_scroll = 99
        self.s.switch(SCREEN_DASHBOARD)
        assert self.s.dash_scroll == 10
        assert self.s.cli_scroll == 25
        assert self.s.console_scroll == 99


class TestScrollHelpers:

    def test_scroll_for_returns_per_screen(self):
        s = AppState(dash_scroll=1, cli_scroll=2, console_scroll=3)
        assert s.scroll_for(SCREEN_DASHBOARD) == 1
        assert s.scroll_for(SCREEN_CLI) == 2
        assert s.scroll_for(SCREEN_CONSOLE) == 3

    def test_set_scroll_writes_correct_field(self):
        s = AppState()
        s.set_scroll(SCREEN_CLI, 17)
        s.set_scroll(SCREEN_CONSOLE, 31)
        s.set_scroll(SCREEN_DASHBOARD, 5)
        assert s.cli_scroll == 17
        assert s.console_scroll == 31
        assert s.dash_scroll == 5


class TestCommandDispatch:

    def setup_method(self):
        netwatch.app_state.switch(SCREEN_DASHBOARD)
        netwatch.app_state.current_tab = "all"
        netwatch.app_state.dash_scroll = 0
        netwatch.app_state.cli_scroll = 0
        netwatch.app_state.console_scroll = 0

    def test_cli_command_switches_screen(self):
        netwatch.handle_command("cli")
        assert netwatch.app_state.current_screen == SCREEN_CLI

    def test_console_command_switches_screen(self):
        netwatch.handle_command("console")
        assert netwatch.app_state.current_screen == SCREEN_CONSOLE

    def test_dashboard_command_returns_to_dashboard(self):
        netwatch.handle_command("cli")
        netwatch.handle_command("dashboard")
        assert netwatch.app_state.current_screen == SCREEN_DASHBOARD

    def test_dashboard_aliases(self):
        netwatch.handle_command("cli")
        netwatch.handle_command("dash")
        assert netwatch.app_state.current_screen == SCREEN_DASHBOARD
        netwatch.handle_command("console")
        netwatch.handle_command("d")
        assert netwatch.app_state.current_screen == SCREEN_DASHBOARD

    def test_dashboard_command_keeps_console_mode_false(self):
        """Legacy contract preserved: dashboard cmd zeroes console_mode."""
        netwatch.console_mode = True
        netwatch.handle_command("dashboard")
        assert netwatch.console_mode is False

    def test_clear_resets_all_scrolls(self):
        netwatch.app_state.dash_scroll = 50
        netwatch.app_state.cli_scroll = 50
        netwatch.app_state.console_scroll = 50
        netwatch.handle_command("clear")
        assert netwatch.app_state.dash_scroll == 0
        assert netwatch.app_state.cli_scroll == 0
        assert netwatch.app_state.console_scroll == 0

    def test_switching_screens_does_not_lose_tab(self):
        """The bug the user described: navigating away and back must keep tab."""
        netwatch.app_state.current_tab = "honeypot"
        netwatch.handle_command("cli")
        assert netwatch.app_state.current_tab == "honeypot"
        netwatch.handle_command("console")
        assert netwatch.app_state.current_tab == "honeypot"
        netwatch.handle_command("dashboard")
        assert netwatch.app_state.current_tab == "honeypot"


class TestPaintFunctions:

    def test_paint_cli_exists(self):
        assert callable(netwatch._paint_cli)

    def test_paint_console_exists(self):
        assert callable(netwatch._paint_console)

    def test_paint_dashboard_still_exists(self):
        assert callable(netwatch._paint_dashboard)

    def test_render_frame_dispatches_to_cli(self, monkeypatch):
        called = {"name": None}
        monkeypatch.setattr(netwatch, "_paint_cli", lambda: called.__setitem__("name", "cli"))
        monkeypatch.setattr(netwatch, "_paint_console", lambda: called.__setitem__("name", "console"))
        monkeypatch.setattr(netwatch, "_paint_dashboard", lambda: called.__setitem__("name", "dashboard"))
        netwatch._input_active = False
        netwatch.app_state.switch(SCREEN_CLI)
        netwatch._render_frame()
        assert called["name"] == "cli"

    def test_render_frame_dispatches_to_console(self, monkeypatch):
        called = {"name": None}
        monkeypatch.setattr(netwatch, "_paint_cli", lambda: called.__setitem__("name", "cli"))
        monkeypatch.setattr(netwatch, "_paint_console", lambda: called.__setitem__("name", "console"))
        monkeypatch.setattr(netwatch, "_paint_dashboard", lambda: called.__setitem__("name", "dashboard"))
        netwatch._input_active = False
        netwatch.app_state.switch(SCREEN_CONSOLE)
        netwatch._render_frame()
        assert called["name"] == "console"

    def test_render_frame_dispatches_to_dashboard(self, monkeypatch):
        called = {"name": None}
        monkeypatch.setattr(netwatch, "_paint_cli", lambda: called.__setitem__("name", "cli"))
        monkeypatch.setattr(netwatch, "_paint_console", lambda: called.__setitem__("name", "console"))
        monkeypatch.setattr(netwatch, "_paint_dashboard", lambda: called.__setitem__("name", "dashboard"))
        netwatch._input_active = False
        netwatch.app_state.switch(SCREEN_DASHBOARD)
        netwatch._render_frame()
        assert called["name"] == "dashboard"
