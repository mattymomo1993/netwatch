"""
Tests for the TUI command dispatch threading model (dispatch_command).

The raw-terminal input loop must never freeze: long/blocking command handlers
(scan, whois, ssl, …) run on a single serialized background worker so the loop
returns immediately, while instant/local commands (status, help, …) run inline
so their output is available synchronously. These tests prove both halves
without touching the real network — slow handlers are simulated by mocking the
underlying lookups to block on an Event.
"""
import threading
import time

from unittest.mock import patch

import netwatch


def _wait_for(predicate, timeout=5.0, interval=0.01):
    """Spin until predicate() is truthy or timeout elapses. Returns the result."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


class TestBlockingCommandsAreAsync:
    def test_blocking_handler_does_not_block_caller(self):
        """A slow blocking command dispatched through dispatch_command returns
        control to the caller quickly (it is queued, not run inline)."""
        release = threading.Event()
        entered = threading.Event()

        def _slow_whois(_target):
            entered.set()
            # Simulate a long network call. Bounded so a bug can't hang the suite.
            release.wait(timeout=5.0)
            return {"registrar": "Slow Reg"}

        with patch("netwatch.resolve_host", return_value="slow.example.com"), \
             patch("netwatch.osint_whois", side_effect=_slow_whois):
            start = time.monotonic()
            queued = netwatch.dispatch_command("whois 203.0.113.7")
            elapsed = time.monotonic() - start

            try:
                # Dispatch must report it queued the work and return fast.
                assert queued is True
                assert elapsed < 0.5, f"dispatch blocked for {elapsed:.3f}s"

                # The worker really is running the slow handler in the background.
                assert _wait_for(entered.is_set, timeout=3.0), \
                    "background worker never started the handler"
            finally:
                # Let the handler finish and drain the queue so other tests start
                # from a clean worker.
                release.set()
                netwatch._cmd_queue.join()

        # After completion the handler's output landed in the console buffer.
        assert _wait_for(
            lambda: any("registrar" in c for c in netwatch.console_output),
            timeout=3.0), "threaded handler output never appeared"

    def test_blocking_command_is_serialized(self):
        """Two heavy commands queue onto one worker and run one-at-a-time rather
        than piling up concurrently."""
        gate = threading.Event()
        concurrent = []
        running = {"n": 0}
        rlock = threading.Lock()

        def _slow_whois(_target):
            with rlock:
                running["n"] += 1
                concurrent.append(running["n"])
            gate.wait(timeout=5.0)
            with rlock:
                running["n"] -= 1
            return {"registrar": "Reg"}

        with patch("netwatch.resolve_host", return_value="x"), \
             patch("netwatch.osint_whois", side_effect=_slow_whois):
            assert netwatch.dispatch_command("whois 203.0.113.8") is True
            assert netwatch.dispatch_command("whois 203.0.113.9") is True
            # Give the worker a moment to pick up the first job.
            _wait_for(lambda: len(concurrent) >= 1, timeout=3.0)
            time.sleep(0.1)
            gate.set()
            netwatch._cmd_queue.join()

        # The single worker never ran two handlers at the same time.
        assert concurrent and max(concurrent) == 1, \
            f"handlers ran concurrently: {concurrent}"


class TestInstantCommandsRunInline:
    def test_instant_command_runs_inline_and_produces_output(self):
        """An instant command runs synchronously on the caller and its output is
        present immediately after dispatch_command returns."""
        netwatch.console_output.clear()
        queued = netwatch.dispatch_command("status")
        assert queued is False  # ran inline, not queued
        assert len(netwatch.console_output) > 0, "instant command produced no output"

    def test_help_runs_inline(self):
        netwatch.console_output.clear()
        queued = netwatch.dispatch_command("help")
        assert queued is False
        assert len(netwatch.console_output) > 0

    def test_unknown_command_runs_inline(self):
        netwatch.console_output.clear()
        queued = netwatch.dispatch_command("definitely-not-a-command")
        assert queued is False
        assert any("Unknown" in c for c in netwatch.console_output)

    def test_empty_command_is_noop(self):
        netwatch.console_output.clear()
        assert netwatch.dispatch_command("   ") is False
        assert len(netwatch.console_output) == 0


class TestBlockingActionRegistry:
    def test_known_blocking_actions_are_listed(self):
        # Handlers that do network/subprocess work inline (no internal thread)
        # must route through the serialized background worker.
        for action in ("whois", "banner", "ports", "find", "blocked",
                       "ifinfo", "report"):
            assert action in netwatch._BLOCKING_ACTIONS, \
                f"{action} should route through the background worker"

    def test_instant_actions_are_not_listed(self):
        for action in ("status", "help", "clear", "block", "unblock",
                       "tag", "note", "attackers"):
            assert action not in netwatch._BLOCKING_ACTIONS, \
                f"{action} should run inline, not on the worker"
