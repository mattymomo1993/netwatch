"""CrowdSec bridge — push honeypot captures to the local CrowdSec agent.

When CrowdSec's `cscli` is in PATH and the agent is running, every qualifying
honeypot event becomes a decision (ban) enforced by the crowdsec-firewall-bouncer.
This is the OSS path: no API key, no network egress, local-only.

If `cscli` is missing we no-op silently — netwatch keeps logging, just no auto-ban.

Public API:
    cscli_available() -> bool
    cscli_block(ip, reason, duration="4h") -> bool
    cscli_unblock(ip) -> bool

All subprocess calls use argv lists (no shell=True). Input is validated
through `ipaddress.ip_address()` and a strict reason regex BEFORE reaching
subprocess — no attacker-controlled values reach the command line.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess
import threading
import time

log = logging.getLogger("netwatch.crowdsec")

_REASON_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_DURATION_RE = re.compile(r"^[0-9]+(s|m|h|d)$")

# Hard-allow loopback + private + multicast. CrowdSec also rejects these,
# but we filter early to avoid pointless subprocess calls.
_PRIVATE_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")

# Module-level dedupe so the same IP doesn't get ban-spammed across rapid events.
_RECENT: dict[str, float] = {}
_RECENT_LOCK = threading.Lock()
_DEDUPE_WINDOW = 60.0  # seconds — one decision per IP per minute, max


def cscli_available() -> bool:
    return shutil.which("cscli") is not None


def _is_bannable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return False
    if any(addr in ipaddress.ip_network(n) for n in _PRIVATE_NETS):
        return False
    return True


def _should_dedupe(ip: str) -> bool:
    now = time.monotonic()
    with _RECENT_LOCK:
        last = _RECENT.get(ip, 0.0)
        if now - last < _DEDUPE_WINDOW:
            return True
        _RECENT[ip] = now
        # Cheap LRU cap.
        if len(_RECENT) > 4096:
            cutoff = now - _DEDUPE_WINDOW * 10
            for k in [k for k, v in _RECENT.items() if v < cutoff]:
                _RECENT.pop(k, None)
    return False


def cscli_block(ip: str, reason: str, duration: str = "4h") -> bool:
    """Push a ban decision to CrowdSec. Returns True if cscli was invoked successfully."""
    if not cscli_available():
        return False
    if not _is_bannable(ip):
        return False
    if not _REASON_RE.match(reason or ""):
        reason = "netwatch"
    if not _DURATION_RE.match(duration or ""):
        duration = "4h"
    if _should_dedupe(ip):
        return False
    try:
        r = subprocess.run(
            ["cscli", "decisions", "add",
             "--ip", ip,
             "--duration", duration,
             "--reason", f"netwatch:{reason}",
             "--type", "ban"],
            capture_output=True, timeout=5, text=True,
        )
        if r.returncode != 0:
            log.warning("cscli block failed for %s: %s", ip, r.stderr.strip()[:200])
            return False
        return True
    except (subprocess.TimeoutExpired, OSError) as e:
        log.warning("cscli block exception for %s: %s", ip, e)
        return False


def cscli_unblock(ip: str) -> bool:
    if not cscli_available():
        return False
    if not _is_bannable(ip):
        return False
    try:
        r = subprocess.run(
            ["cscli", "decisions", "delete", "--ip", ip],
            capture_output=True, timeout=5, text=True,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


# Services where a single hit is enough to ban. Generic `http` is excluded —
# too noisy (every operator dashboard poll generates one).
_HOT_SERVICES = frozenset({
    "credential", "malware_attempt", "ftp_upload",
    "telnet", "telnet_cmd", "rtsp", "ftp",
})


def maybe_defend(service: str, ip: str) -> None:
    """Decide whether to push a ban for this event. Fire-and-forget from a daemon thread."""
    if service not in _HOT_SERVICES:
        return
    cscli_block(ip, service)
