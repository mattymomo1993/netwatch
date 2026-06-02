"""NetWatch session replay — data layer.

Reads captured FTP honeypot sessions from logs/ftp_session_*.log and exposes
them as a unified timeline that the TUI and web dashboard can both render.

Public API:
    replay_loader(session_id, log_dir=None) -> dict
    replay_index(log_dir=None)              -> list[dict]
    load_intel(ip, log_dir=None)            -> dict

Read-only. No edits to underlying logs. Stdlib only, no new deps.
"""

import json
import os
import re
import threading
import time as _time
from datetime import datetime, timezone

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(_BASE_DIR, "logs")

# IPv4 dotted, IPv6 colon-hex, plus _HHMMSS suffix from ftp_log.
# \A / \Z (not ^ / $) — Python's $ allows a trailing newline; we don't.
SESSION_ID_RE = re.compile(r"\A[0-9a-fA-F.:]+_[0-9]{6}\Z")

# Legacy session-log lines pre-dating the JSON ftp_log() schema.
_LEGACY_LINE_RE = re.compile(r"^\[(\d{2}:\d{2}:\d{2}\.\d{3})\]\s+(\w+):\s*(.*)$")

_INDEX_CACHE_TTL = 5.0
_index_cache = {"at": 0.0, "data": None, "dir": None}
_cache_lock = threading.Lock()


def _resolve_log_dir(log_dir):
    return log_dir if log_dir else LOG_DIR


def _validate_session_id(session_id):
    if not SESSION_ID_RE.match(session_id or ""):
        raise ValueError(f"invalid session_id: {session_id!r}")


def _session_log_path(session_id, log_dir):
    return os.path.join(log_dir, f"ftp_session_{session_id}.log")


def _parse_log_line(line):
    """Parse one session-log line.

    Modern (post-patch): {"ts": "HH:MM:SS.mmm", "dir": "...", "data": "..."}
    Legacy            : [HH:MM:SS.mmm] DIR: data
    Returns (ts, direction, data) or None.
    """
    s = line.strip()
    if not s:
        return None
    if s.startswith("{"):
        try:
            d = json.loads(s)
        except json.JSONDecodeError:
            return None
        ts = d.get("ts") or ""
        return ts, d.get("dir", ""), d.get("data", "")
    m = _LEGACY_LINE_RE.match(s)
    if m:
        return m.group(1), m.group(2), m.group(3)
    return None


def _hhmmss_to_ms(hms, anchor_date):
    """Combine HH:MM:SS.mmm with an anchor date -> unix epoch ms (UTC).

    ftp_log() writes local time without a date. Anchor with file mtime so we
    know which day. Sessions that bridge midnight will look out-of-order; v1
    limitation documented in [[netwatch-session-replay]].
    """
    try:
        t = datetime.strptime(hms, "%H:%M:%S.%f").time()
    except (ValueError, TypeError):
        return None
    dt = datetime(anchor_date.year, anchor_date.month, anchor_date.day,
                  t.hour, t.minute, t.second, t.microsecond,
                  tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _anchor_date_for(path):
    try:
        return datetime.fromtimestamp(
            os.path.getmtime(path), tz=timezone.utc).date()
    except OSError:
        return datetime.now(tz=timezone.utc).date()


def replay_loader(session_id, log_dir=None):
    """Return a unified, scrubbable timeline for one captured session.

    Output:
        {
            "session_id": str,
            "ip"        : str,
            "started_at": ISO8601 UTC,
            "ended_at"  : ISO8601 UTC,
            "duration_ms": int,
            "events"    : [
                {"t_ms": int (offset from start),
                 "kind": "client"|"server"|"server_fail"|"cred"|"data_send"|...,
                 "text": str},
                ...
            ],
        }

    Raises FileNotFoundError if the session log isn't present, ValueError if
    the session_id fails the regex guard.
    """
    _validate_session_id(session_id)
    log_dir = _resolve_log_dir(log_dir)
    path = _session_log_path(session_id, log_dir)
    if not os.path.exists(path):
        raise FileNotFoundError(f"no session log: {path}")

    ip = session_id.rsplit("_", 1)[0]
    anchor = _anchor_date_for(path)
    raw = []
    with open(path) as f:
        for line in f:
            parsed = _parse_log_line(line)
            if parsed is None:
                continue
            hms, direction, data = parsed
            ms = _hhmmss_to_ms(hms, anchor)
            if ms is None:
                continue
            raw.append((ms, direction.lower(), data))

    if not raw:
        return {"session_id": session_id, "ip": ip,
                "started_at": "", "ended_at": "",
                "duration_ms": 0, "events": []}

    raw.sort(key=lambda x: x[0])
    start_ms = raw[0][0]
    end_ms = raw[-1][0]
    events = [{"t_ms": ms - start_ms, "kind": kind, "text": text}
              for ms, kind, text in raw]
    return {
        "session_id": session_id,
        "ip": ip,
        "started_at": datetime.fromtimestamp(
            start_ms / 1000, tz=timezone.utc).isoformat(),
        "ended_at": datetime.fromtimestamp(
            end_ms / 1000, tz=timezone.utc).isoformat(),
        "duration_ms": end_ms - start_ms,
        "events": events,
    }


def replay_index(log_dir=None):
    """List captured FTP sessions on disk, newest first.

    Output: list of {session_id, ip, started_at_mtime, size_bytes}.
    Cached for 5 seconds — repeated dashboard polls don't re-walk logs/.
    """
    log_dir = _resolve_log_dir(log_dir)
    now = _time.monotonic()
    with _cache_lock:
        if (_index_cache["dir"] == log_dir
                and _index_cache["data"] is not None
                and now - _index_cache["at"] < _INDEX_CACHE_TTL):
            return _index_cache["data"]

    out = []
    try:
        names = os.listdir(log_dir)
    except OSError:
        names = []
    prefix = "ftp_session_"
    suffix = ".log"
    for name in names:
        if not (name.startswith(prefix) and name.endswith(suffix)):
            continue
        session_id = name[len(prefix):-len(suffix)]
        if not SESSION_ID_RE.match(session_id):
            continue
        path = os.path.join(log_dir, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        out.append({
            "session_id": session_id,
            "ip": session_id.rsplit("_", 1)[0],
            "started_at_mtime": datetime.fromtimestamp(
                st.st_mtime, tz=timezone.utc).isoformat(),
            "size_bytes": st.st_size,
        })
    out.sort(key=lambda r: r["started_at_mtime"], reverse=True)
    with _cache_lock:
        _index_cache.update({"at": now, "data": out, "dir": log_dir})
    return out


def _intel_path(ip, log_dir):
    safe = ip.replace(".", "_").replace(":", "_")
    return os.path.join(log_dir, f"recon_{safe}.json")


def load_intel(ip, log_dir=None):
    """Load passive OSINT for an attacker IP from logs/recon_<ip>.json.

    Returns {} when missing or unreadable. Surface fields only — mirrors the
    whitelist used by NetWatch's existing /api/recon/<ip> route so dashboards
    can't accidentally leak nested blobs.
    """
    log_dir = _resolve_log_dir(log_dir)
    path = _intel_path(ip, log_dir)
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        "ip": ip,
        "country": raw.get("country", ""),
        "city": raw.get("city", ""),
        "asn": raw.get("asn", ""),
        "org": raw.get("org", ""),
        "abuse_score": raw.get("abuse_score", ""),
        "tags": raw.get("tags", []) or [],
        "hostname": raw.get("hostname", ""),
        "notes": raw.get("notes", ""),
    }
