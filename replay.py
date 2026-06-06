"""NetWatch session replay — data layer.

Reads captured honeypot sessions (FTP per-session logs + synthesized Telnet
sessions from telnet.json) and exposes them as a unified timeline that the
TUI and web dashboard can both render.

Public API:
    replay_loader(session_id, protocol="ftp", log_dir=None) -> dict
    replay_index(log_dir=None)                              -> list[dict]
    load_intel(ip, log_dir=None)                            -> dict

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

# Accepts two forms:
#   <ip>_HHMMSS[_microsec]  — per-connect session (FTP + per-attempt telnet)
#   all_<ip>                — aggregated telnet rollup (every attempt from this IP)
# \A / \Z (not ^ / $) — Python's $ allows a trailing newline; we don't.
SESSION_ID_RE = re.compile(
    r"\A(?:all_[0-9a-fA-F.:]+|[0-9a-fA-F.:]+_[0-9]{6}(?:_[0-9]+)?)\Z"
)
_TELNET_AGG_PREFIX = "all_"

# Strips trailing _HHMMSS (+ optional _microsec) from a session_id to recover the IP.
_SESSION_TIME_SUFFIX_RE = re.compile(r"_[0-9]{6}(?:_[0-9]+)?\Z")

# Legacy session-log lines pre-dating the JSON ftp_log() schema.
_LEGACY_LINE_RE = re.compile(r"^\[(\d{2}:\d{2}:\d{2}\.\d{3})\]\s+(\w+):\s*(.*)$")

_INDEX_CACHE_TTL = 5.0
_index_cache = {"at": 0.0, "data": None, "dir": None, "dir_mtime": 0.0}
_cache_lock = threading.Lock()


def _dir_mtime(path):
    try:
        return os.stat(path).st_mtime
    except OSError:
        return 0.0


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


def _build_timeline(session_id, ip, raw):
    """Sort (ms, kind, text) triples into a zero-anchored timeline dict."""
    if not raw:
        return {"session_id": session_id, "ip": ip,
                "started_at": "", "ended_at": "",
                "duration_ms": 0, "events": []}
    raw.sort(key=lambda x: x[0])
    start_ms, end_ms = raw[0][0], raw[-1][0]
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


def _load_ftp_session(session_id, log_dir):
    """Parse a per-session FTP log into (ms, kind, text) triples."""
    path = _session_log_path(session_id, log_dir)
    if not os.path.exists(path):
        raise FileNotFoundError(f"no session log: {path}")
    ip = _SESSION_TIME_SUFFIX_RE.sub("", session_id)
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
    return ip, raw


# Telnet sessions don't have per-session log files — they're synthesized from
# `all_events.json` by grouping events from the same IP within a time gap.
# Default 5 min; override at runtime with NETWATCH_TELNET_GAP_SEC to collapse
# longer campaigns into fewer "── ATTEMPT N ──" markers (e.g. 86400 = one
# marker per day). Read lazily so env changes take effect without re-import.
TELNET_SESSION_GAP_SEC = 300  # historical default; the live value is _telnet_gap_sec().


def _telnet_gap_sec():
    try:
        v = int(os.environ.get("NETWATCH_TELNET_GAP_SEC", str(TELNET_SESSION_GAP_SEC)))
        return max(1, v)
    except ValueError:
        return TELNET_SESSION_GAP_SEC
_TELNET_SERVICES = {"telnet", "telnet_cmd", "malware_attempt"}


def _iter_telnet_events(log_dir):
    """Yield (timestamp_iso, ip, service, data) from all_events.json."""
    path = os.path.join(log_dir, "all_events.json")
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("service") not in _TELNET_SERVICES:
                continue
            ts = e.get("timestamp", "")
            ip = e.get("source_ip", "")
            if not ts or not ip:
                continue
            yield ts, ip, e.get("service", ""), e.get("data") or {}


def _format_telnet_event(service, data):
    """Render a telnet event into (kind, text) for the timeline."""
    if service == "telnet":
        u = data.get("username", "")
        p = data.get("password", "")
        if u or p:
            return "login", f"{u or '∅'} : {p or '∅'}"
        return "connect", f"port={data.get('port','?')}"
    if service == "telnet_cmd":
        return "cmd", data.get("command", "")[:200]
    if service == "malware_attempt":
        return "malware", data.get("command", "")[:200]
    return service, str(data)[:200]


def _group_telnet_sessions(log_dir):
    """Group telnet.* events into synthetic sessions keyed by (ip, first_ts).

    Returns dict: session_id -> {"ip", "first_ms", "raw": [(ms, kind, text)]}.
    A session ends when there's a gap > NETWATCH_TELNET_GAP_SEC from the same IP.
    """
    gap_ms = _telnet_gap_sec() * 1000
    by_ip = {}
    for ts, ip, service, data in _iter_telnet_events(log_dir):
        try:
            dt = datetime.fromisoformat(ts)
        except ValueError:
            continue
        ms = int(dt.timestamp() * 1000)
        kind, text = _format_telnet_event(service, data)
        by_ip.setdefault(ip, []).append((ms, kind, text))

    sessions = {}
    for ip, events in by_ip.items():
        events.sort(key=lambda x: x[0])
        cur_first = None
        cur_last = None
        bucket = []
        for ms, kind, text in events:
            if cur_first is None or (ms - cur_last) > gap_ms:
                # close previous bucket
                if bucket:
                    _flush_telnet_bucket(sessions, ip, cur_first, bucket)
                cur_first = ms
                bucket = []
            cur_last = ms
            bucket.append((ms, kind, text))
        if bucket:
            _flush_telnet_bucket(sessions, ip, cur_first, bucket)
    return sessions


def _flush_telnet_bucket(sessions, ip, first_ms, bucket):
    hhmmss = datetime.fromtimestamp(first_ms / 1000, tz=timezone.utc).strftime("%H%M%S")
    sid = f"{ip}_{hhmmss}"
    sessions[sid] = {"ip": ip, "first_ms": first_ms, "raw": bucket}


def _group_telnet_by_ip(log_dir):
    """Roll up every telnet event from each IP into one synthetic session.

    Visible "── ATTEMPT N (yyyy-mm-dd HH:MM:SS UTC) ──" connect markers separate
    bursts (same gap rule as _group_telnet_sessions). Returns:
        dict: ip -> {"ip", "first_ms", "raw": [(ms, kind, text)], "attempts": int}
    """
    by_ip = {}
    for ts, ip, service, data in _iter_telnet_events(log_dir):
        try:
            dt = datetime.fromisoformat(ts)
        except ValueError:
            continue
        ms = int(dt.timestamp() * 1000)
        kind, text = _format_telnet_event(service, data)
        by_ip.setdefault(ip, []).append((ms, kind, text))

    gap_ms = _telnet_gap_sec() * 1000
    out = {}
    for ip, events in by_ip.items():
        events.sort(key=lambda x: x[0])
        merged = []
        attempt_num = 0
        prev_ms = None
        for ms, kind, text in events:
            if prev_ms is None or (ms - prev_ms) > gap_ms:
                attempt_num += 1
                label = datetime.fromtimestamp(
                    ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                merged.append((ms, "connect", f"── ATTEMPT {attempt_num} ({label}) ──"))
            merged.append((ms, kind, text))
            prev_ms = ms
        if merged:
            out[ip] = {
                "ip": ip,
                "first_ms": events[0][0],
                "raw": merged,
                "attempts": attempt_num,
            }
    return out


def _load_telnet_session(session_id, log_dir):
    # all_<ip> form replays every attempt from one IP, marker-separated.
    if session_id.startswith(_TELNET_AGG_PREFIX):
        ip = session_id[len(_TELNET_AGG_PREFIX):]
        by_ip = _group_telnet_by_ip(log_dir)
        s = by_ip.get(ip)
        if s is None:
            raise FileNotFoundError(f"no telnet session: {session_id}")
        return s["ip"], s["raw"]
    sessions = _group_telnet_sessions(log_dir)
    s = sessions.get(session_id)
    if s is None:
        raise FileNotFoundError(f"no telnet session: {session_id}")
    return s["ip"], s["raw"]


def replay_loader(session_id, protocol="ftp", log_dir=None):
    """Return a unified, scrubbable timeline for one captured session.

    Output:
        {
            "session_id" : str,
            "ip"         : str,
            "protocol"   : "ftp" | "telnet",
            "started_at" : ISO8601 UTC,
            "ended_at"   : ISO8601 UTC,
            "duration_ms": int,
            "events"     : [
                {"t_ms": int, "kind": str, "text": str},
                ...
            ],
        }

    Raises FileNotFoundError if the session isn't present, ValueError if the
    session_id fails the regex guard or protocol is unknown.
    """
    _validate_session_id(session_id)
    log_dir = _resolve_log_dir(log_dir)
    if protocol == "ftp":
        ip, raw = _load_ftp_session(session_id, log_dir)
    elif protocol == "telnet":
        ip, raw = _load_telnet_session(session_id, log_dir)
    else:
        raise ValueError(f"unknown protocol: {protocol!r}")
    out = _build_timeline(session_id, ip, raw)
    out["protocol"] = protocol
    return out


def replay_index(log_dir=None):
    """List captured sessions (FTP + Telnet) newest first.

    Output: list of {session_id, ip, protocol, started_at_mtime, event_count}.
    `event_count` is bytes for FTP (rough proxy) or message count for Telnet.
    Cached for 5 seconds — repeated dashboard polls don't re-walk logs/.
    """
    log_dir = _resolve_log_dir(log_dir)
    now = _time.monotonic()
    dmtime = _dir_mtime(log_dir)
    with _cache_lock:
        if (_index_cache["dir"] == log_dir
                and _index_cache["data"] is not None
                and now - _index_cache["at"] < _INDEX_CACHE_TTL
                and _index_cache["dir_mtime"] == dmtime):
            # Shallow copy so callers can sort/mutate without corrupting the cache.
            return list(_index_cache["data"])

    out = []
    # FTP — per-session log files on disk
    try:
        names = os.listdir(log_dir)
    except OSError:
        names = []
    prefix, suffix = "ftp_session_", ".log"
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
            "ip": _SESSION_TIME_SUFFIX_RE.sub("", session_id),
            "protocol": "ftp",
            "started_at_mtime": datetime.fromtimestamp(
                st.st_mtime, tz=timezone.utc).isoformat(),
            "event_count": st.st_size,
        })

    # Telnet — one row per IP with all attempts rolled up. Per-attempt session_ids
    # (e.g. "1.2.3.4_120000") still load via _load_telnet_session for drill-down.
    for ip, info in _group_telnet_by_ip(log_dir).items():
        out.append({
            "session_id": f"{_TELNET_AGG_PREFIX}{ip}",
            "ip": ip,
            "protocol": "telnet",
            "started_at_mtime": datetime.fromtimestamp(
                info["first_ms"] / 1000, tz=timezone.utc).isoformat(),
            "event_count": len(info["raw"]),
            "attempts": info["attempts"],
        })

    out.sort(key=lambda r: r["started_at_mtime"], reverse=True)
    with _cache_lock:
        _index_cache.update({"at": now, "data": out, "dir": log_dir, "dir_mtime": dmtime})
    return list(out)


def _intel_path(ip, log_dir):
    # Match the writer at netwatch.py:2294 — only "." is flattened.
    # IPv6 with ":" in the filename works on Linux but is a known v1 gap.
    safe = ip.replace(".", "_")
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
