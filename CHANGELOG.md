# Changelog

All notable changes to NetWatch are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.2.0 — 2026-06-05

### Added
- Session replay viewer (web + TUI) — scrubbable playback of captured attacker sessions.
- Same-IP telnet sessions roll up into one aggregated entry (`all_<ip>`) with visible `── ATTEMPT N ──` separator events; per-attempt drill-down still works via the original session_id.
- Honeypot tarpit — RTSP credential-capture handshake now streams a looped MP4 (`cat_loop.mp4` by default) at a rate-limited speed after auth; HTTP fake-cam endpoints (`/cam01.mp4`, `/video.mp4`, `/stream.mp4`, `/Streaming/Channels/<N>`, `/cgi-bin/snapshot.cgi`) trickle the same video. Configurable via `NETWATCH_TARPIT`, `NETWATCH_TARPIT_VIDEO`, `NETWATCH_TARPIT_RATE`, `NETWATCH_TARPIT_MAX_SEC`. Whitelisted IPs bypass.
- CrowdSec auto-ban integration — local `cscli` bridge, ipset-backed enforcement, 60s same-IP dedupe.
- Scan tab — HTTP probe events split off the honeypot tab so signal density stays high.
- Port configuration via env vars: `NETWATCH_HTTP_PORT`, `NETWATCH_TELNET_PORT`, `NETWATCH_FTP_PORT`, `NETWATCH_RTSP_PORT`.

### Security
- ANSI/control-char stripper applied to all attacker-influenced text in the replay UI (intel sidebar, event stream, session list) — defense vs `\x1b]52` clipboard hijack, screen wipe, fake-prompt class attacks.
- `_validate_session_id` now requires structural IP validation (`ipaddress.ip_address`) in addition to the regex shape check.
- `_group_telnet_by_ip` cached so unauthenticated `/api/replay/all_<random>` requests can't force repeated full log re-parses (DoS).
- `_index_cache` key now includes `NETWATCH_TELNET_GAP_SEC` so runtime env changes invalidate immediately.
- `NETWATCH_TELNET_GAP_SEC` clamped to 30-day max so absurd values can't OOM the renderer.

### Fixed
- Termux launcher — skip sudo re-exec on Android and fall through to passive mode.

## 1.1.0

Prior release. See git history for details.
