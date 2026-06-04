# Drop #4 — TUI Session Replay (Plan)

Branch: `feature/session-replay`
Status: not started; web replay (Drop #3) is live but has 4 missing controls per spec.
Companion plan: pricing/tier work lives in `pro_beta/PRICING_PLAN_v2.md` and does NOT block this.

This file is the working spec for finishing the AGPL replay viewer in the TUI. It is the engineering plan, not a feature list.

---

## 1. Context

The replay viewer is NetWatch's hero feature for the AGPL beta launch. The 5-drop cadence stands at:

- ✅ Drop #1 — FTP per-connect logs (commit `3ea6a8e`)
- ✅ Drop #2 — `replay.py` data layer (commit `bb053e8`)
- ✅ Drop #3 — Web UI: index, scrubbable player, intel sidebar (commit `6337c16`)
- 🟡 **Drop #4 — TUI parity** *(this plan)*
- 🟡 Drop #5 — Dual-pane sync (filesystem state evolution as attacker scrubs)

Diagnosis on Drop #3 (this session) confirmed the web data layer is healthy. The web player is missing the step / jump / boundary / speed-step controls — those land in this plan too because TUI parity has to match a web that actually has them.

---

## 2. Hook points in `netwatch.py`

| Area | Line(s) | What changes |
|---|---|---|
| `SCREEN_DASHBOARD` constants | 2423–2426 | add `SCREEN_REPLAY = "replay"`; append to `SCREENS` |
| `AppState` dataclass | 2446–2484 | add replay fields (see §3) |
| `handle_command()` dispatch | 2659+ | add `replay [session_id]` command that loads via `replay.replay_loader()` and switches screen |
| Screen switch logic | 2782+ | add `SCREEN_REPLAY` arm to switch chain |
| Render loop | (existing `_render_frame()`) | route to new `_paint_replay()` when current screen is replay |
| Key handler | (existing `_read_key()` / key dispatch) | replay-specific bindings active only when `current_screen == SCREEN_REPLAY` |
| Web parity | 6090–6208 (`_REPLAY_PLAYER_HTML`) | small JS additions for the 4 missing controls |

No edits to `replay.py`. All playback logic stays in the data layer.

---

## 3. New `AppState` fields

```
# replay state (None when not in replay screen)
replay_session_id: str | None = None
replay_protocol: str = "ftp"             # "ftp" | "telnet"
replay_timeline: dict | None = None      # the dict returned by replay.replay_loader()
replay_cursor_ms: int = 0                # current playback cursor
replay_playing: bool = False
replay_speed: float = 1.0                # 0.25 / 0.5 / 1 / 2 / 4 / 8
replay_last_tick: float = 0.0            # monotonic seconds since last advance
```

`switch()` already handles `needs_clear`. When switching away from `SCREEN_REPLAY`, leave `replay_*` populated so returning to it via `replay` with no args resumes — same UX as CLI/console scroll restore.

---

## 4. `_paint_replay()` — render contract

Renders the same three regions the web has, terminal-styled:

```
┌─ HEADER ────────────────────────────────────────────────────────────────────┐
│ session 127.0.0.1_093945  ·  ip 127.0.0.1  ·  ftp  ·  dur 00:01 / events 3  │
├─ EVENT STREAM ─────────────────────────────────┬─ INTEL ────────────────────┤
│ 00:00  SERVER         220 banner sent          │ IP       198.51.100.4      │
│ 00:00  CLIENT         LIST                     │ Country  RU                │
│ ▶00:01 SESSION_END    closed                   │ ASN      AS12345           │
│        (future events dimmed)                   │ Abuse    97               │
│                                                 │ Tags     scanner, brute   │
│                                                 │                            │
├─ FOOTER ────────────────────────────────────────┴────────────────────────────┤
│ [▶] 1.0x  ◀━━━━━━━━━━●━━━━━━━━━━━━▶  00:01 / 00:01    space/←→/</>/+-/home/end│
└──────────────────────────────────────────────────────────────────────────────┘
```

Implementation: reuse the existing box-drawing helpers (`_section_*`, the dashboard's right-pane patterns). Cursor row is the most recent event with `t_ms ≤ replay_cursor_ms`. Future events render at half-intensity (ANSI dim).

Intel pane: identical fields to the web sidebar. Empty intel shows the same "Run `recon` from the dashboard" hint.

Edge cases:
- `replay_timeline is None` → "no session loaded; type `replay <session_id>` to load."
- Empty `events` array (banner-only session) → "no events captured."
- `duration_ms == 0` → progress bar shows full, no playback advance.

---

## 5. Key bindings (active only on `SCREEN_REPLAY`)

| Key | Action |
|---|---|
| `space` | toggle play/pause |
| `←` | cursor −1s |
| `→` | cursor +1s |
| `<` | cursor −10s |
| `>` | cursor +10s |
| `home` | cursor = 0 |
| `end` | cursor = duration_ms |
| `+` / `=` | speed up one step (0.25 → 0.5 → 1 → 2 → 4 → 8) |
| `-` / `_` | speed down one step |
| `q` or `esc` | switch back to `last_screen` |
| `?` | overlay help (reuses existing help renderer) |

Playback tick: when `replay_playing == True`, the render loop's `_redraw_event.wait(0.1)` is sufficient. Each frame: `dt = (now - last_tick) * speed; cursor_ms += int(dt * 1000)`. Clamp to `duration_ms`; stop on reach.

---

## 6. `handle_command()` additions

```
replay                    # resume last session or show index
replay <session_id>       # load FTP session and switch screen
replay <session_id> telnet # load Telnet protocol
replay list               # print session index in console (mirrors /api/replay)
```

Resolution path:
1. Validate session_id against `replay.SESSION_ID_RE`.
2. Call `replay.replay_loader(sid, protocol=...)` — catches `FileNotFoundError` and `ValueError`.
3. Call `replay.load_intel(timeline['ip'])`.
4. Store both on `app_state.replay_timeline` (intel attached on the dict under `intel`, matching web shape).
5. `app_state.switch(SCREEN_REPLAY)` and reset `replay_cursor_ms = 0`.

`replay list` just renders `replay.replay_index()` into the existing console output buffer — no new screen.

---

## 7. Web parity — finish the 4 missing controls

Same control set as TUI, added to `_REPLAY_PLAYER_HTML` JS (netwatch.py:6149–6207):

- `keydown` handlers for `ArrowLeft`/`ArrowRight` (±1s), `<`/`>` (±10s), `Home`/`End` (boundaries), `+`/`-` (speed step through the same six speeds).
- Add two visible speed-step buttons (`⏪` and `⏩`) so it's not keyboard-only.
- Speed indicator updates on every step.

Pure JS edit, ~30 lines added. No backend change, no risk to SSE.

---

## 8. Test plan

`tests/test_replay.py` already covers the data layer (29 tests). Adds:

- `tests/test_replay_web.py` — Flask test client against `/api/replay`, `/api/replay/<sid>` (200/400/404, intel attachment, `?proto=telnet` whitelist).
- `tests/test_replay_tui.py` — exercises `_paint_replay()` against a synthetic `AppState` with a known timeline; asserts cursor row markup, future dimming, footer time format, speed display.

Baseline: existing 1842 tests must stay green. Run after each step:
```
cd ~/agents/honeypot && python3 -m pytest tests/ -q
```

---

## 9. Step sequence (small, independently testable, harvestable as commits)

1. **Add `SCREEN_REPLAY` constant + `AppState` fields.** No behavior change yet. Tests: existing suite green.
2. **Add `replay list` command** (data only, prints index to console). Tests: integration test on output.
3. **Add `_paint_replay()` + screen switch** (renders static cursor, no playback). Tests: snapshot of frame against fixture timeline.
4. **Add keyboard bindings + playback tick** (space/←/→/</>/+/-/home/end). Tests: simulate key sequence, assert cursor advances.
5. **Web parity for the 4 missing controls.** JS-only edit. Manual browser smoke + a Selenium-free check that the keys reach the handlers.
6. **Add web + TUI integration tests** (`test_replay_web.py`, `test_replay_tui.py`).
7. **Update `README.md`** with the replay quickstart (TUI command + web URL). One paragraph.

Each step is a candidate for its own commit, per `organic-commits` rule — user harvests when ready, no auto-commits from this session.

---

## 10. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Adding a screen breaks dashboard render loop | Build `_paint_replay()` in parallel; don't change `_render_frame()` dispatch until the new painter exists and is tested via direct call |
| Key conflicts with global TUI shortcuts (`q`, `?`, arrows) | Bindings gated on `app_state.current_screen == SCREEN_REPLAY`; outside that screen, all existing bindings unchanged |
| Heavy timeline blocks render | `replay.replay_loader()` is already O(events); cached on `AppState` after load — render reads the cached dict only |
| Telnet sessions have no real data on disk | The grouping function returns `{}` cleanly; UX shows "no session loaded" — already handled |
| Live SSE / dashboard regression | Replay code paths are isolated; no shared globals touched. Tests will assert SSE stream still streams |

Rollback path: every step is additive. Revert the last commit on the feature branch — no data migration, no schema change.

---

## 11. Out of scope for Drop #4

- Dual-pane filesystem state evolution (that's Drop #5).
- Annotation / bookmarking.
- Multi-session diff.
- Exporting replay to MP4 / asciinema.
- Live in-flight replay (replay only captures finished sessions).

---

## 12. Commit-time hints (for the operator — copy/paste only when ready)

```
cd ~/agents/honeypot
git checkout feature/session-replay
git status
# stage each step as its own commit; example for step 1:
git add netwatch.py
git commit -m "replay: SCREEN_REPLAY + AppState fields (no behavior change)"
# do NOT push until tests are green AND the step renders as expected
```

Nothing in this plan touches main. Nothing here is a Pro feature — the entire replay viewer ships AGPL-free (see `pro_beta/PRICING_PLAN_v2.md` §10 open question #5).
