# NetWatch — Release Roadmap

> Current as of 2026-06-06. Tier definitions and pricing rationale live in [PRICING.md](PRICING.md).

## v1.2.0 — shipped 2026-06-05
- Session replay viewer (web + TUI)
- Telnet aggregation (`all_<ip>`) with per-attempt drill-down
- CrowdSec auto-ban integration
- Scan tab — HTTP probes split from honeypot tab
- Honeypot ports via env (`NETWATCH_*_PORT`)
- Cat-video tarpit (RTSP + HTTP fake-cam)
- Red team fixes: ANSI/control-char stripper, `_group_telnet_by_ip` cache, session_id IP validation, gap-clamp, lock for `_replay_last_index`
- 2094 tests passing

## v1.3.0 — 4-6 weeks (Pro alpha, first paying users)
- License key system (Ed25519, already drafted in netwatch-pro)
- 5 honeypot personalities (Dahua, Hikvision, Cisco IOS, MikroTik RouterOS, Synology NAS)
- Replay export (GIF/JSON/PCAP) gated behind Pro
- Webhooks (Slack/Discord/Teams) gated behind Pro
- Free-tier 24h log retention cap
- Pricing page live at netwatch-sec.com
- Stripe checkout + license issuance pipeline
- CrowdSec community blocklist sync

## v1.4.0 — 8-10 weeks (Business beta, SOC integrations)
- Splunk HEC + Microsoft Sentinel + Datadog + Elasticsearch connectors
- Attack-pattern correlation engine (same-cred-multi-honeypot detection)
- MISP + STIX 2.1 export gated behind Business
- AI session summary (Anthropic / OpenAI / Ollama)
- Fleet view (3 nodes Pro / 25 nodes Business)
- Email alerts (SMTP/SES/SendGrid)
- AbuseIPDB + VirusTotal cached lookups
- Geo-block via MaxMind GeoLite2

## v2.0.0 — 16-20 weeks (Enterprise GA)
- SAML/SSO + RBAC + audit log
- Multi-tenant fleet (MSP carve-up)
- Air-gapped license mode
- Custom personality builder UI (record real device → replay)
- Compliance documentation pack (SOC 2, HIPAA, NIST 800-53)
- Modular refactor — split netwatch.py into a package
- Public PyPI extras: `netwatch-sec[pro]`, `netwatch-sec[business]`, `netwatch-sec[enterprise]`
- On-prem SIEM/SOAR connectors with field-mapping UI

## Backlog (unscheduled)
- HTTPS GeoIP (local MaxMind DB option instead of `http://ip-api.com`)
- Honeypot bind-interface env var (security hardening — don't bind 0.0.0.0 by default)
- Replay end-of-session badge in web viewer (deferred from 1.2.0)
- Web replay incremental cursor render perf (deferred from 1.2.0)
- Mobile-responsive web dashboard
- Honeypot personality builder CLI scaffolding (precursor to v2 UI)
