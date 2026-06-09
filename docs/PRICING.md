# NetWatch — Pricing & Tier Plan

> Current as of 2026-06-06. Anchored against paid OSINT / honeypot / SIEM tools so the value gap is explicit.

## Competitor pricing (annual)

| Tool | Tier | Annual cost | What you get |
|---|---|---|---|
| Thinkst Canary | per device | **$7,500/yr** | 1 honeypot, alerts, no SIEM |
| Shodan | Corporate | $13,188/yr | Internet-wide search |
| Shodan | Small Biz | $3,588/yr | 10k IPs/month |
| Shodan | Freelancer | $708/yr | 1k IPs/month |
| GreyNoise | Enterprise | **$13,000+/yr** | Internet noise tagging |
| AbuseIPDB | Premium | $2,400/yr | 1M IP lookups |
| DomainTools | Pro | $3,000+/yr | Whois/DNS history |
| Maltego | Pro | $1,999/yr | OSINT graph, 1 seat |
| VirusTotal | Premium | $10,000+/yr | File/URL intel |
| Recorded Future | Standard | **$50,000+/yr** | Full TI feeds |
| ThreatConnect | Pro | $25,000+/yr | Platform + TI |
| Censys | Standard | $5,000+/yr | Asset surface |
| Splunk Cloud | per GB | **$1,800/GB/yr** | SIEM ingest |
| Datadog Security | per host | $180/host/yr | SIEM + observability |
| Sentinel | per GB | ~$2/GB | Azure SIEM |
| CrowdSec | per agent | $60/agent/yr | Block list + agent |
| T-Pot / Cowrie | OSS | $0 (DIY) | No support, no UI |

A mid-size SOC already spends **$30k–$80k/yr** stitching these together. NetWatch undercuts by 10-50× and still leaves margin.

---

## Tier matrix

### Free — $0
**Sticky baseline. Drives Pro upgrade when users want to ACT on alerts.**

- 4 honeypot listeners (HTTP / Telnet / FTP / RTSP)
- Cat-video tarpit (rate-limited, looped MP4)
- Session replay viewer (read-only, no export)
- TUI + web dashboard, **1 node only**
- **24-hour log retention cap** ← upgrade trigger
- **1 generic NVR personality** ← upgrade trigger when scanners ignore it
- Local iptables blocking only
- Telnet aggregation
- Community Discord support
- AGPL-3.0 license (open source)

### Pro — $15/mo or $144/yr ($12/mo annual)
**Solo ops, hobbyist, security researcher. Replaces Shodan Freelancer + AbuseIPDB API ≈ $3k/yr saved.**

Everything in Free, plus:
- Unlimited log retention + S3/local archive
- **5 personalities**: Dahua, Hikvision, Cisco IOS, MikroTik RouterOS, Synology NAS
- **Replay export**: GIF (already wired) + JSON + PCAP per session
- CrowdSec community blocklist auto-sync (millions of malicious IPs)
- **Webhooks**: Slack, Discord, Teams, generic JSON, PagerDuty
- Threat intel lookups: AbuseIPDB + VirusTotal (cached, your API keys)
- Email alerts (SMTP, AWS SES, SendGrid)
- Signed PDF incident reports (Ed25519)
- Canary tokens (basic): leak monitor for GitHub + Pastebin
- **3 nodes** (basic fleet aggregation)
- Commercial license
- Email support, 72h SLA

### Business — $79/mo or $790/yr
**SOC team, MSSP starter. Replaces Splunk add-on + AbuseIPDB + DomainTools ≈ $15k/yr saved.**

Everything in Pro, plus:
- **25 nodes** in fleet
- **SIEM integrations**: Splunk HEC, Microsoft Sentinel, Datadog, Elasticsearch, generic Syslog
- Attack correlation: "same credential tried at 5+ honeypots in 1h" pattern alerts
- MISP + STIX 2.1 export
- AI session summary (Anthropic / OpenAI / Ollama — your keys)
- Geo-block (MaxMind GeoLite2 country allow/deny pre-filter)
- Advanced canary: credit-card-shaped strings, fake API keys, decoy files with beacons
- Slack/Discord auto-PR daily intel digest channel post
- Custom dashboards (saved queries)
- Priority email support, **24h SLA**
- Onboarding call (30 min)

### Enterprise — starts $10k+/yr (custom quote)
**MSP, government, large corp. Comparable to Thinkst Canary ($7.5k × n devices), Recorded Future ($50k+), or DIY at ~$100k/yr salaried.**

Everything in Business, plus:
- **Unlimited nodes** (fleet, multi-region)
- **Multi-tenant**: MSP carves up nodes by customer with separate dashboards
- **SAML/SSO** (Okta, Azure AD, Google Workspace, generic SAML 2.0)
- **RBAC + audit log** (who-saw-what trail)
- **Air-gapped license** (no phone-home, perpetual cryptographically-signed)
- **Custom personality builder**: record real device responses → instant honeypot persona
- **On-prem connectors**: SIEM/SOAR with field-mapping UI (Splunk apps, Sentinel data connectors, IBM QRadar)
- **Compliance pack**: SOC 2 evidence binder, HIPAA mapping, NIST 800-53 control matrix
- Dedicated Slack channel + 24/7 support + on-call escalation
- Optional: red team engagement, custom feature dev

---

## Tier comparison summary

| Lever | Free | Pro | Business | Enterprise |
|---|---|---|---|---|
| Cost vs alternatives | $0 | 1/20 of Shodan SB | 1/10 of Thinkst+Splunk | 1/5 of Recorded Future |
| Friction to upgrade | 24h retention wall hits daily | 3-node ceiling | 25-node ceiling | Sales-led |
| Target user | Hobbyist, researcher | Solo SOC, indie hacker | SMB SOC, MSSP starter | Enterprise SOC, gov, MSP |
| Acquisition channel | OSS / SEO / Twitter | OSS conversion | Pro upsell | Direct sales / referral |
| Conversion goal | 2-3% Free → Pro | 5-10% Pro → Business | 1-2% Business → Enterprise | — |

---

## Revenue model (10k installs, year 1)

- 10,000 Free installs × 2% → 200 Pro × $144/yr = **$28,800/yr**
- 200 Pro × 5% → 10 Business × $790/yr = **$7,900/yr**
- 10 Business × 10% → 1 Enterprise × $15k avg = **$15,000/yr**
- **Total ARR: ~$51k/yr**

Year 2 with 30k installs at same conversion rates → ~$153k/yr ARR.
