# Security Policy

NetWatch is a defensive network-security tool. We take its own security seriously and welcome reports from the research community.

## Supported Versions

| Version | Supported           |
| ------- | ------------------- |
| 1.1.x   | :white_check_mark:  |
| < 1.1   | :x:                 |

Only the latest 1.1.x release receives security fixes. We recommend running the most recent version from PyPI (`pip install -U netwatch-sec`) or from `main`.

## Reporting a Vulnerability

**Please do not report security issues in public GitHub issues, pull requests, or discussions.**

### Preferred channel

Open a private advisory via GitHub Security Advisories:

> https://github.com/Mattmorris-dev/netwatch-sec/security/advisories/new

This creates a private thread between you and the maintainers, supports CVE issuance, and is the fastest path to a fix.

### Email fallback

If you cannot use GitHub, email: **matthewjmorris1993@gmail.com**
Subject line: `[netwatch-sec security] <short title>`

PGP not currently offered — send plaintext, we will not publish your report.

### What to include

- NetWatch version (`netwatch --version` or check `netwatch.py` `VERSION` constant)
- Operating system + Python version
- Clear steps to reproduce, ideally with a minimal proof-of-concept
- Impact assessment (what an attacker gains)
- Any suggested mitigation

### What NOT to do

- Do not run proofs-of-concept against third-party hosts, scanners, or honeypots you do not own or have explicit permission to test.
- Do not exfiltrate data beyond what is strictly necessary to demonstrate the issue.
- Do not perform denial-of-service testing against public NetWatch instances.

## Response Timeline

NetWatch is maintained by a small team / solo author. We aim for:

- **Acknowledgement:** within 3 business days
- **Triage + severity rating:** within 7 business days
- **Fix or mitigation:** as soon as practical, prioritized by severity

These are targets, not guarantees. If you have not heard back in 14 days, escalate by emailing again with `[follow-up]` in the subject.

## Disclosure

We follow coordinated disclosure:

1. Reporter sends details privately.
2. Maintainer triages, confirms, and develops a fix.
3. Fix is released; an advisory + CVE (where applicable) is published.
4. Reporter is credited in the advisory and in this repository's acknowledgements section, unless they request anonymity.

We aim to publish advisories within **90 days** of the initial report. If a fix is not yet available at that point, we will coordinate with the reporter on next steps.

## Scope

### In scope

- Authentication bypass on the web dashboard (`:9090`)
- Remote code execution in honeypot services (HTTP `:8080`, Telnet `:2323`, FTP `:2121`, RTSP `:8554`)
- Server-side request forgery (SSRF) in OSINT commands
- Path traversal in FTP honeypot uploads or log handling
- Cross-site scripting (XSS) in the web dashboard
- Cross-site request forgery (CSRF) on state-changing endpoints
- Cryptographic weaknesses in session cookies, key derivation, or token handling
- Privilege escalation from the NetWatch user to root
- Sensitive data exposure (tokens, credentials, capture data) via the web API
- Dependency vulnerabilities with a clear exploit path through NetWatch

### Out of scope (by design)

- Attackers connecting to and interacting with the honeypot services — that is the entire point.
- Requirement that NetWatch runs as root for raw sockets, iptables, and low-port binding.
- Information disclosure from logs (`logs/`, `ftp_root/`) that the operator has chosen to expose.
- Self-XSS that requires the operator to type a payload into their own command bar.
- DNS rebinding against the default `0.0.0.0:9090` bind — operators are expected to firewall the admin port or place it behind a reverse proxy / SSH tunnel.
- Social engineering of maintainers, contributors, or users.
- Physical attacks against deployed sensors.
- Volumetric DDoS against the listener.

## Safe Harbor

We support good-faith security research. If you:

- Make a good-faith effort to avoid privacy violations, data destruction, and service disruption;
- Only interact with accounts, hosts, or data you own or have explicit permission to access;
- Report any vulnerability you discover promptly through the channels above;
- Do not exploit a vulnerability beyond what is necessary to confirm its presence;

...then we will not initiate or support legal action against you for that research. This safe harbor applies only to claims under our control; it does not bind third parties whose systems may be incidentally affected.

If you are unsure whether an activity is covered, ask first via the email above with `[scope question]` in the subject.

## Acknowledgements

Researchers who have responsibly disclosed issues will be listed here with their permission.

*(no entries yet — be the first)*

---

*Last updated: 2026-06-04*
