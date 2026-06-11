"""Free-tier `doctor` command — dependency + environment self-check."""
import re

import netwatch


def _run_doctor(monkeypatch):
    out = []
    monkeypatch.setattr(netwatch, "add_console", lambda *a, **k: out.append(a[0] if a else ""))
    netwatch._disp_doctor([])
    return "\n".join(re.sub(r"\x1b\[[0-9;]*m", "", line) for line in out)


def test_doctor_reports_env_and_deps(monkeypatch):
    text = _run_doctor(monkeypatch)
    assert "Env:" in text
    assert "flask" in text          # a required pip dep is listed
    assert "nmap" in text           # a system tool is listed
    assert "cloudflared" in text    # tunnel tool surfaced


def test_doctor_flags_passive_when_no_root(monkeypatch):
    monkeypatch.setattr(netwatch, "HAS_RAW_NET", False)
    text = _run_doctor(monkeypatch)
    assert "PASSIVE" in text


def test_doctor_handler_is_registered():
    assert callable(netwatch._disp_doctor)
