"""Cross-platform cloudflared: detection, arch mapping, install gate."""
import platform

import netwatch


def test_arch_mapping(monkeypatch):
    for machine, expect in [("x86_64", "amd64"), ("aarch64", "arm64"),
                            ("armv7l", "arm"), ("i686", "386")]:
        monkeypatch.setattr(platform, "machine", lambda m=machine: m)
        assert netwatch._cloudflared_arch() == expect


def test_find_prefers_path(monkeypatch):
    monkeypatch.setattr(netwatch.shutil, "which", lambda n: "/usr/bin/cloudflared")
    assert netwatch._find_cloudflared_bin() == "/usr/bin/cloudflared"


def test_find_env_override(monkeypatch, tmp_path):
    monkeypatch.setattr(netwatch.shutil, "which", lambda n: None)
    f = tmp_path / "cf"
    f.write_text("x")
    monkeypatch.setenv("NETWATCH_CLOUDFLARED_BIN", str(f))
    assert netwatch._find_cloudflared_bin() == str(f)


def test_find_none_when_absent(monkeypatch):
    monkeypatch.setattr(netwatch.shutil, "which", lambda n: None)
    monkeypatch.delenv("NETWATCH_CLOUDFLARED_BIN", raising=False)
    monkeypatch.delenv("PREFIX", raising=False)
    monkeypatch.setattr(netwatch.os.path, "isfile", lambda p: False)
    assert netwatch._find_cloudflared_bin() is None


def test_install_hint_includes_arch(monkeypatch):
    monkeypatch.setattr(platform, "machine", lambda: "aarch64")
    hint = netwatch._cloudflared_install_hint()
    assert "arm64" in hint and "cloudflared" in hint


def test_tunnel_install_is_confirm_gated(monkeypatch):
    out = []
    monkeypatch.setattr(netwatch, "add_console", lambda *a, **k: out.append(a[0] if a else ""))
    monkeypatch.setattr(netwatch, "_find_cloudflared_bin", lambda: None)
    monkeypatch.setattr(netwatch, "_tunnel_url", "")
    called = {"dl": 0}
    monkeypatch.setattr(netwatch, "_download_cloudflared",
                        lambda: (called.__setitem__("dl", called["dl"] + 1), "/x")[1])

    netwatch._disp_show_tunnel(["tunnel"])          # plain: must NOT download
    assert called["dl"] == 0
    netwatch._disp_show_tunnel(["tunnel", "install"])  # explicit: downloads
    assert called["dl"] == 1
