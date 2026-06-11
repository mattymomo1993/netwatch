"""Meshtastic connect: env-port override, surfaced failures, no-device path."""
import glob
from unittest.mock import MagicMock

import netwatch


def test_mesh_not_installed(monkeypatch):
    monkeypatch.setattr(netwatch, "_HAS_MESH", False)
    monkeypatch.setattr(netwatch, "mesh_interface", None)
    assert netwatch._mesh_connect() is False
    assert "meshtastic" in netwatch._mesh_last_error.lower()


def test_mesh_env_port_override(monkeypatch):
    monkeypatch.setattr(netwatch, "_HAS_MESH", True)
    monkeypatch.setattr(netwatch, "add_console", lambda *a, **k: None)
    monkeypatch.setattr(netwatch, "mesh_interface", None)
    serial_mod = MagicMock()
    serial_mod.SerialInterface.return_value = MagicMock()
    monkeypatch.setattr(netwatch, "_mesh_serial", serial_mod, raising=False)
    monkeypatch.setenv("NETWATCH_MESH_PORT", "/dev/ttyACM9")

    assert netwatch._mesh_connect() is True
    serial_mod.SerialInterface.assert_called_once_with("/dev/ttyACM9")


def test_mesh_no_device_surfaces_error(monkeypatch):
    monkeypatch.setattr(netwatch, "_HAS_MESH", True)
    monkeypatch.setattr(netwatch, "add_console", lambda *a, **k: None)
    monkeypatch.setattr(netwatch, "mesh_interface", None)
    monkeypatch.delenv("NETWATCH_MESH_PORT", raising=False)
    monkeypatch.setattr(glob, "glob", lambda pattern: [])

    assert netwatch._mesh_connect() is False
    assert "no serial device" in netwatch._mesh_last_error.lower()


def test_mesh_open_failure_surfaces_error(monkeypatch):
    monkeypatch.setattr(netwatch, "_HAS_MESH", True)
    monkeypatch.setattr(netwatch, "add_console", lambda *a, **k: None)
    monkeypatch.setattr(netwatch, "mesh_interface", None)
    monkeypatch.delenv("NETWATCH_MESH_PORT", raising=False)
    monkeypatch.setattr(glob, "glob",
                        lambda pattern: ["/dev/ttyACM0"] if "ACM" in pattern else [])
    serial_mod = MagicMock()
    serial_mod.SerialInterface.side_effect = OSError("port busy")
    monkeypatch.setattr(netwatch, "_mesh_serial", serial_mod, raising=False)

    assert netwatch._mesh_connect() is False
    assert "could not open" in netwatch._mesh_last_error.lower()
