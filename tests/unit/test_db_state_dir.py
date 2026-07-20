"""_resolve_state_dir() must never try to write inside a read-only package
install (pip site-packages, PyInstaller _MEIPASS) -- it should fall back to
~/.ocinferno there, while keeping the existing dev-checkout location (next to
pyproject.toml) unchanged."""
from __future__ import annotations

from pathlib import Path

from ocinferno.core import db as db_module


def _fake_package_dir(tmp_path, *, with_pyproject: bool) -> Path:
    repo_root = tmp_path / "ocinferno"
    package_dir = repo_root / "ocinferno"
    (package_dir / "core").mkdir(parents=True)
    if with_pyproject:
        (repo_root / "pyproject.toml").write_text("")
    return package_dir


def test_env_override_wins(monkeypatch, tmp_path):
    custom = tmp_path / "custom-home"
    monkeypatch.setenv("OCINFERNO_HOME", str(custom))
    assert db_module._resolve_state_dir() == custom


def test_writable_dev_checkout_uses_package_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("OCINFERNO_HOME", raising=False)
    package_dir = _fake_package_dir(tmp_path, with_pyproject=True)
    monkeypatch.setattr(db_module, "__file__", str(package_dir / "core" / "db.py"))

    assert db_module._resolve_state_dir() == package_dir


def test_missing_pyproject_falls_back_to_home(monkeypatch, tmp_path):
    monkeypatch.delenv("OCINFERNO_HOME", raising=False)
    package_dir = _fake_package_dir(tmp_path, with_pyproject=False)
    monkeypatch.setattr(db_module, "__file__", str(package_dir / "core" / "db.py"))
    fake_home = tmp_path / "fakehome"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    assert db_module._resolve_state_dir() == fake_home / ".ocinferno"


def test_non_writable_package_dir_falls_back_to_home(monkeypatch, tmp_path):
    monkeypatch.delenv("OCINFERNO_HOME", raising=False)
    package_dir = _fake_package_dir(tmp_path, with_pyproject=True)
    monkeypatch.setattr(db_module, "__file__", str(package_dir / "core" / "db.py"))
    monkeypatch.setattr(db_module.os, "access", lambda path, mode: False)
    fake_home = tmp_path / "fakehome2"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    assert db_module._resolve_state_dir() == fake_home / ".ocinferno"
