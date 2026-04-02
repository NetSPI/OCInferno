from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(autouse=True)
def _block_network_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent accidental outbound network calls across test runs."""
    if os.getenv("OCINFERNO_TEST_ALLOW_NETWORK", "").strip() == "1":
        return

    real_socket = socket.socket

    class _GuardedSocket(real_socket):
        def connect(self, address):  # type: ignore[override]
            if isinstance(address, tuple):
                raise AssertionError(f"network access blocked in tests: connect({address!r})")
            return super().connect(address)

        def connect_ex(self, address):  # type: ignore[override]
            if isinstance(address, tuple):
                raise AssertionError(f"network access blocked in tests: connect_ex({address!r})")
            return super().connect_ex(address)

    def _blocked_create_connection(*args, **kwargs):
        raise AssertionError(f"network access blocked in tests: create_connection(args={args!r}, kwargs={kwargs!r})")

    monkeypatch.setattr(socket, "socket", _GuardedSocket)
    monkeypatch.setattr(socket, "create_connection", _blocked_create_connection)
