from __future__ import annotations

import os
import sys
import tempfile
import types
from pathlib import Path


def _install_oci_stub() -> None:
    if "oci" in sys.modules:
        return

    class _DynamicStub:
        def __init__(self, name: str = "stub"):
            self._name = name

        def __getattr__(self, item: str):
            return _DynamicStub(f"{self._name}.{item}")

        def __call__(self, *args, **kwargs):
            return _DynamicStub(f"{self._name}()")

    oci_mod = types.ModuleType("oci")
    util_mod = types.ModuleType("oci.util")
    util_mod.to_dict = lambda obj: obj
    oci_mod.util = util_mod
    oci_mod.__getattr__ = lambda attr: _DynamicStub(f"oci.{attr}")

    sys.modules["oci"] = oci_mod
    sys.modules["oci.util"] = util_mod


_install_oci_stub()

from ocinferno.core.session import SessionUtility


def test_default_api_log_path_does_not_create_output_dirs():
    original_cwd = Path.cwd()
    try:
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)

            session = SessionUtility.__new__(SessionUtility)
            session.workspace_id = 1
            session.workspace_name = "TEST"

            expected = Path(td) / "ocinferno_output" / "1_TEST" / "tool_logs" / "telemetry_api.log"
            resolved = Path(session._default_api_log_path())

            assert resolved == expected
            assert not (Path(td) / "ocinferno_output").exists()
    finally:
        os.chdir(original_cwd)
