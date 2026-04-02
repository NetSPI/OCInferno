from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
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

from ocinferno.core.api_logger import ApiRequestLogger


class TestApiRequestLogger(unittest.TestCase):
    def test_basic_verbosity_includes_module_and_params(self):
        with tempfile.TemporaryDirectory() as td:
            log_file = Path(td) / "audit.jsonl"
            lg = ApiRequestLogger(workspace_id=7, workspace_slug="ws-7", credname="credA")
            lg.set_enabled(True)
            lg.set_log_path(str(log_file))
            lg.set_verbosity("basic")
            lg.set_run_context(run_id="run-abc")

            lg.record(
                service="network",
                operation="ListVcns",
                method="GET",
                url="https://iaas.us-ashburn-1.oraclecloud.com/20160918/vcns?compartmentId=ocid1.compartment.oc1..aaa",
                params={"query_params": {"compartmentId": "ocid1.compartment.oc1..aaa"}, "path_params": {}},
                status="200",
                duration_ms=321,
                opc_request_id="req-123",
                module_run="enum_core_network",
            )

            row = json.loads(log_file.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(row["module_run"], "enum_core_network")
            self.assertEqual(row["service"], "network")
            self.assertIn("params", row)
            self.assertEqual(row["run_id"], "run-abc")
            self.assertIn("event_id", row)
            self.assertIn("host", row)
            self.assertIn("user", row)
            self.assertIn("pid", row)
            self.assertNotIn("request_headers", row)
            self.assertNotIn("response_headers", row)

    def test_verbose_verbosity_includes_headers_and_redacts(self):
        with tempfile.TemporaryDirectory() as td:
            log_file = Path(td) / "audit.jsonl"
            lg = ApiRequestLogger(workspace_id=9, workspace_slug="ws-9", credname="credB")
            lg.set_enabled(True)
            lg.set_log_path(str(log_file))
            lg.set_verbosity("verbose")
            lg.set_run_context(run_id="run-xyz")

            lg.record(
                service="identity",
                operation="ListUsers",
                method="GET",
                url="https://identity.us-phoenix-1.oraclecloud.com/20160918/users",
                params={"query_params": {}, "path_params": {}},
                request_headers={
                    "Authorization": "Bearer really-long-secret-token",
                    "X-Api-Key": "abc123",
                    "X-Custom": "ok",
                },
                response_headers={
                    "opc-request-id": "req-999",
                    "etag": "foo",
                },
                status="200",
                duration_ms=51,
                module_run="enum_identity_users",
                retry_attempt=2,
                retry_max=4,
                retry_scheduled=True,
                event_type="oci_api_retry",
            )

            row = json.loads(log_file.read_text(encoding="utf-8").splitlines()[0])
            self.assertIn("request_headers", row)
            self.assertIn("response_headers", row)
            self.assertEqual(row["request_headers"]["Authorization"], "<redacted>")
            self.assertEqual(row["request_headers"]["X-Api-Key"], "<redacted>")
            self.assertEqual(row["request_headers"]["X-Custom"], "ok")
            self.assertEqual(row["module_run"], "enum_identity_users")
            self.assertEqual(row["event_type"], "oci_api_retry")
            self.assertEqual(row["retry_attempt"], 2)
            self.assertEqual(row["retry_max"], 4)
            self.assertEqual(row["retry_scheduled"], True)


if __name__ == "__main__":
    unittest.main()
