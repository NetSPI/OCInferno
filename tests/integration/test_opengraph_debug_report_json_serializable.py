from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

from tests.integration.opengraph_test_harness import IntegrationTestDataController, OpenGraphTestSession

# Only stub the ANTLR-backed parser package when it's genuinely not installed --
# unconditionally installing a fake module here would permanently shadow the real
# oci_lexer_parser for the rest of the pytest session for any other test file that
# needs the real one (e.g. tests/unit/test_config_audit.py's identity-policy tests).
try:
    import oci_lexer_parser  # noqa: F401
except ImportError:
    parser_stub = types.ModuleType("oci_lexer_parser")
    parser_stub.parse_dynamic_group_matching_rules = lambda *_a, **_k: []
    parser_stub.parse_policy_statements = lambda *_a, **_k: []
    sys.modules["oci_lexer_parser"] = parser_stub

from ocinferno.modules.opengraph.processing.process_oracle_cloud_hound_data import run_module

WORKSPACE_ID = 7373
TENANCY_OCID = "ocid1.tenancy.oc1..testtenant"
COMPARTMENT_ID = "ocid1.compartment.oc1..testcompartment"


class TestOpenGraphDebugReportJsonSerializable(unittest.TestCase):
    """`--debug-report` must produce valid JSON.

    build_idd_app_role_graph_offline's default run always sets
    `res["allowlist"] = DEFAULT_ALLOWLIST` (a frozenset of (app_id, role_name)
    tuples) regardless of whether any IDD app-role data exists, and that dict
    flows straight into process_oracle_cloud_hound_data's `--debug-report`
    output via `builder_stats["identity_domains"]["app_roles"]`. json.dumps()
    cannot serialize a frozenset, so the allowlist must be converted to a
    JSON-native type before it reaches the debug report, even against an empty
    tenancy where the main graph JSON would otherwise write fine on its own.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_path = Path(self._tmp.name)
        self.dc = IntegrationTestDataController(self._tmp_path)
        self.assertTrue(self.dc.create_service_tables_from_schema())
        self.session = OpenGraphTestSession(
            self.dc,
            workspace_id=WORKSPACE_ID,
            workspace_name="test",
            compartment_id=COMPARTMENT_ID,
            tenant_id=TENANCY_OCID,
            output_root=self._tmp_path / "exports",
        )

    def tearDown(self):
        self.dc.close()
        self._tmp.cleanup()

    def test_debug_report_is_valid_json_against_empty_tenancy(self):
        out_path = self._tmp_path / "graph.json"
        run_module(["--debug-report", "--out", str(out_path)], self.session)

        debug_path = out_path.with_suffix(out_path.suffix + ".debug.json")
        self.assertTrue(debug_path.exists(), "expected a .debug.json file alongside --out")

        report = json.loads(debug_path.read_text(encoding="utf-8"))
        allowlist = report["builder_stats"]["identity_domains"]["app_roles"]["allowlist"]
        self.assertIsInstance(allowlist, list)
        self.assertTrue(all(isinstance(pair, list) for pair in allowlist))
