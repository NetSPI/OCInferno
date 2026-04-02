import copy
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

from tests.integration.opengraph_test_harness import IntegrationTestDataController, OpenGraphTestSession

WORKSPACE_ID = 5252
TENANCY_OCID = "ocid1.tenancy.oc1..testtenant"
COMPARTMENT_A = "ocid1.compartment.oc1..compa"
COMPARTMENT_B = "ocid1.compartment.oc1..compb"
DOMAIN_OCID = "ocid1.domain.oc1..testdomain"

INSTANCE_A = "ocid1.instance.oc1..insta"
INSTANCE_B = "ocid1.instance.oc1..instb"
INSTANCE_C = "ocid1.instance.oc1..instc"

RULE_INSTANCE_ID_A = "RULE_INSTANCE_ID_A"
RULE_INSTANCE_ID_B = "RULE_INSTANCE_ID_B"
RULE_INSTANCE_ID_MISSING = "RULE_INSTANCE_ID_MISSING"
RULE_TAG_ENV_PROD = "RULE_TAG_ENV_PROD"
RULE_TAG_TEAM_EXISTS = "RULE_TAG_TEAM_EXISTS"
RULE_RESOURCE_TYPE_INSTANCES = "RULE_RESOURCE_TYPE_INSTANCES"
RULE_MULTI_ID_A_B = "RULE_MULTI_ID_A_B"

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"


def _clause(lhs: str, op: str | None = None, rhs: dict | None = None) -> dict:
    node = {"lhs": lhs}
    if op is not None:
        node["op"] = op
    if rhs is not None:
        node["rhs"] = rhs
    return {"type": "clause", "node": node}


def _lit(value: str) -> dict:
    return {"type": "literal", "value": value}


def _all(*items: dict) -> dict:
    return {"type": "group", "mode": "all", "items": list(items)}


def _rules(*exprs: dict) -> dict:
    return {"rules": [{"expr": e} for e in exprs]}


_RULE_AST_MAP = {
    RULE_INSTANCE_ID_A: _rules(_all(_clause("resource.id", "eq", _lit(INSTANCE_A)))),
    RULE_INSTANCE_ID_B: _rules(_all(_clause("resource.id", "eq", _lit(INSTANCE_B)))),
    RULE_INSTANCE_ID_MISSING: _rules(
        _all(_clause("resource.id", "eq", _lit("ocid1.instance.oc1..doesnotexist")))
    ),
    RULE_TAG_ENV_PROD: _rules(_all(_clause("tag.team.env.value", "eq", _lit("prod")))),
    RULE_TAG_TEAM_EXISTS: _rules(_all(_clause("tag.team.env.value", "exists"))),
    RULE_RESOURCE_TYPE_INSTANCES: _rules(_all(_clause("resource.type", "eq", _lit("instance")))),
    RULE_MULTI_ID_A_B: _rules(
        _all(_clause("resource.id", "eq", _lit(INSTANCE_A))),
        _all(_clause("resource.id", "eq", _lit(INSTANCE_B))),
    ),
}


def _parse_dynamic_group_matching_rules_stub(rule_text, *_args, **_kwargs):
    return copy.deepcopy(_RULE_AST_MAP.get(str(rule_text or "").strip(), {"rules": []}))


# Stub parser symbols before importing OpenGraph runner.
parser_stub = sys.modules.get("oci_lexer_parser", types.ModuleType("oci_lexer_parser"))
parser_stub.parse_dynamic_group_matching_rules = _parse_dynamic_group_matching_rules_stub
parser_stub.parse_policy_statements = lambda *_a, **_k: []
sys.modules["oci_lexer_parser"] = parser_stub

from ocinferno.modules.opengraph.enumeration.enum_oracle_cloud_hound_data import run_module
from ocinferno.modules.opengraph.utilities.helpers import matching_rules_engine as _mre


def _compute_instance(
    inst_id: str,
    compartment_id: str,
    display_name: str,
    defined_tags: dict | str | None = None,
) -> dict:
    return {
        "id": inst_id,
        "compartment_id": compartment_id,
        "display_name": display_name,
        "defined_tags": defined_tags if defined_tags is not None else {},
        "lifecycle_state": "RUNNING",
    }


def _idd_dynamic_group(ocid: str, name: str, rule: str, compartment_ocid: str) -> dict:
    return {
        "id": f"scim::{name}",
        "ocid": ocid,
        "display_name": name,
        "matching_rule": rule,
        "compartment_ocid": compartment_ocid,
        "domain_ocid": DOMAIN_OCID,
        "tenancy_ocid": TENANCY_OCID,
        "delete_in_progress": "",
        "schemas": "[]",
        "tags": "[]",
    }


def _classic_dynamic_group(
    dg_id: str,
    name: str,
    rule: str,
    compartment_id: str | None = None,
) -> dict:
    row = {
        "id": dg_id,
        "name": name,
        "matching_rule": rule,
        "description": f"Obfuscated classic dynamic group fixture for {name}",
        "lifecycle_state": "ACTIVE",
        "inactive_status": "",
    }
    if compartment_id is not None:
        row["compartment_id"] = compartment_id
    return row


BASE_TABLES = {
    "resource_compartments": [
        {
            "compartment_id": TENANCY_OCID,
            "parent_compartment_id": "",
            "name": "tenant",
            "display_name": "tenant",
            "lifecycle_state": "ACTIVE",
        },
        {
            "compartment_id": COMPARTMENT_A,
            "parent_compartment_id": TENANCY_OCID,
            "name": "compa",
            "display_name": "compa",
            "lifecycle_state": "ACTIVE",
        },
        {
            "compartment_id": COMPARTMENT_B,
            "parent_compartment_id": TENANCY_OCID,
            "name": "compb",
            "display_name": "compb",
            "lifecycle_state": "ACTIVE",
        },
    ],
    "identity_domains": [
        {
            "id": DOMAIN_OCID,
            "display_name": "TestDomain",
            "url": "https://idcs-testdomain.identity.oraclecloud.com:443",
            "compartment_id": COMPARTMENT_A,
        }
    ],
}


# Add custom dynamic-group scenarios here.
# Pattern:
#   1) Add a new key under SCENARIO_SEEDS with table rows to seed.
#   2) Add a matching test_* method at the bottom that calls
#      _run_scenario_and_compare_golden(<scenario_key>, <golden_file_name>).
SCENARIO_SEEDS = {
    "mixed_idd_and_classic_matches": {
        "compute_instances": [
            _compute_instance(
                INSTANCE_A,
                COMPARTMENT_A,
                "inst-a",
                defined_tags={"team": {"env": "prod"}, "department": {"operations": "yes"}},
            ),
            _compute_instance(INSTANCE_B, COMPARTMENT_B, "inst-b", defined_tags={"team": {"env": "dev"}}),
        ],
        "identity_domain_dynamic_groups": [
            _idd_dynamic_group("ocid1.dynamicgroup.oc1..idddg01", "IDD DG One", RULE_INSTANCE_ID_A, COMPARTMENT_A),
        ],
        "identity_dynamic_groups": [
            _classic_dynamic_group("ocid1.dynamicgroup.oc1..classicdg01", "classic_dg_one", RULE_TAG_ENV_PROD, COMPARTMENT_A),
        ],
    },
    "idd_compartment_scope_limits_broad_rule": {
        "compute_instances": [
            _compute_instance(INSTANCE_A, COMPARTMENT_A, "inst-a"),
            _compute_instance(INSTANCE_B, COMPARTMENT_B, "inst-b"),
        ],
        "identity_domain_dynamic_groups": [
            _idd_dynamic_group(
                "ocid1.dynamicgroup.oc1..idddg_scope",
                "IDD DG Scoped",
                RULE_RESOURCE_TYPE_INSTANCES,
                COMPARTMENT_A,
            ),
        ],
    },
    "classic_dynamic_group_no_matching_rule": {
        "compute_instances": [_compute_instance(INSTANCE_A, COMPARTMENT_A, "inst-a")],
        "identity_dynamic_groups": [
            _classic_dynamic_group("ocid1.dynamicgroup.oc1..classic_no_rule", "classic_no_rule", "", COMPARTMENT_A),
        ],
    },
    "idd_dynamic_group_no_matches": {
        "compute_instances": [_compute_instance(INSTANCE_A, COMPARTMENT_A, "inst-a")],
        "identity_domain_dynamic_groups": [
            _idd_dynamic_group(
                "ocid1.dynamicgroup.oc1..idddg_nomatch",
                "IDD DG NoMatch",
                RULE_INSTANCE_ID_MISSING,
                COMPARTMENT_A,
            ),
        ],
    },
    "duplicate_idd_and_classic_id_dedupes_classic": {
        "compute_instances": [
            _compute_instance(INSTANCE_A, COMPARTMENT_A, "inst-a"),
            _compute_instance(INSTANCE_B, COMPARTMENT_B, "inst-b"),
        ],
        "identity_domain_dynamic_groups": [
            _idd_dynamic_group("ocid1.dynamicgroup.oc1..shared01", "IDD DG Shared", RULE_INSTANCE_ID_A, COMPARTMENT_A),
        ],
        "identity_dynamic_groups": [
            _classic_dynamic_group("ocid1.dynamicgroup.oc1..shared01", "classic_shared", RULE_INSTANCE_ID_B, COMPARTMENT_B),
        ],
    },
    "multi_rule_matches_two_instances": {
        "compute_instances": [
            _compute_instance(INSTANCE_A, COMPARTMENT_A, "inst-a"),
            _compute_instance(INSTANCE_B, COMPARTMENT_B, "inst-b"),
        ],
        "identity_dynamic_groups": [
            _classic_dynamic_group("ocid1.dynamicgroup.oc1..classicmulti", "classic_multi", RULE_MULTI_ID_A_B, compartment_id=None),
        ],
    },
    "tag_exists_rule_matches_only_tagged_instance": {
        "compute_instances": [
            _compute_instance(INSTANCE_A, COMPARTMENT_A, "inst-a", defined_tags={"team": {"env": "prod"}}),
            _compute_instance(INSTANCE_C, COMPARTMENT_A, "inst-c", defined_tags={"department": {"ops": "x"}}),
        ],
        "identity_domain_dynamic_groups": [
            _idd_dynamic_group("ocid1.dynamicgroup.oc1..idddg_tag_exists", "IDD DG TagExists", RULE_TAG_TEAM_EXISTS, COMPARTMENT_A),
        ],
    },
    "empty_dynamic_group_tables": {
        "compute_instances": [
            _compute_instance(INSTANCE_A, COMPARTMENT_A, "inst-a"),
        ],
    },
}


class TestDynamicGroupMembershipOpenGraphModule(unittest.TestCase):
    def setUp(self):
        # Ensure our dynamic-rule parser stub is active even if another test module
        # imported matching_rules_engine earlier with a different parser stub.
        _mre.parse_dynamic_group_matching_rules = _parse_dynamic_group_matching_rules_stub
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_path = Path(self._tmp.name)
        self.dc = IntegrationTestDataController(self._tmp_path)
        self.assertTrue(self.dc.create_service_tables_from_yaml())
        self.session = OpenGraphTestSession(
            self.dc,
            workspace_id=WORKSPACE_ID,
            workspace_name="test",
            compartment_id=COMPARTMENT_A,
            tenant_id=TENANCY_OCID,
            output_root=self._tmp_path / "exports",
        )

    def tearDown(self):
        self._cleanup_tables()
        try:
            self.dc.close()
        finally:
            self._tmp.cleanup()

    def _cleanup_tables(self):
        touched_tables = [
            "opengraph_edges",
            "opengraph_nodes",
            "identity_domain_dynamic_groups",
            "identity_dynamic_groups",
            "compute_instances",
            "identity_domains",
            "resource_compartments",
        ]
        for table_name in touched_tables:
            self.dc.delete_dict_row(
                db="service",
                table_name=table_name,
                where={"workspace_id": WORKSPACE_ID},
                require_where=True,
                commit=True,
            )

    def _seed_rows(self, rows_by_table: dict):
        for table_name, rows in (rows_by_table or {}).items():
            for row in (rows or []):
                ok = self.dc.save_dict_row(
                    db="service",
                    table_name=table_name,
                    row={**dict(row), "workspace_id": WORKSPACE_ID},
                    on_conflict="replace",
                    commit=True,
                )
                self.assertTrue(ok, msg=f"failed seeding {table_name}: {row}")

    @staticmethod
    def _canonicalize_graph_payload(payload: dict) -> dict:
        out = copy.deepcopy(payload or {})
        metadata = out.get("metadata")
        if isinstance(metadata, dict):
            # Keep only stable metadata keys this test suite cares about.
            out["metadata"] = {"source_kind": metadata.get("source_kind")}
        graph = out.setdefault("graph", {})
        nodes = [n for n in (graph.get("nodes") or []) if isinstance(n, dict)]
        edges = [e for e in (graph.get("edges") or []) if isinstance(e, dict)]
        nodes.sort(key=lambda x: str(x.get("id") or ""))
        edges.sort(
            key=lambda x: (
                str((x.get("start") or {}).get("value") or ""),
                str((x.get("end") or {}).get("value") or ""),
                str(x.get("kind") or ""),
            )
        )
        graph["nodes"] = nodes
        graph["edges"] = edges
        return out

    def _compose_seed(self, scenario_name: str) -> dict:
        merged = {}
        for src in (BASE_TABLES, SCENARIO_SEEDS.get(scenario_name, {})):
            for table_name, rows in src.items():
                merged.setdefault(table_name, []).extend(list(rows or []))
        return merged

    def _assert_dynamic_group_membership_only(self, payload: dict):
        graph = payload.get("graph") or {}
        nodes = [n for n in (graph.get("nodes") or []) if isinstance(n, dict)]
        edges = [e for e in (graph.get("edges") or []) if isinstance(e, dict)]

        allowed_node_kinds = {
            "OCIDynamicGroup",
            "OCIComputeInstance",
            "OCIResource",
            "OCIGenericResource",
            "OCIPrincipal",
            "OCIBase",
        }
        for n in nodes:
            kinds = set(n.get("kinds") or [])
            self.assertTrue(kinds.issubset(allowed_node_kinds), msg=f"unexpected node kinds: {kinds}")
            self.assertTrue(
                ("OCIDynamicGroup" in kinds) or ("OCIComputeInstance" in kinds) or ("OCIResource" in kinds) or ("OCIGenericResource" in kinds),
                msg=f"unexpected node content: {n}",
            )

        for e in edges:
            self.assertEqual(e.get("kind"), "OCI_DYNAMIC_GROUP_MEMBER", msg=f"unexpected edge kind: {e}")
            edge_props = e.get("properties") if isinstance(e.get("properties"), dict) else {}
            self.assertEqual(edge_props.get("edge_category"), "GROUP_MEMBERSHIP", msg=f"unexpected edge category: {e}")
            self.assertEqual(edge_props.get("group_type"), "dynamic", msg=f"unexpected group_type: {e}")

        disallowed_edge_kinds = {"OCI_GROUP_MEMBER", "OCI_POLICY_SUBJECT"}
        self.assertFalse(any((e.get("kind") in disallowed_edge_kinds) for e in edges), msg=f"found disallowed edge kinds: {edges}")

    def _run_scenario_and_compare_golden(self, scenario_name: str, golden_filename: str):
        # Custom test-case hook:
        # call this helper from a new test_* method after adding your
        # scenario to SCENARIO_SEEDS and a corresponding golden file.
        self._seed_rows(self._compose_seed(scenario_name))

        out_path = self.session.resolve_output_path(
            requested_path="",
            service_name="opengraph",
            filename="oracle_cloud_hound.json",
            compartment_id=COMPARTMENT_A,
            subdirs=["bloodhound"],
            target="export",
        )
        result = run_module(["--dynamic-groups"], self.session)
        self.assertTrue(out_path.exists(), msg=f"output missing: {out_path}")
        produced = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(produced, result)
        produced_norm = self._canonicalize_graph_payload(produced)

        golden_path = GOLDEN_DIR / golden_filename
        if os.getenv("OCINFERNO_REGEN_GOLDEN", "").strip() == "1":
            golden_path.parent.mkdir(parents=True, exist_ok=True)
            golden_path.write_text(json.dumps(produced_norm, indent=2, sort_keys=False), encoding="utf-8")

        self.assertTrue(golden_path.exists(), msg=f"golden file missing: {golden_path}")
        expected = json.loads(golden_path.read_text(encoding="utf-8"))
        expected_norm = self._canonicalize_graph_payload(expected)
        self.assertEqual(produced_norm, expected_norm)
        self._assert_dynamic_group_membership_only(produced_norm)

    def test_dynamic_group_graph__mixed_idd_and_classic_matches__matches_golden(self):
        self._run_scenario_and_compare_golden(
            "mixed_idd_and_classic_matches",
            "dynamic_group_memberships_mixed_idd_and_classic_matches.golden.json",
        )

    def test_dynamic_group_graph__idd_compartment_scope_limits_broad_rule__matches_golden(self):
        self._run_scenario_and_compare_golden(
            "idd_compartment_scope_limits_broad_rule",
            "dynamic_group_memberships_idd_compartment_scope_limits_broad_rule.golden.json",
        )

    def test_dynamic_group_graph__classic_dynamic_group_no_matching_rule__matches_golden(self):
        self._run_scenario_and_compare_golden(
            "classic_dynamic_group_no_matching_rule",
            "dynamic_group_memberships_classic_dynamic_group_no_matching_rule.golden.json",
        )

    def test_dynamic_group_graph__idd_dynamic_group_no_matches__matches_golden(self):
        self._run_scenario_and_compare_golden(
            "idd_dynamic_group_no_matches",
            "dynamic_group_memberships_idd_dynamic_group_no_matches.golden.json",
        )

    def test_dynamic_group_graph__duplicate_idd_and_classic_id_dedupes_classic__matches_golden(self):
        self._run_scenario_and_compare_golden(
            "duplicate_idd_and_classic_id_dedupes_classic",
            "dynamic_group_memberships_duplicate_idd_and_classic_id_dedupes_classic.golden.json",
        )

    def test_dynamic_group_graph__multi_rule_matches_two_instances__matches_golden(self):
        self._run_scenario_and_compare_golden(
            "multi_rule_matches_two_instances",
            "dynamic_group_memberships_multi_rule_matches_two_instances.golden.json",
        )

    def test_dynamic_group_graph__tag_exists_rule_matches_only_tagged_instance__matches_golden(self):
        self._run_scenario_and_compare_golden(
            "tag_exists_rule_matches_only_tagged_instance",
            "dynamic_group_memberships_tag_exists_rule_matches_only_tagged_instance.golden.json",
        )

    def test_dynamic_group_graph__empty_dynamic_group_tables__matches_golden(self):
        self._run_scenario_and_compare_golden(
            "empty_dynamic_group_tables",
            "dynamic_group_memberships_empty_dynamic_group_tables.golden.json",
        )


if __name__ == "__main__":
    unittest.main()
