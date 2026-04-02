import copy
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

from tests.integration.opengraph_test_harness import IntegrationTestDataController, OpenGraphTestSession

# Group-only tests still import the full OpenGraph module, which imports parser-backed
# builders. Stub parser symbols so this test does not depend on oci_lexer_parser.
if "oci_lexer_parser" not in sys.modules:
    parser_stub = types.ModuleType("oci_lexer_parser")
    parser_stub.parse_dynamic_group_matching_rules = lambda *_a, **_k: []
    parser_stub.parse_policy_statements = lambda *_a, **_k: []
    sys.modules["oci_lexer_parser"] = parser_stub

from ocinferno.modules.opengraph.enumeration.enum_oracle_cloud_hound_data import run_module


WORKSPACE_ID = 4242
TENANCY_OCID = "ocid1.tenancy.oc1..testtenant"
COMPARTMENT_ID = "ocid1.compartment.oc1..testcompartment"
DOMAIN_OCID = "ocid1.domain.oc1..testdomain"

IDD_USER_1 = "ocid1.user.oc1..idduser01"
IDD_USER_2 = "ocid1.user.oc1..idduser02"
IDD_GROUP_1 = "ocid1.group.oc1..iddgroup01"
IDD_GROUP_2 = "ocid1.group.oc1..iddgroup02"
IDD_MEMBERSHIP_1 = "ocid1.groupmembership.oc1..iddmembership01"
IDD_MEMBERSHIP_2 = "ocid1.groupmembership.oc1..iddmembership02"

CLASSIC_USER_1 = "ocid1.user.oc1..classicuser01"
CLASSIC_USER_2 = "ocid1.user.oc1..classicuser02"
CLASSIC_GROUP_1 = "ocid1.group.oc1..classicgroup01"
CLASSIC_GROUP_2 = "ocid1.group.oc1..classicgroup02"
CLASSIC_MEMBERSHIP_1 = "classic-membership-01"
CLASSIC_MEMBERSHIP_2 = "classic-membership-02"

ORPHAN_CLASSIC_USER = "ocid1.user.oc1..orphanclassicuser01"
ORPHAN_CLASSIC_GROUP = "ocid1.group.oc1..orphanclassicgroup01"
ORPHAN_CLASSIC_MEMBERSHIP = "classic-membership-orphan-01"
ORPHAN_IDD_USER = "ocid1.user.oc1..orphanidduser01"
ORPHAN_IDD_GROUP = "ocid1.group.oc1..orphaniddgroup01"
ORPHAN_IDD_MEMBERSHIP = "ocid1.groupmembership.oc1..orphaniddmembership01"

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"


def _idd_user(ocid: str, scim_id: str, user_name: str, display_name: str, groups: str = "[]") -> dict:
    return {
        "active": "true",
        "addresses": "[]",
        "delete_in_progress": "",
        "description": f"Obfuscated IDD user fixture for {user_name}",
        "id": scim_id,
        "ocid": ocid,
        "user_name": user_name,
        "display_name": display_name,
        "emails": json.dumps(
            [
                {
                    "type": "work",
                    "primary": True,
                    "value": f"{user_name}@example.com",
                    "verified": True,
                }
            ]
        ),
        "entitlements": "[]",
        "external_id": "",
        "groups": groups,
        "password": "",
        "phone_numbers": "[]",
        "roles": "[]",
        "schemas": json.dumps(
            [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User",
            ]
        ),
        "tags": "[]",
        "domain_ocid": DOMAIN_OCID,
        "compartment_ocid": COMPARTMENT_ID,
        "tenancy_ocid": TENANCY_OCID,
        "user_type": "",
        "app_role_ids": "[]",
    }


def _idd_group(ocid: str, scim_id: str, name: str, display_name: str, members: str = "[]") -> dict:
    return {
        "delete_in_progress": "",
        "id": scim_id,
        "ocid": ocid,
        "display_name": display_name,
        "external_id": name,
        "members": members,
        "meta": "{}",
        "schemas": json.dumps(["urn:ietf:params:scim:schemas:core:2.0:Group"]),
        "tags": "[]",
        "domain_ocid": DOMAIN_OCID,
        "compartment_ocid": COMPARTMENT_ID,
        "tenancy_ocid": TENANCY_OCID,
        "app_role_ids": "[]",
    }


def _classic_user(user_id: str, name: str) -> dict:
    return {
        "id": user_id,
        "name": name,
        "compartment_id": COMPARTMENT_ID,
        "tenant_id": TENANCY_OCID,
        "email": f"{name}@example.com",
        "description": f"Obfuscated classic user fixture for {name}",
        "time_created": "2026-01-01T00:00:00+00:00",
        "lifecycle_state": "ACTIVE",
        "freeform_tags": "{}",
        "defined_tags": "{}",
    }


def _classic_group(group_id: str, name: str) -> dict:
    return {
        "id": group_id,
        "name": name,
        "compartment_id": COMPARTMENT_ID,
        "description": f"Obfuscated classic group fixture for {name}",
        "time_created": "2026-01-01T00:00:00+00:00",
        "lifecycle_state": "ACTIVE",
        "freeform_tags": "{}",
        "defined_tags": "{}",
    }


def _membership_idd(membership_ocid: str, user_id: str, group_id: str, user_name: str, group_name: str) -> dict:
    return {
        "id": membership_ocid,
        "membership_ocid": membership_ocid,
        "user_id": user_id,
        "group_id": group_id,
        "user_name": user_name,
        "group_name": group_name,
        "domain_ocid": DOMAIN_OCID,
        "tenancy_ocid": TENANCY_OCID,
        "compartment_id": COMPARTMENT_ID,
        "inactive_status": "",
    }


def _membership_classic(membership_id: str, user_id: str, group_id: str, user_name: str, group_name: str) -> dict:
    return {
        "id": membership_id,
        "membership_id": membership_id,
        "user_id": user_id,
        "group_id": group_id,
        "user_name": user_name,
        "group_name": group_name,
        "tenancy_ocid": TENANCY_OCID,
        "compartment_id": COMPARTMENT_ID,
        "inactive_status": "0",
    }


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
            "compartment_id": COMPARTMENT_ID,
            "parent_compartment_id": TENANCY_OCID,
            "name": "root-compartment",
            "display_name": "root-compartment",
            "lifecycle_state": "ACTIVE",
        },
    ],
    "identity_domains": [
        {
            "id": DOMAIN_OCID,
            "display_name": "TestDomain",
            "url": "https://idcs-testdomain.identity.oraclecloud.com:443",
            "compartment_id": COMPARTMENT_ID,
        }
    ],
}


# Add custom scenarios here.
# Pattern:
#   1) Add a new key under SCENARIO_SEEDS with table rows to seed.
#   2) Add a matching test_* method at the bottom that calls
#      _run_scenario_and_compare_golden(<scenario_key>, <golden_file_name>).
SCENARIO_SEEDS = {
    "mixed_idd_classic": {
        "identity_domain_users": [
            _idd_user(IDD_USER_1, "idd-user-scim-01", "idd_user_one", "IDD User One"),
        ],
        "identity_domain_groups": [
            _idd_group(IDD_GROUP_1, "idd-group-scim-01", "idd_group_one", "IDD Group One"),
        ],
        "identity_users": [
            _classic_user(CLASSIC_USER_1, "classic_user_one"),
        ],
        "identity_groups": [
            _classic_group(CLASSIC_GROUP_1, "classic_group_one"),
        ],
        "identity_user_group_memberships": [
            _membership_idd(IDD_MEMBERSHIP_1, IDD_USER_1, IDD_GROUP_1, "idd_user_one", "idd_group_one"),
            _membership_classic(CLASSIC_MEMBERSHIP_1, CLASSIC_USER_1, CLASSIC_GROUP_1, "classic_user_one", "classic_group_one"),
        ],
    },
    "idd_only": {
        "identity_domain_users": [
            _idd_user(IDD_USER_1, "idd-user-scim-01", "idd_user_one", "IDD User One"),
        ],
        "identity_domain_groups": [
            _idd_group(IDD_GROUP_1, "idd-group-scim-01", "idd_group_one", "IDD Group One"),
        ],
        "identity_user_group_memberships": [
            _membership_idd(IDD_MEMBERSHIP_1, IDD_USER_1, IDD_GROUP_1, "idd_user_one", "idd_group_one"),
        ],
    },
    "classic_only": {
        "identity_users": [
            _classic_user(CLASSIC_USER_1, "classic_user_one"),
        ],
        "identity_groups": [
            _classic_group(CLASSIC_GROUP_1, "classic_group_one"),
        ],
        "identity_user_group_memberships": [
            _membership_classic(CLASSIC_MEMBERSHIP_1, CLASSIC_USER_1, CLASSIC_GROUP_1, "classic_user_one", "classic_group_one"),
        ],
    },
    "idd_user_groups_only": {
        "identity_domain_users": [
            _idd_user(
                IDD_USER_1,
                "idd-user-scim-01",
                "idd_user_one",
                "IDD User One",
                groups=json.dumps(
                    [
                        {
                            "ocid": IDD_GROUP_1,
                            "display": "IDD Group One",
                            "membership_ocid": IDD_MEMBERSHIP_1,
                        }
                    ]
                ),
            ),
        ],
        "identity_domain_groups": [
            _idd_group(IDD_GROUP_1, "idd-group-scim-01", "idd_group_one", "IDD Group One"),
        ],
    },
    "idd_group_users_only": {
        "identity_domain_users": [
            _idd_user(IDD_USER_1, "idd-user-scim-01", "idd_user_one", "IDD User One"),
        ],
        "identity_domain_groups": [
            _idd_group(
                IDD_GROUP_1,
                "idd-group-scim-01",
                "idd_group_one",
                "IDD Group One",
                members=json.dumps(
                    [
                        {
                            "ocid": IDD_USER_1,
                            "display": "IDD User One",
                            "membership_ocid": IDD_MEMBERSHIP_1,
                        }
                    ]
                ),
            ),
        ],
    },
    "idd_multi_source_dedupe": {
        "identity_domain_users": [
            _idd_user(
                IDD_USER_1,
                "idd-user-scim-01",
                "idd_user_one",
                "IDD User One",
                groups=json.dumps(
                    [
                        {
                            "ocid": IDD_GROUP_1,
                            "display": "IDD Group One",
                            "membership_ocid": IDD_MEMBERSHIP_1,
                        }
                    ]
                ),
            ),
        ],
        "identity_domain_groups": [
            _idd_group(IDD_GROUP_1, "idd-group-scim-01", "idd_group_one", "IDD Group One"),
        ],
        "identity_user_group_memberships": [
            _membership_idd(IDD_MEMBERSHIP_1, IDD_USER_1, IDD_GROUP_1, "idd_user_one", "idd_group_one"),
        ],
    },
    "no_memberships_users_and_groups": {
        "identity_domain_users": [
            _idd_user(IDD_USER_1, "idd-user-scim-01", "idd_user_one", "IDD User One"),
            _idd_user(IDD_USER_2, "idd-user-scim-02", "idd_user_two", "IDD User Two"),
        ],
        "identity_domain_groups": [
            _idd_group(IDD_GROUP_1, "idd-group-scim-01", "idd_group_one", "IDD Group One"),
            _idd_group(IDD_GROUP_2, "idd-group-scim-02", "idd_group_two", "IDD Group Two"),
        ],
        "identity_users": [
            _classic_user(CLASSIC_USER_1, "classic_user_one"),
            _classic_user(CLASSIC_USER_2, "classic_user_two"),
        ],
        "identity_groups": [
            _classic_group(CLASSIC_GROUP_1, "classic_group_one"),
            _classic_group(CLASSIC_GROUP_2, "classic_group_two"),
        ],
    },
    "users_only_no_groups": {
        "identity_domain_users": [
            _idd_user(IDD_USER_1, "idd-user-scim-01", "idd_user_one", "IDD User One"),
        ],
        "identity_users": [
            _classic_user(CLASSIC_USER_1, "classic_user_one"),
        ],
    },
    "groups_only_no_users": {
        "identity_domain_groups": [
            _idd_group(IDD_GROUP_1, "idd-group-scim-01", "idd_group_one", "IDD Group One"),
        ],
        "identity_groups": [
            _classic_group(CLASSIC_GROUP_1, "classic_group_one"),
        ],
    },
    "orphan_memberships_create_stub_nodes": {
        "identity_user_group_memberships": [
            _membership_classic(
                ORPHAN_CLASSIC_MEMBERSHIP,
                ORPHAN_CLASSIC_USER,
                ORPHAN_CLASSIC_GROUP,
                "orphan_classic_user",
                "orphan_classic_group",
            ),
            {
                **_membership_idd(
                    ORPHAN_IDD_MEMBERSHIP,
                    ORPHAN_IDD_USER,
                    ORPHAN_IDD_GROUP,
                    "orphan_idd_user",
                    "orphan_idd_group",
                ),
                "domain_ocid": DOMAIN_OCID,
            },
        ],
    },
}


class TestGroupMembershipOpenGraphModule(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_path = Path(self._tmp.name)
        self.dc = IntegrationTestDataController(self._tmp_path)
        self.assertTrue(self.dc.create_service_tables_from_yaml())
        self.session = OpenGraphTestSession(
            self.dc,
            workspace_id=WORKSPACE_ID,
            workspace_name="test",
            compartment_id=COMPARTMENT_ID,
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
            "identity_user_group_memberships",
            "identity_users",
            "identity_groups",
            "identity_domain_users",
            "identity_domain_groups",
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

    def _assert_group_membership_only(self, payload: dict):
        graph = payload.get("graph") or {}
        nodes = [n for n in (graph.get("nodes") or []) if isinstance(n, dict)]
        edges = [e for e in (graph.get("edges") or []) if isinstance(e, dict)]

        for n in nodes:
            kinds = set(n.get("kinds") or [])
            self.assertTrue(
                kinds.issubset({"OCIUser", "OCIGroup", "OCIPrincipal", "OCIBase"}),
                msg=f"unexpected node kinds: {kinds}",
            )
            self.assertTrue(("OCIUser" in kinds) or ("OCIGroup" in kinds), msg=f"node is not user/group: {n}")

        for e in edges:
            self.assertEqual(e.get("kind"), "OCI_GROUP_MEMBER", msg=f"unexpected edge kind: {e}")
            edge_props = e.get("properties") if isinstance(e.get("properties"), dict) else {}
            self.assertEqual(edge_props.get("edge_category"), "GROUP_MEMBERSHIP", msg=f"unexpected edge category: {e}")

        disallowed_edge_kinds = {
            "OCI_DYNAMIC_GROUP_MEMBER",
            "OCI_POLICY_SUBJECT",
        }
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
            compartment_id=COMPARTMENT_ID,
            subdirs=["bloodhound"],
            target="export",
        )
        result = run_module(["--groups"], self.session)
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
        self._assert_group_membership_only(produced_norm)

    def test_group_membership_graph__mixed_identity_domain_and_classic__matches_golden(self):
        self._run_scenario_and_compare_golden("mixed_idd_classic", "group_memberships_mixed.golden.json")

    def test_group_membership_graph__identity_domain_membership_table_only__matches_golden(self):
        self._run_scenario_and_compare_golden("idd_only", "group_memberships_idd_only.golden.json")

    def test_group_membership_graph__classic_membership_table_only__matches_golden(self):
        self._run_scenario_and_compare_golden("classic_only", "group_memberships_classic_only.golden.json")

    def test_group_membership_graph__identity_domain_user_groups_field_only__matches_golden(self):
        self._run_scenario_and_compare_golden("idd_user_groups_only", "group_memberships_idd_user_groups_only.golden.json")

    def test_group_membership_graph__identity_domain_group_members_field_only__matches_golden(self):
        self._run_scenario_and_compare_golden("idd_group_users_only", "group_memberships_idd_group_users_only.golden.json")

    def test_group_membership_graph__identity_domain_multi_source_deduplicates_edges__matches_golden(self):
        self._run_scenario_and_compare_golden(
            "idd_multi_source_dedupe",
            "group_memberships_idd_multi_source_dedupe.golden.json",
        )

    def test_group_membership_graph__users_and_groups_without_memberships__nodes_only_matches_golden(self):
        self._run_scenario_and_compare_golden(
            "no_memberships_users_and_groups",
            "group_memberships_no_memberships_users_and_groups.golden.json",
        )

    def test_group_membership_graph__users_without_groups__user_nodes_only_matches_golden(self):
        self._run_scenario_and_compare_golden("users_only_no_groups", "group_memberships_users_only_no_groups.golden.json")

    def test_group_membership_graph__groups_without_users__group_nodes_only_matches_golden(self):
        self._run_scenario_and_compare_golden("groups_only_no_users", "group_memberships_groups_only_no_users.golden.json")

    def test_group_membership_graph__orphan_memberships_create_stub_user_and_group_nodes__matches_golden(self):
        self._run_scenario_and_compare_golden(
            "orphan_memberships_create_stub_nodes",
            "group_memberships_orphan_memberships_create_stub_nodes.golden.json",
        )


if __name__ == "__main__":
    unittest.main()
