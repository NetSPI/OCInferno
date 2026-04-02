from __future__ import annotations

import json
import sys
import types
import unittest


if "oci_lexer_parser" not in sys.modules:
    parser_stub = types.ModuleType("oci_lexer_parser")
    parser_stub.parse_dynamic_group_matching_rules = lambda *_a, **_k: {"rules": []}
    parser_stub.parse_policy_statements = lambda *_a, **_k: ({"statements": []}, {"errors": [], "error_count": 0})
    sys.modules["oci_lexer_parser"] = parser_stub

from ocinferno.modules.opengraph.enumeration import enum_oracle_cloud_hound_data as og  # noqa: E402


class TestOpenGraphExportContract(unittest.TestCase):
    def test_export_metadata_contract_and_sorting(self):
        node_rows = [
            {"node_id": "z-node", "node_type": "OCIUser", "node_properties": '{"name":"Zulu"}'},
            {"node_id": "a-node", "node_type": "OCIGroup", "node_properties": '{"name":"Alpha"}'},
        ]
        edge_rows = [
            {
                "source_id": "z-node",
                "destination_id": "a-node",
                "edge_type": "OCI_GROUP_MEMBER",
                "edge_properties": '{"edge_category":"GROUP_MEMBERSHIP","edge_inner_properties":{"membership_id":"m2"}}',
            },
            {
                "source_id": "a-node",
                "destination_id": "z-node",
                "edge_type": "OCI_POLICY_SUBJECT",
                "edge_properties": '{"edge_category":"PERMISSION","edge_inner_properties":{"is_priv_escalation":false}}',
            },
        ]

        payload = og.export_opengraph_json(node_rows=node_rows, edge_rows=edge_rows, debug=False)
        metadata = payload.get("metadata") or {}
        graph = payload.get("graph") or {}
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []

        self.assertEqual(metadata, {"source_kind": "OCIBase"})
        self.assertNotIn("schema_version", metadata)
        self.assertEqual([n.get("id") for n in nodes], ["a-node", "z-node"])
        self.assertEqual(
            [
                (("a-node"), ("z-node"), "OCI_POLICY_SUBJECT"),
                (("z-node"), ("a-node"), "OCI_GROUP_MEMBER"),
            ],
            [((e.get("start") or {}).get("value"), (e.get("end") or {}).get("value"), e.get("kind")) for e in edges],
        )


class TestNodeEdgeTransforms(unittest.TestCase):
    def test_node_transform_principal_resource_and_unknown(self):
        principal = og._node_to_opengraph(  # pylint: disable=protected-access
            {
                "node_id": "ocid1.user.oc1..abc",
                "node_type": "OCIUser",
                "node_properties": json.dumps({"name": "UserA", "meta": {"x": "y"}}),
            }
        )
        resource = og._node_to_opengraph(  # pylint: disable=protected-access
            {
                "node_id": "all@ocid1.compartment.oc1..abc",
                "node_type": "OCIAllResources",
                "node_properties": "{}",
            }
        )
        unknown = og._node_to_opengraph(  # pylint: disable=protected-access
            {
                "node_id": "mystery-node",
                "node_type": "",
                "node_properties": "{}",
            }
        )

        self.assertIn("OCIPrincipal", principal["kinds"])
        self.assertEqual(principal["properties"]["name"], "UserA")
        self.assertEqual(principal["properties"]["meta.x"], "y")

        self.assertIn("OCIResource", resource["kinds"])
        self.assertIn("OCIAllResources", resource["kinds"])

        self.assertEqual(unknown["kinds"], ["OCIUnknown"])
        self.assertEqual(unknown["properties"]["name"], "mystery-node")

    def test_edge_transform_filters_non_bloodhound_safe_values(self):
        edge = og._edge_to_opengraph(  # pylint: disable=protected-access
            {
                "source_id": "src",
                "destination_id": "dst",
                "edge_type": "OCI_UPDATE_POLICY",
                "edge_properties": json.dumps(
                    {
                        "edge_category": "PERMISSION",
                        "edge_inner_properties": {
                            "is_priv_escalation": True,
                            "resolved_policy": ["p1", "p2"],
                            "invalid_objects": [{"a": 1}],
                            "empty_list_ok": [],
                        },
                    }
                ),
            }
        )

        props = edge.get("properties") or {}
        self.assertEqual(edge.get("kind"), "OCI_UPDATE_POLICY")
        self.assertEqual((edge.get("start") or {}).get("value"), "src")
        self.assertEqual((edge.get("end") or {}).get("value"), "dst")
        self.assertEqual(props.get("edge_category"), "PERMISSION")
        self.assertEqual(props.get("is_priv_escalation"), True)
        self.assertEqual(props.get("resolved_policy"), ["p1", "p2"])
        self.assertEqual(props.get("empty_list_ok"), [])
        self.assertNotIn("invalid_objects", props)


class TestPruningAndCollapse(unittest.TestCase):
    def test_prune_orphan_idd_application_nodes(self):
        nodes = [
            {"node_id": "app-keep", "node_type": "OCIIDDApplication"},
            {"node_id": "app-drop", "node_type": "OCIIDDApplication"},
            {"node_id": "user-1", "node_type": "OCIUser"},
        ]
        edges = [
            {"source_id": "user-1", "destination_id": "app-keep", "edge_type": "APP_ROLE_GRANTED"},
        ]

        kept, pruned = og._prune_orphan_idd_app_nodes(nodes, edges, enabled=True, debug=False)  # pylint: disable=protected-access
        self.assertEqual(pruned, 1)
        self.assertEqual({n["node_id"] for n in kept}, {"app-keep", "user-1"})

        kept_disabled, pruned_disabled = og._prune_orphan_idd_app_nodes(nodes, edges, enabled=False, debug=False)  # pylint: disable=protected-access
        self.assertEqual(pruned_disabled, 0)
        self.assertEqual(len(kept_disabled), 3)

    def test_prune_orphan_policy_statement_nodes(self):
        nodes = [
            {"node_id": "stmt-keep", "node_type": "OCIPolicyStatement"},
            {"node_id": "stmt-drop", "node_type": "OCIPolicyStatement"},
            {"node_id": "idd-stmt-drop", "node_type": "OCIIdentityDomainPolicyStatement"},
            {"node_id": "group-1", "node_type": "OCIGroup"},
        ]
        edges = [
            {"source_id": "group-1", "destination_id": "stmt-keep", "edge_type": "OCI_POLICY_SUBJECT"},
        ]

        kept, pruned = og._prune_orphan_policy_statement_nodes(nodes, edges, enabled=True, debug=False)  # pylint: disable=protected-access
        self.assertEqual(pruned, 2)
        self.assertEqual({n["node_id"] for n in kept}, {"stmt-keep", "group-1"})

    def test_collapse_manage_shadowed_permission_edges(self):
        rows = [
            {
                "source_id": "src",
                "destination_id": "dst",
                "edge_type": "OCI_MANAGE",
                "edge_properties": json.dumps({"edge_category": "PERMISSION", "edge_inner_properties": {"is_priv_escalation": True}}),
            },
            {
                "source_id": "src",
                "destination_id": "dst",
                "edge_type": "OCI_CREATE_POLICY",
                "edge_properties": json.dumps({"edge_category": "PERMISSION", "edge_inner_properties": {}}),
            },
            {
                "source_id": "src",
                "destination_id": "dst",
                "edge_type": "OCI_UPDATE_POLICY",
                "edge_properties": json.dumps({"edge_category": "PERMISSION", "edge_inner_properties": {}}),
            },
            {
                "source_id": "src",
                "destination_id": "dst",
                "edge_type": "OCI_MANAGE",
                "edge_properties": json.dumps({"edge_category": "PERMISSION", "edge_inner_properties": {}}),
            },
            {
                "source_id": "src",
                "destination_id": "dst",
                "edge_type": "OCI_BELONGS_TO",
                "edge_properties": json.dumps({"edge_category": "RESOURCE", "edge_inner_properties": {"resource_used": True}}),
            },
        ]

        kept, stats = og._collapse_manage_shadowed_permission_edges(rows, enabled=True, debug=False)  # pylint: disable=protected-access
        self.assertEqual(stats["pairs_with_manage"], 1)
        self.assertEqual(stats["collapsed_edges"], 2)
        self.assertEqual(stats["duplicate_manage_edges_pruned"], 1)

        edge_types = [str(r.get("edge_type") or "") for r in kept]
        self.assertIn("OCI_MANAGE", edge_types)
        self.assertIn("OCI_BELONGS_TO", edge_types)
        self.assertNotIn("OCI_CREATE_POLICY", edge_types)
        self.assertNotIn("OCI_UPDATE_POLICY", edge_types)

        manage = next(r for r in kept if str(r.get("edge_type") or "") == "OCI_MANAGE")
        manage_props = json.loads(str(manage.get("edge_properties") or "{}"))
        inner = manage_props.get("edge_inner_properties") or {}
        self.assertEqual(inner.get("includes_other_edges"), ["OCI_CREATE_POLICY", "OCI_UPDATE_POLICY"])

    def test_collapse_manage_disabled_returns_original_rows(self):
        rows = [
            {
                "source_id": "s",
                "destination_id": "d",
                "edge_type": "OCI_CREATE_POLICY",
                "edge_properties": json.dumps({"edge_category": "PERMISSION", "edge_inner_properties": {}}),
            },
        ]
        kept, stats = og._collapse_manage_shadowed_permission_edges(rows, enabled=False, debug=False)  # pylint: disable=protected-access
        self.assertEqual(kept, rows)
        self.assertEqual(stats["pairs_with_manage"], 0)
        self.assertEqual(stats["collapsed_edges"], 0)
        self.assertEqual(stats["duplicate_manage_edges_pruned"], 0)


if __name__ == "__main__":
    unittest.main()
