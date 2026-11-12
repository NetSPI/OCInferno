"""OpenGraph modeling for Identity Propagation Trusts.

Proves the identity-domain builder turns a propagation-trust row into an
OCIIdentityPropagationTrust node and an IDD_PROPAGATION_IMPERSONATE edge to the
OCI user the federated external token is allowed to become — the exact path a
misconfigured 'trust any GitHub repo' trust creates.
"""
from __future__ import annotations

import unittest

from ocinferno.modules.opengraph.utilities.identity_domain_graph_builder import (
    EDGE_IPT_IMPERSONATE,
    NODE_IDD_PROPAGATION_TRUST,
    NODE_USER,
    _impersonation_user_refs,
    _link_credential_to_users,
)


class _CaptureCtx:
    """Captures upsert_node + write_edge calls from the builder helpers."""

    def __init__(self):
        self.nodes = []
        self.edges = []
        self.og_state = {
            "existing_nodes_set": set(),
            "existing_edges_set": set(),
            "existing_node_types": {},
        }

    def upsert_node(self, **kwargs):
        self.nodes.append(dict(kwargs))
        return kwargs.get("node_id") or ""

    def write_edge(self, source_id, source_type, destination_id, destination_type,
                   edge_type, *, edge_properties=None, commit=True, on_conflict="update"):
        self.edges.append({
            "source_id": source_id, "source_type": source_type,
            "destination_id": destination_id, "destination_type": destination_type,
            "edge_type": edge_type, "edge_properties": edge_properties,
        })
        return True

    def tenant_for_compartment(self, _cid):
        return "ocid1.tenancy.oc1..test"


class TestImpersonationUserRefs(unittest.TestCase):

    def test_extracts_ocid_ref_value_in_priority(self):
        trust = {"impersonation_service_users": [
            {"ocid": "ocid1.user.oc1..admin", "rule": 'userName eq "admin"', "value": "admin"},
            {"value": "svc-user"},
        ]}
        self.assertEqual(_impersonation_user_refs(trust), ["ocid1.user.oc1..admin", "svc-user"])

    def test_empty_when_no_impersonation(self):
        self.assertEqual(_impersonation_user_refs({}), [])


class TestTrustImpersonateEdge(unittest.TestCase):

    def test_trust_links_to_impersonated_user(self):
        ctx = _CaptureCtx()
        user_ocid = "ocid1.user.oc1..admin"
        user_by_ocid = {user_ocid: {"ocid": user_ocid, "user_name": "admin"}}
        _link_credential_to_users(
            ctx=ctx,
            did="ocid1.domain.oc1..d",
            domain_url="https://idcs-x.identity.oraclecloud.com",
            credential_node_id="ocid1.idprop.oc1..ghtrust",
            credential_node_type=NODE_IDD_PROPAGATION_TRUST,
            user_refs=_impersonation_user_refs({
                "impersonation_service_users": [{"ocid": user_ocid}],
            }),
            user_by_scim={},
            user_by_ocid=user_by_ocid,
            default_compartment_id="ocid1.compartment.oc1..c",
            default_tenant_id="ocid1.tenancy.oc1..t",
            edge_type=EDGE_IPT_IMPERSONATE,
            edge_description="Identity propagation trust lets a federated external token impersonate this user.",
        )
        # The user node was ensured, and a trust -> user IMPERSONATE edge emitted.
        self.assertTrue(any(n["node_type"] == NODE_USER and n["node_id"] == user_ocid for n in ctx.nodes))
        imp_edges = [e for e in ctx.edges if e["edge_type"] == EDGE_IPT_IMPERSONATE]
        self.assertEqual(len(imp_edges), 1)
        self.assertEqual(imp_edges[0]["source_id"], "ocid1.idprop.oc1..ghtrust")
        self.assertEqual(imp_edges[0]["source_type"], NODE_IDD_PROPAGATION_TRUST)
        self.assertEqual(imp_edges[0]["destination_id"], user_ocid)


if __name__ == "__main__":
    unittest.main()
