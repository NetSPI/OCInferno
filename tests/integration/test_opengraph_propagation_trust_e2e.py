"""End-to-end: a seeded Identity Propagation Trust row flows through the identity-domain
OpenGraph builder into an OCIIdentityPropagationTrust node + an IDD_PROPAGATION_IMPERSONATE
edge to the OCI user it can impersonate (the misconfigured 'trust any GitHub repo' path)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ocinferno.modules.opengraph.utilities.helpers.context import OfflineIamContext
from ocinferno.modules.opengraph.utilities.identity_domain_graph_builder import (
    build_identity_domain_graph_offline,
)
from tests.integration.opengraph_test_harness import (
    IntegrationTestDataController,
    OpenGraphTestSession,
)

WID = 1
COMP = "ocid1.compartment.oc1..app"
TEN = "ocid1.tenancy.oc1..t"
DOM = "ocid1.domain.oc1..d"
USER = "ocid1.user.oc1..admin"
TRUST = "ocid1.idprop.oc1..ghtrust"


class TestPropagationTrustInOpenGraph(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        p = Path(self._tmp.name)
        self.dc = IntegrationTestDataController(p)
        self.assertTrue(self.dc.create_service_tables_from_schema())
        self.session = OpenGraphTestSession(
            self.dc, workspace_id=WID, workspace_name="t",
            compartment_id=COMP, tenant_id=TEN, output_root=p / "exports",
        )

    def tearDown(self):
        self.dc.close()
        self._tmp.cleanup()

    def _seed(self, table, row):
        self.dc.save_dict_row(db="service", table_name=table,
                              row={"workspace_id": WID, **row}, on_conflict="replace")

    def test_unrestricted_github_trust_appears_as_impersonate_edge(self):
        self._seed("identity_domains", {
            "id": DOM, "display_name": "Default",
            "url": "https://idcs-x.identity.oraclecloud.com", "compartment_id": COMP,
        })
        self._seed("identity_domain_users", {
            "id": "scim-admin", "ocid": USER, "user_name": "admin",
            "domain_ocid": DOM, "compartment_ocid": COMP, "tenancy_ocid": TEN,
        })
        self._seed("identity_domain_identity_propagation_trusts", {
            "id": "scim-trust", "ocid": TRUST, "name": "gh-trust", "type": "JWT",
            "issuer": "https://token.actions.githubusercontent.com",
            "subject_claim_name": "sub", "client_claim_values": None,
            "unrestricted_client_claim": "yes", "allow_impersonation": True,
            "impersonation_service_users": [{"ocid": USER, "rule": 'userName eq "admin"', "value": "admin"}],
            "domain_ocid": DOM, "compartment_ocid": COMP, "tenancy_ocid": TEN,
        })

        ctx = OfflineIamContext(session=self.session)
        build_identity_domain_graph_offline(session=self.session, ctx=ctx, auto_commit=True)

        nodes = self.session.get_resource_fields("opengraph_nodes") or []
        edges = self.session.get_resource_fields("opengraph_edges") or []

        trust_nodes = [n for n in nodes if n.get("node_type") == "OCIIdentityPropagationTrust"]
        self.assertTrue(trust_nodes, "propagation-trust node missing from opengraph")
        self.assertEqual(trust_nodes[0].get("node_id"), TRUST)

        imp_edges = [
            e for e in edges
            if e.get("edge_type") == "IDD_PROPAGATION_IMPERSONATE"
            and e.get("source_id") == TRUST and e.get("destination_id") == USER
        ]
        self.assertTrue(imp_edges, "GitHub-trust -> admin IMPERSONATE edge missing from opengraph")


if __name__ == "__main__":
    unittest.main()
