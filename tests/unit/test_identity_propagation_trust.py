"""Detection logic for over-broad Identity Propagation Trusts (workload OIDC federation).

A trust with no client_claim_values restriction trusts ANY principal from its issuer
(e.g. any GitHub repo), the 'confused deputy' misconfiguration this question is about.
"""
import unittest

from ocinferno.modules.identityclient.utilities.helpers import (
    IdentityIddIdentityPropagationTrustsResource,
    ipt_unrestricted_client_claim,
)


class TestIptUnrestrictedClientClaim(unittest.TestCase):

    def test_empty_client_claim_values_is_unrestricted(self):
        # GitHub Actions issuer with NO repo allowlist -> trusts any repo.
        row = {
            "name": "gh-trust",
            "issuer": "https://token.actions.githubusercontent.com",
            "client_claim_values": [],
        }
        self.assertEqual(ipt_unrestricted_client_claim(row), "yes")

    def test_absent_client_claim_values_is_unrestricted(self):
        row = {"issuer": "https://token.actions.githubusercontent.com"}
        self.assertEqual(ipt_unrestricted_client_claim(row), "yes")

    def test_restricted_to_specific_repo_is_safe(self):
        row = {
            "issuer": "https://token.actions.githubusercontent.com",
            "client_claim_name": "repository",
            "client_claim_values": ["my-org/my-repo"],
        }
        self.assertEqual(ipt_unrestricted_client_claim(row), "no")

    def test_non_dict_is_safe_default(self):
        self.assertEqual(ipt_unrestricted_client_claim(None), "no")

    def test_component_registered(self):
        # The enumerator is wired into enum_identity.
        from ocinferno.modules.identityclient.enumeration.enum_identity import COMPONENTS
        self.assertTrue(any(c[0] == "idd_identity_propagation_trusts" for c in COMPONENTS))
        self.assertTrue(hasattr(IdentityIddIdentityPropagationTrustsResource, "list"))


if __name__ == "__main__":
    unittest.main()
