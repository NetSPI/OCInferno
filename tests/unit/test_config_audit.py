import json
import unittest

try:
    from ocinferno.modules.everything.utilities.config_audit import (
        ObjectStorageServiceAuditor,
        ComputeServiceAuditor,
        VaultServiceAuditor,
        KubernetesServiceAuditor,
        ContainerRegistryServiceAuditor,
        DNSServiceAuditor,
        NetworkFirewallServiceAuditor,
        IdentityDomainsServiceAuditor,
    )
    _CONFIG_AUDIT_AVAILABLE = True
except Exception:  # pragma: no cover - optional deps (oci) may be missing
    _CONFIG_AUDIT_AVAILABLE = False


class _Session:
    def __init__(self, tables):
        self._tables = tables

    def get_resource_fields(self, table_name, where_conditions=None, columns=None):
        rows = list(self._tables.get(table_name, []))
        if not where_conditions:
            return rows
        out = []
        for r in rows:
            ok = True
            for k, v in where_conditions.items():
                if r.get(k) != v:
                    ok = False
                    break
            if ok:
                out.append(r)
        return out


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditObjectStorage(unittest.TestCase):
    def test_bucket_public_access_flags(self):
        session = _Session(
            {
                "object_storage_buckets": [
                    {
                        "id": "bucket1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "public_access_type": "ObjectRead",
                    }
                ]
            }
        )
        auditor = ObjectStorageServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("OBJECT_STORAGE_BUCKET_PUBLIC_DOWNLOAD_AND_LIST", codes)

    def test_bucket_versioning_disabled_flags(self):
        session = _Session(
            {
                "object_storage_buckets": [
                    {
                        "id": "bucket2",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "versioning": "Disabled",
                    }
                ]
            }
        )
        auditor = ObjectStorageServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("OBJECT_STORAGE_BUCKET_VERSIONING_DISABLED", codes)

    def test_bucket_cmk_missing_flags(self):
        session = _Session(
            {
                "object_storage_buckets": [
                    {
                        "id": "bucket3",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "kms_key_id": "",
                        "get_run": True,
                    }
                ]
            }
        )
        auditor = ObjectStorageServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("OBJECT_STORAGE_BUCKET_CMK_NOT_SET_UP", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditCompute(unittest.TestCase):
    def test_imds_v1_flags(self):
        session = _Session(
            {
                "compute_instances": [
                    {
                        "id": "ocid1.instance.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "instance_options": json.dumps(
                            {"are_legacy_imds_endpoints_disabled": False}
                        ),
                        "launch_options": json.dumps(
                            {"is_pv_encryption_in_transit_enabled": True}
                        ),
                        "platform_config": json.dumps(
                            {"is_memory_encryption_enabled": True}
                        ),
                    }
                ]
            }
        )
        auditor = ComputeServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("COMPUTE_IMDS_V1", codes)

    def test_shielded_instance_flags(self):
        session = _Session(
            {
                "compute_instances": [
                    {
                        "id": "ocid1.instance.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "platform_config": json.dumps(
                            {
                                "is_measured_boot_enabled": False,
                                "is_secure_boot_enabled": False,
                                "is_trusted_platform_module_enabled": False,
                                "is_memory_encryption_enabled": True,
                            }
                        ),
                        "instance_options": json.dumps(
                            {"are_legacy_imds_endpoints_disabled": True}
                        ),
                        "launch_options": json.dumps(
                            {"is_pv_encryption_in_transit_enabled": True}
                        ),
                    }
                ]
            }
        )
        auditor = ComputeServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("COMPUTE_SHIELDED_INSTANCES", codes)

    def test_confidential_computing_flags(self):
        session = _Session(
            {
                "compute_instances": [
                    {
                        "id": "ocid1.instance.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "platform_config": json.dumps(
                            {
                                "is_measured_boot_enabled": True,
                                "is_secure_boot_enabled": True,
                                "is_trusted_platform_module_enabled": True,
                                "is_memory_encryption_enabled": False,
                            }
                        ),
                        "instance_options": json.dumps(
                            {"are_legacy_imds_endpoints_disabled": True}
                        ),
                        "launch_options": json.dumps(
                            {"is_pv_encryption_in_transit_enabled": True}
                        ),
                    }
                ]
            }
        )
        auditor = ComputeServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("COMPUTE_CONFIDENTIAL_COMPUTING", codes)

    def test_in_transit_encryption_flags(self):
        session = _Session(
            {
                "compute_instances": [
                    {
                        "id": "ocid1.instance.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "platform_config": json.dumps(
                            {
                                "is_measured_boot_enabled": True,
                                "is_secure_boot_enabled": True,
                                "is_trusted_platform_module_enabled": True,
                                "is_memory_encryption_enabled": True,
                            }
                        ),
                        "instance_options": json.dumps(
                            {"are_legacy_imds_endpoints_disabled": True}
                        ),
                        "launch_options": json.dumps(
                            {"is_pv_encryption_in_transit_enabled": False}
                        ),
                    }
                ]
            }
        )
        auditor = ComputeServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("COMPUTE_IN_TRANSIT_ENCRYPTION", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditVault(unittest.TestCase):
    def test_vault_not_vpv_flags(self):
        session = _Session(
            {
                "vault_vaults": [
                    {
                        "id": "ocid1.vault.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "vault_type": "DEFAULT",
                    }
                ]
            }
        )
        auditor = VaultServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("VAULT_KMS_VIRTUAL_PRIVATE_VAULT", codes)

    def test_software_key_flags(self):
        session = _Session(
            {
                "vault_keys": [
                    {
                        "id": "ocid1.key.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "protection_mode": "SOFTWARE",
                    }
                ]
            }
        )
        auditor = VaultServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("VAULT_KMS_SOFTWARE_KEY", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditKubernetes(unittest.TestCase):
    def test_public_endpoint_flags(self):
        session = _Session(
            {
                "containerengine_clusters": [
                    {
                        "id": "ocid1.cluster.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "endpoint_config": {"is_public_ip_enabled": True},
                        "endpoints": {"public_endpoint": "https://example"},
                    }
                ]
            }
        )
        auditor = KubernetesServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("KUBERNETES_ENGINE_PUBLIC_ENDPOINT", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditContainerRegistry(unittest.TestCase):
    def test_public_repo_flags(self):
        session = _Session(
            {
                "cr_repositories": [
                    {
                        "id": "ocid1.repo.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "is_public": "true",
                    }
                ]
            }
        )
        auditor = ContainerRegistryServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("PUBLIC_REPOSITORY", codes)

    def test_repo_mutable_flags(self):
        session = _Session(
            {
                "cr_repositories": [
                    {
                        "id": "ocid1.repo.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "is_public": "false",
                        "is_immutable": "false",
                    }
                ]
            }
        )
        auditor = ContainerRegistryServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("CONTAINER_REGISTRY_REPO_MUTABLE", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditDNS(unittest.TestCase):
    def test_dnssec_disabled_flags(self):
        session = _Session(
            {
                "dns_zones": [
                    {
                        "id": "ocid1.dnszone.oc1..example",
                        "compartment_ocid": "ocid1.compartment.oc1..example",
                        "scope": "GLOBAL",
                        "dnssec_state": "DISABLED",
                    }
                ]
            }
        )
        auditor = DNSServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("DNS_DNSSEC_DISABLED", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditNetworkFirewall(unittest.TestCase):
    def test_allow_without_conditions_flags(self):
        session = _Session(
            {
                "network_firewall_security_rules": [
                    {
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "network_firewall_policy_id": "ocid1.nfwpolicy.oc1..example",
                        "name": "allow-all",
                        "action": "ALLOW",
                        "condition": {},
                    }
                ]
            }
        )
        auditor = NetworkFirewallServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("NETWORK_FIREWALL_ALLOW_WITHOUT_MATCH_CRITERIA", codes)

    def test_inspect_without_mode_flags(self):
        session = _Session(
            {
                "network_firewall_security_rules": [
                    {
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "network_firewall_policy_id": "ocid1.nfwpolicy.oc1..example",
                        "name": "inspect-missing",
                        "action": "INSPECT",
                        "inspection": "",
                        "condition": {"source_address": ["10.0.0.0/8"]},
                    }
                ]
            }
        )
        auditor = NetworkFirewallServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("NETWORK_FIREWALL_INSPECT_WITHOUT_MODE", codes)

    def test_allow_any_any_flags(self):
        session = _Session(
            {
                "network_firewall_security_rules": [
                    {
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "network_firewall_policy_id": "ocid1.nfwpolicy.oc1..example",
                        "name": "allow-any-any",
                        "action": "ALLOW",
                        "condition": {
                            "source_address": ["ANY"],
                            "destination_address": ["ANY"],
                            "service": ["*"],
                        },
                    }
                ]
            }
        )
        auditor = NetworkFirewallServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("NETWORK_FIREWALL_ALLOW_ANY_ANY", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditIdentityDomains(unittest.TestCase):
    def test_mfa_disabled_flags(self):
        session = _Session(
            {
                "identity_domain_authentication_factor_settings": [
                    {
                        "id": "mfa1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "domain_ocid": "ocid1.domain.oc1..example",
                        "mfa_enabled_category": "disabled",
                    }
                ]
            }
        )
        auditor = IdentityDomainsServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("IDD_MFA_DISABLED_OR_UNKNOWN", codes)

    def test_user_not_in_group_flags(self):
        session = _Session(
            {
                "identity_domain_users": [
                    {
                        "id": "user1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "domain_ocid": "ocid1.domain.oc1..example",
                        "groups": [],
                    }
                ]
            }
        )
        auditor = IdentityDomainsServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("IDD_USER_NOT_IN_GROUP", codes)

    def test_multiple_api_keys_flags(self):
        session = _Session(
            {
                "identity_domain_user_api_keys": [
                    {
                        "id": "key1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "domain_ocid": "ocid1.domain.oc1..example",
                        "user": json.dumps({"ocid": "user1", "name": "User One", "id": "user1"}),
                    },
                    {
                        "id": "key2",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "domain_ocid": "ocid1.domain.oc1..example",
                        "user": json.dumps({"ocid": "user1", "name": "User One", "id": "user1"}),
                    },
                ]
            }
        )
        auditor = IdentityDomainsServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("IDD_USER_WITH_MULTIPLE_API_KEYS", codes)

    def test_weak_password_policy_flags(self):
        session = _Session(
            {
                "identity_domain_password_policies": [
                    {
                        "id": "pw1",
                        "name": "Default",
                        "compartment_ocid": "ocid1.compartment.oc1..example",
                        "domain_ocid": "ocid1.domain.oc1..example",
                        "priority": 1,
                        "min_length": 8,
                        "password_expires_after": 180,
                        "num_passwords_in_history": 2,
                        "max_incorrect_attempts": 10,
                        "min_lower_case": False,
                        "min_numerals": False,
                        "min_special_chars": False,
                        "min_upper_case": False,
                    }
                ]
            }
        )
        auditor = IdentityDomainsServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("IDD_PW_WEAK_POLICY", codes)
