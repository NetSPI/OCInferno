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
        NetworkingServiceAuditor,
        NetworkLoadBalancerServiceAuditor,
        LoggingServiceAuditor,
        DatabaseServiceAuditor,
        GoldenGateServiceAuditor,
        IdentityServiceAuditor,
        ResourceManagerServiceAuditor,
        BastionServiceAuditor,
        BlockchainServiceAuditor,
        DataCatalogServiceAuditor,
        CacheServiceAuditor,
        WafServiceAuditor,
        WaasServiceAuditor,
        ApiGatewayServiceAuditor,
        NotificationsServiceAuditor,
        IoTServiceAuditor,
        ManagedKafkaServiceAuditor,
        IntegrationServiceAuditor,
        FileStorageServiceAuditor,
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

    def test_par_any_object_readwrite_flags_critical(self):
        session = _Session(
            {
                "object_storage_buckets": [
                    {
                        "namespace": "ns1",
                        "name": "bucket1",
                        "id": "bucket1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                    }
                ],
                "object_storage_preauthenticated_requests": [
                    {
                        "namespace": "ns1",
                        "bucket_name": "bucket1",
                        "id": "par1",
                        "name": "leak",
                        "access_type": "AnyObjectReadWrite",
                    }
                ],
            }
        )
        auditor = ObjectStorageServiceAuditor(session=session)
        res = auditor.run_checks()
        findings = [f for f in res.findings if f.issue_code == "OBJECT_STORAGE_PAR_ANY_OBJECT_WRITE"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertEqual(findings[0].location.get("compartment_id"), "ocid1.compartment.oc1..example")

    def test_par_any_object_read_flags_high(self):
        session = _Session(
            {
                "object_storage_buckets": [
                    {
                        "namespace": "ns1",
                        "name": "bucket1",
                        "id": "bucket1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                    }
                ],
                "object_storage_preauthenticated_requests": [
                    {
                        "namespace": "ns1",
                        "bucket_name": "bucket1",
                        "id": "par1",
                        "name": "leak",
                        "access_type": "AnyObjectRead",
                    }
                ],
            }
        )
        auditor = ObjectStorageServiceAuditor(session=session)
        res = auditor.run_checks()
        findings = [f for f in res.findings if f.issue_code == "OBJECT_STORAGE_PAR_ANY_OBJECT_READ"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_par_scoped_to_single_object_not_flagged(self):
        session = _Session(
            {
                "object_storage_buckets": [
                    {
                        "namespace": "ns1",
                        "name": "bucket1",
                        "id": "bucket1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                    }
                ],
                "object_storage_preauthenticated_requests": [
                    {
                        "namespace": "ns1",
                        "bucket_name": "bucket1",
                        "id": "par1",
                        "name": "scoped",
                        "access_type": "ObjectReadWrite",
                        "object_name": "single-file.txt",
                    }
                ],
            }
        )
        auditor = ObjectStorageServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("OBJECT_STORAGE_PAR_ANY_OBJECT_WRITE", codes)
        self.assertNotIn("OBJECT_STORAGE_PAR_ANY_OBJECT_READ", codes)


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
    def test_public_endpoint_not_flagged_when_deleted(self):
        session = _Session(
            {
                "containerengine_clusters": [
                    {
                        "id": "ocid1.cluster.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "DELETED",
                        "endpoint_config": {"is_public_ip_enabled": True},
                        "endpoints": {"public_endpoint": "https://example"},
                    }
                ]
            }
        )
        auditor = KubernetesServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("KUBERNETES_ENGINE_PUBLIC_ENDPOINT", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditContainerRegistry(unittest.TestCase):
    def test_public_repo_flags(self):
        session = _Session(
            {
                "cr_repositories": [
                    {
                        "id": "ocid1.repo.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "AVAILABLE",
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
                        "lifecycle_state": "AVAILABLE",
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
class TestConfigAuditLifecycleStateFilters(unittest.TestCase):
    """Dead/terminal-lifecycle rows must not be flagged."""

    def test_bastion_allowlist_any_ignored_when_deleted(self):
        session = _Session(
            {
                "bastion_bastions": [
                    {
                        "id": "ocid1.bastion.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "DELETED",
                        "cidr_block_allow_list": json.dumps(["0.0.0.0/0"]),
                    }
                ]
            }
        )
        auditor = BastionServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("BASTION_ALLOWLIST_ANY", codes)

    def test_bastion_allowlist_any_flags_when_active(self):
        session = _Session(
            {
                "bastion_bastions": [
                    {
                        "id": "ocid1.bastion.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "cidr_block_allow_list": json.dumps(["0.0.0.0/0"]),
                    }
                ]
            }
        )
        auditor = BastionServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("BASTION_ALLOWLIST_ANY", codes)

    def test_blockchain_http_endpoint_ignored_when_inactive(self):
        session = _Session(
            {
                "blockchain_platforms": [
                    {
                        "id": "ocid1.blockchainplatform.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "INACTIVE",
                        "service_endpoint": "http://example.com:7443",
                    }
                ]
            }
        )
        auditor = BlockchainServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("BLOCKCHAIN_SERVICE_ENDPOINT_HTTP", codes)

    def test_blockchain_http_endpoint_flags_when_active(self):
        session = _Session(
            {
                "blockchain_platforms": [
                    {
                        "id": "ocid1.blockchainplatform.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "service_endpoint": "http://example.com:7443",
                    }
                ]
            }
        )
        auditor = BlockchainServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("BLOCKCHAIN_SERVICE_ENDPOINT_HTTP", codes)

    def test_compute_checks_ignore_terminated_instance(self):
        session = _Session(
            {
                "compute_instances": [
                    {
                        "id": "ocid1.instance.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "TERMINATED",
                        "instance_options": json.dumps(
                            {"are_legacy_imds_endpoints_disabled": False}
                        ),
                        "launch_options": json.dumps(
                            {"is_pv_encryption_in_transit_enabled": False}
                        ),
                        "platform_config": json.dumps(
                            {
                                "is_measured_boot_enabled": False,
                                "is_secure_boot_enabled": False,
                                "is_trusted_platform_module_enabled": False,
                                "is_memory_encryption_enabled": False,
                            }
                        ),
                    }
                ]
            }
        )
        auditor = ComputeServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertEqual(set(), codes)

    def test_data_catalog_private_endpoint_no_subnet_ignored_when_deleted(self):
        session = _Session(
            {
                "data_catalog_private_endpoints": [
                    {
                        "id": "ocid1.datacatalogprivateendpoint.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "DELETED",
                        "subnet_id": "",
                        "dns_zones": json.dumps([]),
                    }
                ]
            }
        )
        auditor = DataCatalogServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("DATA_CATALOG_PRIVATE_ENDPOINT_NO_SUBNET", codes)
        self.assertNotIn("DATA_CATALOG_PRIVATE_ENDPOINT_NO_DNS_ZONES", codes)

    def test_data_catalog_private_endpoint_no_subnet_flags_when_active(self):
        session = _Session(
            {
                "data_catalog_private_endpoints": [
                    {
                        "id": "ocid1.datacatalogprivateendpoint.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "subnet_id": "",
                        "dns_zones": json.dumps([]),
                    }
                ]
            }
        )
        auditor = DataCatalogServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("DATA_CATALOG_PRIVATE_ENDPOINT_NO_SUBNET", codes)
        self.assertIn("DATA_CATALOG_PRIVATE_ENDPOINT_NO_DNS_ZONES", codes)

    def test_cache_cluster_no_nsg_ignored_when_not_active(self):
        session = _Session(
            {
                "cache_clusters": [
                    {
                        "id": "ocid1.rediscluster.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "DELETING",
                        "nsg_ids": json.dumps([]),
                    }
                ]
            }
        )
        auditor = CacheServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("CACHE_CLUSTER_NO_NSG", codes)

    def test_cache_cluster_no_nsg_flags_when_active(self):
        session = _Session(
            {
                "cache_clusters": [
                    {
                        "id": "ocid1.rediscluster.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "nsg_ids": json.dumps([]),
                    }
                ]
            }
        )
        auditor = CacheServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("CACHE_CLUSTER_NO_NSG", codes)


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

    def test_dnssec_disabled_not_flagged_for_secondary_zone(self):
        session = _Session(
            {
                "dns_zones": [
                    {
                        "id": "ocid1.dnszone.oc1..secondary",
                        "compartment_ocid": "ocid1.compartment.oc1..example",
                        "scope": "GLOBAL",
                        "zone_type": "SECONDARY",
                        "dnssec_state": "DISABLED",
                    }
                ]
            }
        )
        auditor = DNSServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("DNS_DNSSEC_DISABLED", codes)

    def test_dnssec_disabled_not_flagged_for_deleted_zone(self):
        session = _Session(
            {
                "dns_zones": [
                    {
                        "id": "ocid1.dnszone.oc1..deleted",
                        "compartment_ocid": "ocid1.compartment.oc1..example",
                        "scope": "GLOBAL",
                        "zone_type": "PRIMARY",
                        "lifecycle_state": "DELETED",
                        "dnssec_state": "DISABLED",
                    }
                ]
            }
        )
        auditor = DNSServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("DNS_DNSSEC_DISABLED", codes)


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

    def _any_any_rule(self):
        return {
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

    def test_allow_any_any_is_critical_when_policy_attached_to_live_firewall(self):
        session = _Session(
            {
                "network_firewall_security_rules": [self._any_any_rule()],
                "network_firewall_firewalls": [
                    {
                        "id": "ocid1.networkfirewall.oc1..fw1",
                        "lifecycle_state": "ACTIVE",
                        "network_firewall_policy_id": "ocid1.nfwpolicy.oc1..example",
                    }
                ],
            }
        )
        auditor = NetworkFirewallServiceAuditor(session=session)
        res = auditor.run_checks()
        findings = [f for f in res.findings if f.issue_code == "NETWORK_FIREWALL_ALLOW_ANY_ANY"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_allow_any_any_is_low_when_policy_not_attached_to_any_firewall(self):
        session = _Session(
            {
                "network_firewall_security_rules": [self._any_any_rule()],
                "network_firewall_firewalls": [],
            }
        )
        auditor = NetworkFirewallServiceAuditor(session=session)
        res = auditor.run_checks()
        findings = [f for f in res.findings if f.issue_code == "NETWORK_FIREWALL_ALLOW_ANY_ANY"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_allow_any_any_is_low_when_only_attaching_firewall_is_deleted(self):
        session = _Session(
            {
                "network_firewall_security_rules": [self._any_any_rule()],
                "network_firewall_firewalls": [
                    {
                        "id": "ocid1.networkfirewall.oc1..fw1",
                        "lifecycle_state": "DELETED",
                        "network_firewall_policy_id": "ocid1.nfwpolicy.oc1..example",
                    }
                ],
            }
        )
        auditor = NetworkFirewallServiceAuditor(session=session)
        res = auditor.run_checks()
        findings = [f for f in res.findings if f.issue_code == "NETWORK_FIREWALL_ALLOW_ANY_ANY"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")


try:
    import oci_lexer_parser  # noqa: F401
    _OCI_LEXER_PARSER_AVAILABLE = True
except Exception:  # pragma: no cover - optional dep may be missing
    _OCI_LEXER_PARSER_AVAILABLE = False


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
@unittest.skipUnless(_OCI_LEXER_PARSER_AVAILABLE, "oci-lexer-parser not available")
class TestConfigAuditIdentityAnyUserAnyGroup(unittest.TestCase):
    def _policy(self, statements):
        return {
            "compartment_id": "ocid1.compartment.oc1..example",
            "id": "ocid1.policy.oc1..example",
            "statements": statements,
        }

    def test_any_user_unconditional_manage_all_resources_is_critical(self):
        session = _Session(
            {"identity_policies": [self._policy(["Allow any-user to manage all-resources in tenancy"])]}
        )
        auditor = IdentityServiceAuditor(session=session)
        res = auditor.run_checks()
        findings = [f for f in res.findings if f.issue_code == "IAM_POLICY_ANY_USER_OR_GROUP_NO_CONDITIONS"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_any_group_unconditional_narrow_verb_is_high(self):
        session = _Session(
            {"identity_policies": [self._policy(["Allow any-group to inspect buckets in tenancy"])]}
        )
        auditor = IdentityServiceAuditor(session=session)
        res = auditor.run_checks()
        findings = [f for f in res.findings if f.issue_code == "IAM_POLICY_ANY_USER_OR_GROUP_NO_CONDITIONS"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_any_user_with_where_clause_not_flagged(self):
        session = _Session(
            {
                "identity_policies": [
                    self._policy(
                        ["Allow any-user to read objects in tenancy where request.principal.type='instance'"]
                    )
                ]
            }
        )
        auditor = IdentityServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IAM_POLICY_ANY_USER_OR_GROUP_NO_CONDITIONS", codes)

    def test_named_group_unconditional_not_flagged(self):
        session = _Session(
            {"identity_policies": [self._policy(["Allow group Admins to manage all-resources in tenancy"])]}
        )
        auditor = IdentityServiceAuditor(session=session)
        res = auditor.run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IAM_POLICY_ANY_USER_OR_GROUP_NO_CONDITIONS", codes)

    def test_malformed_statement_does_not_shift_indices_or_crash(self):
        session = _Session(
            {
                "identity_policies": [
                    self._policy(
                        [
                            "Allow any-user to manage all-resources in tenancy",
                            "this is not a valid policy statement !!!",
                            "Allow group Admins to manage all-resources in tenancy",
                        ]
                    )
                ]
            }
        )
        auditor = IdentityServiceAuditor(session=session)
        res = auditor.run_checks()
        self.assertEqual(res.errors, [])
        findings = [f for f in res.findings if f.issue_code == "IAM_POLICY_ANY_USER_OR_GROUP_NO_CONDITIONS"]
        self.assertEqual(len(findings), 1)
        self.assertIn("any-user to manage all-resources", findings[0].description)


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


# -----------------------------------------------------------------------------
# Rows use the SQLite round-trip encoding they actually carry when read back
# from the DB:
#   * bool columns are stored as int 1/0
#   * dict/list columns are stored as JSON strings
# Each check below must fire on a bad row and stay quiet on a good one when
# evaluating values in that encoding.
# -----------------------------------------------------------------------------


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditLogging(unittest.TestCase):
    def test_disabled_log_flags_on_int_zero(self):
        session = _Session(
            {
                "logging_logs": [
                    {
                        "id": "ocid1.log.oc1..disabled",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "is_enabled": 0,  # bool False -> int 0 on round-trip
                    }
                ]
            }
        )
        res = LoggingServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("LOGGING_LOG_DISABLED", codes)

    def test_enabled_log_not_flagged_on_int_one(self):
        session = _Session(
            {
                "logging_logs": [
                    {
                        "id": "ocid1.log.oc1..enabled",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "is_enabled": 1,  # bool True -> int 1 on round-trip
                    }
                ]
            }
        )
        res = LoggingServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("LOGGING_LOG_DISABLED", codes)

    def test_disabled_log_not_flagged_when_deleting(self):
        session = _Session(
            {
                "logging_logs": [
                    {
                        "id": "ocid1.log.oc1..disabled",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "DELETING",
                        "is_enabled": 0,
                        "retention_duration": 7,
                    }
                ]
            }
        )
        res = LoggingServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("LOGGING_LOG_DISABLED", codes)
        self.assertNotIn("LOGGING_RETENTION_SHORT", codes)

    def test_disabled_log_still_flags_when_inactive_lifecycle(self):
        # INACTIVE is a real, currently-existing log-configuration state (distinct
        # from is_enabled) -- must NOT be treated as dead/excluded.
        session = _Session(
            {
                "logging_logs": [
                    {
                        "id": "ocid1.log.oc1..disabled",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "INACTIVE",
                        "is_enabled": 0,
                    }
                ]
            }
        )
        res = LoggingServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("LOGGING_LOG_DISABLED", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditNetworkingSubnet(unittest.TestCase):
    def test_public_subnet_flags_on_int_zero(self):
        session = _Session(
            {
                "virtual_network_subnets": [
                    {
                        "id": "ocid1.subnet.oc1..public",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "vcn_id": "ocid1.vcn.oc1..example",
                        "prohibit_public_ip_on_vnic": 0,  # allows public IPs
                    }
                ]
            }
        )
        res = NetworkingServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("VCN_SUBNET_ALLOWS_PUBLIC_IP", codes)

    def test_private_subnet_not_flagged_on_int_one(self):
        session = _Session(
            {
                "virtual_network_subnets": [
                    {
                        "id": "ocid1.subnet.oc1..private",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "vcn_id": "ocid1.vcn.oc1..example",
                        "prohibit_public_ip_on_vnic": 1,  # prohibits public IPs
                    }
                ]
            }
        )
        res = NetworkingServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("VCN_SUBNET_ALLOWS_PUBLIC_IP", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditNetworkingAttachment(unittest.TestCase):
    def _any_any_ingress_sl(self):
        return {
            "id": "ocid1.securitylist.oc1..sl1",
            "compartment_id": "ocid1.compartment.oc1..example",
            "vcn_id": "ocid1.vcn.oc1..example",
            "lifecycle_state": "AVAILABLE",
            "ingress_security_rules": [
                {"source": "0.0.0.0/0", "protocol": "all"}
            ],
            "egress_security_rules": [],
        }

    def test_security_list_ingress_any_any_critical_when_attached_to_live_subnet(self):
        session = _Session(
            {
                "virtual_network_security_lists": [self._any_any_ingress_sl()],
                "virtual_network_subnets": [
                    {
                        "id": "ocid1.subnet.oc1..s1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "vcn_id": "ocid1.vcn.oc1..example",
                        "lifecycle_state": "AVAILABLE",
                        "security_list_ids": json.dumps(["ocid1.securitylist.oc1..sl1"]),
                    }
                ],
            }
        )
        res = NetworkingServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "VCN_SECURITY_LIST_INGRESS_ANY_ANY"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_security_list_ingress_any_any_low_when_not_attached_to_any_subnet(self):
        session = _Session(
            {
                "virtual_network_security_lists": [self._any_any_ingress_sl()],
                "virtual_network_subnets": [],
            }
        )
        res = NetworkingServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "VCN_SECURITY_LIST_INGRESS_ANY_ANY"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_security_list_ingress_any_any_low_when_only_referencing_subnet_terminated(self):
        session = _Session(
            {
                "virtual_network_security_lists": [self._any_any_ingress_sl()],
                "virtual_network_subnets": [
                    {
                        "id": "ocid1.subnet.oc1..s1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "vcn_id": "ocid1.vcn.oc1..example",
                        "lifecycle_state": "TERMINATED",
                        "security_list_ids": json.dumps(["ocid1.securitylist.oc1..sl1"]),
                    }
                ],
            }
        )
        res = NetworkingServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "VCN_SECURITY_LIST_INGRESS_ANY_ANY"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_security_list_itself_terminated_not_flagged(self):
        sl = self._any_any_ingress_sl()
        sl["lifecycle_state"] = "TERMINATED"
        session = _Session(
            {
                "virtual_network_security_lists": [sl],
                "virtual_network_subnets": [
                    {
                        "id": "ocid1.subnet.oc1..s1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "vcn_id": "ocid1.vcn.oc1..example",
                        "lifecycle_state": "AVAILABLE",
                        "security_list_ids": json.dumps(["ocid1.securitylist.oc1..sl1"]),
                    }
                ],
            }
        )
        res = NetworkingServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("VCN_SECURITY_LIST_INGRESS_ANY_ANY", codes)

    def _igw_route_table(self):
        return {
            "id": "ocid1.routetable.oc1..rt1",
            "compartment_id": "ocid1.compartment.oc1..example",
            "vcn_id": "ocid1.vcn.oc1..example",
            "lifecycle_state": "AVAILABLE",
            "route_rules": [
                {"destination": "0.0.0.0/0", "network_entity_id": "ocid1.internetgateway.oc1..igw1"}
            ],
        }

    def test_route_table_default_to_igw_medium_when_attached_to_live_subnet(self):
        session = _Session(
            {
                "virtual_network_route_tables": [self._igw_route_table()],
                "virtual_network_subnets": [
                    {
                        "id": "ocid1.subnet.oc1..s1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "vcn_id": "ocid1.vcn.oc1..example",
                        "lifecycle_state": "AVAILABLE",
                        "route_table_id": "ocid1.routetable.oc1..rt1",
                    }
                ],
            }
        )
        res = NetworkingServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "VCN_ROUTE_TABLE_DEFAULT_TO_IGW"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_route_table_default_to_igw_low_when_not_attached_to_any_subnet(self):
        session = _Session(
            {
                "virtual_network_route_tables": [self._igw_route_table()],
                "virtual_network_subnets": [],
            }
        )
        res = NetworkingServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "VCN_ROUTE_TABLE_DEFAULT_TO_IGW"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditNetworkLoadBalancer(unittest.TestCase):
    def test_public_nlb_flags_on_int_zero(self):
        session = _Session(
            {
                "network_load_balancers": [
                    {
                        "id": "ocid1.nlb.oc1..public",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "subnet_id": "ocid1.subnet.oc1..example",
                        "is_private": 0,  # public NLB
                    }
                ]
            }
        )
        res = NetworkLoadBalancerServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("NLB_PUBLIC", codes)

    def test_private_nlb_not_flagged_on_int_one(self):
        session = _Session(
            {
                "network_load_balancers": [
                    {
                        "id": "ocid1.nlb.oc1..private",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "subnet_id": "ocid1.subnet.oc1..example",
                        "is_private": 1,  # private NLB
                    }
                ]
            }
        )
        res = NetworkLoadBalancerServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("NLB_PUBLIC", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditKubernetesRoundTrip(unittest.TestCase):
    def test_public_endpoint_flags_on_json_string(self):
        # endpoint_config/endpoints round-trip as JSON strings, not dicts.
        session = _Session(
            {
                "containerengine_clusters": [
                    {
                        "id": "ocid1.cluster.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "endpoint_config": json.dumps({"is_public_ip_enabled": True}),
                        "endpoints": json.dumps({"public_endpoint": "https://example"}),
                    }
                ]
            }
        )
        res = KubernetesServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("KUBERNETES_ENGINE_PUBLIC_ENDPOINT", codes)

    def test_private_endpoint_not_flagged_on_json_string(self):
        session = _Session(
            {
                "containerengine_clusters": [
                    {
                        "id": "ocid1.cluster.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "endpoint_config": json.dumps({"is_public_ip_enabled": False}),
                        "endpoints": json.dumps({"private_endpoint": "10.0.0.5"}),
                    }
                ]
            }
        )
        res = KubernetesServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("KUBERNETES_ENGINE_PUBLIC_ENDPOINT", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditComputeRoundTrip(unittest.TestCase):
    def test_null_platform_config_does_not_abort(self):
        # First row has null blobs (common for most shapes); it must be skipped
        # WITHOUT aborting the check for the second, offending row.
        session = _Session(
            {
                "compute_instances": [
                    {
                        "id": "ocid1.instance.oc1..noblob",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "platform_config": None,
                        "instance_options": None,
                        "launch_options": None,
                    },
                    {
                        "id": "ocid1.instance.oc1..imdsv1",
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
                    },
                ]
            }
        )
        res = ComputeServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("COMPUTE_IMDS_V1", codes)
        self.assertEqual(res.errors, [])


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditObjectStorageLogs(unittest.TestCase):
    def test_null_log_config_does_not_abort(self):
        # A log row with a null/non-service configuration must not crash the
        # read/write-log check; the bucket should still get NO_WRITE/READ_LOG.
        session = _Session(
            {
                "object_storage_buckets": [
                    {
                        "id": "ocid1.bucket.oc1..b",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "name": "mybucket",
                    }
                ],
                "logging_logs": [
                    {"id": "ocid1.log.oc1..bad", "configuration": None},
                ],
            }
        )
        res = ObjectStorageServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("OBJECT_STORAGE_NO_WRITE_LOG", codes)
        self.assertIn("OBJECT_STORAGE_NO_READ_LOG", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditAutonomousDatabase(unittest.TestCase):
    def test_public_adb_flags(self):
        session = _Session(
            {
                "db_autonomous_databases": [
                    {
                        "id": "ocid1.autonomousdatabase.oc1..public",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "public_endpoint": "adb.example.oraclecloud.com",
                        "is_mtls_connection_required": 1,
                        "kms_key_id": "ocid1.key.oc1..example",
                    }
                ]
            }
        )
        res = DatabaseServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("AUTONOMOUS_DB_PUBLIC_EXPOSURE", codes)

    def test_no_access_controls_adb_flags(self):
        session = _Session(
            {
                "db_autonomous_databases": [
                    {
                        "id": "ocid1.autonomousdatabase.oc1..open",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "public_endpoint": "",
                        "whitelisted_ips": json.dumps([]),
                        "subnet_id": "",
                        "private_endpoint": "",
                        "is_mtls_connection_required": 0,
                        "kms_key_id": "",
                    }
                ]
            }
        )
        res = DatabaseServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("AUTONOMOUS_DB_PUBLIC_EXPOSURE", codes)
        self.assertIn("AUTONOMOUS_DB_MTLS_NOT_REQUIRED", codes)
        self.assertIn("AUTONOMOUS_DB_NO_CMK", codes)

    def test_private_adb_not_flagged(self):
        session = _Session(
            {
                "db_autonomous_databases": [
                    {
                        "id": "ocid1.autonomousdatabase.oc1..private",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "public_endpoint": "",
                        "whitelisted_ips": json.dumps([]),
                        "subnet_id": "ocid1.subnet.oc1..example",
                        "private_endpoint": "10.0.0.9",
                        "is_mtls_connection_required": 1,
                        "kms_key_id": "ocid1.key.oc1..example",
                    }
                ]
            }
        )
        res = DatabaseServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("AUTONOMOUS_DB_PUBLIC_EXPOSURE", codes)
        self.assertNotIn("AUTONOMOUS_DB_MTLS_NOT_REQUIRED", codes)
        self.assertNotIn("AUTONOMOUS_DB_NO_CMK", codes)

    def test_oracle_db_no_cmk_flags_against_real_table(self):
        # T_ORACLE must point at "db_db_systems" (the table this data actually
        # lands in) so the check can fire against real data.
        session = _Session(
            {
                "db_db_systems": [
                    {
                        "id": "ocid1.dbsystem.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "kms_key_id": "",
                    }
                ]
            }
        )
        res = DatabaseServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("ORACLE_DB_NO_CMK", codes)

    def test_oracle_db_with_cmk_not_flagged(self):
        session = _Session(
            {
                "db_db_systems": [
                    {
                        "id": "ocid1.dbsystem.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "kms_key_id": "ocid1.key.oc1..example",
                    }
                ]
            }
        )
        res = DatabaseServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("ORACLE_DB_NO_CMK", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditResourceManager(unittest.TestCase):
    def test_config_source_provider_missing_secret_ref_flags_against_real_table(self):
        # T_CONFIG_SOURCE_PROVIDER must point at "resource_manager_config_source_providers"
        # (the table registered in database_info.json) so the check can fire.
        session = _Session(
            {
                "resource_manager_config_source_providers": [
                    {
                        "id": "ocid1.configsourceprovider.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "username": "octocat",
                        "secret_id": "",
                    }
                ]
            }
        )
        res = ResourceManagerServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("ORM_CONFIG_SOURCE_PROVIDER_MISSING_SECRET_REF", codes)

    def test_config_source_provider_with_secret_ref_not_flagged(self):
        session = _Session(
            {
                "resource_manager_config_source_providers": [
                    {
                        "id": "ocid1.configsourceprovider.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "username": "octocat",
                        "secret_id": "ocid1.vaultsecret.oc1..example",
                    }
                ]
            }
        )
        res = ResourceManagerServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("ORM_CONFIG_SOURCE_PROVIDER_MISSING_SECRET_REF", codes)

    def test_private_endpoint_no_nsg_flags(self):
        # `nsg_id_list` is the field that scopes inbound access for a private
        # endpoint. `source_ips` is Oracle's own auto-assigned OUTBOUND address and
        # is never a customer inbound allowlist, so the check must key off nsg_id_list.
        session = _Session(
            {
                "resource_manager_private_endpoints": [
                    {
                        "id": "ocid1.privateendpoint.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "nsg_id_list": json.dumps([]),
                        "source_ips": json.dumps(["100.72.1.5", "100.72.1.6"]),
                    }
                ]
            }
        )
        res = ResourceManagerServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("ORM_PRIVATE_ENDPOINT_SOURCE_IP_ANY", codes)
        self.assertIn("ORM_PRIVATE_ENDPOINT_NO_NSG", codes)

    def test_private_endpoint_with_nsg_not_flagged(self):
        session = _Session(
            {
                "resource_manager_private_endpoints": [
                    {
                        "id": "ocid1.privateendpoint.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "nsg_id_list": json.dumps(["ocid1.networksecuritygroup.oc1..example"]),
                        "source_ips": json.dumps(["100.72.1.5"]),
                    }
                ]
            }
        )
        res = ResourceManagerServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("ORM_PRIVATE_ENDPOINT_NO_NSG", codes)

    def test_private_endpoint_deleted_not_flagged(self):
        session = _Session(
            {
                "resource_manager_private_endpoints": [
                    {
                        "id": "ocid1.privateendpoint.oc1..example",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "DELETED",
                        "nsg_id_list": json.dumps([]),
                    }
                ]
            }
        )
        res = ResourceManagerServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("ORM_PRIVATE_ENDPOINT_NO_NSG", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditGoldenGate(unittest.TestCase):
    def test_plaintext_credential_flags(self):
        session = _Session(
            {
                "goldengate_connections": [
                    {
                        "id": "ocid1.goldengateconnection.oc1..plain",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "username": "ggadmin",
                        "vault_id": "",
                        "key_id": "",
                    }
                ]
            }
        )
        res = GoldenGateServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("GOLDENGATE_CONNECTION_PLAINTEXT_CREDENTIAL", codes)

    def test_vault_backed_credential_not_flagged(self):
        session = _Session(
            {
                "goldengate_connections": [
                    {
                        "id": "ocid1.goldengateconnection.oc1..vault",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "username": "ggadmin",
                        "vault_id": "ocid1.vault.oc1..example",
                        "key_id": "ocid1.key.oc1..example",
                    }
                ]
            }
        )
        res = GoldenGateServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("GOLDENGATE_CONNECTION_PLAINTEXT_CREDENTIAL", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditWaf(unittest.TestCase):
    def _allow_default_policy(self):
        return {
            "id": "ocid1.webappfirewallpolicy.oc1..example",
            "compartment_id": "ocid1.compartment.oc1..example",
            "lifecycle_state": "ACTIVE",
            "actions": json.dumps([{"name": "default-action", "type": "ALLOW"}]),
            "request_access_control": json.dumps({"default_action_name": "default-action"}),
        }

    def test_default_action_not_blocking_medium_when_deployed(self):
        session = _Session(
            {
                "web_app_firewall_policies": [self._allow_default_policy()],
                "web_app_firewalls": [
                    {
                        "id": "ocid1.webappfirewall.oc1..fw1",
                        "lifecycle_state": "ACTIVE",
                        "web_app_firewall_policy_id": "ocid1.webappfirewallpolicy.oc1..example",
                    }
                ],
            }
        )
        res = WafServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "WAF_POLICY_DEFAULT_ACTION_NOT_BLOCKING"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_default_action_not_blocking_low_when_not_deployed(self):
        session = _Session(
            {
                "web_app_firewall_policies": [self._allow_default_policy()],
                "web_app_firewalls": [],
            }
        )
        res = WafServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "WAF_POLICY_DEFAULT_ACTION_NOT_BLOCKING"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_default_action_not_blocking_low_when_only_deployment_deleted(self):
        session = _Session(
            {
                "web_app_firewall_policies": [self._allow_default_policy()],
                "web_app_firewalls": [
                    {
                        "id": "ocid1.webappfirewall.oc1..fw1",
                        "lifecycle_state": "DELETED",
                        "web_app_firewall_policy_id": "ocid1.webappfirewallpolicy.oc1..example",
                    }
                ],
            }
        )
        res = WafServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "WAF_POLICY_DEFAULT_ACTION_NOT_BLOCKING"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def _check_only_rate_limit_policy(self):
        return {
            "id": "ocid1.webappfirewallpolicy.oc1..example",
            "compartment_id": "ocid1.compartment.oc1..example",
            "lifecycle_state": "ACTIVE",
            "actions": json.dumps([{"name": "check-action", "type": "CHECK"}]),
            "request_rate_limiting": json.dumps(
                {"rules": [{"name": "rl1", "action_name": "check-action"}]}
            ),
        }

    def test_rate_limit_check_only_flags_regardless_of_deployment(self):
        session = _Session(
            {
                "web_app_firewall_policies": [self._check_only_rate_limit_policy()],
                "web_app_firewalls": [],
            }
        )
        res = WafServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "WAF_POLICY_RATE_LIMIT_ACTION_CHECK_ONLY"]
        self.assertEqual(len(findings), 1)
        self.assertIn("not currently deployed", findings[0].title)

    def test_rate_limit_check_only_deployed_title_has_no_not_deployed_suffix(self):
        session = _Session(
            {
                "web_app_firewall_policies": [self._check_only_rate_limit_policy()],
                "web_app_firewalls": [
                    {
                        "id": "ocid1.webappfirewall.oc1..fw1",
                        "lifecycle_state": "ACTIVE",
                        "web_app_firewall_policy_id": "ocid1.webappfirewallpolicy.oc1..example",
                    }
                ],
            }
        )
        res = WafServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "WAF_POLICY_RATE_LIMIT_ACTION_CHECK_ONLY"]
        self.assertEqual(len(findings), 1)
        self.assertNotIn("not currently deployed", findings[0].title)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditWaas(unittest.TestCase):
    def _expired_cert(self):
        return {
            "id": "ocid1.waascertificate.oc1..example",
            "compartment_id": "ocid1.compartment.oc1..example",
            "lifecycle_state": "ACTIVE",
            "time_not_valid_after": "2000-01-01T00:00:00Z",
            "is_trust_verification_disabled": "false",
        }

    def test_certificate_expired_medium_when_attached_to_policy(self):
        session = _Session(
            {
                "waas_certificates": [self._expired_cert()],
                "waas_waas_policies": [
                    {
                        "id": "ocid1.waaspolicy.oc1..p1",
                        "lifecycle_state": "ACTIVE",
                        "policy_config": json.dumps(
                            {"certificate_id": "ocid1.waascertificate.oc1..example"}
                        ),
                    }
                ],
            }
        )
        res = WaasServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "WAAS_CERTIFICATE_EXPIRED"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_certificate_expired_low_when_not_attached_to_any_policy(self):
        session = _Session(
            {
                "waas_certificates": [self._expired_cert()],
                "waas_waas_policies": [],
            }
        )
        res = WaasServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "WAAS_CERTIFICATE_EXPIRED"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_certificate_expired_low_when_only_referencing_policy_deleted(self):
        session = _Session(
            {
                "waas_certificates": [self._expired_cert()],
                "waas_waas_policies": [
                    {
                        "id": "ocid1.waaspolicy.oc1..p1",
                        "lifecycle_state": "DELETED",
                        "policy_config": json.dumps(
                            {"certificate_id": "ocid1.waascertificate.oc1..example"}
                        ),
                    }
                ],
            }
        )
        res = WaasServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "WAAS_CERTIFICATE_EXPIRED"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_certificate_expired_low_when_policy_enumerated_without_get(self):
        # policy_config is absent entirely (summary-only enumeration) -- must not
        # be misread as "attached".
        session = _Session(
            {
                "waas_certificates": [self._expired_cert()],
                "waas_waas_policies": [
                    {
                        "id": "ocid1.waaspolicy.oc1..p1",
                        "lifecycle_state": "ACTIVE",
                    }
                ],
            }
        )
        res = WaasServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "WAAS_CERTIFICATE_EXPIRED"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditApiGatewayAuthentication(unittest.TestCase):
    def _public_gateway(self):
        return {
            "id": "ocid1.apigateway.oc1..gw1",
            "compartment_id": "ocid1.compartment.oc1..example",
            "lifecycle_state": "ACTIVE",
            "endpoint_type": "PUBLIC",
        }

    def test_deployment_no_authentication_critical_on_public_gateway(self):
        session = _Session(
            {
                "apigw_gateways": [self._public_gateway()],
                "apigw_deployments": [
                    {
                        "id": "ocid1.apideployment.oc1..d1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "gateway_id": "ocid1.apigateway.oc1..gw1",
                        "lifecycle_state": "ACTIVE",
                        "path_prefix": "/v1",
                        "specification": json.dumps(
                            {"request_policies": {}, "routes": [{"path": "/orders", "methods": ["GET"]}]}
                        ),
                    }
                ],
            }
        )
        res = ApiGatewayServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("APIGW_DEPLOYMENT_NO_AUTHENTICATION", codes)
        findings = [f for f in res.findings if f.issue_code == "APIGW_DEPLOYMENT_NO_AUTHENTICATION"]
        self.assertEqual(findings[0].severity, "CRITICAL")
        # Should not also emit a route-level anonymous finding -- the whole
        # deployment is already unauthenticated, so it would just be noise.
        self.assertNotIn("APIGW_ROUTE_ANONYMOUS_AUTHORIZATION", codes)

    def test_deployment_with_authentication_not_flagged(self):
        session = _Session(
            {
                "apigw_gateways": [self._public_gateway()],
                "apigw_deployments": [
                    {
                        "id": "ocid1.apideployment.oc1..d1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "gateway_id": "ocid1.apigateway.oc1..gw1",
                        "lifecycle_state": "ACTIVE",
                        "path_prefix": "/v1",
                        "specification": json.dumps(
                            {
                                "request_policies": {
                                    "authentication": {"type": "JWT_AUTHENTICATION"}
                                },
                                "routes": [{"path": "/orders", "methods": ["GET"]}],
                            }
                        ),
                    }
                ],
            }
        )
        res = ApiGatewayServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("APIGW_DEPLOYMENT_NO_AUTHENTICATION", codes)
        self.assertNotIn("APIGW_ROUTE_ANONYMOUS_AUTHORIZATION", codes)

    def test_route_anonymous_override_flags_high_when_deployment_authenticated(self):
        session = _Session(
            {
                "apigw_gateways": [self._public_gateway()],
                "apigw_deployments": [
                    {
                        "id": "ocid1.apideployment.oc1..d1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "gateway_id": "ocid1.apigateway.oc1..gw1",
                        "lifecycle_state": "ACTIVE",
                        "path_prefix": "/v1",
                        "specification": json.dumps(
                            {
                                "request_policies": {
                                    "authentication": {
                                        "type": "JWT_AUTHENTICATION",
                                        "is_anonymous_access_allowed": True,
                                    }
                                },
                                "routes": [
                                    {
                                        "path": "/health",
                                        "methods": ["GET"],
                                        "request_policies": {"authorization": {"type": "ANONYMOUS"}},
                                    },
                                    {"path": "/orders", "methods": ["GET"]},
                                ],
                            }
                        ),
                    }
                ],
            }
        )
        res = ApiGatewayServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "APIGW_ROUTE_ANONYMOUS_AUTHORIZATION"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("/v1/health", findings[0].description or findings[0].title or str(findings[0].location))

    def test_deployment_not_flagged_when_gateway_private(self):
        session = _Session(
            {
                "apigw_gateways": [
                    {
                        "id": "ocid1.apigateway.oc1..gw1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "endpoint_type": "PRIVATE",
                    }
                ],
                "apigw_deployments": [
                    {
                        "id": "ocid1.apideployment.oc1..d1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "gateway_id": "ocid1.apigateway.oc1..gw1",
                        "lifecycle_state": "ACTIVE",
                        "path_prefix": "/v1",
                        "specification": json.dumps({"request_policies": {}, "routes": []}),
                    }
                ],
            }
        )
        res = ApiGatewayServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("APIGW_DEPLOYMENT_NO_AUTHENTICATION", codes)

    def test_deployment_not_flagged_when_specification_absent(self):
        # specification absent entirely == list-only (no --get) enumeration --
        # must not be misread as "no authentication configured".
        session = _Session(
            {
                "apigw_gateways": [self._public_gateway()],
                "apigw_deployments": [
                    {
                        "id": "ocid1.apideployment.oc1..d1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "gateway_id": "ocid1.apigateway.oc1..gw1",
                        "lifecycle_state": "ACTIVE",
                        "path_prefix": "/v1",
                    }
                ],
            }
        )
        res = ApiGatewayServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("APIGW_DEPLOYMENT_NO_AUTHENTICATION", codes)

    def test_deployment_not_flagged_when_deleted(self):
        session = _Session(
            {
                "apigw_gateways": [self._public_gateway()],
                "apigw_deployments": [
                    {
                        "id": "ocid1.apideployment.oc1..d1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "gateway_id": "ocid1.apigateway.oc1..gw1",
                        "lifecycle_state": "DELETED",
                        "path_prefix": "/v1",
                        "specification": json.dumps({"request_policies": {}, "routes": []}),
                    }
                ],
            }
        )
        res = ApiGatewayServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("APIGW_DEPLOYMENT_NO_AUTHENTICATION", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditCacheUserAuthMode(unittest.TestCase):
    def test_password_mode_no_hashes_flags_critical(self):
        session = _Session(
            {
                "cache_users": [
                    {
                        "id": "ocid1.ocicacheuser.oc1..u1",
                        "name": "default",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "status": "ON",
                        "authentication_mode": json.dumps(
                            {"authentication_type": "PASSWORD", "hashed_passwords": []}
                        ),
                        "acl_string": "on ~* &* +@all",
                    }
                ]
            }
        )
        res = CacheServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "CACHE_USER_WEAK_AUTH_MODE"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_acl_string_nopass_flags_critical(self):
        session = _Session(
            {
                "cache_users": [
                    {
                        "id": "ocid1.ocicacheuser.oc1..u1",
                        "name": "default",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "status": "ON",
                        "authentication_mode": json.dumps({"authentication_type": "IAM"}),
                        "acl_string": "on nopass ~* &* +@all",
                    }
                ]
            }
        )
        res = CacheServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "CACHE_USER_WEAK_AUTH_MODE"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_password_mode_with_hashes_not_flagged(self):
        session = _Session(
            {
                "cache_users": [
                    {
                        "id": "ocid1.ocicacheuser.oc1..u1",
                        "name": "app-user",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "status": "ON",
                        "authentication_mode": json.dumps(
                            {"authentication_type": "PASSWORD", "hashed_passwords": ["abc123"]}
                        ),
                        "acl_string": "on >abc123 ~* &* +@all",
                    }
                ]
            }
        )
        res = CacheServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("CACHE_USER_WEAK_AUTH_MODE", codes)

    def test_iam_mode_not_flagged(self):
        session = _Session(
            {
                "cache_users": [
                    {
                        "id": "ocid1.ocicacheuser.oc1..u1",
                        "name": "app-user",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "status": "ON",
                        "authentication_mode": json.dumps({"authentication_type": "IAM"}),
                        "acl_string": "on ~* &* +@all",
                    }
                ]
            }
        )
        res = CacheServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("CACHE_USER_WEAK_AUTH_MODE", codes)

    def test_nopass_user_with_status_off_not_flagged(self):
        session = _Session(
            {
                "cache_users": [
                    {
                        "id": "ocid1.ocicacheuser.oc1..u1",
                        "name": "default",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "status": "OFF",
                        "authentication_mode": json.dumps(
                            {"authentication_type": "PASSWORD", "hashed_passwords": []}
                        ),
                        "acl_string": "off nopass ~* &* +@all",
                    }
                ]
            }
        )
        res = CacheServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("CACHE_USER_WEAK_AUTH_MODE", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditNotifications(unittest.TestCase):
    def test_http_endpoint_flags(self):
        session = _Session(
            {
                "notification_subscriptions": [
                    {
                        "id": "ocid1.onssubscription.oc1..s1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "protocol": "CUSTOM_HTTPS",
                        "endpoint": "http://example.com/hook",
                    }
                ]
            }
        )
        res = NotificationsServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("NOTIFICATION_HTTP_SUBSCRIPTION", codes)

    def test_https_endpoint_not_flagged(self):
        session = _Session(
            {
                "notification_subscriptions": [
                    {
                        "id": "ocid1.onssubscription.oc1..s1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "protocol": "CUSTOM_HTTPS",
                        "endpoint": "https://example.com/hook",
                    }
                ]
            }
        )
        res = NotificationsServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("NOTIFICATION_HTTP_SUBSCRIPTION", codes)

    def test_deleted_subscription_not_flagged(self):
        session = _Session(
            {
                "notification_subscriptions": [
                    {
                        "id": "ocid1.onssubscription.oc1..s1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "DELETED",
                        "protocol": "CUSTOM_HTTPS",
                        "endpoint": "http://example.com/hook",
                    }
                ]
            }
        )
        res = NotificationsServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("NOTIFICATION_HTTP_SUBSCRIPTION", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditIoT(unittest.TestCase):
    def test_domain_group_empty_allowlist_flags_when_collected(self):
        session = _Session(
            {
                "iot_domain_groups": [
                    {
                        "id": "ocid1.iotdomaingroup.oc1..g1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "db_allow_listed_vcn_ids": json.dumps([]),
                    }
                ]
            }
        )
        res = IoTServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("IOT_DOMAIN_GROUP_VCN_ALLOWLIST_EMPTY", codes)

    def test_domain_group_not_flagged_when_not_collected_via_get(self):
        session = _Session(
            {
                "iot_domain_groups": [
                    {
                        "id": "ocid1.iotdomaingroup.oc1..g1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        # db_allow_listed_vcn_ids absent entirely (list-only enumeration)
                    }
                ]
            }
        )
        res = IoTServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IOT_DOMAIN_GROUP_VCN_ALLOWLIST_EMPTY", codes)

    def test_domain_group_not_flagged_when_deleted(self):
        session = _Session(
            {
                "iot_domain_groups": [
                    {
                        "id": "ocid1.iotdomaingroup.oc1..g1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "DELETED",
                        "db_allow_listed_vcn_ids": json.dumps([]),
                    }
                ]
            }
        )
        res = IoTServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IOT_DOMAIN_GROUP_VCN_ALLOWLIST_EMPTY", codes)

    def test_domain_identity_allowlist_populated_not_flagged(self):
        session = _Session(
            {
                "iot_domains": [
                    {
                        "id": "ocid1.iotdomain.oc1..d1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "db_allow_listed_identity_group_names": json.dumps(["approved-group"]),
                    }
                ]
            }
        )
        res = IoTServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IOT_DOMAIN_IDENTITY_GROUP_ALLOWLIST_EMPTY", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditManagedKafka(unittest.TestCase):
    def test_plaintext_bootstrap_flags_on_listener_name(self):
        session = _Session(
            {
                "kafka_clusters": [
                    {
                        "id": "ocid1.kafkacluster.oc1..c1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "kafka_bootstrap_urls": json.dumps(
                            [{"name": "PLAINTEXT", "url": "10.0.0.5:9092"}]
                        ),
                    }
                ]
            }
        )
        res = ManagedKafkaServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("KAFKA_PLAINTEXT_BOOTSTRAP_URL", codes)

    def test_tls_only_bootstrap_not_flagged(self):
        session = _Session(
            {
                "kafka_clusters": [
                    {
                        "id": "ocid1.kafkacluster.oc1..c1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "kafka_bootstrap_urls": json.dumps(
                            [{"name": "TLS", "url": "10.0.0.5:9093"}]
                        ),
                    }
                ]
            }
        )
        res = ManagedKafkaServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("KAFKA_PLAINTEXT_BOOTSTRAP_URL", codes)

    def test_bootstrap_not_flagged_when_not_collected_via_get(self):
        session = _Session(
            {
                "kafka_clusters": [
                    {
                        "id": "ocid1.kafkacluster.oc1..c1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                    }
                ]
            }
        )
        res = ManagedKafkaServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("KAFKA_PLAINTEXT_BOOTSTRAP_URL", codes)
        self.assertNotIn("KAFKA_AUTH_MATERIAL_NOT_CONFIGURED", codes)

    def test_auth_material_missing_flags_when_collected(self):
        session = _Session(
            {
                "kafka_clusters": [
                    {
                        "id": "ocid1.kafkacluster.oc1..c1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "kafka_bootstrap_urls": json.dumps(
                            [{"name": "TLS", "url": "10.0.0.5:9093"}]
                        ),
                        "secret_id": "",
                        "client_certificate_bundle": "",
                    }
                ]
            }
        )
        res = ManagedKafkaServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("KAFKA_AUTH_MATERIAL_NOT_CONFIGURED", codes)

    def test_auth_material_present_not_flagged(self):
        session = _Session(
            {
                "kafka_clusters": [
                    {
                        "id": "ocid1.kafkacluster.oc1..c1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "kafka_bootstrap_urls": json.dumps(
                            [{"name": "TLS", "url": "10.0.0.5:9093"}]
                        ),
                        "secret_id": "ocid1.vaultsecret.oc1..example",
                        "client_certificate_bundle": "",
                    }
                ]
            }
        )
        res = ManagedKafkaServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("KAFKA_AUTH_MATERIAL_NOT_CONFIGURED", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditIntegration(unittest.TestCase):
    def test_public_no_allowlist_flags(self):
        session = _Session(
            {
                "integration_instances": [
                    {
                        "id": "ocid1.integrationinstance.oc1..i1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "network_endpoint_details": json.dumps(
                            {"network_endpoint_type": "PUBLIC"}
                        ),
                    }
                ]
            }
        )
        res = IntegrationServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertIn("INTEGRATION_INSTANCE_NO_NETWORK_ALLOWLIST", codes)

    def test_public_with_runtime_allowlist_not_flagged(self):
        # Restricted exclusively through the nested runtime allowlist, leaving the
        # legacy top-level allowlisted_http_ips/vcns empty -- must not false-positive.
        session = _Session(
            {
                "integration_instances": [
                    {
                        "id": "ocid1.integrationinstance.oc1..i1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "network_endpoint_details": json.dumps(
                            {
                                "network_endpoint_type": "PUBLIC",
                                "runtime": {"allowlisted_http_ips": ["203.0.113.5/32"]},
                            }
                        ),
                    }
                ]
            }
        )
        res = IntegrationServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("INTEGRATION_INSTANCE_NO_NETWORK_ALLOWLIST", codes)

    def test_public_with_design_time_vcn_allowlist_not_flagged(self):
        session = _Session(
            {
                "integration_instances": [
                    {
                        "id": "ocid1.integrationinstance.oc1..i1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "network_endpoint_details": json.dumps(
                            {
                                "network_endpoint_type": "PUBLIC",
                                "design_time": {"allowlisted_http_vcns": [{"id": "ocid1.vcn.oc1..example"}]},
                            }
                        ),
                    }
                ]
            }
        )
        res = IntegrationServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("INTEGRATION_INSTANCE_NO_NETWORK_ALLOWLIST", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditFileStorageCmk(unittest.TestCase):
    def test_file_system_without_cmk_is_flagged(self):
        session = _Session(
            {
                "file_storage_file_systems": [
                    {
                        "id": "ocid1.filesystem.oc1..fs1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "kms_key_id": "",
                    }
                ]
            }
        )
        res = FileStorageServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "FILE_STORAGE_FILE_SYSTEM_NO_CMK"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_file_system_with_cmk_not_flagged(self):
        session = _Session(
            {
                "file_storage_file_systems": [
                    {
                        "id": "ocid1.filesystem.oc1..fs1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "kms_key_id": "ocid1.key.oc1..k1",
                    }
                ]
            }
        )
        res = FileStorageServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("FILE_STORAGE_FILE_SYSTEM_NO_CMK", codes)

    def test_deleted_file_system_not_flagged(self):
        session = _Session(
            {
                "file_storage_file_systems": [
                    {
                        "id": "ocid1.filesystem.oc1..fs1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "DELETED",
                        "kms_key_id": "",
                    }
                ]
            }
        )
        res = FileStorageServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("FILE_STORAGE_FILE_SYSTEM_NO_CMK", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditIdentityApiKeyRotationAndAdminExposure(unittest.TestCase):
    @staticmethod
    def _iso_days_ago(days):
        from datetime import datetime, timedelta, timezone

        return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    def test_stale_active_api_key_is_flagged(self):
        session = _Session(
            {
                "identity_user_api_keys": [
                    {
                        "key_id": "k1",
                        "user_id": "u1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "time_created": self._iso_days_ago(200),
                    }
                ]
            }
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "IAM_USER_API_KEY_STALE"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_fresh_active_api_key_not_flagged(self):
        session = _Session(
            {
                "identity_user_api_keys": [
                    {
                        "key_id": "k1",
                        "user_id": "u1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "time_created": self._iso_days_ago(5),
                    }
                ]
            }
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IAM_USER_API_KEY_STALE", codes)

    def test_stale_inactive_api_key_not_flagged(self):
        session = _Session(
            {
                "identity_user_api_keys": [
                    {
                        "key_id": "k1",
                        "user_id": "u1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "INACTIVE",
                        "time_created": self._iso_days_ago(400),
                    }
                ]
            }
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IAM_USER_API_KEY_STALE", codes)

    def test_admin_group_member_with_active_key_is_flagged(self):
        session = _Session(
            {
                "identity_user_group_memberships": [
                    {"user_id": "u1", "group_name": "Administrators"},
                ],
                "identity_user_api_keys": [
                    {
                        "key_id": "k1",
                        "user_id": "u1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "time_created": self._iso_days_ago(5),
                    }
                ],
            }
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "IAM_ADMIN_USER_HAS_API_KEY"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_non_admin_group_member_with_active_key_not_flagged(self):
        session = _Session(
            {
                "identity_user_group_memberships": [
                    {"user_id": "u1", "group_name": "Developers"},
                ],
                "identity_user_api_keys": [
                    {
                        "key_id": "k1",
                        "user_id": "u1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "ACTIVE",
                        "time_created": self._iso_days_ago(5),
                    }
                ],
            }
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IAM_ADMIN_USER_HAS_API_KEY", codes)

    def test_admin_group_member_with_inactive_key_not_flagged(self):
        session = _Session(
            {
                "identity_user_group_memberships": [
                    {"user_id": "u1", "group_name": "Administrators"},
                ],
                "identity_user_api_keys": [
                    {
                        "key_id": "k1",
                        "user_id": "u1",
                        "compartment_id": "ocid1.compartment.oc1..example",
                        "lifecycle_state": "DELETED",
                        "time_created": self._iso_days_ago(5),
                    }
                ],
            }
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IAM_ADMIN_USER_HAS_API_KEY", codes)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit dependencies not available")
class TestConfigAuditIdentityPolicyPrivilegeEscalation(unittest.TestCase):
    def _policy(self, statements):
        return {
            "compartment_id": "ocid1.compartment.oc1..example",
            "id": "ocid1.policy.oc1..example",
            "statements": statements,
        }

    def test_non_admin_group_manage_all_resources_is_flagged(self):
        session = _Session(
            {"identity_policies": [self._policy(["Allow group DevOps to manage all-resources in tenancy"])]}
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        findings = [
            f for f in res.findings if f.issue_code == "IAM_POLICY_MANAGE_ALL_RESOURCES_NON_ADMIN_GROUP"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_administrators_group_manage_all_resources_not_flagged(self):
        session = _Session(
            {
                "identity_policies": [
                    self._policy(["Allow group Administrators to manage all-resources in tenancy"])
                ]
            }
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IAM_POLICY_MANAGE_ALL_RESOURCES_NON_ADMIN_GROUP", codes)

    def test_scoped_grant_not_flagged(self):
        session = _Session(
            {"identity_policies": [self._policy(["Allow group DevOps to manage instances in tenancy"])]}
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IAM_POLICY_MANAGE_ALL_RESOURCES_NON_ADMIN_GROUP", codes)

    def test_use_groups_without_admin_exclusion_is_flagged(self):
        session = _Session(
            {"identity_policies": [self._policy(["Allow group IAMAdmins to use groups in tenancy"])]}
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        findings = [f for f in res.findings if f.issue_code == "IAM_POLICY_ADMIN_GROUP_NOT_PROTECTED"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_use_groups_with_admin_exclusion_not_flagged(self):
        session = _Session(
            {
                "identity_policies": [
                    self._policy(
                        [
                            "Allow group IAMAdmins to use groups in tenancy "
                            "where target.group.name != 'Administrators'"
                        ]
                    )
                ]
            }
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IAM_POLICY_ADMIN_GROUP_NOT_PROTECTED", codes)

    def test_use_users_compartment_scoped_not_flagged(self):
        session = _Session(
            {
                "identity_policies": [
                    self._policy(["Allow group HelpDesk to use users in compartment Sandbox"])
                ]
            }
        )
        res = IdentityServiceAuditor(session=session).run_checks()
        codes = {f.issue_code for f in res.findings}
        self.assertNotIn("IAM_POLICY_ADMIN_GROUP_NOT_PROTECTED", codes)
