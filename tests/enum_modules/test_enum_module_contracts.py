from __future__ import annotations

import pytest

from tests.enum_modules.harness import assert_module_flags_parse, assert_module_runs_offline

# One entry per enum/process module: its argparse flags must parse, and it must run
# end-to-end offline (no network) against a stubbed session without raising.
MODULES = [
    "ocinferno.modules.everything.enumeration.enum_all",
    "ocinferno.modules.apigateway.enumeration.enum_apigateway",
    "ocinferno.modules.artifactregistry.enumeration.enum_artifactregistry",
    "ocinferno.modules.bastion.enumeration.enum_bastion",
    "ocinferno.modules.blockchain.enumeration.enum_blockchain",
    "ocinferno.modules.cloudguard.enumeration.enum_cloudguard",
    "ocinferno.modules.identityclient.enumeration.enum_comp",
    "ocinferno.modules.containerinstances.enumeration.enum_container_instances",
    "ocinferno.modules.containerregistry.enumeration.enum_containerregistry",
    "ocinferno.modules.core.enumeration.enum_core_block_storage",
    "ocinferno.modules.core.enumeration.enum_core_compute",
    "ocinferno.modules.core.enumeration.enum_core_network",
    "ocinferno.modules.databases.enumeration.enum_databases",
    "ocinferno.modules.dataflow.enumeration.enum_dataflow",
    "ocinferno.modules.datascience.enumeration.enum_datascience",
    "ocinferno.modules.desktops.enumeration.enum_desktops",
    "ocinferno.modules.devops.enumeration.enum_devops",
    "ocinferno.modules.dns.enumeration.enum_dns",
    "ocinferno.modules.email.enumeration.enum_email",
    "ocinferno.modules.filestorage.enumeration.enum_filestorage",
    "ocinferno.modules.functions.enumeration.enum_functions",
    "ocinferno.modules.identityclient.enumeration.enum_identity",
    "ocinferno.modules.iot.enumeration.enum_iot",
    "ocinferno.modules.kubernetes.enumeration.enum_kubernetes",
    "ocinferno.modules.logging.enumeration.enum_logs",
    "ocinferno.modules.managedkafka.enumeration.enum_managedkafka",
    "ocinferno.modules.networkfirewall.enumeration.enum_networkfirewall",
    "ocinferno.modules.networkloadbalancer.enumeration.enum_network_load_balancers",
    "ocinferno.modules.notifications.enumeration.enum_notifications",
    "ocinferno.modules.objectstorage.enumeration.enum_objectstorage",
    "ocinferno.modules.os_management_hub.enumeration.enum_os_management_hub",
    "ocinferno.modules.resourcemanager.enumeration.enum_resourcemanager",
    "ocinferno.modules.resourcescheduler.enumeration.enum_resource_schedules",
    "ocinferno.modules.resource_search.enumeration.enum_resource_search",
    "ocinferno.modules.service_connector.enumeration.enum_service_connector",
    "ocinferno.modules.tagging.enumeration.enum_tagging",
    "ocinferno.modules.vault.enumeration.enum_vault",
    "ocinferno.modules.everything.processing.process_config_check",
    "ocinferno.modules.opengraph.processing.process_oracle_cloud_hound_data",
]


@pytest.mark.parametrize("module_name", MODULES, ids=lambda m: m.rsplit(".", 1)[-1])
def test_module_flags_and_offline_smoke(module_name: str) -> None:
    assert_module_flags_parse(module_name)
    assert_module_runs_offline(module_name)
