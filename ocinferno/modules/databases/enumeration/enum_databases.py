#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.databases.utilities.helpers import (
    DatabasesAutonomousResource,
    DatabasesAutonomousContainerDatabasesResource,
    DatabasesAutonomousVmClustersResource,
    DatabasesCloudAutonomousVmClustersResource,
    DatabasesCloudExadataInfrastructuresResource,
    DatabasesCloudVmClustersResource,
    DatabasesDatabasesResource,
    DatabasesDbSystemsResource,
    DatabasesExadataInfrastructuresResource,
    DatabasesExternalContainerDatabasesResource,
    DatabasesExternalNonContainerDatabasesResource,
    DatabasesExternalPluggableDatabasesResource,
    DatabasesPluggableDatabasesResource,
    DatabasesVmClustersResource,
)

COMPONENTS = [
    Component("autonomous_databases", DatabasesAutonomousResource,
              help_text="Enumerate Autonomous Databases (ADB-S/ADB-D)", cache_table="db_autonomous_databases"),
    Component("autonomous_container_databases", DatabasesAutonomousContainerDatabasesResource,
              help_text="Enumerate Autonomous Container Databases (Dedicated Exadata)", cache_table="db_autonomous_container_databases"),
    Component("db_systems", DatabasesDbSystemsResource,
              help_text="Enumerate Base Database DB Systems (VM/BM/Exadata)", cache_table="db_db_systems"),
    Component("databases", DatabasesDatabasesResource,
              help_text="Enumerate individual databases within DB Systems", cache_table="db_databases"),
    Component("pluggable_databases", DatabasesPluggableDatabasesResource,
              help_text="Enumerate Pluggable Databases (PDBs)", cache_table="db_pluggable_databases"),
    Component("cloud_exadata_infrastructures", DatabasesCloudExadataInfrastructuresResource,
              help_text="Enumerate Cloud Exadata Infrastructure", cache_table="db_cloud_exadata_infrastructures"),
    Component("cloud_vm_clusters", DatabasesCloudVmClustersResource,
              help_text="Enumerate Cloud VM Clusters on Cloud Exadata", cache_table="db_cloud_vm_clusters"),
    Component("exadata_infrastructures", DatabasesExadataInfrastructuresResource,
              help_text="Enumerate Exadata Infrastructure (Exadata Cloud@Customer)", cache_table="db_exadata_infrastructures"),
    Component("vm_clusters", DatabasesVmClustersResource,
              help_text="Enumerate VM Clusters on Exadata Cloud@Customer", cache_table="db_vm_clusters"),
    Component("autonomous_vm_clusters", DatabasesAutonomousVmClustersResource,
              help_text="Enumerate Autonomous VM Clusters (Exadata Cloud@Customer)", cache_table="db_autonomous_vm_clusters"),
    Component("cloud_autonomous_vm_clusters", DatabasesCloudAutonomousVmClustersResource,
              help_text="Enumerate Cloud Autonomous VM Clusters (Exadata Cloud Service)", cache_table="db_cloud_autonomous_vm_clusters"),
    Component("external_container_databases", DatabasesExternalContainerDatabasesResource,
              help_text="Enumerate External Container Databases (on-prem CDB connections)", cache_table="db_external_container_databases"),
    Component("external_non_container_databases", DatabasesExternalNonContainerDatabasesResource,
              help_text="Enumerate External Non-Container Databases (on-prem non-CDB connections)", cache_table="db_external_non_container_databases"),
    Component("external_pluggable_databases", DatabasesExternalPluggableDatabasesResource,
              help_text="Enumerate External Pluggable Databases (on-prem PDB connections)", cache_table="db_external_pluggable_databases"),
]


def run_module(user_args, session):
    return run_components(user_args, session, COMPONENTS,
                         module_name="enum_databases",
                         description="Enumerate Databases resources")
