#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class DatabasesAutonomousResource(OciListResource):
    """Autonomous Databases (ADB) via oci.database. High value: --get exposes
    connection_strings / connection_urls (APEX, SQL Dev Web, database console)."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_autonomous_databases"
    LIST_METHOD = "list_autonomous_databases"
    GET_METHOD = "get_autonomous_database"
    GET_ID_PARAM = "autonomous_database_id"
    COLUMNS = ["id", "display_name", "db_name", "lifecycle_state", "db_workload", "is_free_tier", "time_created"]


class DatabasesDbSystemsResource(OciListResource):
    """Base Database Service DB Systems (VM/BM/Exadata) via oci.database. --get
    exposes shape, hostname, listener/scan details, and licensing."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_db_systems"
    LIST_METHOD = "list_db_systems"
    GET_METHOD = "get_db_system"
    GET_ID_PARAM = "db_system_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "shape", "database_edition", "hostname", "time_created"]


class DatabasesDatabasesResource(OciListResource):
    """Individual databases within DB Systems. --get exposes connection details,
    DB unique name, PDB name, and character set."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_databases"
    LIST_METHOD = "list_databases"
    GET_METHOD = "get_database"
    GET_ID_PARAM = "database_id"
    COLUMNS = ["id", "db_name", "db_unique_name", "lifecycle_state", "db_workload", "db_system_id", "time_created"]


class DatabasesPluggableDatabasesResource(OciListResource):
    """Pluggable Databases (PDBs) within Container Databases."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_pluggable_databases"
    LIST_METHOD = "list_pluggable_databases"
    GET_METHOD = "get_pluggable_database"
    GET_ID_PARAM = "pluggable_database_id"
    COLUMNS = ["id", "pdb_name", "lifecycle_state", "container_database_id", "open_mode", "time_created"]


class DatabasesAutonomousContainerDatabasesResource(OciListResource):
    """Autonomous Container Databases (ACDs) on Dedicated Exadata. Each ACD
    hosts one or more Autonomous Databases in dedicated infrastructure."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_autonomous_container_databases"
    LIST_METHOD = "list_autonomous_container_databases"
    GET_METHOD = "get_autonomous_container_database"
    GET_ID_PARAM = "autonomous_container_database_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "service_level_agreement_type", "autonomous_exadata_infrastructure_id", "time_created"]


class DatabasesCloudExadataInfrastructuresResource(OciListResource):
    """Cloud Exadata Infrastructure — the physical Exadata hardware backing
    Cloud VM Clusters and Cloud Autonomous VM Clusters."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_cloud_exadata_infrastructures"
    LIST_METHOD = "list_cloud_exadata_infrastructures"
    GET_METHOD = "get_cloud_exadata_infrastructure"
    GET_ID_PARAM = "cloud_exadata_infrastructure_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "shape", "compute_count", "storage_count", "time_created"]


class DatabasesCloudVmClustersResource(OciListResource):
    """Cloud VM Clusters on Cloud Exadata Infrastructure. Hosts Base Database
    or Autonomous Databases in Exadata Cloud Service."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_cloud_vm_clusters"
    LIST_METHOD = "list_cloud_vm_clusters"
    GET_METHOD = "get_cloud_vm_cluster"
    GET_ID_PARAM = "cloud_vm_cluster_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "shape", "hostname", "cloud_exadata_infrastructure_id", "time_created"]


class DatabasesExadataInfrastructuresResource(OciListResource):
    """Exadata Infrastructures (Exadata Cloud@Customer — on-prem Exadata managed via OCI)."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_exadata_infrastructures"
    LIST_METHOD = "list_exadata_infrastructures"
    GET_METHOD = "get_exadata_infrastructure"
    GET_ID_PARAM = "exadata_infrastructure_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "shape", "compute_count", "storage_count", "time_created"]


class DatabasesVmClustersResource(OciListResource):
    """VM Clusters on Exadata Cloud@Customer infrastructure."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_vm_clusters"
    LIST_METHOD = "list_vm_clusters"
    GET_METHOD = "get_vm_cluster"
    GET_ID_PARAM = "vm_cluster_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "shape", "exadata_infrastructure_id", "time_created"]


class DatabasesAutonomousVmClustersResource(OciListResource):
    """Autonomous VM Clusters on Exadata Cloud@Customer — dedicated compute
    for Autonomous Container Databases."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_autonomous_vm_clusters"
    LIST_METHOD = "list_autonomous_vm_clusters"
    GET_METHOD = "get_autonomous_vm_cluster"
    GET_ID_PARAM = "autonomous_vm_cluster_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "exadata_infrastructure_id", "vm_cluster_network_id", "time_created"]


class DatabasesCloudAutonomousVmClustersResource(OciListResource):
    """Cloud Autonomous VM Clusters on Cloud Exadata Infrastructure — dedicated
    compute for Autonomous Container Databases in Exadata Cloud Service."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_cloud_autonomous_vm_clusters"
    LIST_METHOD = "list_cloud_autonomous_vm_clusters"
    GET_METHOD = "get_cloud_autonomous_vm_cluster"
    GET_ID_PARAM = "cloud_autonomous_vm_cluster_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "cloud_exadata_infrastructure_id", "time_created"]


class DatabasesExternalContainerDatabasesResource(OciListResource):
    """External Container Databases — connections to on-premises Oracle CDBs
    managed via OCI External Database Service."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_external_container_databases"
    LIST_METHOD = "list_external_container_databases"
    GET_METHOD = "get_external_container_database"
    GET_ID_PARAM = "external_container_database_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "db_unique_name", "database_version", "time_created"]


class DatabasesExternalNonContainerDatabasesResource(OciListResource):
    """External Non-Container Databases — connections to on-premises Oracle non-CDB instances."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_external_non_container_databases"
    LIST_METHOD = "list_external_non_container_databases"
    GET_METHOD = "get_external_non_container_database"
    GET_ID_PARAM = "external_non_container_database_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "db_unique_name", "database_version", "time_created"]


class DatabasesExternalPluggableDatabasesResource(OciListResource):
    """External Pluggable Databases — connections to on-premises Oracle PDBs."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_external_pluggable_databases"
    LIST_METHOD = "list_external_pluggable_databases"
    GET_METHOD = "get_external_pluggable_database"
    GET_ID_PARAM = "external_pluggable_database_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "external_container_database_id", "time_created"]
