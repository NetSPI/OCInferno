#!/usr/bin/env python3

from argparse import Namespace
from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.module_helpers import ids_from_db, parse_csv_args, save_rows
from ocinferno.core.utils.service_runtime import _init_client


def build_managed_kafka_client(session, region: Optional[str] = None):
    """Initialize a Managed Kafka client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.managed_kafka.KafkaClusterClient,
        session=session,
        service_name="Managed Kafka",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class ManagedKafkaClustersResource:
    TABLE_NAME = "kafka_clusters"
    COLUMNS = ["id", "display_name", "lifecycle_state", "kafka_version", "cluster_type", "cluster_config_id", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_managed_kafka_client(session=session, region=region)

    # List Kafka clusters in a compartment.
    def list(self, *, compartment_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {}
        if compartment_id:
            kwargs["compartment_id"] = compartment_id
        resp = oci.pagination.list_call_get_all_results(self.client.list_kafka_clusters, **kwargs)
        return oci.util.to_dict(resp.data) or []

    # Get one Kafka cluster by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_kafka_cluster(kafka_cluster_id=resource_id).data) or {}

    # Save cluster rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)

    # No binary download endpoint for cluster rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class ManagedKafkaClusterConfigsResource:
    TABLE_NAME = "kafka_cluster_configs"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "time_updated"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_managed_kafka_client(session=session, region=region)

    # List Kafka cluster configs in a compartment.
    def list(self, *, compartment_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {}
        if compartment_id:
            kwargs["compartment_id"] = compartment_id
        resp = oci.pagination.list_call_get_all_results(self.client.list_kafka_cluster_configs, **kwargs)
        return oci.util.to_dict(resp.data) or []

    # Get one Kafka cluster config by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_kafka_cluster_config(kafka_cluster_config_id=resource_id).data) or {}

    # Save cluster-config rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)

    # No binary download endpoint for cluster-config rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class ManagedKafkaClusterConfigVersionsResource:
    TABLE_NAME = "kafka_cluster_config_versions"
    TABLE_CLUSTER_CONFIGS = "kafka_cluster_configs"
    COLUMNS = ["config_id", "version_number", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_managed_kafka_client(session=session, region=region)

    # Resolve config IDs from CLI, cache, or live list.
    def resolve_cluster_config_ids(self, comp_id: Optional[str], args: Namespace) -> List[str]:
        cli_ids = parse_csv_args(list(getattr(args, "cluster_config_ids", []) or []))
        if cli_ids:
            return cli_ids

        db_cached = ids_from_db(self.session, table_name=self.TABLE_CLUSTER_CONFIGS, compartment_id=comp_id)
        if db_cached:
            return db_cached

        try:
            rows = ManagedKafkaClusterConfigsResource(self.session).list(compartment_id=comp_id) or []
            return parse_csv_args([row.get("id") for row in rows if isinstance(row, dict) and row.get("id")])
        except Exception:
            return []

    # Deduplicate config-version rows by (config_id, version_number).
    @staticmethod
    def unique_cfg_version_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen = set()
        for row in rows or []:
            key = (row.get("config_id"), row.get("version_number"))
            if key in seen:
                continue
            seen.add(key)
            out.append(row)
        return out

    # List versions for one config OCID.
    def list(self, *, kafka_cluster_config_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_kafka_cluster_config_versions,
            kafka_cluster_config_id=kafka_cluster_config_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one config version.
    def get(self, *, kafka_cluster_config_id: str, version_number: int) -> Dict[str, Any]:
        resp = self.client.get_kafka_cluster_config_version(
            kafka_cluster_config_id=kafka_cluster_config_id,
            version_number=version_number,
        )
        return oci.util.to_dict(resp.data) or {}

    # Save config-version rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)

    # No binary download endpoint for config-version rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


normalize_csv_args = parse_csv_args
db_ids = ids_from_db
