from __future__ import annotations

from pathlib import Path

from ocinferno.core.db import DataController


class IntegrationTestDataController(DataController):
    """Isolated DB controller for integration tests."""

    def __init__(self, db_root: Path):
        self.metadata_db = str(db_root / "organization_metadata.db")
        self.service_db = str(db_root / "service_info.db")
        super().__init__()


class OpenGraphTestSession:
    """
    Lightweight session shim used by OpenGraph integration tests.
    Mirrors only the methods that builders/module runners call.
    """

    def __init__(
        self,
        dc: DataController,
        *,
        workspace_id: int,
        workspace_name: str,
        compartment_id: str,
        tenant_id: str,
        output_root: Path | None = None,
    ):
        self.data_master = dc
        self.workspace_id = workspace_id
        self.workspace_name = workspace_name
        self.compartment_id = compartment_id
        self.tenant_id = tenant_id
        self.debug = False
        self.individual_run_debug = False
        self._output_root = Path(output_root) if output_root else None

    def commit(self):
        self.data_master.commit("service")

    def get_resource_fields(self, table_name, where_conditions=None, columns=None):
        where = dict(where_conditions or {})
        where["workspace_id"] = self.workspace_id
        return self.data_master.fetch_column_from_table(
            db="service",
            table_name=table_name,
            columns=columns,
            where=where,
            as_dict=True,
        )

    def delete_resource(self, table_name: str, where=None):
        where_clause = dict(where or {})
        where_clause["workspace_id"] = self.workspace_id
        return self.data_master.delete_dict_row(
            db="service",
            table_name=table_name,
            where=where_clause,
            require_where=True,
            commit=True,
        )

    def set_node_fields(self, row: dict, *, commit: bool = True, on_conflict: str = "update_nulls") -> bool:
        payload = dict(row or {})
        payload["workspace_id"] = self.workspace_id
        return self.data_master.save_dict_row(
            db="service",
            table_name="opengraph_nodes",
            row=payload,
            on_conflict=on_conflict,
            conflict_cols=["node_type", "node_id", "workspace_id"],
            commit=commit,
        )

    def set_edge_fields(self, row: dict, *, commit: bool = True, on_conflict: str = "ignore") -> bool:
        payload = dict(row or {})
        payload["workspace_id"] = self.workspace_id
        return self.data_master.save_dict_row(
            db="service",
            table_name="opengraph_edges",
            row=payload,
            on_conflict=on_conflict,
            conflict_cols=["source_id", "edge_type", "destination_id", "workspace_id"],
            commit=commit,
        )

    def resolve_output_path(
        self,
        *,
        requested_path="",
        service_name="",
        filename="oracle_cloud_hound.json",
        compartment_id=None,
        subdirs=None,
        target="export",
    ) -> Path:
        if requested_path:
            p = Path(requested_path)
        else:
            base = self._output_root or Path.cwd() / "exports"
            p = Path(base)
            if service_name:
                p = p / str(service_name)
            if compartment_id:
                p = p / str(compartment_id)
            for part in (subdirs or []):
                if part:
                    p = p / str(part)
            p = p / filename
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
