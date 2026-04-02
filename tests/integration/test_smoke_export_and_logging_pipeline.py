from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

from ocinferno.core.api_logger import ApiRequestLogger
from ocinferno.core.utils.module_helpers import export_sqlite_dbs_to_json_blob


def _build_smoke_db(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    cur = conn.cursor()
    try:
        cur.execute('CREATE TABLE "compute_instances" (id TEXT, name TEXT)')
        cur.execute(
            'INSERT INTO "compute_instances" (id, name) VALUES (?, ?)',
            ("ocid1.instance.oc1..smoke", "smoke-instance"),
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()


def test_smoke_export_and_logging_pipeline():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        db_path = root / "service_info.db"
        out_json = root / "sqlite_blob.json"
        log_path = root / "telemetry_api.log"
        _build_smoke_db(db_path)

        export_result = export_sqlite_dbs_to_json_blob(
            db_paths=[str(db_path)],
            out_json_path=str(out_json),
        )
        assert export_result["ok"] is True
        assert out_json.exists()

        logger = ApiRequestLogger(workspace_id=1, workspace_slug="1_smoke", credname="smoke_cred")
        logger.set_enabled(True)
        logger.set_log_path(str(log_path))
        logger.set_verbosity("verbose")
        logger.set_run_context(run_id="smoke-run-1")
        logger.record(
            service="identity",
            operation="ListPolicies",
            method="GET",
            url="https://identity.us-ashburn-1.oraclecloud.com/20160918/policies?compartmentId=ocid1.compartment.oc1..smoke",
            params={"query_params": {"compartmentId": "ocid1.compartment.oc1..smoke"}},
            request_headers={"Authorization": "Bearer secret"},
            status="200",
            duration_ms=10,
            module_run="enum_identity",
        )

        payload = json.loads(out_json.read_text(encoding="utf-8"))
        records = payload.get("records") or []
        assert len(records) == 1
        assert records[0].get("resource") == "compute_instances"

        log_row = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
        assert log_row["run_id"] == "smoke-run-1"
        assert log_row["event_type"] == "oci_api_call"
        assert log_row["module_run"] == "enum_identity"
        assert log_row["request_headers"]["Authorization"] == "<redacted>"
