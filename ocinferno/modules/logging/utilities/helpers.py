from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import oci

from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.service_runtime import ResourceBase, _init_client


def build_logging_client(session, region: Optional[str] = None):
    """Build a configured OCI Logging Management client."""
    return _init_client(
        oci.logging.LoggingManagementClient,
        session=session,
        service_name="Logging",
        region=region,
    )


class LoggingLogGroupsResource(OciListResource):
    CLIENT_CLS = oci.logging.LoggingManagementClient
    SERVICE_NAME = "Logging"
    LIST_METHOD = "list_log_groups"
    GET_METHOD = "get_log_group"
    GET_ID_PARAM = "log_group_id"
    TABLE_NAME = "logging_log_groups"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class LoggingLogsResource(ResourceBase):
    TABLE_NAME = "logging_logs"
    COLUMNS = ["id", "display_name", "lifecycle_state", "log_type", "time_created", "log_group_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_logging_client(session=session, region=region)

    # List logs under one log group.
    def list(self, *, log_group_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_logs,
            log_group_id=log_group_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one log by OCID.
    def get(self, *, log_group_id: str, log_id: str) -> Dict[str, Any]:
        resp = self.client.get_log(log_group_id=log_group_id, log_id=log_id)
        return oci.util.to_dict(resp.data) or {}


class LoggingSearchResource:
    """Downloads log content via the OCI Logging Search API.

    Uses ``oci.loggingsearch.LogSearchClient`` to pull log entries for a specific
    log stream and writes them as JSONL.  Covers any log that routes through OCI
    Logging — DS job runs, Functions invocations, build-pipeline output, Container
    Instance stdout, etc.
    """

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = _init_client(
            oci.loggingsearch.LogSearchClient,
            session=session,
            service_name="Logging",
            region=region,
        )

    # OCI Logging search accepts a time range no wider than 14 days per query.
    _MAX_WINDOW = timedelta(days=14)

    def download_log_content(
        self,
        *,
        compartment_id: str,
        log_group_id: str,
        log_id: str,
        hours: int = 24,
        out_path: str,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        search_terms: Optional[List[str]] = None,
    ) -> int:
        """Fetch log entries for one stream and write them as JSONL.

        Returns the number of log entries written (0 if none or on error).

        Args:
            compartment_id: OCID of the log's compartment — REQUIRED as the first
                segment of the OCI Logging search source.
            hours: lookback window; ignored when ``time_start`` is given.
            time_start/time_end: absolute window; override ``hours``. Clamped to
                the API's 14-day maximum range.
            search_terms: keywords for client-side filtering — an entry is kept
                only if its serialized text contains any term (case-insensitive).
                Filtering client-side (not via the query language) matches terms
                anywhere in the entry and avoids silent-zero from a wrong field path.
        """
        if not compartment_id:
            return 0

        _now = datetime.now(tz=timezone.utc)
        _end = time_end or _now
        _start = time_start or (_end - timedelta(hours=max(1, hours)))
        # Clamp to the 14-day max range (prefer the most recent window).
        if _end - _start > self._MAX_WINDOW:
            _start = _end - self._MAX_WINDOW

        # Source format is "<compartmentOCID>/<logGroupOCID>/<logOCID>" — the
        # leading compartment OCID is mandatory.
        query = f'search "{compartment_id}/{log_group_id}/{log_id}"'

        details = oci.loggingsearch.models.SearchLogsDetails(
            time_start=_start,
            time_end=_end,
            search_query=query,
            is_return_field_info=False,
        )

        # Normalize search terms for case-insensitive client-side matching.
        terms = [str(t).lower() for t in (search_terms or []) if str(t).strip()]

        def _keep(entry: Any) -> bool:
            if not terms:
                return True
            try:
                blob = json.dumps(entry, default=str).lower()
            except Exception:
                blob = str(entry).lower()
            return any(t in blob for t in terms)

        entries: List[Any] = []
        page: Optional[str] = None
        while True:
            kwargs: Dict[str, Any] = {"limit": 1000}
            if page:
                kwargs["page"] = page
            try:
                resp = self.client.search_logs(search_logs_details=details, **kwargs)
            except oci.exceptions.ServiceError:
                break
            except Exception:
                break
            results = getattr(resp.data, "results", None) or []
            for r in results:
                raw = getattr(r, "data", r)
                if isinstance(raw, dict):
                    entry = raw
                else:
                    try:
                        entry = oci.util.to_dict(raw)
                    except Exception:
                        entry = {"raw": str(raw)}
                if _keep(entry):
                    entries.append(entry)
            page = resp.headers.get("opc-next-page") if hasattr(resp, "headers") else None
            if not page or not results:
                break

        if not entries:
            return 0

        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                for entry in entries:
                    fh.write(json.dumps(entry, default=str) + "\n")
            return len(entries)
        except Exception:
            return 0
