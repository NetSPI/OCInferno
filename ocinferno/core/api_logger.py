from __future__ import annotations

import json
import os
import socket
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import getpass

from ocinferno.core.console import UtilityTools


@dataclass
class ApiLogEvent:
    ts: str
    event_type: str
    schema_version: int
    event_id: str
    run_id: str
    tool: str
    workspace_id: int
    host: str
    user: str
    pid: int
    credname: str
    module_run: str
    service: str
    operation: str
    method: str
    url: str
    status: str
    duration_ms: int
    opc_request_id: str = ""
    resource: str = ""
    params: Dict[str, Any] | None = None
    args: Dict[str, Any] | None = None
    request_headers: Dict[str, Any] | None = None
    response_headers: Dict[str, Any] | None = None
    retry_attempt: int = 1
    retry_max: int = 1
    retry_scheduled: bool = False
    err: str | None = None


class ApiRequestLogger:
    """
    JSONL logger for actual API calls only.

    Configurable:
      - enabled (bool)
      - log_path (string)
      - attributes (list[str]) controls which fields are written
    """

    def __init__(self, *, workspace_id: int, workspace_slug: str, credname: str = ""):
        self.workspace_id = int(workspace_id)
        self.workspace_slug = workspace_slug
        self.credname = credname or ""
        self.run_id = ""
        self.tool = "ocinferno"
        self.host = socket.gethostname()
        try:
            self.user = getpass.getuser()
        except Exception:
            self.user = ""
        self.pid = os.getpid()

        self.enabled: bool = False
        self._log_path: str = ""
        self.verbosity: str = "standard"
        self.attributes: list[str] = [
            "ts",
            "event_type",
            "schema_version",
            "event_id",
            "run_id",
            "tool",
            "workspace_id",
            "host",
            "user",
            "pid",
            "credname",
            "module_run",
            "service",
            "operation",
            "status",
            "method",
            "url",
            "duration_ms",
            "opc_request_id",
            "params",
        ]

    # -----------------
    # setters
    # -----------------
    def set_enabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)

    def set_log_path(self, path: str) -> None:
        self._log_path = str(path or "").strip()

    def set_attributes(self, attrs: list[str]) -> None:
        if isinstance(attrs, list) and attrs:
            self.attributes = [str(a).strip() for a in attrs if str(a).strip()]

    def set_verbosity(self, level: str) -> None:
        lvl = str(level or "").strip().lower()
        if lvl not in {"basic", "standard", "verbose"}:
            lvl = "standard"
        self.verbosity = lvl

    def set_credname(self, credname: str) -> None:
        self.credname = credname or ""

    def set_run_context(self, *, run_id: str, tool: str = "ocinferno") -> None:
        self.run_id = str(run_id or "").strip()
        if tool:
            self.tool = str(tool).strip()

    # -----------------
    # internals
    # -----------------
    def _ensure_dirs(self, path: str) -> None:
        try:
            p = Path(path)
            if p.parent:
                os.makedirs(str(p.parent), exist_ok=True)
        except Exception:
            pass

    def log_path(self) -> str:
        """
        If a path isn't set, fall back to the default workspace-slug path.
        (SessionUtility normally sets this.)
        """
        if self._log_path:
            self._ensure_dirs(self._log_path)
            return self._log_path

        fallback = f"./ocinferno_output/{self.workspace_slug}/tool_logs/telemetry_api.log"
        self._ensure_dirs(fallback)
        return fallback

    def sanitize_args(self, obj: Any) -> Any:
        if hasattr(UtilityTools, "sanitize_args"):
            return UtilityTools.sanitize_args(obj)

        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                ks = str(k).lower()
                if "token" in ks or "secret" in ks or "password" in ks or ks == "authorization":
                    out[k] = "<redacted>"
                else:
                    out[k] = self.sanitize_args(v)
            return out
        if isinstance(obj, list):
            return [self.sanitize_args(x) for x in obj]
        return obj

    def _select_fields(self, ev: ApiLogEvent) -> Dict[str, Any]:
        """
        Build dict using attributes list; always safe.
        """
        data = ev.__dict__.copy()

        # Normalize args
        if data.get("args") is None:
            data["args"] = {}
        else:
            data["args"] = self.sanitize_args(data["args"])
        if data.get("params") is None:
            data["params"] = {}
        else:
            data["params"] = self.sanitize_args(data["params"])
        if data.get("request_headers") is None:
            data["request_headers"] = {}
        else:
            data["request_headers"] = self.sanitize_args(data["request_headers"])
        if data.get("response_headers") is None:
            data["response_headers"] = {}
        else:
            data["response_headers"] = self.sanitize_args(data["response_headers"])
        data["url"] = UtilityTools.sanitize_url(str(data.get("url") or ""))
        data["err"] = UtilityTools.sanitize_args(data.get("err"))

        basic = [
            "ts",
            "event_type",
            "schema_version",
            "event_id",
            "run_id",
            "tool",
            "workspace_id",
            "host",
            "user",
            "pid",
            "credname",
            "module_run",
            "service",
            "operation",
            "method",
            "url",
            "status",
            "duration_ms",
            "opc_request_id",
        ]
        standard = basic + ["resource", "params", "args"]
        verbose = standard + ["request_headers", "response_headers", "retry_attempt", "retry_max", "retry_scheduled", "err"]
        preset = {"basic": basic, "standard": standard, "verbose": verbose}.get(self.verbosity, standard)

        attrs: list[str] = []
        for a in (self.attributes or []):
            if a in data and a not in attrs:
                attrs.append(a)
        for a in preset:
            if a in data and a not in attrs:
                attrs.append(a)
        if not attrs:
            attrs = [a for a in preset if a in data]

        return {k: data.get(k) for k in attrs}

    def append(self, event: ApiLogEvent) -> None:
        """
        Append JSON line. Must never crash the run.
        """
        try:
            p = self.log_path()
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps(self._select_fields(event), ensure_ascii=False, default=str) + "\n")
        except Exception:
            return

    def record(
        self,
        *,
        service: str,
        operation: str,
        method: str = "",
        url: str = "",
        args: Optional[Dict[str, Any]] = None,
        status: str = "",
        duration_ms: int = 0,
        opc_request_id: str = "",  # ✅ add this
        params: Optional[Dict[str, Any]] = None,
        err: Optional[str] = None,
        resource: str = "",
        module_run: str = "",
        request_headers: Optional[Dict[str, Any]] = None,
        response_headers: Optional[Dict[str, Any]] = None,
        retry_attempt: int = 1,
        retry_max: int = 1,
        retry_scheduled: bool = False,
        event_type: str = "oci_api_call",
    ) -> None:
        if not self.enabled:
            return
        if not self.credname:
            return

        ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        ev = ApiLogEvent(
            ts=ts,
            event_type=event_type or "oci_api_call",
            schema_version=2,
            event_id=uuid.uuid4().hex,
            run_id=self.run_id or "",
            tool=self.tool or "ocinferno",
            workspace_id=self.workspace_id,
            host=self.host or "",
            user=self.user or "",
            pid=int(self.pid or 0),
            credname=self.credname,
            module_run=module_run or "",
            service=service,
            operation=operation,
            method=method or "",
            url=url or "",
            status=str(status or ""),
            duration_ms=int(duration_ms or 0),
            opc_request_id=str(opc_request_id or ""),  
            resource=resource or "",
            params=params or {},
            args=args or {},
            request_headers=request_headers or {},
            response_headers=response_headers or {},
            retry_attempt=max(1, int(retry_attempt or 1)),
            retry_max=max(1, int(retry_max or 1)),
            retry_scheduled=bool(retry_scheduled),
            err=(err[:2000] if err else None),
        )
        self.append(ev)
