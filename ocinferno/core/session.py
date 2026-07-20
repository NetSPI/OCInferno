#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

import oci
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
try:
    from oci.config import from_file, validate_config
except Exception:  # pragma: no cover - allows lightweight test stubs to import session.py
    def from_file(**_kwargs):
        return {}

    def validate_config(_cfg):
        return True

try:
    from oci.exceptions import ConfigFileNotFound, InvalidKeyFilePath, ProfileNotFound
except Exception:  # pragma: no cover - allows lightweight test stubs to import session.py
    class ConfigFileNotFound(Exception):
        pass

    class InvalidKeyFilePath(Exception):
        pass

    class ProfileNotFound(Exception):
        pass
try:
    from oci.auth.certificate_retriever import PEMStringCertificateRetriever
    from oci.auth.federation_client import X509FederationClient
    from oci.auth.session_key_supplier import SessionKeySupplier
    from oci.auth.signers import SecurityTokenSigner, X509FederationClientBasedSecurityTokenSigner
except Exception:  # pragma: no cover - allows lightweight test stubs to import session.py
    PEMStringCertificateRetriever = None
    X509FederationClient = None
    SessionKeySupplier = None
    SecurityTokenSigner = None
    X509FederationClientBasedSecurityTokenSigner = None


from ocinferno.core.db import DataController
from ocinferno.core.config import (
    WORKSPACE_CONFIG_KEYS,
)
from ocinferno.core.http_policy import HttpPolicyService
from ocinferno.core.console import UtilityTools
from ocinferno.core import output_paths as _output_paths
from ocinferno.core.workspace_config import WorkspaceConfigMixin
from ocinferno.core.coerce import _safe_str
from ocinferno.core.auth import AuthMixin, CredRecord

# Your logger (ensure ApiRequestLogger.record supports opc_request_id)
from ocinferno.core.api_logger import ApiRequestLogger, ApiLogEvent  # ApiLogEvent must exist in LoggingController



class SessionUtility(WorkspaceConfigMixin, AuthMixin):
    """
    Session wrapper.

    Logging configs (DB):
      - api_logging_enabled: bool
      - api_logging_file_path: str  (user override)
      - api_logging_verbosity: basic | standard | verbose
      - api_logging_attributes: list[str]
      - std_output_format: "table" | "txt"

    Effective logging path:
      - If api_logging_file_path is empty -> default background path:
          <output_root>/<workspace_slug>/tool_logs/telemetry_api.log
      - On startup/migration we persist the default path if unset.
    """
    ALLOWED_CONFIG_KEYS = set(WORKSPACE_CONFIG_KEYS)
    DEFAULT_API_LOG_ATTRIBUTES = [
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
        "retry_attempt",
        "retry_max",
        "retry_scheduled",
    ]
    WORKSPACE_CONFIG_SCHEMA_VERSION = 5
    DEFAULT_HTTP_RETRY_STATUSES = (408, 409, 425, 429, 500, 502, 503, 504)

    _GLOBAL_REQUESTS_PATCH_LOCK = threading.Lock()
    _GLOBAL_REQUESTS_PATCHED = False
    _GLOBAL_REQUESTS_OWNER = None
    _GLOBAL_OCI_PATCH_LOCK = threading.Lock()
    _GLOBAL_OCI_PATCHED = False
    _GLOBAL_OCI_OWNER = None

    # ----------------------------
    # Workspace slug + dirs
    # ----------------------------
    # Output-path layout now lives in core/output_paths.py (extracted from this
    # god-object); kept here as an alias so `self.OUTPUT_DIR_NAMES` call sites work.
    OUTPUT_DIR_NAMES = _output_paths.OUTPUT_DIR_NAMES

    # ----------------------------
    # Per-run settings
    # ----------------------------
    @property
    def individual_run_proxy(self) -> Optional[str]:
        return getattr(self, "_individual_run_proxy", None)

    @individual_run_proxy.setter
    def individual_run_proxy(self, value: Optional[str]) -> None:
        self._individual_run_proxy = value

    @property
    def individual_run_debug(self) -> bool:
        return bool(getattr(self, "_individual_run_debug", False))

    @individual_run_debug.setter
    def individual_run_debug(self, value: Any) -> None:
        self._individual_run_debug = bool(value)

    # These path helpers now live in core/output_paths.py; kept as thin delegating
    # wrappers so existing call sites and the class API are unchanged.
    @staticmethod
    def _safe_path_component(x: str) -> str:
        return _output_paths.safe_path_component(x)

    @staticmethod
    def _compact_filename_component(filename: str, *, max_len: int = 128) -> str:
        return _output_paths.compact_filename_component(filename, max_len=max_len)

    @classmethod
    def _default_output_base_root(cls) -> Path:
        return _output_paths.default_output_base_root()

    @classmethod
    def _compact_compartment_path_component(cls, x: str) -> str:
        return _output_paths.compact_compartment_path_component(x)

    def _default_workspace_slug(self) -> str:
        safe = re.sub(r"\s+", "_", (self.workspace_name or "workspace").strip().lower())
        safe = re.sub(r"[^a-z0-9_\-]+", "", safe) or "workspace"
        return f"{self.workspace_id}_{safe}"

    def _ensure_workspace_dirs(self) -> None:
        # Canonical output layout under ocinferno_output.
        out_root = self.get_workspace_output_root(mkdir=True)
        (out_root / self.OUTPUT_DIR_NAMES["logs"]).mkdir(parents=True, exist_ok=True)

    def _default_api_log_path(self) -> str:
        # Resolve default path lazily without creating directories up front.
        # Directory creation is deferred until a real write occurs.
        out_root = self.get_workspace_output_root(mkdir=False)
        return str(out_root / self.OUTPUT_DIR_NAMES["logs"] / "telemetry_api.log")

    def _install_global_requests_rate_limit_hook(self) -> None:
        """
        Patch requests.Session.request once process-wide so direct requests-based
        traffic can share the same workspace HTTP pacing controls.
        """
        with self._GLOBAL_REQUESTS_PATCH_LOCK:
            type(self)._GLOBAL_REQUESTS_OWNER = self
            if type(self)._GLOBAL_REQUESTS_PATCHED:
                return

            original_request = requests.sessions.Session.request

            def patched_request(req_self, method, url, **kwargs):
                owner = type(self)._GLOBAL_REQUESTS_OWNER
                # Sessions already wrapped by _apply_http_rate_limit_to_requests_session
                # perform their own wait and should skip the global wait path.
                if owner is not None and not getattr(req_self, "_ocinferno_rate_limit_wrapped", False):
                    owner._wait_for_http_rate_limit()
                return original_request(req_self, method, url, **kwargs)

            requests.sessions.Session.request = patched_request
            type(self)._GLOBAL_REQUESTS_PATCHED = True

    def _infer_service_name_from_url(self, url: str) -> str:
        host = ""
        try:
            host = (urlparse(url or "").netloc or "").lower()
        except Exception:
            host = ""
        if not host:
            return "oci"
        if host.startswith("cell") and ".submit.email." in host:
            return "email_data_plane"
        # first DNS label is usually a useful OCI service identifier
        label = host.split(".", 1)[0]
        return label or "oci"

    def _record_operation_permissions(self, operation: str, service: str, resource: str = "") -> None:
        """Passively record the IAM permission(s) a SUCCESSFUL OCI operation proves.

        A 2xx for e.g. ``ListInstances`` proves the caller holds ``INSTANCE_READ``
        (per the OCI policy reference, encoded in
        ``mappings/oci_api_operation_permissions.json``). Merged into the
        ``user_permissions`` table with provenance so ``creds me`` / exports can show the
        caller's discovered effective access. Best-effort -- never breaks enumeration.
        """
        try:
            credname = str(getattr(self, "credname", "") or "")
            workspace_id = getattr(self, "workspace_id", None)
            if not credname or workspace_id is None:
                return

            from ocinferno.core.permission_map import resolve_permissions

            perms = resolve_permissions(operation, service)
            if not perms:
                return

            from datetime import datetime, timezone

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            res = str(resource or "")
            evidence = [{"service": service, "op": operation, "ts": ts}]
            permissions_delta = {
                perm: {"resources": ([res] if res else []), "evidence": list(evidence)}
                for perm in perms
            }
            apis_success_delta = {service: [{"op": operation, "resource": res, "ts": ts}]}
            self.data_master.upsert_user_permissions_merge(
                int(workspace_id),
                credname,
                permissions_delta=permissions_delta,
                apis_success_delta=apis_success_delta,
            )
        except Exception:
            pass

    def _install_global_oci_api_logging_hook(self) -> None:
        """
        Patch OCI SDK BaseClient.call_api once process-wide so list/get (HTTP GET)
        calls are logged with URL/method/status/duration and selected arguments.
        """
        with self._GLOBAL_OCI_PATCH_LOCK:
            type(self)._GLOBAL_OCI_OWNER = self
            if type(self)._GLOBAL_OCI_PATCHED:
                return

            try:
                from oci.base_client import BaseClient
            except Exception:
                return

            original_call_api = BaseClient.call_api

            def patched_call_api(base_client_self, *args, **kwargs):
                owner = type(self)._GLOBAL_OCI_OWNER

                resource_path = kwargs.get("resource_path")
                method = kwargs.get("method") or kwargs.get("http_method")
                if resource_path is None and len(args) >= 1:
                    resource_path = args[0]
                if method is None and len(args) >= 2:
                    method = args[1]
                method_s = str(method or "").upper()

                operation = str(kwargs.get("operation_name") or kwargs.get("operation") or "")
                endpoint = str(kwargs.get("endpoint") or getattr(base_client_self, "endpoint", "") or "")
                query_params = kwargs.get("query_params") or {}
                path_params = kwargs.get("path_params") or {}

                path_s = str(resource_path or "")
                if isinstance(path_params, dict):
                    try:
                        for k, v in path_params.items():
                            path_s = path_s.replace("{" + str(k) + "}", str(v))
                    except Exception:
                        pass

                url = ""
                if endpoint and path_s:
                    url = endpoint.rstrip("/") + "/" + path_s.lstrip("/")
                else:
                    url = endpoint or path_s

                if isinstance(query_params, dict) and query_params:
                    try:
                        qs = urlencode(query_params, doseq=True)
                    except Exception:
                        qs = ""
                    if qs:
                        join = "&" if "?" in url else "?"
                        url = f"{url}{join}{qs}"

                service = owner._infer_service_name_from_url(endpoint or url) if owner else "oci"
                should_log = bool(owner and owner.api_logger.enabled and owner.credname and method_s)
                def _record_event(**event_kwargs):
                    if not owner:
                        return
                    lg = getattr(owner, "api_logger", None)
                    if lg is not None and hasattr(lg, "record"):
                        lg.record(**event_kwargs)
                request_headers = kwargs.get("header_params") if isinstance(kwargs.get("header_params"), dict) else {}
                params_obj = {
                    "query_params": query_params if isinstance(query_params, dict) else {},
                    "path_params": path_params if isinstance(path_params, dict) else {},
                }
                module_run = str(getattr(owner, "active_module_name", "") or "") if owner else ""
                retry_policy = owner._effective_http_retry_policy() if owner else {
                    "enabled": False,
                    "max_attempts": 1,
                    "base_delay_seconds": 0.0,
                    "max_delay_seconds": 0.0,
                    "jitter_seconds": 0.0,
                    "statuses": [],
                }
                max_attempts = int(retry_policy.get("max_attempts", 1) or 1)
                retry_statuses = list(retry_policy.get("statuses", []))

                attempt = 1
                while True:
                    t0 = time.time()
                    if owner:
                        owner._wait_for_http_rate_limit()
                    try:
                        resp = original_call_api(base_client_self, *args, **kwargs)
                        status_code = int(getattr(resp, "status", 0) or 0)
                        should_retry = bool(
                            retry_policy.get("enabled")
                            and attempt < max_attempts
                            and status_code in retry_statuses
                        )
                        if should_log:
                            duration_ms = int((time.time() - t0) * 1000)
                            status = str(status_code or "")
                            headers = getattr(resp, "headers", None)
                            opc_request_id = ""
                            response_headers = {}
                            if isinstance(headers, dict):
                                response_headers = dict(headers)
                                opc_request_id = str(
                                    headers.get("opc-request-id")
                                    or headers.get("opc_request_id")
                                    or ""
                                )
                            _record_event(
                                service=service,
                                operation=operation or "GET",
                                method=method_s,
                                url=url,
                                params=params_obj,
                                args=params_obj,
                                request_headers=request_headers,
                                response_headers=response_headers,
                                module_run=module_run,
                                status=status,
                                duration_ms=duration_ms,
                                opc_request_id=opc_request_id,
                                resource=path_s,
                                retry_attempt=attempt,
                                retry_max=max_attempts,
                                retry_scheduled=should_retry,
                                event_type=("oci_api_retry" if should_retry else "oci_api_call"),
                            )
                        # Passive permission recording: a 2xx proves the caller holds
                        # the operation's required permission(s). Runs independent of the
                        # (opt-in) telemetry logger; best-effort, never breaks enumeration.
                        if owner and 200 <= status_code < 300 and not should_retry:
                            owner._record_operation_permissions(operation, service, path_s)
                        if should_retry:
                            delay_s = owner._compute_retry_delay(
                                attempt=attempt,
                                base_delay=float(retry_policy.get("base_delay_seconds", 0.0) or 0.0),
                                max_delay=float(retry_policy.get("max_delay_seconds", 0.0) or 0.0),
                                jitter=float(retry_policy.get("jitter_seconds", 0.0) or 0.0),
                            ) if owner else 0.0
                            if delay_s > 0:
                                time.sleep(delay_s)
                            attempt += 1
                            continue
                        return resp
                    except Exception as e:
                        should_retry = bool(
                            owner
                            and retry_policy.get("enabled")
                            and attempt < max_attempts
                            and owner._is_retryable_exception(e, retry_statuses)
                        )
                        if should_log:
                            duration_ms = int((time.time() - t0) * 1000)
                            status = str(getattr(e, "status", "") or "ERR")
                            opc_request_id = str(getattr(e, "opc_request_id", "") or "")
                            req_endpoint = str(getattr(e, "request_endpoint", "") or "")
                            url_final = url
                            method_final = method_s
                            if req_endpoint:
                                parts = req_endpoint.split(" ", 1)
                                if len(parts) == 2:
                                    if not method_final:
                                        method_final = parts[0].upper()
                                    if not url_final:
                                        url_final = parts[1]
                                elif not url_final:
                                    url_final = req_endpoint

                            _record_event(
                                service=service,
                                operation=operation or "GET",
                                method=method_final or "GET",
                                url=url_final,
                                params=params_obj,
                                args=params_obj,
                                request_headers=request_headers,
                                response_headers={},
                                module_run=module_run,
                                status=status,
                                duration_ms=duration_ms,
                                opc_request_id=opc_request_id,
                                err=f"{type(e).__name__}: {e}",
                                resource=path_s,
                                retry_attempt=attempt,
                                retry_max=max_attempts,
                                retry_scheduled=should_retry,
                                event_type=("oci_api_retry" if should_retry else "oci_api_call"),
                            )
                        if should_retry:
                            delay_s = owner._compute_retry_delay(
                                attempt=attempt,
                                base_delay=float(retry_policy.get("base_delay_seconds", 0.0) or 0.0),
                                max_delay=float(retry_policy.get("max_delay_seconds", 0.0) or 0.0),
                                jitter=float(retry_policy.get("jitter_seconds", 0.0) or 0.0),
                            ) if owner else 0.0
                            if delay_s > 0:
                                time.sleep(delay_s)
                            attempt += 1
                            continue
                        raise

            BaseClient.call_api = patched_call_api
            type(self)._GLOBAL_OCI_PATCHED = True

    # ----------------------------
    # Allowed attrs = source of truth from ApiLogEvent dataclass
    # ----------------------------
    def _allowed_api_log_attrs(self) -> set[str]:
        try:
            return set(ApiLogEvent.__dataclass_fields__.keys())
        except Exception:
            # fallback if import/reflection fails
            return {
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
                "resource",
                "params",
                "args",
                "request_headers",
                "response_headers",
                "retry_attempt",
                "retry_max",
                "retry_scheduled",
                "err",
            }

    # ----------------------------
    # Init
    # ----------------------------
    def __init__(
        self,
        workspace_id: int,
        workspace_name: str,
        credname: Optional[str],
        auth_type: Optional[str],
        resume: bool = False,
        extra_args: Optional[dict] = None,
        startup_auth_proxy: Optional[str] = None,
    ):

        self.enum_all_scanned_cids = set() # used in enum_all

        self.workspace_id = int(workspace_id)
        self.workspace_name = workspace_name

        self.workspace_directory_name = self._default_workspace_slug()

        # For runner level args
        self.individual_run_proxy = None
        self.individual_run_debug = False
        self.debug_http = False
        self.startup_auth_proxy = (str(startup_auth_proxy).strip() if startup_auth_proxy else "")

        self.credname: Optional[str] = None
        self.credentials: Any = None
        self.credentials_type: Optional[str] = None

        self.tenant_id: Optional[str] = None
        self.compartment_id: Optional[str] = None
        self.region: Optional[str] = None

        # Per-download-unit wall-clock cap in seconds (0 = unlimited). Set by
        # download-capable enum modules from their --download-timeout flag and
        # consumed by DownloadBudget (core.utils.download_budget).
        self.download_time_budget: int = 0

        # DB
        self.data_master = DataController()
        self.data_master.create_service_tables_from_schema()

        # cached configs (from DB)
        self.config_global_proxy_dict: Optional[str] = None
        self.config_current_default_region: str = ""
        self.config_module_auto_save: bool = True
        self.config_rate_limit_seconds: float = 0.0
        self.config_rate_limit_jitter_seconds: float = 0.0
        self.config_http_retry_enabled: bool = True
        self.config_http_retry_max_attempts: int = 4
        self.config_http_retry_base_delay_seconds: float = 0.5
        self.config_http_retry_max_delay_seconds: float = 8.0
        self.config_http_retry_jitter_seconds: float = 0.25
        self.config_http_retry_statuses: List[int] = list(self.DEFAULT_HTTP_RETRY_STATUSES)

        # logging configs
        self.config_api_logging_enabled: bool = False
        self.config_api_logging_file_path: str = ""
        self.config_api_logging_verbosity: str = "standard"
        self.config_api_logging_attributes: List[str] = []
        self.config_std_output_format: str = "table"

        self.http_policy = HttpPolicyService(
            get_rate_limit_seconds=lambda: self._effective_http_rate_limit_seconds(),
            get_rate_limit_jitter_seconds=lambda: self._effective_rate_limit_jitter_seconds(),
        )

        # Ensure direct requests.* calls and SDK sessions can honor shared rate limits.
        self._install_global_requests_rate_limit_hook()
        self._install_global_oci_api_logging_hook()

        # capture last HTTP request from OCI client instrumentation
        self._last_http: Dict[str, str] = {"service": "", "method": "", "url": ""}

        # compartments snapshot
        self.global_compartment_list: List[Dict[str, Any]] = []

        # logger instance
        self.api_logger = ApiRequestLogger(
            workspace_id=self.workspace_id,
            workspace_slug=self.workspace_directory_name,
            credname="",
        )
        self.session_run_id = uuid.uuid4().hex
        self.api_logger.set_run_context(run_id=self.session_run_id, tool="ocinferno")

        # Persist a per-workspace module-run history log (blue-team audit trail) beside
        # the telemetry API log in tool_logs/. Records every module START/END so an
        # assessment's actions can be reconstructed and correlated against OCI Audit.
        try:
            out_root = self.get_workspace_output_root(mkdir=True)
            UtilityTools.set_history_log_path(
                str(out_root / self.OUTPUT_DIR_NAMES["logs"] / "history_log.txt")
            )
        except Exception:
            pass

        extra_args = extra_args or {}

        if resume:
            if credname:
                self.load_stored_creds(credname)
            else:
                print("[X] resume=True but no credname provided")
        else:
            
            if auth_type == "profile":
                self.add_profile_name(credname, extra_args, assume=True)
            elif auth_type == "api-key":
                self.add_api_key(credname, extra_args)
            elif auth_type == "session-token":
                self.add_session_token(credname, extra_args)
            elif auth_type == "instance-principal":
                self.add_instance_profile_token(credname, extra_args)
            elif auth_type == "resource-principal":
                self.add_resource_profile_token(credname, extra_args)
            elif not credname and not auth_type:
                pass
            else:
                print(f"[X] Unknown auth_type: {auth_type}")

        # Pull configs and apply them (includes logger config)
        self._migrate_workspace_config(self.workspace_id)
        self.sync_workspace_config_keys_to_session(self.workspace_id)

        # Load compartments list
        self.global_compartment_list = self.get_all_compartment_ids(self.workspace_id)

    # ----------------------------
    # Transactions / proxy helpers
    # ----------------------------
    def tx(self, db: str = "service"):
        return self.data_master.transaction(db)

    def _resolve_proxy(self, explicit: Optional[str] = None, *, include_auth_proxy: bool = False) -> str:
        proxy = (explicit or "").strip()
        if not proxy and include_auth_proxy:
            proxy = (getattr(self, "startup_auth_proxy", "") or "").strip()
        if not proxy:
            proxy = (self.individual_run_proxy or "").strip()
        if not proxy:
            proxy = (self.config_global_proxy_dict or "").strip()

        if proxy and not proxy.startswith(("http://", "https://")):
            proxy = f"http://{proxy}"
        return proxy

    def _coerce_rate_limit_seconds(self, raw: Any, *, default: float = 0.0) -> float:
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return float(default)
        if value < 0:
            return float(default)
        return value

    def _effective_http_rate_limit_seconds(self) -> float:
        return self._coerce_rate_limit_seconds(self.config_rate_limit_seconds, default=0.0)

    def _effective_rate_limit_jitter_seconds(self) -> float:
        return self._coerce_non_negative_float(self.config_rate_limit_jitter_seconds, default=0.0)

    def _coerce_retry_attempts(self, raw: Any, *, default: int = 4) -> int:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return int(default)
        if value < 1:
            return int(default)
        return min(value, 12)

    def _coerce_non_negative_float(self, raw: Any, *, default: float = 0.0) -> float:
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return float(default)
        if value < 0:
            return float(default)
        return float(value)

    def _coerce_retry_statuses(self, raw: Any) -> List[int]:
        out: List[int] = []
        items = self._parse_list_csv(raw)
        for item in items:
            try:
                status = int(str(item).strip())
            except (TypeError, ValueError):
                continue
            if 100 <= status <= 599 and status not in out:
                out.append(status)
        return out or list(self.DEFAULT_HTTP_RETRY_STATUSES)

    def _effective_http_retry_policy(self) -> Dict[str, Any]:
        statuses = self._coerce_retry_statuses(self.config_http_retry_statuses)
        return HttpPolicyService.default_retry_policy(
            enabled=bool(self.config_http_retry_enabled),
            max_attempts=self._coerce_retry_attempts(self.config_http_retry_max_attempts, default=4),
            base_delay_seconds=self._coerce_non_negative_float(self.config_http_retry_base_delay_seconds, default=0.5),
            max_delay_seconds=self._coerce_non_negative_float(self.config_http_retry_max_delay_seconds, default=8.0),
            jitter_seconds=self._coerce_non_negative_float(self.config_http_retry_jitter_seconds, default=0.25),
            statuses=statuses,
        )

    def _is_retryable_exception(self, exc: Exception, retry_statuses: List[int]) -> bool:
        return HttpPolicyService.is_retryable_exception(exc, retry_statuses)

    def _compute_retry_delay(self, *, attempt: int, base_delay: float, max_delay: float, jitter: float) -> float:
        return HttpPolicyService.compute_retry_delay(
            attempt=attempt,
            base_delay=base_delay,
            max_delay=max_delay,
            jitter=jitter,
        )

    def _wait_for_http_rate_limit(self) -> None:
        hp = getattr(self, "http_policy", None)
        if hp is None:
            hp = HttpPolicyService(get_rate_limit_seconds=lambda: self._effective_http_rate_limit_seconds())
            self.http_policy = hp
        hp.wait_for_rate_limit()

    def _apply_http_rate_limit_to_requests_session(self, req_session):
        """
        Wrap a requests.Session.request method to enforce a global delay between
        request start times for this SessionUtility instance.
        """
        if req_session is None:
            return req_session
        if getattr(req_session, "_ocinferno_rate_limit_wrapped", False):
            return req_session

        original_request = req_session.request

        def wrapped_request(method, url, **kwargs):
            self._wait_for_http_rate_limit()
            return original_request(method, url, **kwargs)

        req_session.request = wrapped_request
        req_session._ocinferno_rate_limit_wrapped = True
        return req_session

    def add_proxy_config(self, client, *, proxy_address: Optional[str] = None):
        """
        Apply proxy configuration to an OCI client.

        Precedence:
        1) Explicit proxy argument (highest priority)
        2) Individual run proxy
        3) Global config proxy
        4) No proxy

        Both values may be:
        - full URL (http://host:port)
        - host:port (http:// is assumed)
        """

        proxy = self._resolve_proxy(proxy_address)

        base_client = getattr(client, "base_client", None)
        sess = getattr(base_client, "session", None)
        if sess is not None:
            self._apply_http_rate_limit_to_requests_session(sess)
        else:
            return client

        if not proxy:
            return client

        # IMPORTANT: OCI uses vendored urllib3 -> suppress THAT warning class
        import warnings
        try:
            from oci._vendor.urllib3.exceptions import InsecureRequestWarning  # <- key fix
            warnings.simplefilter("ignore", InsecureRequestWarning)
            # or:
            # warnings.filterwarnings("ignore", category=InsecureRequestWarning)
        except Exception:
            # fallback: still try generic urllib3 if vendored import changes
            try:
                from urllib3.exceptions import InsecureRequestWarning
                warnings.simplefilter("ignore", InsecureRequestWarning)
            except Exception:
                pass

        # OCI SDK uses requests.Session under the hood
        sess.verify = False
        sess.proxies = {
            "http": proxy,
            "https": proxy,
        }

        return client

    # ----------------------------
    # Logging config application
    # ----------------------------
    def _apply_api_logging_config(self) -> None:
        enabled = bool(self.config_api_logging_enabled)

        user_path = (self.config_api_logging_file_path or "").strip()
        path = user_path if user_path else self._default_api_log_path()

        attrs = self.config_api_logging_attributes or []
        verbosity = str(self.config_api_logging_verbosity or "standard").strip().lower()
        if verbosity not in {"basic", "standard", "verbose"}:
            verbosity = "standard"

        self.api_logger.set_enabled(enabled)
        self.api_logger.set_log_path(path)
        self.api_logger.set_verbosity(verbosity)
        self.api_logger.set_attributes(attrs)

    def _set_logger_credname(self, credname: str) -> None:
        self.api_logger.set_credname(credname or "")

    # ----------------------------
    # Workspace configs (DB-backed)
    # ----------------------------
    def _parse_bool(self, s: str) -> bool:
        v = str(s).strip().lower()
        return v in ("1", "true", "t", "yes", "y", "on", "enabled", "enable")

    def _parse_list_csv(self, s: Any) -> List[str]:
        if s is None:
            return []
        if isinstance(s, list):
            return [str(x).strip() for x in s if str(x).strip()]
        return [p.strip() for p in str(s).split(",") if p.strip()]

    # Path builders now delegate to core/output_paths.py (extracted; same behavior).
    def get_download_save_path(
        self,
        *,
        service_name: str,
        filename: str,
        compartment_id: str,
        resource_name: str | None = None,
        subdirs: list[str] | None = None,
        mkdir: bool = True,
    ) -> Path:
        return _output_paths.download_save_path(
            self.workspace_id, self.workspace_name,
            service_name=service_name, filename=filename, compartment_id=compartment_id,
            resource_name=resource_name, subdirs=subdirs, mkdir=mkdir,
        )

    def get_workspace_output_root(self, *, mkdir: bool = True) -> Path:
        return _output_paths.workspace_output_root(self.workspace_id, self.workspace_name, mkdir=mkdir)

    def get_export_save_path(
        self,
        *,
        service_name: str,
        filename: str,
        compartment_id: str | None = None,
        subdirs: list[str] | None = None,
        mkdir: bool = True,
    ) -> Path:
        return _output_paths.export_save_path(
            self.workspace_id, self.workspace_name,
            service_name=service_name, filename=filename, compartment_id=compartment_id,
            subdirs=subdirs, mkdir=mkdir,
        )

    def resolve_output_path(
        self,
        *,
        requested_path: str | Path | None = None,
        service_name: str,
        filename: str,
        compartment_id: str | None = None,
        subdirs: list[str] | None = None,
        target: str = "export",
        mkdir: bool = True,
    ) -> Path:
        return _output_paths.resolve_output_path(
            self.workspace_id, self.workspace_name,
            requested_path=requested_path, service_name=service_name, filename=filename,
            compartment_id=compartment_id, current_compartment=getattr(self, "compartment_id", None),
            subdirs=subdirs, target=target, mkdir=mkdir,
        )


    def _sync_region_config_from_loaded_creds(self, region: Optional[str]) -> None:
        """
        Keep workspace config default region aligned with loaded credentials.
        Sets current_default_region.
        """
        reg = str(region or "").strip().lower()
        if not reg:
            return
        try:
            cfg = self.get_config_keys(self.workspace_id)
            if not isinstance(cfg, dict):
                return

            changed = False

            if str(cfg.get("current_default_region") or "").strip().lower() != reg:
                cfg["current_default_region"] = reg
                changed = True

            if not changed:
                return

            self.data_master.save_value_to_table_column(
                db="metadata",
                table_name="workspace_index",
                target_column="configs",
                value=json.dumps(cfg),
                where={"id": self.workspace_id},
            )
            self.sync_workspace_config_keys_to_session(self.workspace_id)
        except Exception:
            return

    # ----------------------------
    # Credential CRUD / loading
    # ----------------------------
    def get_all_creds(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        try:
            db_rows = self.data_master.fetch_column_from_table(
                db="metadata",
                table_name="sessions",
                columns=["credname", "credtype", "default_compartment_id", "session_creds"],
                where={"workspace_id": self.workspace_id},
                as_dict=True,
            )
            if db_rows:
                rows = list(db_rows)
        except Exception:
            pass

        # Ensure currently active creds are visible even if DB rows are stale/missing.
        active_credname = (self.credname or "").strip()
        if active_credname:
            found = any(str((r or {}).get("credname") or "").strip() == active_credname for r in rows if isinstance(r, dict))
            if not found:
                rows.append(
                    {
                        "credname": active_credname,
                        "credtype": str(self.credentials_type or "active"),
                        "default_compartment_id": str(self.compartment_id or ""),
                        "session_creds": "",
                    }
                )

        return rows

    def _fetch_cred_record(self, credname: str) -> Optional[CredRecord]:
        row = self.data_master.fetch_cred(self.workspace_id, credname)
        if not row:
            return None
        return CredRecord(
            credname=row.get("credname", credname),
            credtype=row.get("credtype", ""),
            session_creds=row.get("session_creds", ""),
        )

    def update_cred_session_metadata(self, credname: str, updates: Dict[str, Any]) -> bool:
        """
        Merge non-empty metadata keys into stored session_creds JSON for a credential.
        Returns True when DB was updated.
        """
        if not credname or not isinstance(updates, dict):
            return False

        row = self.data_master.fetch_cred(self.workspace_id, credname)
        if not isinstance(row, dict):
            return False

        raw = row.get("session_creds")
        try:
            obj = json.loads(raw) if isinstance(raw, str) and raw.strip() else {}
        except Exception:
            obj = {}

        changed = False

        def _apply_dict(target: Dict[str, Any]) -> None:
            nonlocal changed
            for k, v in updates.items():
                if not k or v is None:
                    continue
                if isinstance(v, str):
                    v = v.strip()
                    if not v:
                        continue
                if target.get(k) != v:
                    target[k] = v
                    changed = True

        if isinstance(obj, dict):
            _apply_dict(obj)
        elif isinstance(obj, list):
            for entry in obj:
                if isinstance(entry, dict):
                    _apply_dict(entry)
        else:
            obj = {}
            _apply_dict(obj)

        if not changed:
            return False

        try:
            self.data_master.save_value_to_table_column(
                db="metadata",
                table_name="sessions",
                target_column="session_creds",
                value=json.dumps(obj),
                where={"workspace_id": self.workspace_id, "credname": credname},
            )
            return True
        except Exception:
            return False

    def set_active_creds(
        self,
        credname: str,
        tenant_id: Optional[str] = None,
        compartment_id: Optional[str] = None,
        *,
        force_refresh: bool = False,
    ) -> bool:
        if not credname:
            print("[X] Missing credname")
            return False

        ok = self.load_stored_creds(credname, force_refresh=force_refresh)
        if not ok:
            return False

        if tenant_id:
            self.tenant_id = tenant_id
        if compartment_id:
            self.compartment_id = compartment_id

        return True

    # Refresh session token since its not built into SecuritySigner naturally



    # ---------------------------------------------------------------------
    # Profile auth (Includes API Key & Temporary Session Token profiles)
    # ---------------------------------------------------------------------

    # ---------------------------------------------------------------------
    # Explicit API-key / session-token auth (reuses profile loader shape)
    # ---------------------------------------------------------------------



    # ---------------------------------------------------------------------
    # Instance principal auth
    # ---------------------------------------------------------------------
    def _ipdbg(self, msg: str, **kv: Any) -> None:
        """Debug-only instance/resource-principal tracing.

        Gated on ``self.debug_http`` (opt-in via ``--debug-http`` at credential
        add time) and sanitized through UtilityTools.sanitize_args -- kv can
        carry ``extra_args``/token/config payloads that include a delegation
        token or key material, so this must never behave like a bare print().
        """
        if not getattr(self, "debug_http", False):
            return
        tail = ""
        if kv:
            parts = []
            for k, v in kv.items():
                try:
                    parts.append(f"{k}={UtilityTools.sanitize_args(v)!r}")
                except Exception:
                    parts.append(f"{k}=<unrepr>")
            tail = " | " + " ".join(parts)
        print(f"[*] instance-principal: {msg}{tail}")

    # ---------------------------------------------------------------------
    # Resource principal auth
    # ---------------------------------------------------------------------

    def _load_resource_profile_reference_file(self, ref_path: str) -> Tuple[Dict[str, Any], Optional[str]]:
        p = Path(ref_path).expanduser()
        if not p.exists():
            return {}, f"reference file does not exist: {p}"
        if not p.is_file():
            return {}, f"reference path is not a file: {p}"

        try:
            raw = p.read_text(encoding="utf-8")
        except Exception as e:
            return {}, f"failed reading reference file: {e}"

        cfg: Dict[str, Any]
        json_error: Optional[str] = None
        try:
            cfg = json.loads(raw)
            if not isinstance(cfg, dict):
                return {}, "reference file JSON must be an object/dictionary"
        except Exception as e:
            json_error = str(e)
            cfg = {}
            for ln in raw.splitlines():
                line = ln.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()

        if not cfg:
            if json_error:
                return {}, f"reference file JSON parse error: {json_error}"
            return {}, "reference file is empty or invalid (expected JSON object or key=value lines)"

        base = p.parent
        for key in ("rpst_file", "security_token_file", "token_file", "private_pem_file", "private_key_file", "key_file", "passphrase_file"):
            val = _safe_str(cfg.get(key)).strip()
            if not val:
                continue
            rp = Path(val).expanduser()
            if not rp.is_absolute():
                rp = (base / rp).resolve()
            cfg[key] = str(rp)

        return cfg, None

    def _resolve_resource_text_or_file(self, raw_value: str, label: str) -> Tuple[str, str, Optional[str]]:
        raw = _safe_str(raw_value).strip()
        if not raw:
            return "", "", None

        path_candidate = raw
        if raw.startswith("file://"):
            path_candidate = raw[len("file://"):]
        p = Path(path_candidate).expanduser()

        if p.exists():
            text, err = self._read_text_file(str(p), label)
            if err:
                return "", "", err
            return _safe_str(text).strip(), str(p), None

        if raw.startswith("file://"):
            return "", "", f"{label} file not found: {p}"

        return raw, "", None

    def _extract_tenancy_from_token(self, token: str) -> str:
        token_s = _safe_str(token).strip()
        if not token_s:
            return ""
        try:
            parts = token_s.split(".")
            if len(parts) < 2:
                return ""
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            obj = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8"))
            if not isinstance(obj, dict):
                return ""
        except Exception:
            return ""

        for key in (
            "res_tenant",
            "tenancy_id",
            "tenancyId",
            "tenant_id",
            "tenantId",
            "tenancy",
            "tenant",
        ):
            val = _safe_str(obj.get(key)).strip()
            if val.startswith("ocid1.tenancy."):
                return val
        return ""

    def _read_text_file(self, path_str: str, label: str) -> Tuple[Optional[str], Optional[str]]:
        p = Path(str(path_str or "")).expanduser()
        if not p.exists():
            return None, f"{label} file not found: {p}"
        if not p.is_file():
            return None, f"{label} path is not a file: {p}"
        try:
            return p.read_text(encoding="utf-8").strip(), None
        except Exception as e:
            return None, f"failed reading {label} file {p}: {e}"

    def _decode_jwt_exp(self, token: str) -> int:
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return 0
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            obj = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8"))
            return int(obj.get("exp") or 0)
        except Exception:
            return 0

    def _validate_pems(self, cert_pem: str, key_pem: str, intermediate_pem: Optional[str], passphrase: Optional[str] = None):
        x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        pw = passphrase.encode("utf-8") if isinstance(passphrase, str) and passphrase else None
        serialization.load_pem_private_key(key_pem.encode("utf-8"), password=pw)
        if intermediate_pem:
            x509.load_pem_x509_certificate(intermediate_pem.encode("utf-8"))

    def _load_instance_profile_reference_file(self, ref_path: str) -> Tuple[Dict[str, Any], Optional[str]]:
        p = Path(ref_path).expanduser()
        if not p.exists():
            return {}, f"reference file does not exist: {p}"
        if not p.is_file():
            return {}, f"reference path is not a file: {p}"

        try:
            raw = p.read_text(encoding="utf-8")
        except Exception as e:
            return {}, f"failed reading reference file: {e}"

        cfg: Dict[str, Any]
        json_error: Optional[str] = None
        try:
            cfg = json.loads(raw)
            if not isinstance(cfg, dict):
                return {}, "reference file JSON must be an object/dictionary"
        except Exception as e:
            json_error = str(e)
            cfg = {}
            for ln in raw.splitlines():
                line = ln.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()

        if not cfg:
            if json_error:
                return {}, f"reference file JSON parse error: {json_error}"
            return {}, "reference file is empty or invalid (expected JSON object or key=value lines)"

        missing: List[str] = []
        if not _safe_str(cfg.get("leaf_cert_file")).strip():
            missing.append("leaf_cert_file")
        if not _safe_str(cfg.get("leaf_key_file")).strip():
            missing.append("leaf_key_file")
        has_intermediate = bool(_safe_str(cfg.get("intermediate_cert_file")).strip())
        if not has_intermediate:
            vals = cfg.get("intermediate_cert_files")
            if isinstance(vals, list):
                has_intermediate = any(isinstance(v, str) and v.strip() for v in vals)
        if not has_intermediate:
            missing.append("intermediate_cert_file|intermediate_cert_files")
        if missing:
            return {}, f"reference file missing required keys: {', '.join(missing)}"

        base = p.parent
        for key in ("leaf_cert_file", "leaf_key_file", "intermediate_cert_file", "passphrase_file", "ca_bundle_file"):
            val = cfg.get(key)
            if isinstance(val, str) and val.strip():
                rp = Path(val.strip()).expanduser()
                if not rp.is_absolute():
                    rp = (base / rp).resolve()
                cfg[key] = str(rp)

        vals = cfg.get("intermediate_cert_files")
        if isinstance(vals, list):
            resolved = []
            for v in vals:
                if not isinstance(v, str) or not v.strip():
                    continue
                rp = Path(v.strip()).expanduser()
                if not rp.is_absolute():
                    rp = (base / rp).resolve()
                resolved.append(str(rp))
            cfg["intermediate_cert_files"] = resolved

        return cfg, None

    def _metadata_lookup_order(self, imds_version: str = "v2") -> Tuple[Tuple[str, Dict[str, str]], ...]:
        v2 = (
            ("http://169.254.169.254/opc/v2/instance/", {"Authorization": "Bearer Oracle"}),
            ("http://169.254.169.254/opc/v2/instance/regionInfo/", {"Authorization": "Bearer Oracle"}),
        )
        v1 = (
            ("http://169.254.169.254/opc/v1/instance/", {}),
            ("http://169.254.169.254/opc/v1/instance/identity/", {}),
            ("http://169.254.169.254/opc/v1/instance/regionInfo/", {}),
        )
        return tuple(v1 + v2) if imds_version == "v1" else tuple(v2 + v1)

    # ---------------------------------------------------------------------
    # Compartments / resources (unchanged)
    # ---------------------------------------------------------------------
    def add_cid(self, cid: str) -> None:
        self.add_compartment_id(cid, parent_compartment_id="N/A", override=False)

    def purge_cid(self, cid: str) -> None:
        try:
            self.data_master.delete_dict_row(
                db="service",
                table_name="resource_compartments",
                where={"workspace_id": self.workspace_id, "compartment_id": cid},
                require_where=True,
            )
            self.global_compartment_list = self.get_all_compartment_ids(self.workspace_id)
        except Exception as e:
            print(f"[X] purge_cid failed: {e}")

    def is_tenant(self, compartment_id: str) -> bool:
        return UtilityTools.is_tenancy_ocid(compartment_id)

    def add_compartment_id(self, compartment_id: str, parent_compartment_id: Optional[str] = None, override: bool = False):
        row_details = {
            "workspace_id": self.workspace_id,
            "compartment_id": compartment_id,
            "parent_compartment_id": parent_compartment_id,
        }
        self.data_master.upsert_fill_unknowns(
            db="service",
            table_name="resource_compartments",
            new_data=row_details,
            override=override,
        )

    def get_all_compartment_ids(self, workspace_id: int) -> List[Dict[str, Any]]:
        return self.data_master.fetch_column_from_table(
            db="service",
            table_name="resource_compartments",
            columns=["compartment_id", "parent_compartment_id", "name", "resource_sum"],
            where={"workspace_id": workspace_id},
            as_dict=True,
        )

    def save_resource(self, data: Any, table_name: str):
        self.save_resources([data], table_name)

    def save_resources(
        self,
        rows: Any,
        table_name: str,
        *,
        on_conflict: str = "update",
        commit: bool = True,
    ) -> int:
        """
        Save multiple rows into a service table with one final commit.

        Returns number of successfully submitted rows.
        """
        if rows is None:
            return 0

        if isinstance(rows, dict):
            iterable = [rows]
        elif isinstance(rows, (list, tuple, set)):
            iterable = rows
        else:
            iterable = [rows]

        # Normalize the whole batch up front, then persist it in ONE executemany
        # (save_dict_rows_bulk) instead of a row-at-a-time loop -- far fewer Python<->C
        # round trips, and still a single commit for the batch (the bulk writer commits
        # only when not already inside a DataController.transaction()).
        normalized: list[dict] = []
        for item in iterable:
            if item is None:
                continue
            row = item
            if not isinstance(row, dict):
                try:
                    row = oci.util.to_dict(row)
                except Exception:
                    continue
            if not isinstance(row, dict):
                continue
            row = dict(row)
            row["workspace_id"] = self.workspace_id
            normalized.append(row)

        if not normalized:
            return 0

        written = self.data_master.save_dict_rows_bulk(
            db="service",
            table_name=table_name,
            rows=normalized,
            on_conflict=on_conflict,
        )

        if written and table_name == "resource_compartments":
            self.global_compartment_list = self.get_all_compartment_ids(self.workspace_id)

        return written

    def delete_resource(self, table_name: str, where=None):
        where = dict(where or {})
        where["workspace_id"] = self.workspace_id

        self.data_master.delete_dict_row(
            db="service",
            table_name=table_name,
            where=where,
            require_where=True,
        )

    def get_resource_fields(self, table_name: str, where_conditions=None, columns=None):
        where = dict(where_conditions or {})
        where["workspace_id"] = self.workspace_id
        return self.data_master.fetch_column_from_table(
            db="service",
            table_name=table_name,
            columns=columns,
            where=where,
            as_dict=True,
        )
    # =============================================================================
    # OpenGraph write helpers (nodes/edges)
    # =============================================================================
    def set_node_fields(
        self,
        row: Dict[str, Any],
        *,
        commit: bool = True,
        on_conflict: str = "update_nulls",
    ) -> bool:
        """
        Upsert into opengraph_nodes (thin wrapper).

        Expected DB columns:
        - node_type
        - node_id
        - node_properties
        - workspace_id

        PK: (node_type, node_id)

        on_conflict modes:
        - "update_nulls" (default): only fill NULLs
        - "update": overwrite with provided values
        """
        if not isinstance(row, dict):
            raise TypeError("set_node_fields(row) expects row to be a dict")

        if not row.get("node_type") or not row.get("node_id"):
            raise ValueError("set_node_fields requires 'node_type' and 'node_id' in row")

        row["workspace_id"] = self.workspace_id

        ok = self.data_master.save_dict_row(
            db="service",
            table_name="opengraph_nodes",
            row=row,
            on_conflict=on_conflict,
            commit=commit,
        )

        if not ok:
            print("[X] save_dict_row returned False for opengraph_nodes")
        return ok

    def set_edge_fields(
        self,
        row: dict,
        *,
        commit: bool = True,
        on_conflict: str = "ignore",  # "ignore" | "replace" | "update"
    ) -> bool:
        """
        Thin wrapper. Expects schema keys:
        workspace_id, source_id, edge_type, destination_id
        Optional:
        edge_properties
        """
        if not row.get("source_id") or not row.get("edge_type") or not row.get("destination_id"):
            raise ValueError("set_edge_fields requires source_id, edge_type, destination_id")

        if getattr(self, "workspace_id", None) is not None and "workspace_id" not in row:
            row["workspace_id"] = self.workspace_id

        ok = self.data_master.save_dict_row(
            db="service",
            table_name="opengraph_edges",
            row=row,
            on_conflict=on_conflict,
            conflict_cols=["source_id", "edge_type", "destination_id", "workspace_id"],
            commit=commit,
        )
        if not ok:
            print("[X] save_dict_row returned False for opengraph_edges")
        return ok
