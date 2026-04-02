#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
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
    KNOWN_OCI_REGION_SET,
    WORKSPACE_CONFIG_KEYS,
    default_workspace_config,
    is_region_format_like,
)
from ocinferno.core.contracts import ErrorCode
from ocinferno.core.contracts import OperationResult
from ocinferno.core.http_policy import HttpPolicyService
from ocinferno.core.console import UtilityTools

# Your logger (ensure ApiRequestLogger.record supports opc_request_id)
from ocinferno.core.api_logger import ApiRequestLogger, ApiLogEvent  # ApiLogEvent must exist in LoggingController
def _safe_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _truthy(x: Any) -> bool:
    if isinstance(x, bool):
        return x
    if isinstance(x, (int, float)):
        return x != 0
    if isinstance(x, str):
        return x.strip().lower() in {"1", "true", "t", "yes", "y", "on"}
    return False

@dataclass
class CredRecord:
    credname: str
    credtype: str
    session_creds: str


class SessionUtility:
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
    OUTPUT_DIR_NAMES = {
        "downloads": "downloads",
        "exports": "exports",
        "reports": "reports",
        "logs": "tool_logs",
    }

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

    @staticmethod
    def _safe_path_component(x: str) -> str:
        x = str(x or "")
        x = x.replace("/", "_").replace("\\", "_").replace(":", "_")
        x = re.sub(r"\s+", "_", x)
        return re.sub(r"[^A-Za-z0-9_.\-]", "", x).strip("._-")

    @staticmethod
    def _compact_filename_component(filename: str, *, max_len: int = 128) -> str:
        safe_name = SessionUtility._safe_path_component(filename) or "file"
        if len(safe_name) <= max_len:
            return safe_name

        stem, dot, ext = safe_name.rpartition(".")
        if not stem:
            stem, ext = safe_name, ""
            dot = ""

        digest = hashlib.sha1(safe_name.encode("utf-8")).hexdigest()[:12]
        ext_len = (len(ext) + 1) if ext else 0
        keep = max(24, max_len - ext_len - len(digest) - 2)
        compact_stem = stem[:keep]
        compact = f"{compact_stem}__{digest}"
        return f"{compact}.{ext}" if ext else compact

    @classmethod
    def _default_output_base_root(cls) -> Path:
        """
        Resolve the base output directory.

        Default:
          current working directory / ocinferno_output
        """
        return Path.cwd() / "ocinferno_output"

    @classmethod
    def _compact_compartment_path_component(cls, x: str) -> str:
        safe = cls._safe_path_component(x)
        if not safe:
            return "global"
        # Keep short values unchanged; compact long OCIDs to avoid oversized paths.
        if len(safe) <= 64:
            return safe
        digest = hashlib.sha1(safe.encode("utf-8")).hexdigest()[:10]
        head = safe[:24]
        tail = safe[-8:]
        return f"{head}__{tail}__{digest}"

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
        self.startup_auth_proxy = (str(startup_auth_proxy).strip() if startup_auth_proxy else "")

        self.credname: Optional[str] = None
        self.credentials: Any = None
        self.credentials_type: Optional[str] = None

        self.tenant_id: Optional[str] = None
        self.compartment_id: Optional[str] = None
        self.region: Optional[str] = None

        # DB
        self.data_master = DataController()
        self.data_master.create_service_tables_from_yaml()

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

    def _default_workspace_config(self) -> Dict[str, Any]:
        return default_workspace_config(
            schema_version=int(self.WORKSPACE_CONFIG_SCHEMA_VERSION),
            default_api_log_attributes=list(self.DEFAULT_API_LOG_ATTRIBUTES),
        )

    def _migrate_workspace_config(self, workspace_id: int) -> None:
        """
        Backfill missing/invalid keys for older workspace config blobs.
        """
        rows = self.data_master.fetch_column_from_table(
            db="metadata",
            table_name="workspace_index",
            columns="configs",
            where={"id": workspace_id},
            as_dict=False,
        )
        if not rows:
            return
        try:
            cfg = json.loads(rows[0] or "{}")
            if not isinstance(cfg, dict):
                cfg = {}
        except Exception:
            cfg = {}

        defaults = self._default_workspace_config()
        original_cfg = json.dumps(cfg, sort_keys=True, default=str)
        for key, value in defaults.items():
            if key not in cfg:
                cfg[key] = value

        # Normalize known-typed keys.
        cfg["module_auto_save"] = bool(cfg.get("module_auto_save", True))
        cfg["api_logging_enabled"] = bool(cfg.get("api_logging_enabled", False))
        cfg["rate_limit_seconds"] = self._coerce_rate_limit_seconds(
            cfg.get("rate_limit_seconds", 0.0),
            default=0.0,
        )
        cfg["rate_limit_jitter_seconds"] = self._coerce_non_negative_float(
            cfg.get("rate_limit_jitter_seconds", 0.0), default=0.0
        )
        verbosity = str(cfg.get("api_logging_verbosity", "standard") or "standard").strip().lower()
        if verbosity not in {"basic", "standard", "verbose"}:
            verbosity = "standard"
        cfg["api_logging_verbosity"] = verbosity
        cfg["current_default_region"] = str(cfg.get("current_default_region") or "").strip()
        cfg["api_logging_attributes"] = self._parse_list_csv(cfg.get("api_logging_attributes"))
        if cfg.get("std_output_format") not in {"table", "txt", "text"}:
            cfg["std_output_format"] = "table"
        if cfg.get("std_output_format") == "text":
            cfg["std_output_format"] = "txt"
        if not str(cfg.get("api_logging_file_path") or "").strip():
            cfg["api_logging_file_path"] = self._default_api_log_path()
        cfg["config_schema_version"] = int(self.WORKSPACE_CONFIG_SCHEMA_VERSION)

        updated_cfg = json.dumps(cfg, sort_keys=True, default=str)
        if updated_cfg == original_cfg:
            return
        self.data_master.save_value_to_table_column(
            db="metadata",
            table_name="workspace_index",
            target_column="configs",
            value=json.dumps(cfg),
            where={"id": workspace_id},
        )

    def get_config_keys(self, workspace_id: int, key: Optional[str] = None):
        db_configs = self.data_master.fetch_column_from_table(
            db="metadata",
            table_name="workspace_index",
            columns="configs",
            where={"id": workspace_id},
            as_dict=False,
        )

        defaults = self._default_workspace_config()

        if not db_configs:
            return defaults if not key else defaults.get(key)

        try:
            cfg = json.loads(db_configs[0] or "{}")
        except Exception:
            cfg = {}

        for k, v in defaults.items():
            if k not in cfg:
                cfg[k] = v

        if key:
            return cfg.get(key)
        return cfg

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
        """Return canonical download path under:
        <output_root>/<workspace>/downloads/<service>/<compartment>/<subdirs...>/<filename>
        """
        safe = self._safe_path_component
        compartment_dir = self._compact_compartment_path_component(compartment_id)

        parts = [
            self.get_workspace_output_root(mkdir=mkdir),
            self.OUTPUT_DIR_NAMES["downloads"],
            safe(service_name),
            compartment_dir,
        ]

        cleaned_subdirs = []
        for raw_part in (subdirs or []):
            cleaned = safe(raw_part)
            if cleaned:
                cleaned_subdirs.append(cleaned)
        if cleaned_subdirs:
            parts.extend(cleaned_subdirs)

        output_filename = self._compact_filename_component(filename)
        if resource_name:
            name_hint = safe(resource_name)
            if name_hint:
                dot = output_filename.rfind(".")
                if dot > 0:
                    stem = output_filename[:dot]
                    ext = output_filename[dot:]
                else:
                    stem = output_filename
                    ext = ""
                if name_hint not in stem:
                    stem = self._compact_filename_component(f"{stem}__{name_hint}")
                    output_filename = f"{stem}{ext}"
        out = Path(*parts) / output_filename

        if mkdir:
            out.parent.mkdir(parents=True, exist_ok=True)

        return out

    def get_workspace_output_root(self, *, mkdir: bool = True) -> Path:
        safe = self._safe_path_component
        workspace_dir = f"{self.workspace_id}_{safe(self.workspace_name)}"
        out = self._default_output_base_root() / workspace_dir
        if mkdir:
            try:
                out.mkdir(parents=True, exist_ok=True)
            except Exception:
                # Fallback to home if current directory is not writable.
                out = Path.home() / "ocinferno_output" / workspace_dir
                out.mkdir(parents=True, exist_ok=True)
        return out

    def get_export_save_path(
        self,
        *,
        service_name: str,
        filename: str,
        compartment_id: str | None = None,
        subdirs: list[str] | None = None,
        mkdir: bool = True,
    ) -> Path:
        """
        Path:
        <output_root>/<workspace>/exports/<service>/<compartment|global>/<subdirs...>/<filename>
        """
        safe = self._safe_path_component
        comp = safe(compartment_id or "global")

        parts = [
            self.get_workspace_output_root(mkdir=mkdir),
            self.OUTPUT_DIR_NAMES["exports"],
            safe(service_name),
            comp,
        ]
        if subdirs:
            parts.extend(safe(s) for s in subdirs)

        out = Path(*parts) / self._compact_filename_component(filename)
        if mkdir:
            out.parent.mkdir(parents=True, exist_ok=True)
        return out

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
        """
        Resolve an output file path from one central place.

        Behavior:
          - If `requested_path` is provided, use it as-is (after expanduser).
          - Otherwise resolve to session-managed `export` or `download` layout.
        """
        if requested_path:
            out = Path(requested_path).expanduser()
            if mkdir:
                out.parent.mkdir(parents=True, exist_ok=True)
            return out

        bucket = str(target or "export").strip().lower()
        if bucket == "download":
            comp = compartment_id or getattr(self, "compartment_id", None) or "global"
            return self.get_download_save_path(
                service_name=service_name,
                filename=filename,
                compartment_id=comp,
                subdirs=subdirs,
                mkdir=mkdir,
            )

        return self.get_export_save_path(
            service_name=service_name,
            filename=filename,
            compartment_id=compartment_id if compartment_id is not None else getattr(self, "compartment_id", None),
            subdirs=subdirs,
            mkdir=mkdir,
        )


    def sync_workspace_config_keys_to_session(self, workspace_id: int) -> None:
        cfg = self.get_config_keys(workspace_id)
        old_proxy = self.config_global_proxy_dict
        old_rate_limit = self.config_rate_limit_seconds
        old_rate_jitter = self.config_rate_limit_jitter_seconds

        self.config_global_proxy_dict = cfg.get("proxy")
        self.config_current_default_region = str(cfg.get("current_default_region") or "").strip()
        self.config_module_auto_save = bool(cfg.get("module_auto_save", True))
        self.config_rate_limit_seconds = self._coerce_rate_limit_seconds(
            cfg.get("rate_limit_seconds", 0.0),
            default=0.0,
        )
        self.config_rate_limit_jitter_seconds = self._coerce_non_negative_float(
            cfg.get("rate_limit_jitter_seconds", 0.0), default=0.0
        )

        if self.config_current_default_region:
            self.region = self.config_current_default_region

        if old_rate_limit != self.config_rate_limit_seconds or old_rate_jitter != self.config_rate_limit_jitter_seconds:
            self.http_policy.reset_rate_limit_window()

        self.config_api_logging_enabled = bool(cfg.get("api_logging_enabled", False))
        self.config_api_logging_file_path = str(cfg.get("api_logging_file_path", "") or "")
        verbosity = str(cfg.get("api_logging_verbosity", "standard") or "standard").strip().lower()
        if verbosity not in {"basic", "standard", "verbose"}:
            verbosity = "standard"
        self.config_api_logging_verbosity = verbosity

        attrs = cfg.get("api_logging_attributes") or []
        if isinstance(attrs, str):
            attrs = self._parse_list_csv(attrs)
        if not isinstance(attrs, list):
            attrs = []

        allowed = self._allowed_api_log_attrs()

        # de-dupe keep order + drop invalid
        seen: set[str] = set()
        out: List[str] = []
        for a in attrs:
            a = str(a).strip()
            if not a:
                continue
            if a not in allowed:
                continue
            if a not in seen:
                seen.add(a)
                out.append(a)

        self.config_api_logging_attributes = out
        std_output_format = str(cfg.get("std_output_format", "table") or "table").strip().lower()
        if std_output_format == "text":
            std_output_format = "txt"
        if std_output_format not in {"table", "txt"}:
            std_output_format = "table"
        self.config_std_output_format = std_output_format
        UtilityTools.TABLE_OUTPUT_FORMAT = std_output_format

        self._apply_api_logging_config()

        # If proxy changed and we're using instance-principal creds, reload signer to apply new proxy
        if old_proxy != self.config_global_proxy_dict:
            if self.credentials_type == "instance-principal" and self.credname:
                try:
                    # Only reload if this cred does NOT already have an explicit proxy
                    rec = self._fetch_cred_record(self.credname)
                    stored_proxy = ""
                    if rec:
                        try:
                            stored = json.loads(rec.session_creds or "{}")
                            stored_proxy = _safe_str(stored.get("proxy")).strip()
                        except Exception:
                            stored_proxy = ""
                    if not stored_proxy and self.config_global_proxy_dict:
                        # Rebuild signer with new proxy without forcing token refresh
                        self.load_stored_creds(self.credname, force_refresh=False)
                except Exception:
                    pass

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

    def set_config_key_result(self, workspace_id: int, key: str, value: str) -> OperationResult:
        key = str(key or "").strip()
        if key not in self.ALLOWED_CONFIG_KEYS:
            print(f"{UtilityTools.BOLD}{UtilityTools.RED}[X] '{key}' is not a recognized config key.{UtilityTools.RESET}")
            return OperationResult.failure(f"Unknown config key: {key}", error_code=ErrorCode.CONFIG_KEY_INVALID)

        cfg = self.get_config_keys(workspace_id)

        if key == "current_default_region":
            reg = str(value or "").strip().lower()
            cfg[key] = reg
            if reg and reg not in KNOWN_OCI_REGION_SET:
                msg = (
                    f"{UtilityTools.YELLOW}[!] Region '{reg}' is not in the built-in OCI region catalog."
                    f"{UtilityTools.RESET}"
                )
                if is_region_format_like(reg):
                    msg += " Continuing (may be a dedicated/private realm region)."
                else:
                    msg += " Continuing, but this value does not match expected OCI region format."
                print(msg)

        elif key == "rate_limit_seconds":
            try:
                parsed = float(value)
            except (TypeError, ValueError):
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] rate_limit_seconds must be a non-negative number.{UtilityTools.RESET}"
                )
                return OperationResult.failure(
                    "rate_limit_seconds must be a non-negative number",
                    error_code=ErrorCode.CONFIG_VALUE_INVALID,
                )
            if parsed < 0:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] rate_limit_seconds must be >= 0.{UtilityTools.RESET}"
                )
                return OperationResult.failure("rate_limit_seconds must be >= 0", error_code=ErrorCode.CONFIG_VALUE_INVALID)
            cfg[key] = parsed
        elif key == "rate_limit_jitter_seconds":
            try:
                parsed = float(value)
            except (TypeError, ValueError):
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {key} must be a non-negative number.{UtilityTools.RESET}"
                )
                return OperationResult.failure(f"{key} must be a non-negative number", error_code=ErrorCode.CONFIG_VALUE_INVALID)
            if parsed < 0:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {key} must be >= 0.{UtilityTools.RESET}"
                )
                return OperationResult.failure(f"{key} must be >= 0", error_code=ErrorCode.CONFIG_VALUE_INVALID)
            cfg[key] = parsed
        elif key == "module_auto_save":
            cfg[key] = self._parse_bool(value)

        elif key == "api_logging_enabled":
            cfg[key] = self._parse_bool(value)
        elif key == "api_logging_verbosity":
            v = str(value or "").strip().lower()
            if v not in {"basic", "standard", "verbose"}:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] api_logging_verbosity must be basic|standard|verbose.{UtilityTools.RESET}"
                )
                return OperationResult.failure(
                    "api_logging_verbosity must be basic|standard|verbose",
                    error_code=ErrorCode.CONFIG_VALUE_INVALID,
                )
            cfg[key] = v

        elif key == "api_logging_attributes":
            attrs = self._parse_list_csv(value)
            allowed = self._allowed_api_log_attrs()
            bad = [a for a in attrs if a not in allowed]
            if bad:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Invalid log attrs: {', '.join(bad)}{UtilityTools.RESET}\n"
                    f"    Allowed: {', '.join(sorted(allowed))}"
                )
                return OperationResult.failure(
                    "Invalid api_logging_attributes",
                    error_code=ErrorCode.CONFIG_VALUE_INVALID,
                    invalid_attrs=bad,
                )

            seen = set()
            out = []
            for a in attrs:
                if a not in seen:
                    seen.add(a)
                    out.append(a)
            cfg[key] = out
        elif key == "std_output_format":
            v = str(value or "").strip().lower()
            if v == "text":
                v = "txt"
            if v not in {"table", "txt"}:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] std_output_format must be 'table' or 'txt'.{UtilityTools.RESET}"
                )
                return OperationResult.failure(
                    "std_output_format must be 'table' or 'txt'",
                    error_code=ErrorCode.CONFIG_VALUE_INVALID,
                )
            cfg[key] = v

        else:
            cfg[key] = value

        self.data_master.save_value_to_table_column(
            db="metadata",
            table_name="workspace_index",
            target_column="configs",
            value=json.dumps(cfg),
            where={"id": workspace_id},
        )
        print(f"{UtilityTools.BOLD}{UtilityTools.BRIGHT_GREEN}[*] Set {key} to {value}{UtilityTools.RESET}")
        self.sync_workspace_config_keys_to_session(workspace_id)
        return OperationResult.success(f"Set {key}", key=key, value=value)

    def unset_config_key_result(self, workspace_id: int, key: str) -> OperationResult:
        key = str(key or "").strip()
        if key not in self.ALLOWED_CONFIG_KEYS:
            print(f"{UtilityTools.BOLD}{UtilityTools.RED}[X] '{key}' is not a recognized config key.{UtilityTools.RESET}")
            return OperationResult.failure(f"Unknown config key: {key}", error_code=ErrorCode.CONFIG_KEY_INVALID)

        cfg = self.get_config_keys(workspace_id)

        if key == "current_default_region":
            cfg[key] = ""
        elif key == "proxy":
            cfg[key] = None
        elif key == "module_auto_save":
            cfg[key] = True
        elif key == "rate_limit_seconds":
            cfg[key] = 0.0
        elif key == "rate_limit_jitter_seconds":
            cfg[key] = 0.0
        elif key == "api_logging_enabled":
            cfg[key] = False
        elif key == "api_logging_file_path":
            cfg[key] = self._default_api_log_path()
        elif key == "api_logging_verbosity":
            cfg[key] = "standard"
        elif key == "api_logging_attributes":
            cfg[key] = list(self.DEFAULT_API_LOG_ATTRIBUTES)
        elif key == "std_output_format":
            cfg[key] = "table"
        else:
            cfg[key] = ""

        self.data_master.save_value_to_table_column(
            db="metadata",
            table_name="workspace_index",
            target_column="configs",
            value=json.dumps(cfg),
            where={"id": workspace_id},
        )
        print(f"{UtilityTools.BOLD}{UtilityTools.BRIGHT_GREEN}[*] Unset {key}{UtilityTools.RESET}")
        self.sync_workspace_config_keys_to_session(workspace_id)
        return OperationResult.success(f"Unset {key}", key=key)

    def list_configs(self, workspace_id: int) -> None:
        cfg = self.get_config_keys(workspace_id)
        defaults = self._default_workspace_config()
        print(f"{UtilityTools.BOLD}[*] Workspace configs (compact):{UtilityTools.RESET}")
        key_labels = {
            "proxy": "Proxy",
            "current_default_region": "Default Region",
            "module_auto_save": "Auto Save Module Output",
            "rate_limit_seconds": "Rate Limit Seconds",
            "rate_limit_jitter_seconds": "Rate Limit Jitter Seconds",
            "api_logging_enabled": "API Logging Enabled",
            "api_logging_file_path": "API Logging File Path",
            "api_logging_verbosity": "API Logging Verbosity",
            "api_logging_attributes": "API Logging Attributes",
            "std_output_format": "Standard Output Format",
        }

        def _is_empty(value: Any) -> bool:
            if value is None:
                return True
            if isinstance(value, str):
                return not value.strip()
            if isinstance(value, (list, dict, tuple, set)):
                return len(value) == 0
            return False

        def _fmt_value(key: str, value: Any) -> str:
            if isinstance(value, bool):
                return "true" if value else "false"
            if isinstance(value, list):
                vals = [str(v).strip() for v in value if str(v).strip()]
                if not vals:
                    return "[]"
                return ", ".join(vals)
            if isinstance(value, dict):
                return json.dumps(value, ensure_ascii=True, sort_keys=True)
            if value is None:
                return "-"
            text = str(value).strip()
            return text if text else "-"

        rows = []
        for key in WORKSPACE_CONFIG_KEYS:
            value = cfg.get(key)
            default_value = defaults.get(key)
            is_default = value == default_value
            is_empty = _is_empty(value)
            status = ""
            if is_empty:
                status = " (empty)"
            elif is_default:
                status = " (default)"
            display_key = f"{key_labels.get(key, key)} ({key})"
            rows.append((display_key, _fmt_value(key, value), status))

        key_width = max(len(k) for k, _, _ in rows)
        for key, value, status in rows:
            print(f"  - {key.ljust(key_width)} : {value}{status}")

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
    def _maybe_refresh_session_token(
        self,
        rec: CredRecord,
        *,
        skew_seconds: int = 600,          # refresh if expiring within 10 minutes
        min_interval_seconds: int = 60,   # don't refresh more than once per minute per session
        debug: bool = False,
    ) -> bool:
        """
        If this credential contains a session token, check JWT exp and refresh via OCI CLI if needed.

        Returns:
        True  -> refreshed (or attempted) and rec.session_creds updated in-memory if refresh succeeded
        False -> no refresh done (not token, not near expiry, or refresh failed)

        Requires stored metadata:
        - profile_name (required)
        - file_location (optional)
        """
        # Parse stored JSON
        try:
            stored = json.loads(rec.session_creds or "{}")
        except Exception:
            return False

        token = (stored.get("security_token_content") or "").strip()
        if not token:
            return False  # not a session-token cred

        # --- decode exp from JWT (payload is base64url in middle segment) ---
        def _jwt_exp(tok: str) -> int:
            parts = tok.split(".")
            if len(parts) < 2:
                return 0
            payload_b64 = parts[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            try:
                payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8"))
            except Exception:
                return 0
            try:
                return int(payload.get("exp") or 0)
            except Exception:
                return 0

        exp = _jwt_exp(token)
        if exp <= 0:
            # Can't decode exp safely; don't auto-refresh (avoid loops)
            if debug:
                print(f"[!] Session token for '{rec.credname}' has no decodable exp; skip refresh.")
            return False
        now = int(time.time())

        # Rate-limit refresh attempts per session instance
        last_ts = int(getattr(self, "_last_session_token_refresh_ts", 0) or 0)
        if last_ts and (now - last_ts) < min_interval_seconds:
            return False

        seconds_left = exp - now
        if seconds_left > skew_seconds:
            return False  # still valid enough

        profile_name = (stored.get("profile_name") or "").strip()
        file_location = (stored.get("file_location") or "").strip()

        if not profile_name:
            if debug:
                print(f"[!] Session token for '{rec.credname}' expiring in {seconds_left}s but no profile_name stored; skip.")
            return False

        # Build CLI command
        cmd = ["oci", "session", "refresh", "--profile", profile_name]
        if file_location:
            cmd += ["--config-file", file_location]

        if debug:
            print(f"[*] Session token for '{rec.credname}' expires in {seconds_left}s -> refreshing...")
            print("    CMD:", " ".join(cmd))

        # Execute CLI refresh
        effective_proxy = self._resolve_proxy(include_auth_proxy=True)
        run_env = None
        if effective_proxy:
            run_env = dict(os.environ)
            run_env["HTTP_PROXY"] = effective_proxy
            run_env["HTTPS_PROXY"] = effective_proxy
            run_env["http_proxy"] = effective_proxy
            run_env["https_proxy"] = effective_proxy

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, env=run_env)
        except Exception as e:
            if debug:
                print(f"[!] Failed to execute OCI CLI refresh: {e}")
            return False

        if proc.returncode != 0:
            if debug:
                msg = (proc.stderr or "").strip() or (proc.stdout or "").strip()
                print(f"[!] OCI session refresh failed (rc={proc.returncode}): {msg[:400]}")
            return False

        # Re-read the refreshed token from config profile
        try:
            kwargs = {"profile_name": profile_name}
            if file_location:
                kwargs["file_location"] = file_location

            refreshed_cfg = from_file(**kwargs)
            token_file = refreshed_cfg.get("security_token_file") or stored.get("security_token_file")

            if not token_file:
                if debug:
                    print("[!] Refresh succeeded but could not find security_token_file in config or stored record.")
                return False

            new_token = Path(str(token_file)).expanduser().read_text(encoding="utf-8").strip()
            if not new_token:
                if debug:
                    print("[!] Refresh succeeded but refreshed token file was empty.")
                return False

            # Update stored JSON and persist back to DB
            stored["security_token_content"] = new_token
            stored["profile_name"] = profile_name
            if file_location:
                stored["file_location"] = file_location
            stored["security_token_file"] = str(token_file)

            self.data_master.save_value_to_table_column(
                db="metadata",
                table_name="sessions",
                target_column="session_creds",
                value=json.dumps(stored),
                where={"workspace_id": self.workspace_id, "credname": rec.credname},
            )

            # Update in-memory record so caller uses the fresh token immediately
            rec.session_creds = json.dumps(stored)

            # Update rate-limit timestamp
            self._last_session_token_refresh_ts = now

            if debug:
                new_exp = _jwt_exp(new_token)
                if new_exp:
                    print(f"[*] Refreshed '{rec.credname}' token exp: {new_exp} (in {new_exp - now}s)")
                else:
                    print(f"[*] Refreshed '{rec.credname}' token (new exp could not be decoded)")

            return True

        except Exception as e:
            if debug:
                print(f"[!] Refresh succeeded but failed to reload/persist token: {e}")
            return False



    def load_stored_creds(self, credname: str, *, force_refresh: bool = False) -> Optional[int]:
        print(f"[*] Loading creds: {credname}")
        rec = self._fetch_cred_record(credname)
        if not rec:
            print(f"[X] Unknown credname: {credname}")
            return None

        # NEW: refresh session tokens on load
        if not force_refresh:
            self._maybe_refresh_session_token(rec, skew_seconds=600, debug=self.individual_run_debug)
        else:
            self._maybe_refresh_session_token(rec, skew_seconds=10**9, debug=True)  # effectively "always refresh"

        if "Profile" in rec.credtype:
            return self._load_profile_from_record(rec)
        if rec.credtype == "session-token":
            try:
                stored = json.loads(rec.session_creds or "{}")
            except Exception as e:
                print(f"[X] Bad stored JSON for {rec.credname}: {e}")
                return -1
            if force_refresh and _safe_str(stored.get("security_token_file")).strip():
                refreshed, err = self._read_text_file(stored["security_token_file"], "session token")
                if err:
                    print(f"[X] {err}")
                    return -1
                stored["security_token_content"] = _safe_str(refreshed).strip()
                rec = CredRecord(credname=rec.credname, credtype=rec.credtype, session_creds=json.dumps(stored))
            profile_rec = CredRecord(
                credname=rec.credname,
                credtype="Profile - Session - INLINE",
                session_creds=rec.session_creds,
            )
            return self._load_profile_from_record(profile_rec)
        if rec.credtype == "api-key":
            profile_rec = CredRecord(
                credname=rec.credname,
                credtype="Profile - API Key - INLINE",
                session_creds=rec.session_creds,
            )
            return self._load_profile_from_record(profile_rec)
        if rec.credtype == "instance-principal":
            return self._load_instance_profile_from_record(rec, force_refresh=force_refresh)
        if rec.credtype == "resource-principal":
            return self._load_resource_profile_from_record(rec, force_refresh=force_refresh)

        print(f"[X] Unsupported credtype: {rec.credtype}")
        return None

    # ---------------------------------------------------------------------
    # Profile auth (Includes API Key & Temporary Session Token profiles)
    # ---------------------------------------------------------------------
    def add_profile_name(self, credname: str, extra_args: dict, assume: bool = False):
        if not credname:
            print("[X] Missing credname")
            return None

        if self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists.{UtilityTools.RESET}")
            return None

        extra_args = extra_args or {}
        profile_name = extra_args.get("profile_name")
        filepath = extra_args.get("filepath")

        try:
            kwargs = {}

            if profile_name:
                kwargs["profile_name"] = profile_name
            if filepath:
                kwargs["file_location"] = filepath

            config = from_file(**kwargs)

        except (ConfigFileNotFound, InvalidKeyFilePath, ProfileNotFound) as e:
            print(f"[X] Failed loading OCI profile: {e}")
            return None

        # Detect whether this profile is API-key or session-token style
        security_token_file = config.get("security_token_file")
        key_file = config.get("key_file")

        # Inline file reader (no separate function on the class)
        _read = lambda p, label: (
            ""
            if not p
            else Path(p).expanduser().read_text(encoding="utf-8").strip()
        )

        try:
            key_content = (config.get("key_content") or "").strip() or _read(key_file, "key")
        except Exception as e:
            print(f"[X] Could not read key_file '{key_file}': {e}")
            return None

        if not key_content:
            print("[X] Missing key_file/key_content in config")
            return None

        try:
            security_token_content = (config.get("security_token_content") or "").strip() or _read(
                security_token_file, "security_token"
            )
        except Exception as e:
            print(f"[X] Could not read security_token_file '{security_token_file}': {e}")
            return None

        serialized = {
            "user": config.get("user"),
            "fingerprint": config.get("fingerprint"),
            "tenancy": config.get("tenancy"),
            "region": config.get("region"),
            "key_content": key_content,
        }

        if profile_name:
            serialized["profile_name"] = profile_name
        if filepath:
            serialized["file_location"] = filepath
        if security_token_file:
            serialized["security_token_file"] = str(security_token_file)

        if security_token_content:
            serialized.update(
                {
                    "security_token_content": security_token_content,
                    "security_token_file": str(security_token_file or ""),
                }
            )

        profile_type = f"Profile - Session - {profile_name}" if security_token_content else f"Profile - API Key - {profile_name}"

        self.data_master.insert_creds(self.workspace_id, credname, profile_type, json.dumps(serialized))
        print(f"{UtilityTools.BRIGHT_GREEN}[*] Credentials added: {credname}{UtilityTools.RESET}")

        if assume:
            self.load_stored_creds(credname)

        tenancy_ocid = serialized.get("tenancy")
        if tenancy_ocid:
            self.add_compartment_id(tenancy_ocid, parent_compartment_id="N/A", override=False)

        return 1

    def _load_profile_from_record(self, rec: CredRecord) -> int:
        cred = rec.credname

        try:
            stored = json.loads(rec.session_creds or "{}")
        except Exception as e:
            print(f"[X] Bad stored JSON for {cred}: {e}")
            return -1

        tenancy = (stored.get("tenancy") or "").strip()
        region = (stored.get("region") or "").strip()
        key_content = (stored.get("key_content") or "").strip()
        token = (stored.get("security_token_content") or "").strip()

        user = (stored.get("user") or "").strip()
        fingerprint = (stored.get("fingerprint") or "").strip()

        if not tenancy or not region:
            print(f"[X] Profile '{cred}' missing tenancy/region in DB")
            return -1
        if not key_content:
            print(f"[X] Profile '{cred}' missing key_content in DB")
            return -1

        # ---- Session-token profile ----
        if token:
            try:
                pass_phrase = stored.get("pass_phrase")
                if isinstance(pass_phrase, str):
                    pass_phrase_b = pass_phrase.encode("utf-8")
                else:
                    pass_phrase_b = None

                private_key_obj = serialization.load_pem_private_key(
                    key_content.encode("utf-8"),
                    password=pass_phrase_b,
                )
                signer = SecurityTokenSigner(token, private_key_obj)
            except Exception as e:
                print(f"[X] Could not build session-token signer for '{cred}': {e}")
                return -1

            cfg = {
                "tenancy": tenancy,
                "region": region,
            }

            self.credentials = {"config": cfg, "signer": signer}
            self.credentials_type = "Profile Session"

        # ---- API-key profile ----
        else:
            if not user or not fingerprint:
                print(f"[X] API-key profile '{cred}' missing user/fingerprint in DB")
                return -1

            cfg = {
                "user": user,
                "fingerprint": fingerprint,
                "tenancy": tenancy,
                "region": region,
                "key_content": key_content,   # <-- matches Oracle example
            }

            # Optional: validate here if you want early fail (not required)
            try:
                validate_config(cfg)
            except Exception as e:
                print(f"[X] Loaded profile config failed validation: {e}")
                return -1

            self.credentials = {"config": cfg, "signer": None}
            self.credentials_type = "Profile"

        self.credname = cred
        self.tenant_id = tenancy
        self.compartment_id = tenancy
        self.region = region
        self._sync_region_config_from_loaded_creds(region)

        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Loaded profile {cred}{UtilityTools.RESET}")
        self._set_logger_credname(cred or "")
        return 1

    # ---------------------------------------------------------------------
    # Explicit API-key / session-token auth (reuses profile loader shape)
    # ---------------------------------------------------------------------
    def add_api_key(self, credname: str, extra_args: dict):
        if not credname:
            print("[X] Missing credname")
            return None

        if self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists.{UtilityTools.RESET}")
            return None

        extra_args = extra_args or {}

        def _pick_first(*vals: Any) -> str:
            for v in vals:
                s = _safe_str(v).strip()
                if s:
                    return s
            return ""

        user = _pick_first(extra_args.get("user"), extra_args.get("user_ocid"))
        fingerprint = _pick_first(extra_args.get("fingerprint"))
        tenancy = _pick_first(extra_args.get("tenancy_id"), extra_args.get("tenancy"))
        region = _pick_first(extra_args.get("region")).lower()

        key_source = _pick_first(
            extra_args.get("private_key"),
            extra_args.get("private_key_file"),
            extra_args.get("key_content"),
            extra_args.get("key_file"),
        )
        key_content, key_file, err = self._resolve_resource_text_or_file(key_source, "api-key private key")
        if err:
            print(f"[X] {err}")
            return None

        passphrase = _pick_first(extra_args.get("passphrase"), extra_args.get("pass_phrase"))
        passphrase_file = _pick_first(extra_args.get("passphrase_file"))
        if not passphrase and passphrase_file:
            passphrase, err = self._read_text_file(passphrase_file, "api-key private key passphrase")
            if err:
                print(f"[X] {err}")
                return None

        if not user:
            print("[X] Missing user OCID for api-key auth. Provide --user <user_ocid>.")
            return None
        if not fingerprint:
            print("[X] Missing fingerprint for api-key auth. Provide --fingerprint <fingerprint>.")
            return None
        if not tenancy:
            print("[X] Missing tenancy for api-key auth. Provide --tenancy-id <tenancy_ocid>.")
            return None
        if not region:
            print("[X] Missing region for api-key auth. Provide --region <oci_region>.")
            return None
        if not key_content:
            print("[X] Missing private key for api-key auth. Provide --private-key or --private-key-file.")
            return None

        serialized: Dict[str, Any] = {
            "auth_type": "api_key",
            "user": user,
            "fingerprint": fingerprint,
            "tenancy": tenancy,
            "region": region,
            "key_content": key_content,
        }
        if key_file:
            serialized["key_file"] = key_file
        if passphrase:
            serialized["pass_phrase"] = passphrase
        if passphrase_file:
            serialized["passphrase_file"] = passphrase_file

        # Reuse existing profile API-key loader behavior for validation + runtime state.
        load_rec = CredRecord(
            credname=credname,
            credtype="Profile - API Key - INLINE",
            session_creds=json.dumps(serialized),
        )
        ok = self._load_profile_from_record(load_rec)
        if ok != 1:
            print("[X] Could not initialize api-key credentials from supplied settings.")
            return None

        self.data_master.insert_creds(self.workspace_id, credname, "api-key", json.dumps(serialized))
        self.credname = credname
        self._set_logger_credname(credname or "")
        self.add_compartment_id(tenancy, parent_compartment_id="N/A", override=False)
        print(f"{UtilityTools.BRIGHT_GREEN}[*] Credentials added: {credname}{UtilityTools.RESET}")
        return 1

    def add_session_token(self, credname: str, extra_args: dict):
        if not credname:
            print("[X] Missing credname")
            return None

        if self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists.{UtilityTools.RESET}")
            return None

        extra_args = extra_args or {}

        def _pick_first(*vals: Any) -> str:
            for v in vals:
                s = _safe_str(v).strip()
                if s:
                    return s
            return ""

        token_source = _pick_first(
            extra_args.get("token"),
            extra_args.get("token_value"),
            extra_args.get("token_file"),
            extra_args.get("security_token_content"),
            extra_args.get("security_token"),
            extra_args.get("security_token_file"),
        )
        token, token_file, err = self._resolve_resource_text_or_file(token_source, "session token")
        if err:
            print(f"[X] {err}")
            return None
        if not token:
            print("[X] Missing session token. Provide --token or --token-file.")
            return None

        key_source = _pick_first(
            extra_args.get("private_key"),
            extra_args.get("private_key_file"),
            extra_args.get("key_content"),
            extra_args.get("key_file"),
        )
        key_content, key_file, err = self._resolve_resource_text_or_file(key_source, "session token private key")
        if err:
            print(f"[X] {err}")
            return None
        if not key_content:
            print("[X] Missing private key for session-token auth. Provide --private-key or --private-key-file.")
            return None

        passphrase = _pick_first(extra_args.get("passphrase"), extra_args.get("pass_phrase"))
        passphrase_file = _pick_first(extra_args.get("passphrase_file"))
        if not passphrase and passphrase_file:
            passphrase, err = self._read_text_file(passphrase_file, "session token private key passphrase")
            if err:
                print(f"[X] {err}")
                return None

        region = _pick_first(extra_args.get("region")).lower()
        tenancy = _pick_first(
            extra_args.get("tenancy_id"),
            extra_args.get("tenancy"),
            self._extract_tenancy_from_token(token),
        )

        if not region:
            print("[X] Missing region for session-token auth. Provide --region <oci_region>.")
            return None
        if not tenancy:
            print("[X] Missing tenancy for session-token auth. Provide --tenancy-id <tenancy_ocid>.")
            return None

        serialized: Dict[str, Any] = {
            "auth_type": "session_token",
            "security_token_content": token,
            "key_content": key_content,
            "region": region,
            "tenancy": tenancy,
        }
        if token_file:
            serialized["security_token_file"] = token_file
        if key_file:
            serialized["key_file"] = key_file
        if passphrase:
            serialized["pass_phrase"] = passphrase
        if passphrase_file:
            serialized["passphrase_file"] = passphrase_file

        # Reuse existing profile session-token loader behavior for validation + runtime state.
        load_rec = CredRecord(
            credname=credname,
            credtype="Profile - Session - INLINE",
            session_creds=json.dumps(serialized),
        )
        ok = self._load_profile_from_record(load_rec)
        if ok != 1:
            print("[X] Could not initialize session-token signer from supplied settings.")
            return None

        self.data_master.insert_creds(self.workspace_id, credname, "session-token", json.dumps(serialized))
        self.credname = credname
        self._set_logger_credname(credname or "")
        self.add_compartment_id(tenancy, parent_compartment_id="N/A", override=False)
        print(f"{UtilityTools.BRIGHT_GREEN}[*] Credentials added: {credname}{UtilityTools.RESET}")
        return 1



    # ---------------------------------------------------------------------
    # Instance principal auth
    # ---------------------------------------------------------------------
    def _ipdbg(self, msg: str, **kv: Any) -> None:
        tail = ""
        if kv:
            tail = " | " + " ".join(f"{k}={v!r}" for k, v in kv.items())
        print(f"[*] instance-principal: {msg}{tail}")

    def add_instance_profile_token(self, credname: str, extra_args: dict, proxy: str = "", debug_http: bool = False):
        self._ipdbg("start add_instance_profile_token", credname=credname, extra_args=extra_args)
        if not credname:
            print("[X] Missing credname")
            return None

        if self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists.{UtilityTools.RESET}")
            return None

        extra_args = extra_args or {}
        ref_file = (extra_args.get("reference_file") or extra_args.get("filepath") or "").strip()
        on_host = _truthy(extra_args.get("on_host"))
        imds_version = _safe_str(extra_args.get("imds_version")).strip().lower() or "v2"
        region = (extra_args.get("region") or "").strip()
        cli_proxy = _safe_str(extra_args.get("proxy")).strip()
        debug_http = bool(debug_http or _truthy(extra_args.get("debug_http")) or _truthy(extra_args.get("log_requests")))

        if on_host and ref_file:
            print("[X] Use either --on-host OR --reference-file, not both.")
            return None

        if not on_host and not ref_file:
            print("[X] Missing instance-principal mode. Use --on-host or --reference-file.")
            return None

        explicit_proxy = (proxy or "").strip() or cli_proxy
        effective_proxy = self._resolve_proxy(explicit_proxy, include_auth_proxy=True)
        cfg: Dict[str, Any]
        if on_host:
            self._ipdbg("mode on-host selected", imds_version=imds_version, region=region or "<auto>", proxy=effective_proxy or "<none>")
            if not region:
                region = self._detect_instance_region(imds_version=imds_version)
            if not region:
                print("[X] Missing region. Provide --region when using --on-host.")
                return None
            tenancy_id = self._detect_instance_tenancy_ocid(imds_version=imds_version)
            self._ipdbg("on-host metadata resolved", region=region, tenancy_id=tenancy_id or "<empty>")
            cfg = {
                "mode": "on-host",
                "region": region,
                "tenancy_id": tenancy_id,
                "imds_version": imds_version,
                "proxy": effective_proxy,
                "log_requests": bool(debug_http),
            }
        else:
            self._ipdbg("mode reference-file selected", ref_file=ref_file, imds_version=imds_version)
            ref_cfg, err = self._load_instance_profile_reference_file(ref_file)
            if err:
                print(f"[X] Failed loading instance-principal reference file: {err}")
                return None
            if not region:
                region = _safe_str(ref_cfg.get("region")).strip()
            if not region:
                region = self._detect_instance_region(imds_version=imds_version)
            if not region:
                print("[X] Missing region. Provide --region, set 'region' in reference file, or run where IMDS /opc is reachable.")
                return None
            tenancy_id = _safe_str(ref_cfg.get("tenancy_id")).strip() or self._detect_instance_tenancy_ocid(imds_version=imds_version)
            if not tenancy_id:
                print("[X] Missing tenancy_id in reference file and could not auto-detect via instance metadata.")
                return None
            cfg = {
                "mode": "reference-file",
                "reference_file": str(Path(ref_file).expanduser().resolve()),
                "region": region,
                "tenancy_id": tenancy_id,
                "imds_version": imds_version,
                "proxy": effective_proxy,
                "log_requests": bool(ref_cfg.get("log_requests", False)) or bool(debug_http),
            }

        self._ipdbg("attempting initial load", mode=cfg.get("mode"), region=cfg.get("region"), tenancy_id=cfg.get("tenancy_id"))
        load_rec = CredRecord(credname=credname, credtype="instance-principal", session_creds=json.dumps(cfg))
        ok = self._load_instance_profile_from_record(load_rec, force_refresh=True, debug_http=debug_http)
        if ok != 1:
            print("[X] Could not initialize instance-principal signer from supplied settings.")
            return None

        self.data_master.insert_creds(self.workspace_id, credname, "instance-principal", json.dumps(cfg))
        self.credname = credname
        self._set_logger_credname(credname or "")
        tenancy_for_root = _safe_str(cfg.get("tenancy_id")).strip()
        if tenancy_for_root:
            self.add_compartment_id(tenancy_for_root, parent_compartment_id="N/A", override=False)
        print(f"{UtilityTools.BRIGHT_GREEN}[*] Credentials added: {credname}{UtilityTools.RESET}")
        return 1

    def _load_instance_profile_from_record(self, rec: CredRecord, force_refresh: bool = False, debug_http: bool = False) -> int:
        cred = rec.credname
        self._ipdbg("start _load_instance_profile_from_record", credname=cred, force_refresh=force_refresh)
        try:
            stored = json.loads(rec.session_creds or "{}")
        except Exception as e:
            print(f"[X] Bad stored JSON for {cred}: {e}")
            return -1

        mode = _safe_str(stored.get("mode")).strip().lower()
        ref_file = _safe_str(stored.get("reference_file")).strip()
        region = _safe_str(stored.get("region")).strip()
        tenancy_id = _safe_str(stored.get("tenancy_id")).strip()
        imds_version = _safe_str(stored.get("imds_version")).strip().lower() or "v2"
        proxy = _safe_str(stored.get("proxy")).strip()
        log_requests = _truthy(stored.get("log_requests")) or bool(debug_http)

        if not mode:
            mode = "reference-file" if ref_file else "on-host"
        self._ipdbg("parsed stored mode", mode=mode, region=region or "<auto>", imds_version=imds_version)

        if not region:
            region = self._detect_instance_region(imds_version=imds_version)
        if not region:
            print(f"[X] instance-principal '{cred}' missing region and IMDS lookup failed")
            return -1
        if mode == "on-host":
            tenancy_id = tenancy_id or self._detect_instance_tenancy_ocid(imds_version=imds_version)
            self._ipdbg("building on-host signer", region=region, tenancy_id=tenancy_id or "<empty>")
            signer, cfg, err = self._build_on_host_instance_profile_signer(
                region=region,
                tenancy_id=tenancy_id,
                force_refresh=force_refresh,
                debug_http=debug_http,
            )
            if err:
                print(f"[X] Failed building on-host instance-principal signer for '{cred}': {err}")
                return -1
        else:
            if not ref_file:
                print(f"[X] instance-principal '{cred}' missing reference_file in DB")
                return -1
            tenancy_id = tenancy_id or self._detect_instance_tenancy_ocid(imds_version=imds_version)
            if not tenancy_id:
                print(f"[X] instance-principal '{cred}' missing tenancy_id and metadata lookup failed")
                return -1
            self._ipdbg("building reference-file signer", ref_file=ref_file, region=region, tenancy_id=tenancy_id)
            ref_cfg, err = self._load_instance_profile_reference_file(ref_file)
            if err:
                print(f"[X] Failed loading reference file for '{cred}': {err}")
                return -1
            signer, cfg, err = self._build_instance_profile_signer(
                ref_cfg=ref_cfg,
                region=region,
                tenancy_id=tenancy_id,
                proxy=proxy,
                log_requests=log_requests,
                force_refresh=force_refresh,
            )
            if err:
                print(f"[X] Failed building instance-principal signer for '{cred}': {err}")
                return -1

        self.credentials = {"config": cfg, "signer": signer}
        self.credentials_type = "instance-principal"
        self.credname = cred
        self.tenant_id = _safe_str(cfg.get("tenancy")).strip() or tenancy_id
        self.compartment_id = self.tenant_id or tenancy_id
        self.region = region
        self._sync_region_config_from_loaded_creds(region)
        self._set_logger_credname(cred or "")
        self._ipdbg("load complete", credname=cred, tenancy_id=self.tenant_id or "<empty>", region=self.region or "<empty>")
        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Loaded instance-principal {cred}{UtilityTools.RESET}")
        return 1

    # ---------------------------------------------------------------------
    # Resource principal auth
    # ---------------------------------------------------------------------
    def add_resource_profile_token(self, credname: str, extra_args: dict, proxy: str = "", debug_http: bool = False):
        if not credname:
            print("[X] Missing credname")
            return None

        if self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists.{UtilityTools.RESET}")
            return None

        extra_args = extra_args or {}
        ref_file_arg = _safe_str(extra_args.get("reference_file")).strip()
        filepath_arg = _safe_str(extra_args.get("filepath")).strip()
        if ref_file_arg and filepath_arg and ref_file_arg != filepath_arg:
            print("[X] Use only one resource-principal reference file path.")
            return None
        ref_file = ref_file_arg or filepath_arg
        ref_cfg: Dict[str, Any] = {}
        if ref_file:
            ref_cfg, err = self._load_resource_profile_reference_file(ref_file)
            if err:
                print(f"[X] Failed loading resource-principal reference file: {err}")
                return None

        def _pick_first(*vals: Any) -> str:
            for v in vals:
                s = _safe_str(v).strip()
                if s:
                    return s
            return ""

        token_source = _pick_first(
            extra_args.get("token"),
            extra_args.get("rpst"),
            extra_args.get("token_file"),
            ref_cfg.get("rpst_content"),
            ref_cfg.get("rpst"),
            ref_cfg.get("security_token_content"),
            ref_cfg.get("security_token"),
            ref_cfg.get("token"),
            ref_cfg.get("rpst_file"),
            ref_cfg.get("security_token_file"),
            ref_cfg.get("token_file"),
        )
        token, token_file, err = self._resolve_resource_text_or_file(token_source, "resource principal token")
        if err:
            print(f"[X] {err}")
            return None
        if not token:
            print(
                "[X] Missing resource principal token (RPST). "
                "Provide --token, --token-file, or --reference-file."
            )
            return None

        private_key_source = _pick_first(
            extra_args.get("private_key"),
            extra_args.get("private_pem"),
            extra_args.get("private_key_file"),
            ref_cfg.get("private_pem_content"),
            ref_cfg.get("private_pem"),
            ref_cfg.get("private_key"),
            ref_cfg.get("key_content"),
            ref_cfg.get("private_pem_file"),
            ref_cfg.get("private_key_file"),
            ref_cfg.get("key_file"),
        )
        private_pem, private_pem_file, err = self._resolve_resource_text_or_file(private_key_source, "resource principal private key")
        if err:
            print(f"[X] {err}")
            return None
        if not private_pem:
            print(
                "[X] Missing resource principal private key. "
                "Provide --private-key, --private-key-file, or --reference-file."
            )
            return None

        passphrase = _pick_first(
            extra_args.get("passphrase"),
            ref_cfg.get("passphrase"),
        )
        passphrase_file = _pick_first(
            extra_args.get("passphrase_file"),
            ref_cfg.get("passphrase_file"),
        )
        if not passphrase and passphrase_file:
            passphrase, err = self._read_text_file(passphrase_file, "resource principal passphrase")
            if err:
                print(f"[X] {err}")
                return None

        region = _pick_first(
            extra_args.get("region"),
            ref_cfg.get("region"),
        ).lower()
        tenancy = _pick_first(
            extra_args.get("tenancy_id"),
            extra_args.get("tenancy"),
            ref_cfg.get("tenancy_id"),
            ref_cfg.get("tenancy"),
        )
        if not tenancy:
            tenancy = self._extract_tenancy_from_token(token)

        version = _pick_first(
            extra_args.get("version"),
            ref_cfg.get("version"),
        )

        explicit_proxy = _pick_first(proxy, extra_args.get("proxy"), ref_cfg.get("proxy"))
        effective_proxy = self._resolve_proxy(explicit_proxy, include_auth_proxy=True)

        stored: Dict[str, Any] = {
            "resource_principal": True,
            "auth_type": "resource_principal",
            "rpst_content": token,
            "private_pem_content": private_pem,
            "region": region,
            "tenancy": tenancy,
            "version": version,
            "proxy": effective_proxy,
            "log_requests": bool(debug_http or _truthy(extra_args.get("debug_http"))),
        }
        if token_file:
            stored["rpst_file"] = token_file
        if private_pem_file:
            stored["private_pem_file"] = private_pem_file
        if passphrase:
            stored["passphrase"] = passphrase
        if passphrase_file:
            stored["passphrase_file"] = passphrase_file
        if ref_file:
            stored["filepath"] = str(Path(ref_file).expanduser().resolve())

        load_rec = CredRecord(credname=credname, credtype="resource-principal", session_creds=json.dumps(stored))
        ok = self._load_resource_profile_from_record(load_rec, force_refresh=True, debug_http=debug_http)
        if ok != 1:
            print("[X] Could not initialize resource-principal signer from supplied settings.")
            return None

        self.data_master.insert_creds(self.workspace_id, credname, "resource-principal", json.dumps(stored))
        self.credname = credname
        self._set_logger_credname(credname or "")
        if tenancy:
            self.add_compartment_id(tenancy, parent_compartment_id="N/A", override=False)
        print(f"{UtilityTools.BRIGHT_GREEN}[*] Credentials added: {credname}{UtilityTools.RESET}")
        return 1

    def _load_resource_profile_from_record(self, rec: CredRecord, force_refresh: bool = False, debug_http: bool = False) -> int:
        cred = rec.credname
        try:
            stored = json.loads(rec.session_creds or "{}")
        except Exception as e:
            print(f"[X] Bad stored JSON for {cred}: {e}")
            return -1

        signer = self.build_or_reuse_signer(
            stored,
            force_refresh=force_refresh,
            debug_http=debug_http,
            type_of_cred="resource-principal",
        )
        if signer is None:
            print(f"[X] Failed building resource-principal signer for '{cred}'.")
            return -1

        token = _safe_str(stored.get("rpst_content") or stored.get("security_token_content") or stored.get("token")).strip()
        region = _safe_str(stored.get("region")).strip().lower()
        tenancy = _safe_str(stored.get("tenancy") or stored.get("tenancy_id")).strip()
        if not tenancy and token:
            tenancy = self._extract_tenancy_from_token(token)

        cfg: Dict[str, Any] = {}
        if tenancy:
            cfg["tenancy"] = tenancy
        if region:
            cfg["region"] = region

        self.credentials = {"config": cfg, "signer": signer}
        self.credentials_type = "resource-principal"
        self.credname = cred

        if tenancy:
            self.tenant_id = tenancy
            self.compartment_id = tenancy
        if region:
            self.region = region
            self._sync_region_config_from_loaded_creds(region)

        self._set_logger_credname(cred or "")
        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Loaded resource-principal {cred}{UtilityTools.RESET}")
        return 1

    def build_or_reuse_signer(self, cfg: Dict[str, Any], force_refresh: bool = False, debug_http: bool = False, type_of_cred: Optional[str] = None):
        cred_type = _safe_str(type_of_cred).strip().lower()
        if cred_type and cred_type != "resource-principal":
            if debug_http:
                print(f"[!] build_or_reuse_signer does not support type '{type_of_cred}'")
            return None

        if not isinstance(cfg, dict):
            if debug_http:
                print("[!] build_or_reuse_signer: cfg must be a dict")
            return None

        token = _safe_str(cfg.get("rpst_content") or cfg.get("security_token_content") or cfg.get("token")).strip()
        token_file = _safe_str(cfg.get("rpst_file") or cfg.get("security_token_file") or cfg.get("token_file")).strip()
        if token_file and (force_refresh or not token):
            text, err = self._read_text_file(token_file, "resource principal token")
            if err:
                if debug_http:
                    print(f"[!] {err}")
                return None
            token = _safe_str(text).strip()
            cfg["rpst_content"] = token
            cfg["rpst_file"] = token_file
        if not token:
            if debug_http:
                print("[!] Missing RPST token for resource-principal signer")
            return None

        private_pem = _safe_str(cfg.get("private_pem_content") or cfg.get("private_key") or cfg.get("key_content")).strip()
        private_pem_file = _safe_str(cfg.get("private_pem_file") or cfg.get("private_key_file") or cfg.get("key_file")).strip()
        if private_pem_file and (force_refresh or not private_pem):
            text, err = self._read_text_file(private_pem_file, "resource principal private key")
            if err:
                if debug_http:
                    print(f"[!] {err}")
                return None
            private_pem = _safe_str(text).strip()
            cfg["private_pem_content"] = private_pem
            cfg["private_pem_file"] = private_pem_file
        if not private_pem:
            if debug_http:
                print("[!] Missing private key for resource-principal signer")
            return None

        passphrase = _safe_str(cfg.get("passphrase")).strip()
        passphrase_file = _safe_str(cfg.get("passphrase_file")).strip()
        if passphrase_file and (force_refresh or not passphrase):
            text, err = self._read_text_file(passphrase_file, "resource principal passphrase")
            if err:
                if debug_http:
                    print(f"[!] {err}")
                return None
            passphrase = _safe_str(text).strip()
            cfg["passphrase"] = passphrase

        cache = getattr(self, "_resource_principal_signer_cache", None)
        if not isinstance(cache, dict):
            cache = {}
            self._resource_principal_signer_cache = cache

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        cached = cache.get(token_hash)
        if not force_refresh and isinstance(cached, dict):
            exp = int(cached.get("token_exp", 0) or 0)
            signer = cached.get("signer")
            now = int(time.time())
            if signer is not None and (exp == 0 or exp > now + 30):
                return signer

        pw = passphrase.encode("utf-8") if passphrase else None
        try:
            private_key_obj = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=pw)
            signer = SecurityTokenSigner(token, private_key_obj)
        except Exception as e:
            if debug_http:
                print(f"[!] Could not build resource-principal signer: {e}")
            return None

        cache[token_hash] = {"signer": signer, "token_exp": self._decode_jwt_exp(token)}
        return signer

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

    def _detect_instance_tenancy_ocid(self, imds_version: str = "v2") -> str:
        endpoints = self._metadata_lookup_order(imds_version=imds_version)
        self._ipdbg("detect tenancy start", imds_version=imds_version, attempts=len(endpoints))
        for url, headers in endpoints:
            try:
                self._ipdbg("detect tenancy request", url=url)
                self._wait_for_http_rate_limit()
                r = requests.get(url, headers=headers, timeout=2)
                self._ipdbg("detect tenancy response", url=url, status=r.status_code)
                if r.status_code != 200:
                    continue
                data = r.json() if r.text else {}
                if not isinstance(data, dict):
                    continue
                tid = _safe_str(data.get("tenantId") or data.get("tenancyId") or data.get("tenancy_id")).strip()
                if tid:
                    self._ipdbg("detect tenancy success", tenancy_id=tid)
                    return tid
            except Exception:
                self._ipdbg("detect tenancy error", url=url)
                continue
        self._ipdbg("detect tenancy failed")
        return ""

    def _detect_instance_region(self, imds_version: str = "v2") -> str:
        endpoints = self._metadata_lookup_order(imds_version=imds_version)
        self._ipdbg("detect region start", imds_version=imds_version, attempts=len(endpoints))
        for url, headers in endpoints:
            try:
                self._ipdbg("detect region request", url=url)
                self._wait_for_http_rate_limit()
                r = requests.get(url, headers=headers, timeout=2)
                self._ipdbg("detect region response", url=url, status=r.status_code)
                if r.status_code != 200:
                    continue
                data = r.json() if r.text else {}
                if not isinstance(data, dict):
                    continue
                region = _safe_str(
                    data.get("regionName")
                    or data.get("regionIdentifier")
                    or data.get("canonicalRegionName")
                    or data.get("region")
                ).strip()
                if region:
                    self._ipdbg("detect region success", region=region.lower())
                    return region.lower()
            except Exception:
                self._ipdbg("detect region error", url=url)
                continue
        self._ipdbg("detect region failed")
        return ""

    def _build_on_host_instance_profile_signer(
        self,
        *,
        region: str,
        tenancy_id: str,
        force_refresh: bool,
        debug_http: bool,
    ) -> Tuple[Optional[Any], Dict[str, Any], Optional[str]]:
        self._ipdbg("build on-host signer start", region=region, tenancy_id=tenancy_id or "<empty>", force_refresh=force_refresh)
        signer_cls = getattr(getattr(oci, "auth", None), "signers", None)
        signer_cls = getattr(signer_cls, "InstancePrincipalsSecurityTokenSigner", None)
        if signer_cls is None:
            return None, {}, "OCI SDK missing InstancePrincipalsSecurityTokenSigner"

        signer = None
        try:
            self._ipdbg("construct signer with kwargs")
            signer = signer_cls(federation_client_cert_bundle_verify=False, log_requests=bool(debug_http))
        except TypeError:
            try:
                self._ipdbg("construct signer fallback no-arg")
                signer = signer_cls()
            except Exception as e:
                return None, {}, str(e)
        except Exception as e:
            return None, {}, str(e)

        if force_refresh and hasattr(signer, "refresh_security_token"):
            try:
                self._ipdbg("refresh_security_token start")
                signer.refresh_security_token()
                self._ipdbg("refresh_security_token done")
            except Exception:
                self._ipdbg("refresh_security_token failed")
                pass

        cfg: Dict[str, Any] = {"region": region}
        if tenancy_id:
            cfg["tenancy"] = tenancy_id
        self._ipdbg("build on-host signer done")
        return signer, cfg, None

    def _build_instance_profile_signer(
        self,
        *,
        ref_cfg: Dict[str, Any],
        region: str,
        tenancy_id: str,
        proxy: str,
        log_requests: bool,
        force_refresh: bool,
    ) -> Tuple[Optional[X509FederationClientBasedSecurityTokenSigner], Dict[str, Any], Optional[str]]:
        leaf_cert_path = _safe_str(ref_cfg.get("leaf_cert_file")).strip()
        leaf_key_path = _safe_str(ref_cfg.get("leaf_key_file")).strip()
        if not leaf_cert_path or not leaf_key_path:
            return None, {}, "reference file must define leaf_cert_file and leaf_key_file"

        leaf_cert_pem, err = self._read_text_file(leaf_cert_path, "leaf_cert")
        if err:
            return None, {}, err
        leaf_key_pem, err = self._read_text_file(leaf_key_path, "leaf_key")
        if err:
            return None, {}, err

        passphrase: Optional[str] = None
        passphrase_file = _safe_str(ref_cfg.get("passphrase_file")).strip()
        if passphrase_file:
            passphrase, err = self._read_text_file(passphrase_file, "passphrase")
            if err:
                return None, {}, err

        intermediate_pems: List[str] = []
        one_intermediate = _safe_str(ref_cfg.get("intermediate_cert_file")).strip()
        if one_intermediate:
            text, err = self._read_text_file(one_intermediate, "intermediate_cert")
            if err:
                return None, {}, err
            intermediate_pems.append(text or "")

        many_intermediates = ref_cfg.get("intermediate_cert_files")
        if isinstance(many_intermediates, list):
            for idx, ipath in enumerate(many_intermediates):
                if not isinstance(ipath, str) or not ipath.strip():
                    continue
                text, err = self._read_text_file(ipath.strip(), f"intermediate_cert[{idx}]")
                if err:
                    return None, {}, err
                intermediate_pems.append(text or "")

        if not intermediate_pems:
            return None, {}, "reference file must define intermediate_cert_file or intermediate_cert_files"

        try:
            self._validate_pems(
                leaf_cert_pem or "",
                leaf_key_pem or "",
                intermediate_pems[0] if intermediate_pems else None,
                passphrase=passphrase,
            )
        except Exception as e:
            return None, {}, f"invalid PEM material: {e}"

        leaf = PEMStringCertificateRetriever(
            certificate_pem=leaf_cert_pem or "",
            private_key_pem=leaf_key_pem or "",
            passphrase=(passphrase or None),
        )
        intermediates = [PEMStringCertificateRetriever(certificate_pem=x) for x in intermediate_pems if x]

        req_sess = requests.Session()
        self._apply_http_rate_limit_to_requests_session(req_sess)
        explicit_proxy = (proxy or "").strip()
        effective_proxy = self._resolve_proxy(explicit_proxy, include_auth_proxy=True)
        self._ipdbg("instance-principal proxy", proxy=effective_proxy or "<none>")
        req_sess.trust_env = False
        proxy_env_keys = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
        prior_proxy_env = {k: os.environ.get(k) for k in proxy_env_keys}
        if effective_proxy:
            # Ensure proxy is honored even if other libs read env
            os.environ["HTTP_PROXY"] = effective_proxy
            os.environ["HTTPS_PROXY"] = effective_proxy
            os.environ["http_proxy"] = effective_proxy
            os.environ["https_proxy"] = effective_proxy
            req_sess.proxies.update({"http": effective_proxy, "https": effective_proxy})
        try:
            ca_bundle_file = _safe_str(ref_cfg.get("ca_bundle_file")).strip()
            if ca_bundle_file:
                req_sess.verify = ca_bundle_file
                self._ipdbg("instance-principal CA bundle", ca_bundle_file=ca_bundle_file)

            federation_endpoint = _safe_str(ref_cfg.get("federation_endpoint")).strip() or f"https://auth.{region}.oraclecloud.com/v1/x509"
            self._ipdbg("instance-principal federation endpoint", endpoint=federation_endpoint, log_requests=bool(log_requests))
            session_keys = SessionKeySupplier(key_size=2048)
            try:
                if log_requests:
                    try:
                        preflight = req_sess.get(federation_endpoint, timeout=5)
                        self._ipdbg("instance-principal preflight", status=preflight.status_code)
                    except Exception as e:
                        self._ipdbg("instance-principal preflight failed", err=f"{type(e).__name__}: {e}")
                fed = X509FederationClient(
                    federation_endpoint=federation_endpoint,
                    tenancy_id=tenancy_id,
                    session_key_supplier=session_keys,
                    leaf_certificate_retriever=leaf,
                    intermediate_certificate_retrievers=intermediates,
                    cert_bundle_verify=False,
                    requests_session=req_sess,
                    log_requests=bool(log_requests),
                )
                if force_refresh:
                    try:
                        fed.get_security_token()
                    except Exception:
                        pass
                signer = X509FederationClientBasedSecurityTokenSigner(fed)
            except Exception as e:
                return None, {}, str(e)

            cfg = {"tenancy": tenancy_id, "region": region}
            return signer, cfg, None
        finally:
            if effective_proxy:
                for key, old_value in prior_proxy_env.items():
                    if old_value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = old_value

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

        written = 0
        refresh_compartments = False

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
            ok = self.data_master.save_dict_row(
                db="service",
                table_name=table_name,
                row=row,
                on_conflict=on_conflict,
                commit=False,
            )
            if ok:
                written += 1
                if table_name == "resource_compartments":
                    refresh_compartments = True

        if commit and written:
            try:
                self.data_master.commit("service")
            except Exception as e:
                UtilityTools.dlog(
                    bool(getattr(self, "debug", False) or getattr(self, "individual_run_debug", False)),
                    "save_resources: commit failed",
                    table=table_name,
                    err=f"{type(e).__name__}: {e}",
                )
                pass

        if refresh_compartments:
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
            on_conflict=on_conflict,  # ← THIS is the fix
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
