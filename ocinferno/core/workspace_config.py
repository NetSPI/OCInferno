"""Workspace config-key management, extracted from the SessionUtility god-object.

A mixin (SessionUtility inherits it) so the method bodies and `self.*` access are
unchanged -- it just moves ~400 LOC of config-key storage/schema/migration out of
session.py. The config class-attrs (ALLOWED_CONFIG_KEYS, WORKSPACE_CONFIG_SCHEMA_VERSION)
and the shared `_coerce_rate_limit_seconds` helper stay on SessionUtility and resolve via
MRO. Public methods (get_config_keys/set_config_key_result/unset_config_key_result/
list_configs) are called by the REPL via `session.<method>` and are inherited unchanged.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ocinferno.core.config import (
    KNOWN_OCI_REGION_SET,
    WORKSPACE_CONFIG_KEYS,
    default_workspace_config,
    is_region_format_like,
)
from ocinferno.core.coerce import _safe_str
from ocinferno.core.console import UtilityTools
from ocinferno.core.contracts import ErrorCode, OperationResult


class WorkspaceConfigMixin:

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
        std_output_format = str(cfg.get("std_output_format", "txt") or "txt").strip().lower()
        if std_output_format == "text":
            std_output_format = "txt"
        if std_output_format not in {"table", "txt"}:
            std_output_format = "txt"
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
