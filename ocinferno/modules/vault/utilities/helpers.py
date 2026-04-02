#!/usr/bin/env python3
from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import dedupe_strs
from ocinferno.core.utils.service_runtime import _init_client


def build_vault_client(session, client_cls, service_name: str, region: Optional[str] = None, endpoint: Optional[str] = None):
    """Initialize a Vault-family client with shared signer/proxy/session behavior."""
    kwargs: Dict[str, Any] = {}
    if endpoint:
        kwargs["service_endpoint"] = endpoint
    client = _init_client(client_cls, session=session, service_name=service_name, **kwargs)
    target_region = region or getattr(session, "region", None)
    if target_region and not endpoint:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class VaultVaultsResource:
    COLUMNS = ["id", "display_name", "vault_type", "lifecycle_state", "time_created", "management_endpoint", "crypto_endpoint"]
    TABLE_NAME = "vault_vaults"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.region = region or getattr(session, "region", None)
        self.compartment_id = (
            getattr(session, "compartment_id", None)
            or getattr(session, "tenancy_id", None)
            or getattr(session, "tenant_id", None)
        )
        self.client = build_vault_client(session, oci.key_management.KmsVaultClient, "Vault", region=self.region)

    @staticmethod
    def _to_dict_list(data: Any) -> List[Dict[str, Any]]:
        if not data:
            return []
        try:
            value = oci.util.to_dict(data)
            return value if isinstance(value, list) else (value or [])
        except Exception:
            out: List[Dict[str, Any]] = []
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        out.append(entry)
                    else:
                        try:
                            out.append(oci.util.to_dict(entry))
                        except Exception:
                            pass
            return out

    # List vaults in current compartment.
    def list(self) -> List[Dict[str, Any]]:
        if not self.compartment_id:
            raise ValueError("No compartment_id/tenancy_id available")
        resp = oci.pagination.list_call_get_all_results(self.client.list_vaults, compartment_id=self.compartment_id)
        return self._to_dict_list(resp.data)

    # Get one vault by OCID (best-effort via list cache).
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        for row in self.list():
            if isinstance(row, dict) and row.get("id") == resource_id:
                return row
        return {}

    # Save vault rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for vault rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class VaultKeysResource:
    COLUMNS = ["display_name", "id", "vault_id", "protection_mode", "is_auto_rotation_enabled", "lifecycle_state", "time_created"]
    VERSION_COLUMNS = ["id", "key_id", "vault_id", "lifecycle_state", "time_created", "is_auto_rotated"]
    TABLE_VAULTS = "vault_vaults"
    TABLE_KEYS = "vault_keys"
    TABLE_KEY_VERSIONS = "vault_key_versions"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.region = region or getattr(session, "region", None)
        self.compartment_id = (
            getattr(session, "compartment_id", None)
            or getattr(session, "tenancy_id", None)
            or getattr(session, "tenant_id", None)
        )
        self.debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

        self.vault_client = build_vault_client(session, oci.key_management.KmsVaultClient, "Vault", region=self.region)

        self._vault_cache: Dict[str, Dict[str, Any]] = {}
        self._mgmt_by_endpoint: Dict[str, Any] = {}
        self._vault_id_by_key_id: Dict[str, str] = {}
        self._endpoint_by_key_id: Dict[str, str] = {}

    @staticmethod
    def _to_dict_list(data: Any) -> List[Dict[str, Any]]:
        if not data:
            return []
        try:
            value = oci.util.to_dict(data)
            return value if isinstance(value, list) else (value or [])
        except Exception:
            out: List[Dict[str, Any]] = []
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        out.append(entry)
                    else:
                        try:
                            out.append(oci.util.to_dict(entry))
                        except Exception:
                            pass
            return out

    def seed_vault_endpoint(self, *, vault_id: str, management_endpoint: str) -> None:
        if vault_id and management_endpoint:
            self._vault_cache.setdefault(vault_id, {})["management_endpoint"] = management_endpoint

    def _mgmt_client_for_vault_id(self, vault_id: str):
        cache = self._vault_cache.get(vault_id) or {}
        endpoint = cache.get("management_endpoint")
        if not endpoint:
            raise ValueError("Vault missing management_endpoint in cache")

        client = self._mgmt_by_endpoint.get(endpoint)
        if client:
            return client

        client = build_vault_client(
            self.session,
            oci.key_management.KmsManagementClient,
            "KmsManagement",
            region=self.region,
            endpoint=endpoint,
        )
        self._mgmt_by_endpoint[endpoint] = client
        return client

    # Resolve vault IDs from CLI/manual values or cached vault table.
    def resolve_vault_ids(self, *, vault_ids: List[str], vault_endpoint: Optional[str] = None) -> List[str]:
        ids = dedupe_strs([v for v in (vault_ids or []) if isinstance(v, str) and v])
        if ids:
            if vault_endpoint:
                for vid in ids:
                    self.seed_vault_endpoint(vault_id=vid, management_endpoint=vault_endpoint)
            return ids

        compartment_id = getattr(self.session, "compartment_id", None)
        rows = self.session.get_resource_fields(self.TABLE_VAULTS, where_conditions={"compartment_id": compartment_id}) or []
        for row in rows:
            if not isinstance(row, dict):
                continue
            vid = row.get("id")
            if not vid:
                continue
            ids.append(vid)
            endpoint = vault_endpoint or row.get("management_endpoint")
            if endpoint:
                self.seed_vault_endpoint(vault_id=vid, management_endpoint=endpoint)

        return dedupe_strs(ids)

    # List keys for one or more vault IDs.
    def list(self, *, vault_ids: List[str]) -> List[Dict[str, Any]]:
        if not self.compartment_id:
            raise ValueError("No compartment_id/tenancy_id available")

        out: List[Dict[str, Any]] = []
        paginator = oci.pagination.list_call_get_all_results

        for vid in vault_ids:
            try:
                mgmt = self._mgmt_client_for_vault_id(vid)
                resp = paginator(mgmt.list_keys, compartment_id=self.compartment_id)
                rows = self._to_dict_list(resp.data)

                endpoint = (self._vault_cache.get(vid) or {}).get("management_endpoint")
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    kid = row.get("id")
                    if isinstance(kid, str) and kid:
                        self._vault_id_by_key_id[kid] = vid
                        if isinstance(endpoint, str) and endpoint:
                            self._endpoint_by_key_id[kid] = endpoint
                    row.setdefault("vault_id", vid)
                    out.append(row)
            except Exception as e:
                UtilityTools.dlog(self.debug, "list_keys failed", vault_id=vid, err=f"{type(e).__name__}: {e}")

        return out

    # Best-effort get key row by ID from cached listing.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        rows = self.session.get_resource_fields(self.TABLE_KEYS, where_conditions={"id": resource_id}) or []
        for row in rows:
            if isinstance(row, dict):
                return row
        return {}

    # List versions for one or more keys.
    def list_versions(self, *, key_ids: List[str], vault_id_by_key_id: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        paginator = oci.pagination.list_call_get_all_results

        for kid in key_ids:
            vid = (vault_id_by_key_id or {}).get(kid) or self._vault_id_by_key_id.get(kid) or ""
            if not vid:
                UtilityTools.dlog(self.debug, "missing key->vault mapping; skipping key versions", key_id=kid)
                continue

            try:
                endpoint = self._endpoint_by_key_id.get(kid)
                if endpoint:
                    mgmt = self._mgmt_by_endpoint.get(endpoint)
                    if not mgmt:
                        mgmt = build_vault_client(
                            self.session,
                            oci.key_management.KmsManagementClient,
                            "KmsManagement",
                            region=self.region,
                            endpoint=endpoint,
                        )
                        self._mgmt_by_endpoint[endpoint] = mgmt
                else:
                    mgmt = self._mgmt_client_for_vault_id(vid)

                resp = paginator(mgmt.list_key_versions, key_id=kid)
                rows = self._to_dict_list(resp.data)
                for kv in rows:
                    if isinstance(kv, dict):
                        kv.setdefault("key_id", kid)
                        kv.setdefault("vault_id", vid)
                        out.append(kv)
            except Exception as e:
                UtilityTools.dlog(self.debug, "list_key_versions failed", key_id=kid, vault_id=vid, err=f"{type(e).__name__}: {e}")

        return out

    # Save key rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_KEYS)

    # Save key-version rows.
    def save_versions(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_KEY_VERSIONS)

    # Save minimal vault rows for manual vault-id flows.
    def save_manual_vaults(self, *, vault_ids: List[str], vault_endpoint: Optional[str]) -> None:
        rows: List[Dict[str, Any]] = []
        for vault_id in dedupe_strs(vault_ids):
            row = {"id": vault_id}
            if vault_endpoint:
                row["management_endpoint"] = vault_endpoint
            rows.append(row)
        if rows:
            self.session.save_resources(rows, self.TABLE_VAULTS)

    # Save minimal key rows for manual key-id flows.
    def save_manual_keys(self, *, key_ids: List[str], fallback_vault_id: Optional[str]) -> None:
        rows: List[Dict[str, Any]] = []
        for key_id in dedupe_strs(key_ids):
            row = {"id": key_id}
            if fallback_vault_id:
                row["vault_id"] = fallback_vault_id
            rows.append(row)
        if rows:
            self.session.save_resources(rows, self.TABLE_KEYS)

    # No binary download endpoint for key rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class VaultSecretsResource:
    COLUMNS = ["id", "secret_name", "lifecycle_state", "current_version_number", "rotation_status"]
    VERSION_COLUMNS = ["secret_id", "version_number", "stages", "name"]
    DUMP_COLUMNS = ["secret_id", "secret_name", "version_number", "file_path", "mode", "vault_id"]
    TABLE_SECRETS = "vault_secret"
    TABLE_SECRET_VERSIONS = "vault_secret_versions"
    TABLE_SECRET_BUNDLES = "vault_secret_bundle"
    VAULT_TABLE_NAME = "vault_vaults"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.region = region or getattr(session, "region", None)
        self.compartment_id = (
            getattr(session, "compartment_id", None)
            or getattr(session, "tenancy_id", None)
            or getattr(session, "tenant_id", None)
        )
        self.debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

        self.vaults_client = build_vault_client(session, oci.vault.VaultsClient, "Vault", region=self.region)
        self.secrets_client = build_vault_client(session, oci.secrets.SecretsClient, "Secrets", region=self.region)

        self._secret_id_to_vault_id: Dict[str, str] = {}
        self._secret_id_to_name: Dict[str, str] = {}

    @staticmethod
    def _to_dict_list(data: Any) -> List[Dict[str, Any]]:
        if not data:
            return []
        try:
            value = oci.util.to_dict(data)
            return value if isinstance(value, list) else (value or [])
        except Exception:
            out: List[Dict[str, Any]] = []
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        out.append(entry)
                    else:
                        try:
                            out.append(oci.util.to_dict(entry))
                        except Exception:
                            pass
            return out

    @staticmethod
    def _sanitize_filename(value: str, max_len: int = 120) -> str:
        safe = value or "unknown"
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", safe)
        return safe[:max_len].strip("_") or "unknown"

    @staticmethod
    def _secret_bundle_content_bytes(bundle_obj: Any) -> Optional[bytes]:
        try:
            bundle_dict = oci.util.to_dict(bundle_obj) if bundle_obj else {}
        except Exception:
            bundle_dict = {}
        secret_bundle_content = bundle_dict.get("secret_bundle_content") or {}
        content_b64 = secret_bundle_content.get("content")
        if not content_b64:
            return None
        try:
            return base64.b64decode(content_b64)
        except Exception:
            return str(content_b64).encode("utf-8", errors="ignore")

    @staticmethod
    def _normalize_secret_name(s: Dict[str, Any]) -> Optional[str]:
        for k in ("secret_name", "secretName", "name", "display_name", "displayName"):
            v = s.get(k)
            if isinstance(v, str) and v:
                return v
        return None

    @staticmethod
    def _normalize_version_number(v: Dict[str, Any]) -> Optional[int]:
        for k in ("version_number", "versionNumber", "secret_version_number", "secretVersionNumber"):
            x = v.get(k)
            if x is None:
                continue
            try:
                return int(x)
            except Exception:
                return None
        return None

    @staticmethod
    def display_path(path_value: Any) -> str:
        raw = str(path_value or "").strip()
        if not raw:
            return raw
        try:
            p = Path(raw).expanduser()
            if not p.is_absolute():
                return raw
            rel = p.resolve().relative_to(Path.cwd().resolve())
            return f"./{rel.as_posix()}"
        except Exception:
            return raw

    @staticmethod
    def _parse_version_range_spec(spec: str) -> List[int]:
        text = str(spec or "").strip()
        if not text:
            return []
        out: List[int] = []
        for part in text.split(","):
            token = part.strip()
            if not token:
                continue
            if "-" in token:
                bits = token.split("-", 1)
                if len(bits) != 2 or not bits[0].strip().isdigit() or not bits[1].strip().isdigit():
                    raise ValueError(f"Invalid version range token '{token}'. Use e.g. 1-5")
                start = int(bits[0].strip())
                end = int(bits[1].strip())
                if start <= 0 or end <= 0:
                    raise ValueError("Version numbers must be positive integers")
                if end < start:
                    start, end = end, start
                out.extend(range(start, end + 1))
            else:
                if not token.isdigit():
                    raise ValueError(f"Invalid version token '{token}'. Use integers or ranges.")
                v = int(token)
                if v <= 0:
                    raise ValueError("Version numbers must be positive integers")
                out.append(v)
        seen: set[int] = set()
        uniq: List[int] = []
        for v in out:
            if v not in seen:
                seen.add(v)
                uniq.append(v)
        return uniq

    def _resolve_vault_id_for_secret(self, secret_id: str, fallback_vault_id: Optional[str] = None) -> Optional[str]:
        sid = (secret_id or "").strip()
        if not sid:
            return fallback_vault_id

        cached = self._secret_id_to_vault_id.get(sid)
        if cached:
            return cached

        rows = self.session.get_resource_fields(self.TABLE_SECRETS, where_conditions={"id": sid}) or []
        for row in rows:
            if not isinstance(row, dict):
                continue
            vid = row.get("vault_id")
            if isinstance(vid, str) and vid:
                self._secret_id_to_vault_id[sid] = vid
                return vid

        return fallback_vault_id

    def _download_output_path(
        self,
        *,
        dump_dir: Path,
        vault_id: Optional[str],
        secret_id: Optional[str],
        secret_name: str,
        version_label: Any,
    ) -> Path:
        vid = str(vault_id or "unknown_vault")
        secret_name_clean = self._sanitize_filename(secret_name)
        if secret_id and secret_name_clean:
            bundle_source = f"{secret_id}__{secret_name_clean}"
        else:
            bundle_source = str(secret_id or secret_name_clean)
        bundle_id = self._sanitize_filename(f"{bundle_source}__v{version_label}", max_len=180)
        fname = f"{bundle_id}_values.txt"

        try:
            return self.session.get_download_save_path(
                service_name="vault",
                filename=fname,
                compartment_id=vid,
                resource_name=secret_name,
                subdirs=["secrets"],
            )
        except Exception:
            fpath = dump_dir / vid / "secrets" / fname
            fpath.parent.mkdir(parents=True, exist_ok=True)
            return fpath

    # Resolve vault IDs from CLI or cached vault table.
    def resolve_vault_ids(self, *, vault_ids: List[str]) -> List[str]:
        ids = dedupe_strs([v for v in (vault_ids or []) if isinstance(v, str) and v])
        if ids:
            return ids
        rows = self.session.get_resource_fields(self.VAULT_TABLE_NAME) or []
        return dedupe_strs([r.get("id") for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str) and r.get("id")])

    # List secrets for one or more vault IDs.
    def list(self, *, vault_ids: List[str]) -> List[Dict[str, Any]]:
        cid = self.compartment_id
        if not cid:
            raise ValueError("No compartment_id/tenancy_id available for secrets")
        if not vault_ids:
            raise ValueError("list_secrets requires at least one vault_id")

        out: List[Dict[str, Any]] = []
        paginator = oci.pagination.list_call_get_all_results

        for vid in vault_ids:
            try:
                resp = paginator(self.vaults_client.list_secrets, compartment_id=cid, vault_id=vid)
                rows = self._to_dict_list(resp.data)

                for s in rows:
                    if not isinstance(s, dict):
                        continue
                    sid = s.get("id")
                    name = self._normalize_secret_name(s)
                    if isinstance(sid, str) and sid:
                        self._secret_id_to_vault_id[sid] = vid
                        if isinstance(name, str) and name:
                            self._secret_id_to_name[sid] = name
                    s.setdefault("vault_id", vid)
                    if "secret_name" not in s and isinstance(name, str):
                        s["secret_name"] = name
                    out.append(s)
            except Exception as e:
                UtilityTools.dlog(self.debug, "list_secrets failed", vault_id=vid, err=f"{type(e).__name__}: {e}")

        return out

    # Get one secret version metadata by secret ID + version number.
    def get(self, *, resource_id: str, version_number: Optional[int] = None) -> Dict[str, Any]:
        if version_number is None:
            return {}
        try:
            resp = self.vaults_client.get_secret_version(secret_id=resource_id, secret_version_number=int(version_number))
            return oci.util.to_dict(resp.data) if resp and resp.data else {}
        except Exception:
            return {}

    # List secret versions for selected secret IDs.
    def list_versions(
        self,
        *,
        secret_ids: List[str],
        max_versions_per_secret: int = 500,
        do_get_requests: bool = False,
    ) -> List[Dict[str, Any]]:
        if not secret_ids:
            return []

        out: List[Dict[str, Any]] = []
        paginator = oci.pagination.list_call_get_all_results

        for sid in secret_ids:
            try:
                resp = paginator(self.vaults_client.list_secret_versions, secret_id=sid)
                rows = self._to_dict_list(list(resp.data or [])[:max_versions_per_secret])

                if do_get_requests:
                    enriched: List[Dict[str, Any]] = []
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        vn = self._normalize_version_number(row)
                        if vn is None:
                            continue
                        fetched = self.get(resource_id=sid, version_number=vn)
                        enriched.append(fetched if fetched else row)
                    rows = enriched

                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    vn = self._normalize_version_number(row)
                    if vn is None:
                        continue
                    out.append(
                        {
                            "secret_id": sid,
                            "version_number": int(vn),
                            "name": row.get("name") or row.get("display_name"),
                            "stages": row.get("stages") if row.get("stages") is not None else row.get("stage"),
                            "time_created": row.get("time_created"),
                            "time_of_deletion": row.get("time_of_deletion"),
                            "time_of_current_version_expiry": (
                                row.get("time_of_current_version_expiry")
                                or row.get("timeOfCurrentVersionExpiry")
                                or row.get("time_of_expiry")
                                or row.get("timeOfExpiry")
                            ),
                            "content_type": row.get("content_type"),
                            "is_content_auto_generated": row.get("is_content_auto_generated"),
                        }
                    )
            except Exception as e:
                UtilityTools.dlog(self.debug, "list_secret_versions failed", secret_id=sid, err=f"{type(e).__name__}: {e}")

        return out

    @staticmethod
    def _bytes_to_text(raw: Optional[bytes]) -> Optional[str]:
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except Exception:
            return base64.b64encode(raw).decode("ascii")

    # Save secret rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources([s for s in (rows or []) if isinstance(s, dict)], self.TABLE_SECRETS)

    # Save secret-version rows.
    def save_versions(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources([v for v in (rows or []) if isinstance(v, dict)], self.TABLE_SECRET_VERSIONS)

    # Save non-sensitive bundle metadata rows for graph enrichment.
    def save_bundle_metadata(self, *, secrets: List[Dict[str, Any]], secret_versions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        by_key: Dict[Tuple[str, int], Dict[str, Any]] = {}
        secret_name_by_id: Dict[str, str] = {}

        for s in (secrets or []):
            if not isinstance(s, dict):
                continue
            sid = str(s.get("id") or s.get("secret_id") or "").strip()
            if not sid:
                continue
            sname = s.get("secret_name") or self._secret_id_to_name.get(sid)
            if isinstance(sname, str) and sname.strip():
                secret_name_by_id[sid] = sname.strip()

        for sv in (secret_versions or []):
            if not isinstance(sv, dict):
                continue
            sid = str(sv.get("secret_id") or "").strip()
            try:
                vn = int(sv.get("version_number"))
            except Exception:
                continue
            if not sid:
                continue
            by_key[(sid, vn)] = {
                "secret_id": sid,
                "version_number": vn,
                "version_name": sv.get("name") or f"{secret_name_by_id.get(sid, sid)}:v{vn}",
                "stages": sv.get("stages"),
                "metadata": sv.get("metadata"),
                "secret_bundle_content": None,
            }

        rows = list(by_key.values())
        if rows:
            self.session.save_resources(rows, self.TABLE_SECRET_BUNDLES)
        return rows

    def _get_secret_bundle_by_id(
        self,
        *,
        secret_id: str,
        stage: Optional[str] = None,
        secret_version_name: Optional[str] = None,
        version_number: Optional[int] = None,
    ) -> Any:
        kwargs: Dict[str, Any] = {}
        if stage:
            kwargs["stage"] = stage
        if secret_version_name:
            kwargs["secret_version_name"] = secret_version_name
        if version_number is not None:
            kwargs["version_number"] = int(version_number)
        return self.secrets_client.get_secret_bundle(secret_id=secret_id, **kwargs).data

    def _get_secret_bundle_by_name(
        self,
        *,
        secret_name: str,
        vault_id: str,
        stage: Optional[str] = None,
        secret_version_name: Optional[str] = None,
        version_number: Optional[int] = None,
    ) -> Any:
        kwargs: Dict[str, Any] = {}
        if stage:
            kwargs["stage"] = stage
        if secret_version_name:
            kwargs["secret_version_name"] = secret_version_name
        if version_number is not None:
            kwargs["version_number"] = int(version_number)
        return self.secrets_client.get_secret_bundle_by_name(secret_name=secret_name, vault_id=vault_id, **kwargs).data

    # Dump secret bundle values to disk.
    def dump(
        self,
        *,
        dump_dir: Path,
        secrets: Optional[List[Dict[str, Any]]] = None,
        secret_ids: Optional[List[str]] = None,
        secret_name: Optional[str] = None,
        vault_id_for_name: Optional[str] = None,
        stage: Optional[str] = None,
        secret_version_name: Optional[str] = None,
        version_number: Optional[int] = None,
        version_range_spec: Optional[str] = None,
        expand_versions: bool = False,
    ) -> List[Dict[str, Any]]:
        dump_dir.mkdir(parents=True, exist_ok=True)
        out_meta: List[Dict[str, Any]] = []

        selected_range_versions = self._parse_version_range_spec(version_range_spec or "") if version_range_spec else []

        if secret_name:
            if not vault_id_for_name:
                raise ValueError("dump by name requires vault_id_for_name")
            bundle = self._get_secret_bundle_by_name(
                secret_name=secret_name,
                vault_id=vault_id_for_name,
                stage=stage,
                secret_version_name=secret_version_name,
                version_number=version_number,
            )
            raw = self._secret_bundle_content_bytes(bundle)
            if raw is None:
                return []

            bdict = oci.util.to_dict(bundle) if bundle else {}
            ver_label = (
                bdict.get("version_number")
                or bdict.get("versionNumber")
                or bdict.get("version_name")
                or bdict.get("versionName")
                or "CURRENT"
            )
            sid = bdict.get("secret_id")
            fpath = self._download_output_path(
                dump_dir=dump_dir,
                vault_id=vault_id_for_name,
                secret_id=str(sid) if sid else None,
                secret_name=secret_name,
                version_label=ver_label,
            )
            try:
                fpath.write_text(raw.decode("utf-8"), encoding="utf-8", errors="ignore")
            except Exception:
                fpath.write_bytes(raw)

            out_meta.append(
                {
                    "secret_id": sid,
                    "secret_name": secret_name,
                    "version_number": ver_label,
                    "version_name": bdict.get("version_name") or bdict.get("versionName"),
                    "stages": bdict.get("stages"),
                    "metadata": bdict.get("metadata"),
                    "secret_bundle_content": self._bytes_to_text(raw),
                    "file_path": str(fpath),
                    "mode": "by_name",
                    "vault_id": vault_id_for_name,
                }
            )
            return out_meta

        targets_by_id: Dict[str, str] = {}
        for s in (secrets or []):
            if isinstance(s, dict) and s.get("id"):
                sid = str(s["id"])
                sname = str(s.get("secret_name") or self._secret_id_to_name.get(sid) or sid)
                targets_by_id[sid] = sname
        for sid in (secret_ids or []):
            if sid:
                sid2 = str(sid)
                targets_by_id.setdefault(sid2, str(self._secret_id_to_name.get(sid2) or sid2))

        targets: List[Tuple[str, str]] = list(targets_by_id.items())
        if not targets:
            return []

        for sid, sname in targets:
            sid_vault_id = self._resolve_vault_id_for_secret(sid)

            # single selector fetch
            if stage or secret_version_name or (version_number is not None):
                bundle = self._get_secret_bundle_by_id(
                    secret_id=sid,
                    stage=stage,
                    secret_version_name=secret_version_name,
                    version_number=version_number,
                )
                raw = self._secret_bundle_content_bytes(bundle)
                if raw is None:
                    continue
                ver_label = version_number if version_number is not None else (secret_version_name or stage or "CURRENT")
                fpath = self._download_output_path(
                    dump_dir=dump_dir,
                    vault_id=sid_vault_id,
                    secret_id=sid,
                    secret_name=sname,
                    version_label=ver_label,
                )
                try:
                    fpath.write_text(raw.decode("utf-8"), encoding="utf-8", errors="ignore")
                except Exception:
                    fpath.write_bytes(raw)

                bdict = oci.util.to_dict(bundle) if bundle else {}
                out_meta.append(
                    {
                        "secret_id": sid,
                        "secret_name": sname,
                        "version_number": ver_label,
                        "version_name": bdict.get("version_name") or bdict.get("versionName"),
                        "stages": bdict.get("stages"),
                        "metadata": bdict.get("metadata"),
                        "secret_bundle_content": self._bytes_to_text(raw),
                        "file_path": str(fpath),
                        "mode": "by_id_direct",
                        "vault_id": sid_vault_id,
                    }
                )
                continue

            if selected_range_versions:
                version_numbers = list(selected_range_versions)
            elif expand_versions:
                version_rows = self.list_versions(secret_ids=[sid], do_get_requests=False)
                version_numbers = []
                for row in version_rows:
                    if isinstance(row, dict):
                        try:
                            version_numbers.append(int(row["version_number"]))
                        except Exception:
                            pass
                seen = set()
                version_numbers = [v for v in version_numbers if not (v in seen or seen.add(v))]
            else:
                version_numbers = []

            if not version_numbers:
                bundle = self._get_secret_bundle_by_id(secret_id=sid)
                raw = self._secret_bundle_content_bytes(bundle)
                if raw is None:
                    continue
                fpath = self._download_output_path(
                    dump_dir=dump_dir,
                    vault_id=sid_vault_id,
                    secret_id=sid,
                    secret_name=sname,
                    version_label="CURRENT",
                )
                try:
                    fpath.write_text(raw.decode("utf-8"), encoding="utf-8", errors="ignore")
                except Exception:
                    fpath.write_bytes(raw)

                bdict = oci.util.to_dict(bundle) if bundle else {}
                out_meta.append(
                    {
                        "secret_id": sid,
                        "secret_name": sname,
                        "version_number": "CURRENT",
                        "version_name": bdict.get("version_name") or bdict.get("versionName"),
                        "stages": bdict.get("stages"),
                        "metadata": bdict.get("metadata"),
                        "secret_bundle_content": self._bytes_to_text(raw),
                        "file_path": str(fpath),
                        "mode": "by_id_current",
                        "vault_id": sid_vault_id,
                    }
                )
                continue

            for vn in version_numbers:
                try:
                    bundle = self._get_secret_bundle_by_id(secret_id=sid, version_number=int(vn))
                except Exception as e:
                    UtilityTools.dlog(self.debug, "get_secret_bundle failed", secret_id=sid, version=vn, err=f"{type(e).__name__}: {e}")
                    continue

                raw = self._secret_bundle_content_bytes(bundle)
                if raw is None:
                    continue
                fpath = self._download_output_path(
                    dump_dir=dump_dir,
                    vault_id=sid_vault_id,
                    secret_id=sid,
                    secret_name=sname,
                    version_label=vn,
                )
                try:
                    fpath.write_text(raw.decode("utf-8"), encoding="utf-8", errors="ignore")
                except Exception:
                    fpath.write_bytes(raw)

                bdict = oci.util.to_dict(bundle) if bundle else {}
                out_meta.append(
                    {
                        "secret_id": sid,
                        "secret_name": sname,
                        "version_number": int(vn),
                        "version_name": bdict.get("version_name") or bdict.get("versionName"),
                        "stages": bdict.get("stages"),
                        "metadata": bdict.get("metadata"),
                        "secret_bundle_content": self._bytes_to_text(raw),
                        "file_path": str(fpath),
                        "mode": "by_id_versions" if expand_versions else "by_id_range",
                        "vault_id": sid_vault_id,
                    }
                )

        return out_meta

    # Save dumped bundle artifact rows.
    def save_dump_artifacts(self, rows: List[Dict[str, Any]]) -> None:
        out: List[Dict[str, Any]] = []
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            sid = row.get("secret_id")
            vn = row.get("version_number")
            if not sid or vn in (None, ""):
                continue
            out.append(
                {
                    "secret_id": sid,
                    "version_number": vn,
                    "version_name": row.get("version_name") or f"{row.get('secret_name') or sid}:v{vn}",
                    "stages": row.get("stages"),
                    "metadata": row.get("metadata"),
                    "secret_bundle_content": row.get("secret_bundle_content"),
                }
            )
        if out:
            self.session.save_resources(out, self.TABLE_SECRET_BUNDLES)

    # No binary download endpoint for secret rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False
