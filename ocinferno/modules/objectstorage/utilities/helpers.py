from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import oci

from ocinferno.core.coerce import uniq_strs
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import parse_iso_datetime, safe_int, write_response_stream_to_file
from ocinferno.core.utils.selection_helpers import _s
from ocinferno.core.utils.service_runtime import ResourceBase, _init_client


def normalize_sse_c_key(sse_c_key_b64: Union[str, bytes, Path]) -> tuple:
    """Resolve/validate an SSE-C key argument (file path, bytes, or base64 str).

    Accepts the raw ``--sse-c-key-b64`` CLI value -- possibly a path to a file
    containing the key -- and returns ``(key_b64_str, key_sha256_b64_str)``.
    Raises ``ValueError``/``binascii.Error`` if the value isn't valid base64 or
    doesn't decode to exactly 32 bytes (AES-256). Cheap and idempotent, so it's
    safe to call once up-front to validate before a download loop AND again
    per-object inside ``download()``.
    """
    if isinstance(sse_c_key_b64, (str, Path)) and Path(str(sse_c_key_b64)).exists():
        sse_c_key_b64 = Path(str(sse_c_key_b64)).read_text().strip()

    if isinstance(sse_c_key_b64, (bytes, bytearray)):
        sse_c_key_b64 = sse_c_key_b64.decode("ascii")

    key_raw = base64.b64decode(sse_c_key_b64)
    if len(key_raw) != 32:
        raise ValueError("sse_c_key_b64 must decode to exactly 32 bytes (AES-256).")

    sha_b64 = base64.b64encode(hashlib.sha256(key_raw).digest()).decode("ascii")
    return sse_c_key_b64, sha_b64


def build_object_storage_client(session, region: Optional[str] = None):
    """Initialize an Object Storage client with shared signer/proxy/session behavior."""
    client = _init_client(oci.object_storage.ObjectStorageClient, session=session, service_name="ObjectStorage")
    target_region = region or getattr(session, "config_current_default_region", None) or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class ObjectStorageNamespacesResource(ResourceBase):
    TABLE_NAME = "object_storage_namespaces"
    COLUMNS = ["compartment_id", "namespace"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_object_storage_client(session=session, region=region)

    @classmethod
    def resolve_namespace_scope_compartment_id(
        cls,
        session,
        *,
        explicit_compartment_id: Optional[str] = None,
    ) -> Optional[str]:
        # Always scope namespace calls to compartment context when possible.
        explicit = _s(explicit_compartment_id)
        if explicit:
            return explicit

        current = _s(getattr(session, "compartment_id", None))
        if current:
            return current

        tenant_id = _s(getattr(session, "tenant_id", None))
        if tenant_id:
            return tenant_id

        return None

    @classmethod
    def _caller_tenancy_from_session_credentials(
        cls,
        session,
    ) -> str:
        creds = getattr(session, "credentials", None)
        if not isinstance(creds, dict):
            return ""
        cfg = creds.get("config")
        if not isinstance(cfg, dict):
            cfg = {}
        for candidate in (
            cfg.get("tenancy"),
            cfg.get("tenancy_id"),
            creds.get("tenancy"),
            creds.get("tenancy_id"),
        ):
            tid = _s(candidate)
            if tid.startswith("ocid1.tenancy."):
                return tid
        return ""

    @classmethod
    def _resolve_compartment_tenancy_from_session(
        cls,
        session,
        *,
        compartment_id: Optional[str],
    ) -> str:
        cid = _s(compartment_id)
        if not cid:
            return ""
        if cid.startswith("ocid1.tenancy."):
            return cid

        rows = getattr(session, "global_compartment_list", None) or []
        parent_by_id: Dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            row_cid = _s(row.get("compartment_id"))
            if not row_cid:
                continue
            parent_by_id[row_cid] = _s(row.get("parent_compartment_id"))

        if not parent_by_id:
            return ""

        seen: Set[str] = set()
        cur = cid
        for _ in range(128):
            if cur in seen:
                break
            seen.add(cur)
            if cur.startswith("ocid1.tenancy."):
                return cur
            parent = parent_by_id.get(cur, "")
            if not parent or parent.upper() == "N/A":
                break
            if parent.startswith("ocid1.tenancy."):
                return parent
            cur = parent

        return ""

    @classmethod
    def fetch_live_namespace(
        cls,
        *,
        client,
        session,
        explicit_compartment_id: Optional[str] = None,
    ) -> str:
        scope_compartment_id = cls.resolve_namespace_scope_compartment_id(
            session,
            explicit_compartment_id=explicit_compartment_id,
        )
        tenant_id = _s(getattr(session, "tenant_id", None))
        current_cid = _s(getattr(session, "compartment_id", None))
        if not scope_compartment_id:
            raise RuntimeError(
                "Object Storage get_namespace requires compartment-scoped resolution, but no compartment_id was available. "
                f"session.tenant_id={tenant_id or '<unset>'}, session.compartment_id={current_cid or '<unset>'}, "
                f"explicit_compartment_id={_s(explicit_compartment_id) or '<unset>'}"
            )

        caller_tenant_id = cls._caller_tenancy_from_session_credentials(session)
        scope_tenant_id = cls._resolve_compartment_tenancy_from_session(
            session,
            compartment_id=scope_compartment_id,
        )
        can_try_unscoped_first = bool(
            caller_tenant_id
            and scope_tenant_id
            and caller_tenant_id == scope_tenant_id
        )
        unscoped_error: Optional[oci.exceptions.ServiceError] = None
        if can_try_unscoped_first:
            try:
                resp = client.get_namespace()
                return str(resp.data or "").strip()
            except oci.exceptions.ServiceError as exc:
                unscoped_error = exc

        try:
            resp = client.get_namespace(compartment_id=scope_compartment_id)
            return str(resp.data or "").strip()
        except oci.exceptions.ServiceError as exc:
            status = getattr(exc, "status", "unknown")
            code = getattr(exc, "code", "unknown")
            raw_msg = _s(getattr(exc, "message", "")) or str(exc)
            if unscoped_error is not None:
                us_status = getattr(unscoped_error, "status", "unknown")
                us_code = getattr(unscoped_error, "code", "unknown")
                us_msg = _s(getattr(unscoped_error, "message", "")) or str(unscoped_error)
                raise RuntimeError(
                    "Object Storage get_namespace failed for both unscoped and scoped calls. "
                    f"session.tenant_id={tenant_id or '<unset>'}, "
                    f"session.compartment_id={current_cid or '<unset>'}, "
                    f"request.compartment_id={scope_compartment_id}. "
                    f"caller_tenant_id={caller_tenant_id or '<unset>'}. "
                    f"scope_tenant_id={scope_tenant_id or '<unset>'}. "
                    f"unscoped_error: status={us_status}, code={us_code}, message={us_msg}; "
                    f"scoped_error: status={status}, code={code}, message={raw_msg}"
                ) from exc
            raise RuntimeError(
                "Object Storage get_namespace failed with compartment-scoped call. "
                f"session.tenant_id={tenant_id or '<unset>'}, "
                f"session.compartment_id={current_cid or '<unset>'}, "
                f"request.compartment_id={scope_compartment_id}. "
                f"caller_tenant_id={caller_tenant_id or '<unset>'}. "
                f"scope_tenant_id={scope_tenant_id or '<unset>'}. "
                f"SDK error: status={status}, code={code}, message={raw_msg}"
            ) from exc

    @classmethod
    def get_namespaces_from_db(cls, session, *, table_name: str = "object_storage_namespaces") -> List[str]:
        rows = session.get_resource_fields(table_name) or []
        vals: List[str] = []
        for row in rows:
            if isinstance(row, dict):
                vals.append(row.get("namespace") or "")
        return uniq_strs(vals)

    # List namespace for current compartment/tenancy.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        ns = self.fetch_live_namespace(
            client=self.client,
            session=self.session,
            explicit_compartment_id=compartment_id,
        )
        if not ns:
            return []
        return [{"compartment_id": compartment_id, "namespace": ns}]

    # Get namespace metadata.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_namespace_metadata(namespace_name=resource_id)
        out = oci.util.to_dict(resp.data) or {}
        if isinstance(out, dict):
            out.setdefault("namespace", resource_id)
        return out

    # Save namespace rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources([r for r in (rows or []) if isinstance(r, dict)], self.TABLE_NAME)

    # No binary download endpoint for namespace rows.

class ObjectStorageBucketsResource(ResourceBase):
    TABLE_NAME = "object_storage_buckets"
    COLUMNS = ["namespace", "name", "id", "public_access_type", "storage_tier", "kms_key_id", "approximate_count"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_object_storage_client(session=session, region=region)

    # Resolve namespace scope from CLI args, DB cache, or live namespace lookup.
    def resolve_namespaces(self, *, namespace_args: List[str]) -> List[str]:
        namespaces: List[str] = []
        for token in namespace_args or []:
            parts = [p.strip() for p in str(token).split(",") if p.strip()]
            namespaces.extend(parts)
        if namespaces:
            return uniq_strs(namespaces)

        db_namespaces = ObjectStorageNamespacesResource.get_namespaces_from_db(self.session)
        if db_namespaces:
            return db_namespaces

        comp_id = getattr(self.session, "compartment_id", None)
        if not comp_id:
            return []
        live = ObjectStorageNamespacesResource.fetch_live_namespace(
            client=self.client,
            session=self.session,
            explicit_compartment_id=comp_id,
        )
        return [live] if live else []

    # List buckets for provided namespaces.
    def list(self, *, compartment_id: str, namespaces: List[str]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for namespace in uniq_strs(namespaces):
            try:
                resp = oci.pagination.list_call_get_all_results(
                    self.client.list_buckets,
                    namespace_name=namespace,
                    compartment_id=compartment_id,
                )
            except oci.exceptions.ServiceError as err:
                UtilityTools.dlog(
                    True,
                    "list_buckets failed",
                    namespace=namespace,
                    compartment_id=compartment_id,
                    status=getattr(err, "status", None),
                    code=getattr(err, "code", None),
                    msg=getattr(err, "message", str(err)),
                )
                continue
            except Exception as err:
                UtilityTools.dlog(
                    True,
                    "list_buckets failed",
                    namespace=namespace,
                    compartment_id=compartment_id,
                    err=f"{type(err).__name__}: {err}",
                )
                continue
            chunk = oci.util.to_dict(resp.data) or []
            chunk = chunk if isinstance(chunk, list) else [chunk]
            for row in chunk:
                if not isinstance(row, dict):
                    continue
                row.setdefault("namespace", namespace)
                row.setdefault("compartment_id", compartment_id)
                rows.append(row)
        return rows

    # Get one bucket by name+namespace.
    def get(self, *, resource_id: str, namespace: str) -> Dict[str, Any]:
        resp = self.client.get_bucket(namespace_name=namespace, bucket_name=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save bucket rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources([r for r in (rows or []) if isinstance(r, dict)], self.TABLE_NAME)

    # No binary download endpoint for bucket rows.

class ObjectStorageObjectsResource:
    TABLE_NAME = "object_storage_bucket_objects"
    COLUMNS = ["region", "bucket_name", "namespace", "name", "size", "md5"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_object_storage_client(session=session, region=region)

    @staticmethod
    def _dt_to_iso(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    @staticmethod
    def _should_keep(
        *,
        name: str,
        size_bytes: Optional[int],
        time_created_iso: Optional[str],
        prefix: str,
        name_regex: Optional[re.Pattern[str]],
        min_bytes: int,
        max_bytes: int,
        newer_than: Optional[datetime],
        older_than: Optional[datetime],
    ) -> bool:
        if prefix and not name.startswith(prefix):
            return False
        if name_regex and not name_regex.search(name):
            return False
        if min_bytes and (size_bytes is None or size_bytes < min_bytes):
            return False
        if max_bytes and (size_bytes is None or size_bytes > max_bytes):
            return False

        if (newer_than or older_than) and time_created_iso:
            try:
                dt = parse_iso_datetime(time_created_iso)
            except Exception:
                dt = None
            if dt:
                if newer_than and dt < newer_than:
                    return False
                if older_than and dt > older_than:
                    return False

        return True

    @classmethod
    def get_buckets_from_db(
        cls,
        session,
        *,
        table_name: str = "object_storage_buckets",
        namespace: Optional[str] = None,
        compartment_id: Optional[str] = None,
        region: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        where = {}
        if compartment_id:
            where["compartment_id"] = compartment_id
        if region:
            where["region"] = region
        rows = session.get_resource_fields(table_name, where_conditions=where or None) or []

        ns = _s(namespace)
        out: List[Dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if ns:
                row_ns = _s(row.get("namespace"))
                if row_ns and row_ns != ns:
                    continue
            out.append(dict(row))
        return out

    # Resolve bucket rows from CLI scopes, DB cache, or live listing.
    def resolve_bucket_rows(self, *, compartment_id: str, namespaces: List[str], buckets: List[str]) -> List[Dict[str, Any]]:
        bucket_names = uniq_strs(buckets)
        namespace_names = uniq_strs(namespaces)

        if bucket_names:
            if not namespace_names:
                raise ValueError("When --buckets is provided, --namespaces is also required.")
            out: List[Dict[str, Any]] = []
            region = (getattr(self.session, "config_current_default_region", "") or getattr(self.session, "region", "") or "").strip()
            for namespace in namespace_names:
                for bucket in bucket_names:
                    out.append(
                        {
                            "namespace": namespace,
                            "name": bucket,
                            "compartment_id": compartment_id,
                            "region": region,
                        }
                    )
            return out

        region = (getattr(self.session, "config_current_default_region", "") or getattr(self.session, "region", "") or "").strip()
        db_rows = self.get_buckets_from_db(
            self.session,
            compartment_id=compartment_id,
            region=region or None,
        )
        if db_rows:
            return db_rows

        if not namespace_names:
            namespace_names = ObjectStorageNamespacesResource.get_namespaces_from_db(self.session)
            if not namespace_names:
                live_ns = ObjectStorageNamespacesResource.fetch_live_namespace(
                    client=self.client,
                    session=self.session,
                    explicit_compartment_id=compartment_id,
                )
                namespace_names = [live_ns] if live_ns else []

        out: List[Dict[str, Any]] = []
        region = (getattr(self.session, "config_current_default_region", "") or getattr(self.session, "region", "") or "").strip()
        for namespace in namespace_names:
            try:
                resp = oci.pagination.list_call_get_all_results(
                    self.client.list_buckets,
                    namespace_name=namespace,
                    compartment_id=compartment_id,
                )
            except oci.exceptions.ServiceError as err:
                UtilityTools.dlog(
                    True,
                    "resolve_bucket_rows:list_buckets failed",
                    namespace=namespace,
                    compartment_id=compartment_id,
                    status=getattr(err, "status", None),
                    code=getattr(err, "code", None),
                    msg=getattr(err, "message", str(err)),
                )
                continue
            except Exception as err:
                UtilityTools.dlog(
                    True,
                    "resolve_bucket_rows:list_buckets failed",
                    namespace=namespace,
                    compartment_id=compartment_id,
                    err=f"{type(err).__name__}: {err}",
                )
                continue
            rows = oci.util.to_dict(resp.data) or []
            rows = rows if isinstance(rows, list) else [rows]
            for row in rows:
                if not isinstance(row, dict):
                    continue
                out.append(
                    {
                        "namespace": namespace,
                        "name": row.get("name"),
                        "compartment_id": row.get("compartment_id") or compartment_id,
                        "region": row.get("region") or region,
                    }
                )
        return out

    # List objects across selected buckets with optional filters.
    def list(
        self,
        *,
        compartment_id: str,
        bucket_rows: List[Dict[str, Any]],
        prefix: str = "",
        name_regex: str = "",
        min_bytes: int = 0,
        max_bytes: int = 0,
        newer_than: str = "",
        older_than: str = "",
        limit_per_bucket: int = 0,
    ) -> List[Dict[str, Any]]:
        regex = re.compile(name_regex) if name_regex else None
        newer = parse_iso_datetime(newer_than) if newer_than else None
        older = parse_iso_datetime(older_than) if older_than else None

        rows: List[Dict[str, Any]] = []

        for bucket_row in bucket_rows:
            namespace = _s(bucket_row.get("namespace"))
            bucket_name = _s(bucket_row.get("name"))
            if not namespace or not bucket_name:
                continue

            region = _s(bucket_row.get("region")) or _s(getattr(self.session, "config_current_default_region", "")) or _s(getattr(self.session, "region", ""))
            region_client = build_object_storage_client(self.session, region=region)

            start = None
            kept = 0
            while True:
                try:
                    resp = region_client.list_objects(
                        namespace_name=namespace,
                        bucket_name=bucket_name,
                        start=start,
                        fields="archivalState,etag,md5,name,size,storageTier,timeCreated,timeModified",
                    )
                except oci.exceptions.ServiceError as err:
                    UtilityTools.dlog(
                        True,
                        "list_objects failed",
                        namespace=namespace,
                        bucket_name=bucket_name,
                        compartment_id=compartment_id,
                        status=getattr(err, "status", None),
                        code=getattr(err, "code", None),
                        msg=getattr(err, "message", str(err)),
                    )
                    break
                except Exception as err:
                    UtilityTools.dlog(
                        True,
                        "list_objects failed",
                        namespace=namespace,
                        bucket_name=bucket_name,
                        compartment_id=compartment_id,
                        err=f"{type(err).__name__}: {err}",
                    )
                    break
                for obj in (resp.data.objects or []):
                    item = oci.util.to_dict(obj) or {}
                    if not isinstance(item, dict):
                        continue

                    obj_name = _s(item.get("name"))
                    if not obj_name:
                        continue

                    size = safe_int(item.get("size"))
                    created_iso = self._dt_to_iso(item.get("time_created"))
                    modified_iso = self._dt_to_iso(item.get("time_modified"))

                    if not self._should_keep(
                        name=obj_name,
                        size_bytes=size,
                        time_created_iso=created_iso,
                        prefix=prefix,
                        name_regex=regex,
                        min_bytes=min_bytes,
                        max_bytes=max_bytes,
                        newer_than=newer,
                        older_than=older,
                    ):
                        continue

                    item["bucket_name"] = bucket_name
                    item["namespace"] = namespace
                    item["region"] = region
                    item["compartment_id"] = bucket_row.get("compartment_id") or compartment_id
                    if created_iso is not None:
                        item["time_created"] = created_iso
                    if modified_iso is not None:
                        item["time_modified"] = modified_iso
                    rows.append(item)

                    kept += 1
                    if limit_per_bucket and kept >= limit_per_bucket:
                        break

                if limit_per_bucket and kept >= limit_per_bucket:
                    break
                start = resp.data.next_start_with
                if not start:
                    break

        return rows

    # Get object metadata headers via HEAD request.
    def get(self, *, namespace: str, bucket_name: str, object_name: str) -> Dict[str, Any]:
        try:
            resp = self.client.head_object(
                namespace_name=namespace,
                bucket_name=bucket_name,
                object_name=object_name,
            )
        except Exception:
            return {}

        headers = {}
        for k, v in dict(getattr(resp, "headers", {}) or {}).items():
            if k is None:
                continue
            headers[str(k)] = v
        return headers

    # Save object rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources([r for r in (rows or []) if isinstance(r, dict)], self.TABLE_NAME)

    # Download one object to disk.
    def download(
        self,
        *,
        namespace: str,
        bucket_name: str,
        object_name: str,
        out_path: Path,
        sse_c_key_b64: Optional[Union[str, bytes, Path]] = None,
        region: str = "",
    ) -> bool:
        client = build_object_storage_client(self.session, region=region or None)

        kwargs = {
            "namespace_name": namespace,
            "bucket_name": bucket_name,
            "object_name": object_name,
        }

        if sse_c_key_b64 is not None:
            try:
                sse_c_key_b64, sha_b64 = normalize_sse_c_key(sse_c_key_b64)
            except Exception as err:
                debug = bool(getattr(self.session, "individual_run_debug", False) or getattr(self.session, "debug", False))
                UtilityTools.dlog(debug, "invalid sse_c_key_b64", object_name=object_name, err=f"{type(err).__name__}: {err}")
                return False
            kwargs.update(
                {
                    "opc_sse_customer_algorithm": "AES256",
                    "opc_sse_customer_key": sse_c_key_b64,
                    "opc_sse_customer_key_sha256": sha_b64,
                }
            )

        try:
            resp = client.get_object(**kwargs)
            return write_response_stream_to_file(getattr(resp, "data", None), str(out_path))
        except Exception:
            return False


class ObjectStoragePreauthenticatedRequestsResource:
    """Pre-Authenticated Requests (PARs) per bucket.

    PARs are time-boxed, UNAUTHENTICATED URLs granting read/write to a bucket or object
    -- a common data-exfil / backdoor surface. The list API returns only metadata (the
    secret access URI is shown once at creation and is never re-retrievable), which is
    exactly what we surface: which PARs exist, their access type, target object, and
    expiry. Enumerated per bucket (child of the buckets already listed)."""

    TABLE_NAME = "object_storage_preauthenticated_requests"
    COLUMNS = [
        "namespace", "bucket_name", "id", "name", "access_type", "object_name",
        "time_created", "time_expires", "bucket_listing_action",
    ]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_object_storage_client(session=session, region=region)

    def list(self, *, namespace: str, bucket_name: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_preauthenticated_requests,
            namespace_name=namespace, bucket_name=bucket_name,
        )
        rows = oci.util.to_dict(resp.data) or []
        out: List[Dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            row.setdefault("namespace", namespace)
            row.setdefault("bucket_name", bucket_name)
            out.append(row)
        return out

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources([r for r in (rows or []) if isinstance(r, dict)], self.TABLE_NAME)
