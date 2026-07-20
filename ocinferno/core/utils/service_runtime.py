from __future__ import annotations

import argparse
import hashlib
import inspect
import json
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import oci

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import cached_table_count, fill_missing_fields, save_rows


ComponentSpec = Tuple[str, str, str]  # (key, method_suffix, help_text)

# A service/compartment may be unavailable or denied; enum wrappers treat these
# HTTP statuses on listing as an empty result rather than an error.
SOFT_SKIP_STATUSES = (401, 403, 404)


def invoke_run_module(module, passthrough_args: Sequence[str], session):
    """Call a module's ``run_module`` regardless of its parameter ordering.

    The single, canonical module invoker used by both the REPL dispatcher
    (``cli/module_actions``) and the ``enum_all`` orchestrator. Most modules use
    the standard ``run_module(user_args, session)`` contract, but this tolerates
    the ``(session, args)`` ordering a few older modules use so the two callers
    don't each carry their own copy.
    """
    fn = getattr(module, "run_module", None)
    if not callable(fn):
        raise AttributeError("Module does not export run_module")

    params = list(inspect.signature(fn).parameters.values())

    def _pname(i: int) -> str:
        return params[i].name if i < len(params) else ""

    if len(params) >= 2:
        p0, p1 = _pname(0), _pname(1)
        if p0 in ("user_args", "argv", "args") and p1 in ("session",):
            return fn(list(passthrough_args), session)
        if p0 in ("session",) and p1 in ("args", "argv", "user_args", "namespace", "parsed"):
            return fn(session, list(passthrough_args))

    try:
        return fn(list(passthrough_args), session)
    except TypeError:
        return fn(session, list(passthrough_args))


def component_error_summary(err: Exception) -> str:
    """One-line summary of a per-component enumeration error.

    Prefers the OCI SDK's ``status``/``code``/``message`` attributes and falls back
    to the exception type + text. Shared by every enumeration module so error
    formatting lives in one place.
    """
    status = getattr(err, "status", None)
    code = getattr(err, "code", None)
    msg = getattr(err, "message", None)
    if status is not None or code is not None:
        return f"status={status}, code={code}, message={msg or str(err)}"
    return f"{type(err).__name__}: {err}"


def component_soft_skip_or_error(err: Exception, *, component: str, module_name: str = "",
                                 soft_skip_statuses: Tuple[int, ...] = SOFT_SKIP_STATUSES) -> Dict[str, Any]:
    """Turn a hand-rolled component's caught exception into the standard result dict.

    A 401/403/404 (OCI's pervasive "denied or no resources in this scope") becomes a
    VISIBLE per-scope skip -- prints the same ``[-] ... API attempted -> <status>`` line
    as ``run_standard_enum_component`` and returns ``{"ok": True, ..., "skipped": True}``
    -- so denied scopes are reported consistently across framework and hand-rolled modules.
    Any other error stays a hard ``{"ok": False, "component", "error"}``.
    """
    label = f"{module_name}.{component}" if module_name else component
    status = getattr(err, "status", None)
    if soft_skip_statuses and status in soft_skip_statuses:
        code = getattr(err, "code", None)
        print(
            f"{UtilityTools.YELLOW}[-] {label}: API attempted -> {status} {code} "
            f"(access denied or no resources in this scope; scope-specific).{UtilityTools.RESET}"
        )
        return {"ok": True, "component": component, component: 0, "skipped": True, "saved": False}
    summary = component_error_summary(err)
    print(f"[*] {label}: skipped ({summary}).")
    return {"ok": False, "component": component, "error": summary}


CacheTables = Mapping[str, Optional[Tuple[str, Optional[str]]]]


def _init_client(client_cls, *args, session, service_name: str, region: Optional[str] = None, **kwargs):
    creds = getattr(session, "credentials", None)
    # An explicit ``region`` wins; otherwise fall back to the session's region.
    effective_region = (
        region
        or getattr(session, "config_current_default_region", None)
        or getattr(session, "region", None)
        or None
    )
    if not (isinstance(creds, dict) and isinstance(creds.get("config"), dict)):
        raise ValueError(
            f"Invalid session.credentials for {service_name}: expected "
            "{'config': <dict>, 'signer': <object|None>}"
        )

    cfg = dict(creds.get("config") or {})
    if effective_region:
        cfg["region"] = effective_region

    signer = creds.get("signer")
    if signer is None:
        client = client_cls(cfg, *args, **kwargs)
    else:
        client = client_cls(cfg, *args, signer=signer, **kwargs)

    # An explicit region also re-pins the client endpoint.
    if region:
        try:
            client.base_client.set_region(region)
        except Exception:
            pass

    try:
        session.add_proxy_config(client)
    except Exception:
        pass

    return client


# --- Concise stdout display columns -----------------------------------------
# Every resource stores its FULL COLUMNS to the DB, but printing all of them makes
# the prettytable output very wide (OCID columns especially). For stdout we show a
# concise 3-4 column subset; the full row is always saved and queryable via `data`
# / exports (or shown with `--wide`). ``concise_display_columns`` auto-derives that
# subset from a resource's COLUMNS by priority when it doesn't declare an explicit
# ``DISPLAY_COLUMNS``.
_DISPLAY_NAME_COLS = ("display_name", "name")
_DISPLAY_STATE_COLS = ("lifecycle_state", "availability_status", "status")
_DISPLAY_SALIENT_COLS = (
    # exposure / network reach (highest signal for offensive triage)
    "is_public", "is_private", "public_ip_address", "private_ip_address", "public_ip",
    "private_ip", "fqdn", "primary_fqdn", "endpoint_fqdn", "messages_endpoint",
    "primary_endpoint_ip_address", "endpoint", "url", "service_url", "service_api_url",
    "service_console_url", "hostname", "host", "ip_address", "vip",
    # identity / type / version
    "platform_type", "platform_name", "version", "software_version", "cluster_version",
    "db_version", "feature_set", "database_type", "infrastructure_type", "target_type",
    "engine", "shape", "cluster_profile", "node_count", "number_of_nodes",
    # security-relevant
    "severity", "cve_reference", "is_secure", "is_high_availability", "is_unlimited",
    "created_by_principal_id", "time_expires", "target_id", "target_registry",
    # low-priority fallbacks
    "time_created",
)


def concise_display_columns(columns: Sequence[str], limit: int = 4) -> List[str]:
    """Pick a concise (<=``limit``) subset of ``columns`` for stdout tables.

    Priority: a human name (else the id) -> a lifecycle/status field -> the most
    salient exposure/type/security field(s). ``compartment_id`` is skipped (it's the
    scope, redundant in per-compartment output). Returns ``columns`` unchanged when it
    already has <= ``limit`` entries.
    """
    cols = [c for c in (columns or [])]
    if len(cols) <= limit:
        return cols
    picked: List[str] = []

    def take(name: str) -> bool:
        if name in cols and name not in picked:
            picked.append(name)
            return True
        return False

    # 1) human identity, else the raw id
    if not any(take(c) for c in _DISPLAY_NAME_COLS):
        take("id")
    # 2) a state/status field
    for c in _DISPLAY_STATE_COLS:
        if take(c):
            break
    # 3..) salient fields by priority
    for c in _DISPLAY_SALIENT_COLS:
        if len(picked) >= limit:
            break
        take(c)
    # 4) fill any remaining slots (skip the redundant scope column)
    if len(picked) < limit:
        for c in cols:
            if len(picked) >= limit:
                break
            if c == "compartment_id":
                continue
            take(c)
    return picked[:limit]


def field_dump_download(
    *,
    field: str,
    service_name: str,
    subdir: str,
    filename: str,
    get_if_missing: bool = True,
    transform: Optional[Callable[[Any], Any]] = None,
):
    """Build a ``Component.download_fn`` factory that writes each row's ``field`` to a file.

    For "metadata" downloads -- developer-supplied env vars / config / cloud-init
    user-data / build specs -- the value is a field already returned by ``get()`` (not a
    separate data-plane object). This dumps that field under the workspace download tree
    (``<service>/<subdir>/<id>/<filename>``) as text (str/bytes) or pretty JSON, honoring
    the per-unit ``--download-timeout`` budget. ``transform`` post-processes the value
    (e.g. base64-decode user-data). Returns the number of files written.
    """
    def _factory(session: Any, args: Any, resource: Any):
        def _download(rows: List[Dict[str, Any]]) -> int:
            from ocinferno.core.utils.download_budget import DownloadBudget
            budget = DownloadBudget(session, label=f"{service_name} {field}")
            written = 0
            for row in rows:
                if budget.exceeded():
                    break
                rid = row.get("id")
                if not rid:
                    continue
                value = row.get(field)
                if get_if_missing and value in (None, "", {}, []):
                    try:
                        meta = resource.get(resource_id=rid) or {}
                        value = meta.get(field) if isinstance(meta, dict) else None
                    except Exception:
                        value = None
                if value in (None, "", {}, []):
                    continue
                try:
                    payload = transform(value) if callable(transform) else value
                except Exception:
                    continue
                if payload in (None, "", {}, []):
                    continue
                if not isinstance(payload, (str, bytes)):
                    payload = json.dumps(payload, indent=2, default=str)
                comp_id = row.get("compartment_id") or getattr(session, "compartment_id", None) or "unknown"
                try:
                    path = session.get_download_save_path(
                        service_name=service_name, filename=filename,
                        compartment_id=comp_id, subdirs=[subdir, str(rid)],
                    )
                    with open(path, "wb" if isinstance(payload, bytes) else "w") as fh:
                        fh.write(payload)
                    written += 1
                except Exception:
                    continue
            return written
        return _download
    return _factory


def resource_method_download(
    *,
    method: str,
    service_name: str,
    subdir: str,
    filename: str,
    label: Optional[str] = None,
):
    """Build a ``Component.download_fn`` factory that invokes a resource's binary-download
    method (``resource.<method>(resource_id=..., out_path=...)``) once per row.

    Sibling of :func:`field_dump_download`, for "content" downloads where the bytes come
    from a dedicated data-plane call (model artifacts, container-config exports) rather than
    a field already present on the row. Writes under ``<service>/<subdir>/<id>/<filename>``
    honoring the per-unit ``--download-timeout`` budget. Returns the number of files written.
    """
    def _factory(session: Any, args: Any, resource: Any):
        fn = getattr(resource, method, None)

        def _download(rows: List[Dict[str, Any]]) -> int:
            from ocinferno.core.utils.download_budget import DownloadBudget
            if not callable(fn):
                return 0
            budget = DownloadBudget(session, label=label or f"{service_name} {method}")
            written = 0
            for row in rows:
                if budget.exceeded():
                    break
                rid = row.get("id")
                if not rid:
                    continue
                comp_id = row.get("compartment_id") or getattr(session, "compartment_id", None) or "unknown"
                try:
                    path = session.get_download_save_path(
                        service_name=service_name, filename=filename,
                        compartment_id=comp_id, subdirs=[subdir, str(rid)],
                    )
                    if fn(resource_id=rid, out_path=path):
                        written += 1
                except Exception:
                    # Content may be absent (404) or forbidden; skip and keep going.
                    continue
            return written
        return _download
    return _factory


def parse_wrapper_args(
    user_args: Sequence[str],
    *,
    description: str,
    components: Sequence[ComponentSpec],
    add_extra_args: Optional[Callable[[argparse.ArgumentParser], None]] = None,
    include_get: bool = True,
    include_save: bool = True,  # accepted but unused; enumeration always persists to the DB
    include_download: bool = False,
):
    # conflict_handler="resolve": a few hand-rolled download modules define their own
    # --download-timeout via add_extra_args; when include_download also adds it, the
    # module's definition simply overrides (identical dest/type) instead of erroring.
    parser = argparse.ArgumentParser(description=description, allow_abbrev=False, conflict_handler="resolve")

    for key, _suffix, help_text in components:
        parser.add_argument(f"--{key.replace('_', '-')}", dest=key, action="store_true", help=help_text)

    if include_get:
        parser.add_argument("--get", action="store_true", help="Pass through --get to selected components")
    if include_download:
        parser.add_argument("--download", action="store_true", help="Download developer-supplied data for components that support it")
        parser.add_argument(
            "--download-timeout", dest="download_timeout", type=int, default=0,
            help="Wall-clock cap in seconds per download unit (0 = unlimited).",
        )
    parser.add_argument(
        "--wide", action="store_true",
        help="Print ALL columns in stdout tables (default shows a concise subset; full data is always saved).",
    )

    if callable(add_extra_args):
        add_extra_args(parser)

    args, remainder = parser.parse_known_args(list(user_args))
    return args, remainder


def make_parse_args(
    description: str,
    components: Sequence[ComponentSpec],
    **kwargs: Any,
) -> Callable[[Sequence[str]], Any]:
    """Build a thin ``_parse_args(user_args)`` passthrough for enum wrappers.

    Equivalent to defining::

        def _parse_args(user_args):
            return parse_wrapper_args(user_args, description=..., components=COMPONENTS)

    Any extra keyword args (e.g. ``include_get=False``) are forwarded to
    ``parse_wrapper_args``. Only use for wrappers with no custom argparse flags
    (no ``add_extra_args``).
    """

    def _parse_args(user_args: Sequence[str]):
        return parse_wrapper_args(user_args, description=description, components=components, **kwargs)

    return _parse_args


def resolve_selected_components(args: argparse.Namespace, component_keys: Sequence[str]) -> Dict[str, bool]:
    keys = list(component_keys or [])
    any_selected = any(getattr(args, key, False) for key in keys)
    return {key: (bool(getattr(args, key, False)) if any_selected else True) for key in keys}


def append_cached_component_counts(
    *,
    results: List[Dict[str, Any]],
    session: Any,
    selected: Mapping[str, bool],
    component_order: Sequence[str],
    cache_tables: CacheTables,
) -> None:
    comp_id = getattr(session, "compartment_id", None)
    module_name = str(getattr(session, "active_module_name", "") or "").strip()
    recommended_module_name = module_name if module_name and module_name != "enum_all" else ""
    any_selected = any(bool(selected.get(k, False)) for k in component_order)
    download_requested = any(
        bool(r.get("download", False))
        for r in (results or [])
        if isinstance(r, dict)
    )

    for key in component_order:
        if selected.get(key, False):
            continue

        table_info = cache_tables.get(key)
        if not table_info:
            results.append({"ok": True, "cached": True, "component": key, "count": None})
            continue

        table_name, compartment_field = table_info
        count = cached_table_count(
            session,
            table_name=table_name,
            compartment_id=comp_id,
            compartment_field=compartment_field,
        )
        results.append({"ok": True, "cached": True, "component": key, "table": table_name, "count": count})
        if any_selected and isinstance(count, int) and count == 0 and recommended_module_name:
            flag = f"--{str(key).replace('_', '-')}"
            print(f"[*] Missing cached data for '{key}' (table: {table_name}).")
            if download_requested:
                print(f"    Can't download due to missing prerequisite data for '{key}'.")
            print(f"    Run: modules run {recommended_module_name} {flag}")


def _flag_enabled(user_args: Any, flag_name: str) -> bool:
    """Return True when a boolean CLI flag is present on either argv or parsed args."""
    if isinstance(user_args, argparse.Namespace):
        return bool(getattr(user_args, flag_name, False))
    flag = f"--{str(flag_name).replace('_', '-')}"
    try:
        return flag in set(str(x) for x in (list(user_args) if user_args is not None else []))
    except Exception:
        return False


def run_standard_enum_component(
    *,
    user_args: Any,
    session: Any,
    component_key: str,
    list_rows: Callable[[str], List[Dict[str, Any]]],
    get_row: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    save_rows_fn: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    print_columns: Optional[List[str]] = None,
    module_name: str = "",
    attach_compartment_id: bool = True,
    require_compartment: bool = True,
    soft_skip_statuses: Tuple[int, ...] = SOFT_SKIP_STATUSES,
    download_rows_fn: Optional[Callable[[List[Dict[str, Any]]], int]] = None,
) -> Dict[str, Any]:
    """The standard per-component list -> (--get enrich) -> print -> (--save) flow.

    This is the single implementation of the block every enumeration wrapper used
    to hand-roll: list rows in the current compartment, stamp compartment_id, on
    ``--get`` enrich each row via ``get_row`` + ``fill_missing_fields``, print the
    table, on ``--save`` persist via ``save_rows_fn``. Returns the same per-component
    result dict the wrappers collected (``{"ok", <component_key>: count, "enriched",
    "saved", "get"}``); on any error it prints the standard skip line and returns
    ``{"ok": False, "component", "error"}`` -- behaviourally identical to the old
    inline blocks.

    ``soft_skip_statuses`` treats a ``ServiceError`` with one of these HTTP statuses
    as an empty, non-error result: it returns ``{"ok": True, <component_key>: 0,
    "skipped": True, ...}`` and prints a VISIBLE informational line (so the operator
    sees the API was attempted and got denied/not-found) rather than a hard-error
    line. Defaults to ``(401, 403, 404)`` because OCI returns ``404
    NotAuthorizedOrNotFound`` for "denied OR no resources in this scope" pervasively;
    the skip is per-scope (a 404 in one compartment/region says nothing about others).
    Pass ``()`` to force every error (incl. 401/403/404) to be a hard failure.
    """
    do_get = _flag_enabled(user_args, "get")
    label = f"{module_name}.{component_key}" if module_name else component_key
    # Explicit "<Service> - <Component>" title: this helper's own frame (and its
    # callers -- run_components, etc.) don't match the "_run_*"/"enum_*" stack-walk
    # UtilityTools._infer_table_title() relies on for an auto title, so without this
    # it falls through to whatever frame IS matched first -- typically enum_all's own
    # dispatch wrapper, printing an unhelpful "<Service> - Other Module".
    service_part = module_name[len("enum_"):] if module_name.startswith("enum_") else module_name
    table_title = " - ".join(
        UtilityTools._humanize_table_label(part) for part in (service_part, component_key) if part
    )
    try:
        comp_id = getattr(session, "compartment_id", None)
        if require_compartment and not comp_id:
            raise ValueError("session.compartment_id is not set. Select a compartment first.")

        rows = [r for r in (list_rows(comp_id) or []) if isinstance(r, dict)]
        if attach_compartment_id and comp_id:
            for row in rows:
                row.setdefault("compartment_id", comp_id)

        # --get enrichment is best-effort on top of an already-successful list: a
        # permission gap or transient error on the per-row GET (e.g. an operation the
        # credential isn't granted, distinct from whatever authorized the LIST call)
        # must not discard the rows already fetched -- same non-fatal treatment as
        # download_rows_fn below, just per-row instead of per-component.
        enriched = 0
        get_failed = 0
        if do_get and callable(get_row):
            for row in rows:
                rid = row.get("id")
                if not rid:
                    continue
                try:
                    meta = get_row(row) or {}
                except Exception as err:
                    get_failed += 1
                    UtilityTools.dlog(
                        bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False)),
                        f"get_{component_key} failed for one row (non-fatal; row kept from list)",
                        id=rid, err=f"{type(err).__name__}: {err}",
                    )
                    continue
                if isinstance(meta, dict) and fill_missing_fields(row, meta):
                    enriched += 1
        if get_failed:
            print(f"{UtilityTools.YELLOW}[-] {label}: --get enrichment failed for {get_failed}/{len(rows)} row(s) "
                  f"(kept the listed rows; likely a permission gap on the GET operation specifically).{UtilityTools.RESET}")

        if rows:
            UtilityTools.print_limited_table(rows, print_columns or [], title=table_title or None)
        # Enumeration always persists to the DB (no --save opt-in).
        if callable(save_rows_fn):
            save_rows_fn(rows)

        downloaded = 0
        do_download = _flag_enabled(user_args, "download")
        if do_download and callable(download_rows_fn) and rows:
            try:
                downloaded = int(download_rows_fn(rows) or 0)
            except Exception as err:
                UtilityTools.dlog(
                    bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False)),
                    "download failed", label=label, err=f"{type(err).__name__}: {err}",
                )

        return {
            "ok": True,
            component_key: len(rows),
            "enriched": enriched,
            "get_failed": get_failed,
            "saved": True,
            "get": bool(do_get),
            "download": do_download,
            "downloaded": downloaded,
        }
    except Exception as err:
        status = getattr(err, "status", None)
        if soft_skip_statuses and status in soft_skip_statuses:
            # OCI returns 401/403/404 for "denied OR no resources in this scope" (NotAuthorizedOrNotFound).
            # Not a hard error -- but PRINT it so the operator sees the API WAS attempted and its result
            # (per-scope: a 404 here says nothing about other compartments/regions).
            code = getattr(err, "code", None)
            print(
                f"{UtilityTools.YELLOW}[-] {label}: API attempted -> {status} {code} "
                f"(access denied or no resources in this scope; scope-specific).{UtilityTools.RESET}"
            )
            return {"ok": True, component_key: 0, "enriched": 0, "saved": False, "get": bool(do_get), "skipped": True}
        summary = component_error_summary(err)
        print(f"[*] {label}: skipped ({summary}).")
        return {"ok": False, "component": component_key, "error": summary}


class ResourceBase:
    """Base for service Resource classes with the standard ``save`` behavior.

    Subclasses set ``TABLE_NAME`` and assign ``self.session`` in ``__init__``.
    Only replaces the ubiquitous one-line ``save`` (``self.session.save_resources(
    rows or [], self.TABLE_NAME)``); classes with custom ``save`` keep their own.
    """

    TABLE_NAME = ""

    def save(self, rows):
        self.session.save_resources(rows or [], self.TABLE_NAME)

    def download(self, *, resource_id: str, out_path: str) -> bool:
        # No binary artifact by default; services with downloads override this.
        return False


class ServiceEnumOpsBase:
    """Shared helpers for service enumeration wrappers."""

    def __init__(self, session):
        self.session = session
        self.debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

    def _set_client_region(self, client: Any, region: Optional[str] = None) -> None:
        if not client:
            return
        target = region or getattr(self.session, "config_current_default_region", None) or getattr(self.session, "region", None)
        if not target:
            return
        try:
            client.base_client.set_region(target)
        except Exception:
            pass

    def _require_compartment(self) -> str:
        cid = getattr(self.session, "compartment_id", None)
        if cid:
            return cid
        raise ValueError(
            "session.compartment_id is not set.\n"
            "Select a compartment in the module runner (or run via module_actions prompt)."
        )

    @staticmethod
    def _parse_component_args(
        user_args: Sequence[str],
        *,
        description: str,
        add_get: bool = True,
        extra_args: Optional[Callable[[argparse.ArgumentParser], None]] = None,
    ) -> argparse.Namespace:
        p = argparse.ArgumentParser(description=description, allow_abbrev=False)
        if add_get:
            p.add_argument("--get", action="store_true", help="Call get_* per row and fill missing fields.")
        if callable(extra_args):
            extra_args(p)
        args, _ = p.parse_known_args(list(user_args))
        return args

    @staticmethod
    def _list_all(method: Callable[..., Any], **kwargs) -> List[Dict[str, Any]]:
        paginator = oci.pagination.list_call_get_all_results
        resp = paginator(method, **kwargs)
        return oci.util.to_dict(resp.data) or []

    @staticmethod
    def _to_dict(resp: Any) -> Dict[str, Any]:
        return oci.util.to_dict(resp.data) or {}

    @staticmethod
    def _record_hash(row: Dict[str, Any], *, prefix: str = "") -> str:
        raw = json.dumps(row or {}, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha1((prefix + raw).encode("utf-8")).hexdigest()

    def _save_rows(self, rows: List[Dict[str, Any]], *, table_name: str) -> None:
        save_rows(self.session, table_name, rows)

    def _enum_component(
        self,
        user_args: Sequence[str],
        *,
        description: str,
        component_key: str,
        list_fn: Callable[[str], List[Dict[str, Any]]],
        get_fn: Optional[Callable[..., Dict[str, Any]]],
        get_id_param: Optional[str],
        save_table: str,
        print_columns: List[str],
        empty_msg_prefix: str = "",
    ) -> Dict[str, Any]:
        args = self._parse_component_args(user_args, description=description)
        debug = bool(getattr(self.session, "debug", False))
        cid = self._require_compartment()

        try:
            rows: List[Dict[str, Any]] = list_fn(cid) or []
        except oci.exceptions.ServiceError as e:
            print(f"{UtilityTools.RED}[X] list_{component_key} failed: {e.status} {e.message}{UtilityTools.RESET}")
            return {"ok": False, component_key: 0, "saved": False, "get": bool(getattr(args, "get", False))}

        if not rows:
            label = f"{empty_msg_prefix}{component_key}" if empty_msg_prefix else component_key
            UtilityTools.dlog(debug, f"No {label} found", compartment_id=cid)
            return {"ok": True, component_key: 0, "saved": True, "get": bool(getattr(args, "get", False))}

        for r in rows:
            if isinstance(r, dict) and "compartment_id" not in r:
                r["compartment_id"] = cid

        if getattr(args, "get", False) and get_fn and get_id_param:
            for r in rows:
                if not isinstance(r, dict):
                    continue
                rid = r.get("id")
                if not rid:
                    continue
                try:
                    meta = get_fn(**{get_id_param: rid})
                except oci.exceptions.ServiceError as e:
                    UtilityTools.dlog(debug, f"get_{component_key} failed", id=rid, status=e.status, error_message=e.message)
                    continue
                except Exception as e:
                    UtilityTools.dlog(debug, f"get_{component_key} failed", id=rid, err=f"{type(e).__name__}: {e}")
                    continue
                if isinstance(meta, dict):
                    fill_missing_fields(r, meta)

        UtilityTools.print_limited_table(rows, print_columns, resource_type=component_key)

        self._save_rows(rows, table_name=save_table)

        return {
            "ok": True,
            "cid": cid,
            component_key: len(rows),
            "saved": True,
            "get": bool(getattr(args, "get", False)),
        }


__all__ = [
    "ComponentSpec",
    "CacheTables",
    "_init_client",
    "append_cached_component_counts",
    "field_dump_download",
    "resource_method_download",
    "parse_wrapper_args",
    "resolve_selected_components",
    "run_standard_enum_component",
    "ServiceEnumOpsBase",
]
