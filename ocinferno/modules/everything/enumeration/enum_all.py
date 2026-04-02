#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import importlib.util
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ocinferno.modules.everything.utilities.enum_all_summary import (
    print_compartment_tree as _print_compartment_tree_impl,
    resource_type_area as _resource_type_area,
    summarize_resources_by_compartment as _summarize_resources_by_compartment_impl,
)
from ocinferno.core.console import UtilityTools

# Compartment enumerator module
COMP_MODULE = "ocinferno.modules.identityclient.enumeration.enum_comp"

# enum_comp flags
FLAG_ENUM_COMP_RECURSIVE = "--recursive"
FLAG_ENUM_COMP_GET_ALL_COMPS = "--get-all-comps"
FLAG_SAVE = "--save"

MOD_OBJECT_STORAGE = "ocinferno.modules.objectstorage.enumeration.enum_objectstorage"
MOD_API_GATEWAY = "ocinferno.modules.apigateway.enumeration.enum_apigateway"
MOD_ARTIFACT_REGISTRY = "ocinferno.modules.artifactregistry.enumeration.enum_artifactregistry"
MOD_RESOURCE_MANAGER = "ocinferno.modules.resourcemanager.enumeration.enum_resourcemanager"
MOD_VAULT = "ocinferno.modules.vault.enumeration.enum_vault"
MOD_CORE_COMPUTE = "ocinferno.modules.core.enumeration.enum_core_compute"
MOD_IOT = "ocinferno.modules.iot.enumeration.enum_iot"

SERVICE_GROUP_SPECS = [
    {"service": "compartments", "modules": []},
    {"service": "identity", "modules": ["ocinferno.modules.identityclient.enumeration.enum_identity", "ocinferno.modules.tagging.enumeration.enum_tagging"]},
    {"service": "logging", "modules": ["ocinferno.modules.logging.enumeration.enum_logs"]},
    {"service": "cloud_guard", "modules": ["ocinferno.modules.cloudguard.enumeration.enum_cloudguard"]},
    {"service": "core_compute", "modules": ["ocinferno.modules.core.enumeration.enum_core_compute"]},
    {"service": "core_block_storage", "modules": ["ocinferno.modules.core.enumeration.enum_core_block_storage"]},
    {"service": "core_network", "modules": ["ocinferno.modules.core.enumeration.enum_core_network"]},
    {"service": "container_instances", "modules": ["ocinferno.modules.containerinstances.enumeration.enum_container_instances"]},
    {"service": "object_storage", "modules": [MOD_OBJECT_STORAGE]},
    {"service": "functions", "modules": ["ocinferno.modules.functions.enumeration.enum_functions"]},
    {"service": "file_storage", "modules": ["ocinferno.modules.filestorage.enumeration.enum_filestorage"]},
    {"service": "kubernetes", "modules": ["ocinferno.modules.kubernetes.enumeration.enum_kubernetes"]},
    {"service": "databases", "modules": ["ocinferno.modules.databases.enumeration.enum_databases"]},
    {"service": "container_registry", "modules": ["ocinferno.modules.containerregistry.enumeration.enum_containerregistry"]},
    {"service": "blockchain", "modules": ["ocinferno.modules.blockchain.enumeration.enum_blockchain"]},
    {"service": "artifact_registry", "modules": [MOD_ARTIFACT_REGISTRY]},
    {"service": "api_gateway", "modules": [MOD_API_GATEWAY]},
    {"service": "dns", "modules": ["ocinferno.modules.dns.enumeration.enum_dns"]},
    {"service": "iot", "modules": [MOD_IOT]},
    {"service": "managed_kafka", "modules": ["ocinferno.modules.managedkafka.enumeration.enum_managedkafka"]},
    {"service": "network_load_balancer", "modules": ["ocinferno.modules.networkloadbalancer.enumeration.enum_network_load_balancers"]},
    {"service": "network_firewall", "modules": ["ocinferno.modules.networkfirewall.enumeration.enum_networkfirewall"]},
    {"service": "notifications", "modules": ["ocinferno.modules.notifications.enumeration.enum_notifications"]},
    {"service": "resource_manager", "modules": [MOD_RESOURCE_MANAGER]},
    {"service": "resource_scheduler", "modules": ["ocinferno.modules.resourcescheduler.enumeration.enum_resource_schedules"]},
    {"service": "data_flow", "modules": ["ocinferno.modules.dataflow.enumeration.enum_dataflow"]},
    {"service": "data_science", "modules": ["ocinferno.modules.datascience.enumeration.enum_datascience"]},
    {"service": "desktops", "modules": ["ocinferno.modules.desktops.enumeration.enum_desktops"]},
    {"service": "devops", "modules": ["ocinferno.modules.devops.enumeration.enum_devops"]},
    {"service": "vault", "modules": [MOD_VAULT]},
]


# Download token routing for enum_all --download
# NOTE:
# - These are best-effort selectors mapped to module flags.
# - Tokens are intentionally coarse to avoid brittle cross-module coupling.
DOWNLOAD_TOKEN_MODULE_ARGS: Dict[str, Dict[str, List[str]]] = {
    # Object Storage content
    "buckets": {
        MOD_OBJECT_STORAGE: ["--namespaces", "--buckets", "--objects", "--download"],
    },
    "objects": {
        MOD_OBJECT_STORAGE: ["--namespaces", "--buckets", "--objects", "--download"],
    },
    "blobs": {
        MOD_OBJECT_STORAGE: ["--namespaces", "--buckets", "--objects", "--download"],
    },
    "object_storage": {
        MOD_OBJECT_STORAGE: ["--download"],
    },

    # API Gateway artifacts
    "api_content": {
        MOD_API_GATEWAY: ["--apis", "--download"],
    },
    "api_specs": {
        MOD_API_GATEWAY: ["--apis", "--download"],
    },
    "sdks": {
        MOD_API_GATEWAY: ["--sdks", "--download"],
    },

    # Artifact Registry
    "artifacts": {
        MOD_ARTIFACT_REGISTRY: ["--artifacts", "--download"],
    },

    # Resource Manager
    "orm_variables": {
        MOD_RESOURCE_MANAGER: ["--stacks", "--download"],
    },
    "orm_jobs": {
        MOD_RESOURCE_MANAGER: ["--jobs", "--download"],
    },
    "orm_templates": {
        MOD_RESOURCE_MANAGER: ["--templates", "--download"],
    },

    # Vault secret plaintext dump
    "vault_secrets": {
        MOD_VAULT: ["--vaults", "--secrets", "--download"],
    },

    # Compute metadata / instance-agent history artifacts
    "compute": {
        MOD_CORE_COMPUTE: ["--instances", "--instance-agent-commands", "--instance-agent-command-executions", "--download"],
    },

    # IoT model/instance content
    "iot_models": {
        MOD_IOT: ["--domains", "--digital-twin-models", "--download"],
    },
    "iot_instances": {
        MOD_IOT: ["--domains", "--digital-twin-instances", "--download"],
    },
}


DOWNLOAD_TOKEN_ALIASES: Dict[str, str] = {
    # object storage
    "bucket": "buckets",
    "objectstorage": "object_storage",
    "object_storage": "object_storage",

    # API gateway
    "api_content_blobs": "api_content",
    "api_spec": "api_specs",
    "api_deployment_specs": "api_specs",
    "sdk": "sdks",

    # Artifact Registry
    "artifact_registry": "artifacts",
    "generic_artifacts": "artifacts",

    # Resource Manager vars (common typos/aliases)
    "orm_variable": "orm_variables",
    "rm_variables": "orm_variables",
    "resource_manager_variables": "orm_variables",
    "ocr_variables": "orm_variables",
    "ocr_vairables": "orm_variables",

    "resource_manager_jobs": "orm_jobs",
    "rm_jobs": "orm_jobs",
    "resource_manager_templates": "orm_templates",
    "rm_templates": "orm_templates",

    # Vault
    "vault": "vault_secrets",
    "secrets": "vault_secrets",

    # Compute
    "compute_userdata": "compute",
    "instance_agent": "compute",

    # IoT
    "iot_models": "iot_models",
    "iot_instances": "iot_instances",
}

DOWNLOAD_TOKEN_EXCLUSION_EXPANSIONS: Dict[str, Set[str]] = {
    "object_storage": {"object_storage", "buckets", "objects", "blobs"},
}


def _canonical_module_tokens() -> List[str]:
    return sorted(str(spec["service"]) for spec in SERVICE_GROUP_SPECS)


def _canonical_download_tokens() -> List[str]:
    return sorted(DOWNLOAD_TOKEN_MODULE_ARGS.keys())


def _format_help_list(tokens: List[str], *, indent: str = "  ") -> str:
    return "\n".join(f"{indent}- {t}" for t in tokens)

# =============================================================================
# CLI
# =============================================================================

def _parse_args(user_args) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Enumerate All OCI Services",
        allow_abbrev=False,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    p.add_argument(
        "--comp",
        action="store_true",
        help=(
            "Enumerate compartments first via enum_comp.\n"
            "Current scope: also scans newly-discovered compartments in the SAME run.\n"
            "All scope: refreshes discovery then scans all discovered compartments."
        ),
    )
    p.add_argument(
        "--no-recursive-compartments",
        action="store_true",
        help=(
            "Do not recursively expand from root compartment(s). "
            "When set, enum_all scans only the provided root target compartment(s)."
        ),
    )

    p.add_argument(
        "--modules",
        nargs="*",
        default=None,
        help=(
            "Run only selected service groups (CSV/space separated).\n"
            "Examples: --modules dns,devops  OR  --modules dns devops\n"
            "Available modules:\n"
            f"{_format_help_list(_canonical_module_tokens(), indent='    ')}"
        ),
    )
    p.add_argument(
        "--not-modules",
        nargs="*",
        default=None,
        help=(
            "Exclude selected service groups (CSV/space separated).\n"
            "Example: --not-modules object_storage\n"
            "Uses the same module tokens listed under --modules."
        ),
    )

    # once-per-run modules
    p.add_argument("--config-check", dest="config_check", action="store_true", help="Run config_check once (after scans).")
    p.add_argument("--opengraph", action="store_true", help="Run OpenGraph once (after scans).")

    # Pass-through knobs for submodules
    p.add_argument("--save", action="store_true", help="Pass --save to submodules (where supported).")
    p.add_argument(
        "--download",
        nargs="*",
        default=None,
        help=(
            "Enable download routing for enum_all.\n"
            "Examples:\n"
            "  --download                   # all downloads\n"
            "  --download buckets           # object storage content\n"
            "  --download buckets,orm_variables api_content\n"
            "Available tokens:\n"
            "    - all\n"
            f"{_format_help_list(_canonical_download_tokens(), indent='    ')}"
        ),
    )
    p.add_argument(
        "--not-downloads",
        nargs="*",
        default=None,
        help=(
            "Exclude download token groups (CSV/space separated).\n"
            "Examples:\n"
            "  --download --not-downloads object_storage\n"
            "  --not-downloads api_specs,sdks\n"
            "Uses the same download tokens listed under --download."
        ),
    )
    p.add_argument("--get", action="store_true", help="Pass --get to submodules (where supported).")
    # enum_all always enables DB context reuse across modules to avoid ordering foot-guns.
    p.set_defaults(use_db=True)

    return p.parse_args(list(user_args))


# =============================================================================
# Helpers
# =============================================================================

def _normalize_cids(raw: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in raw or []:
        if not x:
            continue
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _is_tenancy_ocid(cid: str) -> bool:
    return UtilityTools.is_tenancy_ocid(cid)


def _get_root_cids_from_session(session) -> List[str]:
    roots = list(getattr(session, "target_root_cids", []) or [])
    roots = [r for r in roots if isinstance(r, str) and r]
    return _normalize_cids(roots)


def _get_discovered_cids(session) -> List[str]:
    rows = getattr(session, "global_compartment_list", None) or []
    out: List[str] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        cid = r.get("compartment_id") or r.get("id")
        if cid:
            out.append(cid)
    return _normalize_cids(out)


def _descendant_compartment_closure(session, roots: List[str]) -> List[str]:
    """
    Return roots + all discovered descendants using parent_compartment_id edges.
    Preserves deterministic traversal order and de-duplicates.
    """
    roots = _normalize_cids([r for r in roots if isinstance(r, str) and r.startswith("ocid1.")])
    if not roots:
        return []

    rows = getattr(session, "global_compartment_list", None) or []
    children: Dict[str, List[str]] = {}
    known: Set[str] = set()

    for r in rows:
        if not isinstance(r, dict):
            continue
        cid = str(r.get("compartment_id") or r.get("id") or "").strip()
        parent = str(r.get("parent_compartment_id") or "").strip()
        if not cid or not cid.startswith("ocid1."):
            continue
        known.add(cid)
        if parent and parent.startswith("ocid1.") and parent != cid:
            children.setdefault(parent, []).append(cid)
        children.setdefault(cid, [])

    for parent in list(children.keys()):
        children[parent] = _normalize_cids(children[parent])

    out: List[str] = []
    seen: Set[str] = set()
    queue: List[str] = list(roots)
    while queue:
        cid = queue.pop(0)
        if cid in seen:
            continue
        seen.add(cid)
        out.append(cid)
        for child in children.get(cid, []):
            if child not in seen:
                queue.append(child)

    # Keep roots even if not currently in discovered set.
    fallback = _normalize_cids([c for c in roots if c not in out])
    return _normalize_cids(out + fallback)


def _invoke_run_module(module, user_args: List[str], session):
    fn = getattr(module, "run_module", None)
    if not callable(fn):
        raise TypeError("module has no run_module()")
    return fn(list(user_args), session)


def _is_nonfatal_service_error(exc: Exception) -> bool:
    status = getattr(exc, "status", None)
    code = str(getattr(exc, "code", "") or "")
    if status not in (401, 403, 404):
        return False
    if code in {"NotAuthorizedOrNotFound", "NotAuthorized", "NotFound"}:
        return True
    return False


def _run_other_module(session, user_args: List[str], module_name: str):
    try:
        module = importlib.import_module(module_name)
        return _invoke_run_module(module, user_args, session)
    except Exception as e:
        debug = bool(getattr(session, "debug", False))
        if _is_nonfatal_service_error(e):
            status = getattr(e, "status", None)
            code = str(getattr(e, "code", "") or "ServiceError")
            print(f"[*] {module_name}: skipped ({status} {code}).")
            UtilityTools.dlog(
                debug,
                "enum_all: skipped module due to non-fatal service error",
                module=module_name,
                status=status,
                code=code,
            )
            return {"ok": True, "module": module_name, "skipped": True, "status": status, "code": code}
        print(f"{UtilityTools.RED}[X] {module_name}: {type(e).__name__}: {e}{UtilityTools.RESET}")
        return None


@lru_cache(maxsize=256)
def _module_supported_flags(module_name: str) -> Set[str]:
    try:
        spec = importlib.util.find_spec(module_name)
    except Exception:
        return set()
    if spec is None or not spec.origin or not spec.origin.endswith(".py"):
        return set()
    try:
        text = Path(spec.origin).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return set()

    flags = set()
    for flag in ("--save", "--get", "--download"):
        if flag in text:
            flags.add(flag)

    # Most enum modules use parse_wrapper_args(). That helper implicitly adds
    # --get/--save by default and adds --download when include_download=True.
    # Relying only on literal "--download" text misses modules that support it
    # via include_download but don't mention the flag string directly.
    if "parse_wrapper_args(" in text:
        flags.update({"--save", "--get"})
        if "include_download=True" in text:
            flags.add("--download")
    return flags


@lru_cache(maxsize=256)
def _module_accepts_unknown_args(module_name: str) -> bool:
    try:
        spec = importlib.util.find_spec(module_name)
    except Exception:
        return False
    if spec is None or not spec.origin or not spec.origin.endswith(".py"):
        return False
    try:
        text = Path(spec.origin).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    return "parse_known_args(" in text


def _module_args(args: argparse.Namespace, module_name: str) -> List[str]:
    download_flag_set = getattr(args, "download", None) is not None
    return _module_args_with_download_plan(
        args,
        module_name,
        download_all=download_flag_set,
        module_download_extras=None,
    )


def _split_csv_tokens(raw_tokens: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    for token in raw_tokens or []:
        if token is None:
            continue
        for part in str(token).split(","):
            p = str(part or "").strip().lower().replace("-", "_")
            if p:
                out.append(p)
    return out


def _split_download_tokens(raw_tokens: Optional[List[str]]) -> List[str]:
    return _split_csv_tokens(raw_tokens)


def _resolve_download_plan(
    args: argparse.Namespace,
    *,
    debug: bool = False,
) -> Tuple[bool, Dict[str, List[str]]]:
    """
    Returns:
      (download_all, module_download_extras)
    """
    known_tokens = set(_canonical_download_tokens())

    download_values = getattr(args, "download", None)
    download_flag_set = download_values is not None

    include_raw = _split_download_tokens(list(download_values or []))
    exclude_raw = _split_download_tokens(list(getattr(args, "not_downloads", None) or []))

    resolved_include: List[str] = []
    resolved_exclude: List[str] = []
    unknown: List[str] = []

    def _resolve_many(raw_tokens: List[str], dst: List[str]) -> None:
        for token in raw_tokens:
            canon = DOWNLOAD_TOKEN_ALIASES.get(token, token)
            if canon in known_tokens or canon == "all":
                if canon not in dst:
                    dst.append(canon)
            else:
                unknown.append(token)

    _resolve_many(include_raw, resolved_include)
    _resolve_many(exclude_raw, resolved_exclude)

    if unknown:
        known = sorted(list(known_tokens))
        raise ValueError(f"Unknown download token(s): {', '.join(unknown)}. Known tokens: {', '.join(known)}")

    # Base include set
    if download_flag_set:
        if (not resolved_include) or ("all" in resolved_include):
            include_set = set(known_tokens)
        else:
            include_set = {t for t in resolved_include if t != "all"}
    elif resolved_exclude:
        # --not-downloads by itself means: all downloads except exclusions.
        include_set = set(known_tokens)
    else:
        # No explicit download controls => no download routing.
        include_set = set()

    # Exclusions
    expanded_exclude: Set[str] = set()
    for tok in resolved_exclude:
        if tok == "all":
            expanded_exclude.add("all")
            continue
        expanded_exclude.update(DOWNLOAD_TOKEN_EXCLUSION_EXPANSIONS.get(tok, {tok}))

    if "all" in expanded_exclude:
        include_set.clear()
    else:
        include_set -= {t for t in expanded_exclude if t != "all"}

    if not include_set:
        return False, {}

    if include_set == known_tokens:
        return True, {}

    resolved_tokens = sorted(include_set)
    module_extras: Dict[str, List[str]] = {}
    for token in resolved_tokens:
        per_module = DOWNLOAD_TOKEN_MODULE_ARGS.get(token, {})
        for module_name, extra_args in per_module.items():
            dst = module_extras.setdefault(module_name, [])
            for a in extra_args:
                if a not in dst:
                    dst.append(a)

    UtilityTools.dlog(debug, "enum_all: resolved selective downloads", tokens=resolved_tokens, modules=list(module_extras.keys()))
    return False, module_extras


def _module_args_with_download_plan(
    args: argparse.Namespace,
    module_name: str,
    *,
    download_all: bool,
    module_download_extras: Optional[Dict[str, List[str]]],
) -> List[str]:
    supported = _module_supported_flags(module_name)
    accepts_unknown = _module_accepts_unknown_args(module_name)
    out: List[str] = []
    if args.save and (("--save" in supported) or accepts_unknown):
        out.append("--save")
    if args.get and (("--get" in supported) or accepts_unknown):
        out.append("--get")
    if download_all and (("--download" in supported) or accepts_unknown):
        out.append("--download")
    extras = (module_download_extras or {}).get(module_name, [])
    for a in extras:
        if a not in out:
            out.append(a)

    return out


def _module_args_for_target(
    args: argparse.Namespace,
    module_name: str,
    cid: str,
    *,
    debug: bool = False,
    download_all: bool = False,
    module_download_extras: Optional[Dict[str, List[str]]] = None,
) -> List[str]:
    """Build module args with target-aware overrides."""
    out = _module_args_with_download_plan(
        args,
        module_name,
        download_all=download_all,
        module_download_extras=module_download_extras,
    )
    return _normalize_cids(out)


def _split_service_selector_tokens(raw_tokens: Optional[List[str]]) -> List[str]:
    return _split_csv_tokens(raw_tokens)


@lru_cache(maxsize=1)
def _module_selector_index() -> Dict[str, str]:
    idx: Dict[str, str] = {}
    for spec in SERVICE_GROUP_SPECS:
        service = str(spec["service"]).strip().lower()
        idx[service] = service

    return idx


def _resolve_service_run_flags(args: argparse.Namespace, *, any_once_flags: bool, debug: bool = False) -> Dict[str, bool]:
    all_services = [str(spec["service"]) for spec in SERVICE_GROUP_SPECS]
    all_service_set = set(all_services)

    selector_idx = _module_selector_index()
    include_tokens = _split_service_selector_tokens(getattr(args, "modules", None))
    exclude_tokens = _split_service_selector_tokens(getattr(args, "not_modules", None))

    unknown_tokens = [t for t in include_tokens + exclude_tokens if t not in selector_idx]
    if unknown_tokens:
        known = sorted(set(selector_idx.keys()))
        raise ValueError(f"Unknown module selector token(s): {', '.join(unknown_tokens)}. Known tokens: {', '.join(known)}")

    include_services = {selector_idx[t] for t in include_tokens if t in selector_idx}
    exclude_services = {selector_idx[t] for t in exclude_tokens if t in selector_idx}

    # Selection behavior:
    # - include list present: run only includes
    # - only excludes present: run all minus excludes
    # - no selectors/flags: preserve old behavior (all unless once-only flags were requested)
    if include_services:
        selected = set(include_services)
    elif exclude_services:
        selected = set(all_service_set)
    else:
        selected = set() if any_once_flags else set(all_service_set)

    selected -= exclude_services

    UtilityTools.dlog(
        debug,
        "enum_all: resolved module selectors",
        include_tokens=include_tokens,
        exclude_tokens=exclude_tokens,
        include_services=sorted(include_services),
        exclude_services=sorted(exclude_services),
        selected_services=sorted(selected),
        any_once_flags=any_once_flags,
    )

    return {svc: (svc in selected) for svc in all_services}


def _summarize_resources_by_compartment(session, target_cids: List[str]) -> dict:
    return _summarize_resources_by_compartment_impl(session, target_cids)


def _print_compartment_tree(session, target_cids: List[str]) -> None:
    _print_compartment_tree_impl(session, target_cids)


def _expand_compartments(session, roots: List[str], *, debug: bool = False, save: bool = False) -> None:
    """
    Runs enum_comp to populate/refresh session.global_compartment_list.
    For both tenancy and non-tenancy roots: recursive mode.
    Includes GetCompartment for root and all discovered compartments.
    """
    try:
        comp_mod = importlib.import_module(COMP_MODULE)
    except Exception as e:
        print(f"{UtilityTools.RED}[X] Could not import {COMP_MODULE}: {type(e).__name__}: {e}{UtilityTools.RESET}")
        return

    roots = _normalize_cids([r for r in roots if isinstance(r, str) and r.startswith("ocid1.")])

    tenancy_roots = [r for r in roots if _is_tenancy_ocid(r)]
    other_roots = [r for r in roots if not _is_tenancy_ocid(r)]

    UtilityTools.dlog(debug, "enum_all: enum_comp roots split", tenancy_roots=tenancy_roots, other_roots=other_roots)

    # 1) tenancy recursion
    for tid in tenancy_roots:
        UtilityTools._log_action("module", f"START enum_comp recursive_all for {tid}", "N/A")
        old = getattr(session, "compartment_id", None)
        try:
            session.compartment_id = tid
            comp_args = [FLAG_ENUM_COMP_RECURSIVE, FLAG_ENUM_COMP_GET_ALL_COMPS]
            if save:
                comp_args.append(FLAG_SAVE)
            _invoke_run_module(comp_mod, comp_args, session)
        finally:
            session.compartment_id = old
            UtilityTools._log_action("module", f"END enum_comp recursive_all for {tid}", "N/A")

    # 2) subtree recursion
    for cid in other_roots:
        UtilityTools._log_action("module", f"START enum_comp cover-all for {cid}", "N/A")
        old = getattr(session, "compartment_id", None)
        try:
            session.compartment_id = cid
            comp_args = [FLAG_ENUM_COMP_RECURSIVE, FLAG_ENUM_COMP_GET_ALL_COMPS]
            if save:
                comp_args.append(FLAG_SAVE)
            _invoke_run_module(comp_mod, comp_args, session)
        finally:
            session.compartment_id = old
            UtilityTools._log_action("module", f"END enum_comp cover-all for {cid}", "N/A")


def _resolve_comp_roots_for_enum_comp(
    session,
    roots: List[str],
    *,
    use_all_discovered: bool,
    debug: bool = False,
) -> List[str]:
    # Explicit non-sentinel roots always win.
    explicit = _normalize_cids([r for r in roots if isinstance(r, str) and r.startswith("ocid1.") and r != "__ALL_DISCOVERED__"])
    if explicit:
        return explicit

    # In all-discovered scope, prefer tenancy roots (one recursive call per tenant).
    if use_all_discovered:
        cur = getattr(session, "compartment_id", None)
        discovered = _get_discovered_cids(session)
        known = _normalize_cids(([cur] if isinstance(cur, str) and cur else []) + discovered)
        tenancy_roots = [cid for cid in known if _is_tenancy_ocid(cid)]
        out = tenancy_roots or known
        UtilityTools.dlog(
            debug,
            "enum_all: resolved comp roots for all-discovered scope",
            tenancy_roots=tenancy_roots,
            total=len(out),
        )
        return out

    # Fallback to current context.
    cur = getattr(session, "compartment_id", None)
    if isinstance(cur, str) and cur.startswith("ocid1."):
        return [cur]
    return []


def _resolve_roots_for_scan(session) -> List[str]:
    roots = _get_root_cids_from_session(session)
    if not roots:
        cur = getattr(session, "compartment_id", None)
        roots = [cur] if cur else []
    return _normalize_cids([r for r in roots if isinstance(r, str) and r])


def _resolve_scan_targets(
    session,
    roots: List[str],
    *,
    use_all_discovered: bool,
    recursive_compartments: bool,
    should_enum_comp: bool,
    save: bool = False,
    debug: bool = False,
) -> List[str]:
    discovered_before = set(_get_discovered_cids(session))

    comp_roots = _resolve_comp_roots_for_enum_comp(
        session,
        roots,
        use_all_discovered=use_all_discovered,
        debug=debug,
    )

    if should_enum_comp:
        UtilityTools.dlog(debug, "enum_all: running enum_comp", comp_roots=comp_roots)
        _expand_compartments(session, comp_roots, debug=debug, save=save)

    discovered_after = set(_get_discovered_cids(session))
    newly_discovered = sorted(list(discovered_after - discovered_before))
    if newly_discovered:
        UtilityTools.dlog(debug, "enum_all: newly discovered cids", count=len(newly_discovered), preview=newly_discovered[:10])

    if use_all_discovered:
        base_targets = _get_discovered_cids(session)
    elif recursive_compartments:
        base_targets = _descendant_compartment_closure(session, roots)
        if not base_targets:
            base_targets = _get_discovered_cids(session) or roots
    else:
        base_targets = roots

    base_targets = _normalize_cids([t for t in base_targets if isinstance(t, str) and t.startswith("ocid1.")])

    if (not use_all_discovered) and recursive_compartments and newly_discovered:
        allowed = set(_descendant_compartment_closure(session, roots))
        for cid in newly_discovered:
            if cid in allowed and cid not in base_targets:
                base_targets.append(cid)

    scanned = getattr(session, "enum_all_scanned_cids", None)
    if not isinstance(scanned, set):
        scanned = set()
        session.enum_all_scanned_cids = scanned

    final_targets: List[str] = []
    for cid in base_targets:
        if cid in scanned:
            continue
        scanned.add(cid)
        final_targets.append(cid)

    UtilityTools.dlog(debug, "enum_all: final targets", total=len(final_targets), preview=final_targets[:10])
    return final_targets


def _build_execution_plan(service_run_flags: Dict[str, bool], *, debug: bool = False) -> List[Tuple[str, bool, List[str]]]:
    execution_plan: List[Tuple[str, bool, List[str]]] = []

    for spec in SERVICE_GROUP_SPECS:
        service_name = str(spec["service"])
        modules = [str(m).strip() for m in (spec.get("modules") or []) if str(m).strip()]
        execution_plan.append((service_name, service_run_flags.get(service_name, False), modules))

    return execution_plan


def _run_execution_plan(
    session,
    args: argparse.Namespace,
    final_targets: List[str],
    execution_plan: List[Tuple[str, bool, List[str]]],
    *,
    download_all: bool,
    module_download_extras: Optional[Dict[str, List[str]]],
    debug: bool = False,
) -> None:
    for cid in final_targets:
        UtilityTools._log_action("module", f"START enum_all target {cid}", "N/A")
        old = getattr(session, "compartment_id", None)
        try:
            session.compartment_id = cid
            for svc_name, should_run, modules in execution_plan:
                if not should_run:
                    continue
                UtilityTools.dlog(debug, "enum_all: running service group", service=svc_name, compartment_id=cid)
                for module_name in modules:
                    print(f"{UtilityTools.BRIGHT_CYAN}[*] Running {module_name} for {UtilityTools.condense_ocid(cid)}{UtilityTools.RESET}")
                    _run_other_module(
                        session,
                        _module_args_for_target(
                            args,
                            module_name,
                            cid,
                            debug=debug,
                            download_all=download_all,
                            module_download_extras=module_download_extras,
                        ),
                        module_name,
                    )
        finally:
            session.compartment_id = old
            UtilityTools._log_action("module", f"END enum_all target {cid}", "N/A")


def _run_once_modules(session, args: argparse.Namespace, *, run_config_check: bool, run_opengraph: bool) -> None:
    if run_config_check:
        UtilityTools._log_action("module", "START enum_config_check", "N/A")
        _run_other_module(session, _module_args(args, "ocinferno.modules.everything.enumeration.enum_config_check"), "ocinferno.modules.everything.enumeration.enum_config_check")
        UtilityTools._log_action("module", "END enum_config_check", "N/A")

    if run_opengraph:
        UtilityTools._log_action("module", "START enum_oracle_cloud_hound_data", "N/A")
        _run_other_module(session, _module_args(args, "ocinferno.modules.opengraph.enumeration.enum_oracle_cloud_hound_data"), "ocinferno.modules.opengraph.enumeration.enum_oracle_cloud_hound_data")
        UtilityTools._log_action("module", "END enum_oracle_cloud_hound_data", "N/A")


def _render_scan_summary(session, final_targets: List[str]) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, int]]]:
    summary = _summarize_resources_by_compartment(session, final_targets)
    tally_rows = summary.get("totals", [])
    detailed_rows = summary.get("detailed", {})

    if tally_rows:
        print("\n[*] enum_all Resource Summary By Compartment")
        UtilityTools.print_limited_table(
            tally_rows,
            ["compartment_name", "compartment_id", "resource_count"],
            max_rows=max(50, len(tally_rows)),
            truncate=160,
            align="l",
        )
        _print_compartment_tree(session, final_targets)

    for cid in final_targets:
        resource_map = detailed_rows.get(cid, {}) if isinstance(detailed_rows, dict) else {}
        if not resource_map:
            continue
        print(f"\n[*] Resource Breakdown: {UtilityTools.condense_ocid(cid)}")
        type_rows = [
            {"area": _resource_type_area(k), "resource_type": k, "count": v}
            for k, v in resource_map.items()
            if int(v) > 0
        ]
        type_rows.sort(key=lambda r: (str(r.get("area", "")), str(r.get("resource_type", ""))))
        UtilityTools.print_limited_table(
            type_rows,
            ["area", "resource_type", "count"],
            max_rows=max(50, len(type_rows)),
            truncate=100,
            condense_ocids=False,
            align="l",
        )

    return tally_rows, detailed_rows


# =============================================================================
# Main
# =============================================================================

def run_module(user_args, session, output_format=None):
    args = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False))

    try:
        download_all, module_download_extras = _resolve_download_plan(args, debug=debug)
    except ValueError as e:
        print(f"{UtilityTools.RED}[X] enum_all: {e}{UtilityTools.RESET}")
        return 0

    any_once_flags = bool(args.config_check or args.opengraph)
    recursive_compartments = not bool(getattr(args, "no_recursive_compartments", False))
    should_enum_comp = bool(args.comp)

    # Clear runtime scan cache EACH enum_all run
    session.enum_all_scanned_cids = set()
    roots = _resolve_roots_for_scan(session)
    if not roots:
        print(f"{UtilityTools.RED}[X] enum_all: no root CID available (set session.compartment_id or pass --cids).{UtilityTools.RESET}")
        return 0

    use_all_discovered = "__ALL_DISCOVERED__" in roots

    UtilityTools.dlog(
        debug,
        "enum_all: scope",
        roots=roots,
        all_discovered=use_all_discovered,
        recursive_compartments=recursive_compartments,
        should_enum_comp=should_enum_comp,
    )

    final_targets = _resolve_scan_targets(
        session,
        roots,
        use_all_discovered=use_all_discovered,
        recursive_compartments=recursive_compartments,
        should_enum_comp=should_enum_comp,
        save=bool(args.save),
        debug=debug,
    )

    try:
        service_run_flags = _resolve_service_run_flags(args, any_once_flags=any_once_flags, debug=debug)
    except ValueError as e:
        print(f"{UtilityTools.RED}[X] enum_all: {e}{UtilityTools.RESET}")
        return 0

    any_service_runs = any(service_run_flags.values())

    # If user asked for --comp and no selected service/post modules, stop after enum_comp.
    if args.comp and not (any_service_runs or any_once_flags):
        UtilityTools.dlog(debug, "enum_all: --comp only requested; stopping after enum_comp")
        return 1

    execution_plan = _build_execution_plan(service_run_flags, debug=debug)
    _run_execution_plan(
        session,
        args,
        final_targets,
        execution_plan,
        download_all=download_all,
        module_download_extras=module_download_extras,
        debug=debug,
    )

    _run_once_modules(
        session,
        args,
        run_config_check=bool(args.config_check),
        run_opengraph=bool(args.opengraph),
    )

    tally_rows, detailed_rows = _render_scan_summary(session, final_targets)

    return {
        "ok": True,
        "targets_scanned": len(final_targets),
        "resource_tally": tally_rows,
        "resource_breakdown": detailed_rows,
    }
