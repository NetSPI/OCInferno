#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import importlib.util
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ocinferno.modules.everything.utilities.enum_all_summary import (
    print_compartment_tree as _print_compartment_tree_impl,
    resource_type_area as _resource_type_area,
    summarize_resources_by_compartment as _summarize_resources_by_compartment_impl,
)
from datetime import datetime, timezone

from ocinferno.core.console import UtilityTools
from ocinferno.core.contracts import AuthError
from ocinferno.core.utils.service_runtime import invoke_run_module as _invoke_run_module
from ocinferno.core.utils.service_runtime import component_error_summary as _component_error_summary
from ocinferno.core.utils.parallel import cancel_requested, clear_cancel, parallel_map, request_cancel
from ocinferno.core.utils.scoped_session import CompartmentScopedSession
from ocinferno.core.utils.regions import home_region, resolve_regions, subscribed_regions
from ocinferno.core.utils import hierarchy as _hierarchy

# Compartment enumerator module
COMP_MODULE = "ocinferno.modules.identityclient.enumeration.enum_comp"

# enum_comp flags
FLAG_ENUM_COMP_RECURSIVE = "--recursive"
FLAG_ENUM_COMP_GET_ALL_COMPS = "--get-all-comps"

MOD_OBJECT_STORAGE = "ocinferno.modules.objectstorage.enumeration.enum_objectstorage"
MOD_API_GATEWAY = "ocinferno.modules.apigateway.enumeration.enum_apigateway"
MOD_ARTIFACT_REGISTRY = "ocinferno.modules.artifactregistry.enumeration.enum_artifactregistry"
MOD_RESOURCE_MANAGER = "ocinferno.modules.resourcemanager.enumeration.enum_resourcemanager"
MOD_VAULT = "ocinferno.modules.vault.enumeration.enum_vault"
MOD_CORE_COMPUTE = "ocinferno.modules.core.enumeration.enum_core_compute"
MOD_IOT = "ocinferno.modules.iot.enumeration.enum_iot"
MOD_FUNCTIONS = "ocinferno.modules.functions.enumeration.enum_functions"
MOD_CONTAINER_INSTANCES = "ocinferno.modules.containerinstances.enumeration.enum_container_instances"
MOD_CERTIFICATES = "ocinferno.modules.certificates.enumeration.enum_certificates"
MOD_DATAFLOW = "ocinferno.modules.dataflow.enumeration.enum_dataflow"
MOD_DATASCIENCE = "ocinferno.modules.datascience.enumeration.enum_datascience"
MOD_DEVOPS = "ocinferno.modules.devops.enumeration.enum_devops"

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
    {"service": "load_balancer", "modules": ["ocinferno.modules.loadbalancer.enumeration.enum_loadbalancer"]},
    {"service": "mysql", "modules": ["ocinferno.modules.mysql.enumeration.enum_mysql"]},
    {"service": "postgresql", "modules": ["ocinferno.modules.postgresql.enumeration.enum_postgresql"]},
    {"service": "nosql", "modules": ["ocinferno.modules.nosql.enumeration.enum_nosql"]},
    {"service": "events", "modules": ["ocinferno.modules.events.enumeration.enum_events"]},
    {"service": "certificates", "modules": ["ocinferno.modules.certificates.enumeration.enum_certificates"]},
    {"service": "audit", "modules": ["ocinferno.modules.audit.enumeration.enum_audit"]},
    {"service": "goldengate", "modules": ["ocinferno.modules.goldengate.enumeration.enum_goldengate"]},
    {"service": "data_integration", "modules": ["ocinferno.modules.dataintegration.enumeration.enum_dataintegration"]},
    {"service": "integration", "modules": ["ocinferno.modules.integration.enumeration.enum_integration"]},
    {"service": "monitoring", "modules": ["ocinferno.modules.monitoring.enumeration.enum_monitoring"]},
    {"service": "streaming", "modules": ["ocinferno.modules.streaming.enumeration.enum_streaming"]},
    {"service": "queue", "modules": ["ocinferno.modules.queue.enumeration.enum_queue"]},
    {"service": "redis", "modules": ["ocinferno.modules.redis.enumeration.enum_redis"]},
    {"service": "opensearch", "modules": ["ocinferno.modules.opensearch.enumeration.enum_opensearch"]},
    {"service": "waf", "modules": ["ocinferno.modules.waf.enumeration.enum_waf"]},
    # --- services added 2026-07 ---
    {"service": "email", "modules": ["ocinferno.modules.email.enumeration.enum_email"]},
    {"service": "data_safe", "modules": ["ocinferno.modules.data_safe.enumeration.enum_data_safe"]},
    {"service": "vulnerability_scanning", "modules": ["ocinferno.modules.vulnerability_scanning.enumeration.enum_vulnerability_scanning"]},
    {"service": "bds", "modules": ["ocinferno.modules.bds.enumeration.enum_bds"]},
    {"service": "data_catalog", "modules": ["ocinferno.modules.data_catalog.enumeration.enum_data_catalog"]},
    {"service": "analytics", "modules": ["ocinferno.modules.analytics.enumeration.enum_analytics"]},
    {"service": "management_agent", "modules": ["ocinferno.modules.management_agent.enumeration.enum_management_agent"]},
    {"service": "generative_ai", "modules": ["ocinferno.modules.generative_ai.enumeration.enum_generative_ai"]},
    {"service": "database_management", "modules": ["ocinferno.modules.database_management.enumeration.enum_database_management"]},
    {"service": "fusion_apps", "modules": ["ocinferno.modules.fusion_apps.enumeration.enum_fusion_apps"]},
    {"service": "oda", "modules": ["ocinferno.modules.oda.enumeration.enum_oda"]},
    {"service": "visual_builder", "modules": ["ocinferno.modules.visual_builder.enumeration.enum_visual_builder"]},
    {"service": "ai_language", "modules": ["ocinferno.modules.ai_language.enumeration.enum_ai_language"]},
    {"service": "delegate_access_control", "modules": ["ocinferno.modules.delegate_access_control.enumeration.enum_delegate_access_control"]},
    # --- Tier 1/2 services added 2026-07 ---
    {"service": "database_tools", "modules": ["ocinferno.modules.database_tools.enumeration.enum_database_tools"]},
    {"service": "operator_access_control", "modules": ["ocinferno.modules.operator_access_control.enumeration.enum_operator_access_control"]},
    {"service": "lockbox", "modules": ["ocinferno.modules.lockbox.enumeration.enum_lockbox"]},
    {"service": "apiaccesscontrol", "modules": ["ocinferno.modules.apiaccesscontrol.enumeration.enum_apiaccesscontrol"]},
    {"service": "waas", "modules": ["ocinferno.modules.waas.enumeration.enum_waas"]},
    {"service": "dbmulticloud", "modules": ["ocinferno.modules.dbmulticloud.enumeration.enum_dbmulticloud"]},
    {"service": "cloud_bridge", "modules": ["ocinferno.modules.cloud_bridge.enumeration.enum_cloud_bridge"]},
    {"service": "cloud_migrations", "modules": ["ocinferno.modules.cloud_migrations.enumeration.enum_cloud_migrations"]},
    {"service": "database_migration", "modules": ["ocinferno.modules.database_migration.enumeration.enum_database_migration"]},
    {"service": "healthchecks", "modules": ["ocinferno.modules.healthchecks.enumeration.enum_healthchecks"]},
    {"service": "tenant_manager", "modules": ["ocinferno.modules.tenant_manager.enumeration.enum_tenant_manager"]},
    {"service": "governance_rules", "modules": ["ocinferno.modules.governance_rules.enumeration.enum_governance_rules"]},
    {"service": "generative_ai_agent", "modules": ["ocinferno.modules.generative_ai_agent.enumeration.enum_generative_ai_agent"]},
    {"service": "ocvp", "modules": ["ocinferno.modules.ocvp.enumeration.enum_ocvp"]},
    {"service": "wlms", "modules": ["ocinferno.modules.wlms.enumeration.enum_wlms"]},
    {"service": "autoscaling", "modules": ["ocinferno.modules.autoscaling.enumeration.enum_autoscaling"]},
    {"service": "bastion", "modules": ["ocinferno.modules.bastion.enumeration.enum_bastion"]},
    {"service": "os_management_hub", "modules": ["ocinferno.modules.os_management_hub.enumeration.enum_os_management_hub"]},
    {"service": "service_connector", "modules": ["ocinferno.modules.service_connector.enumeration.enum_service_connector"]},
]

# Service groups that are GLOBAL (tenancy-wide, not regional): they live in the HOME
# region only, so a multi-region fan-out runs them once (home region) instead of once
# per region (which would duplicate rows + waste calls). Everything else is regional.
_GLOBAL_SERVICE_NAMES = {"compartments", "identity"}


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

    # Functions config (env vars) - developer-supplied metadata
    "function_config": {
        MOD_FUNCTIONS: ["--download"],
    },
    # Container Instances env vars / command / arguments - metadata
    "container_env": {
        MOD_CONTAINER_INSTANCES: ["--download"],
    },
    # DevOps build/deploy pipeline parameters - metadata
    "devops_pipeline_config": {
        MOD_DEVOPS: ["--build-pipelines", "--deploy-pipelines", "--download"],
    },
    # Certificate PEM bundles (chain + exportable private material) - content
    "certificate_bundles": {
        MOD_CERTIFICATES: ["--certificates", "--download"],
    },
    # Data Flow Spark/PySpark driver scripts + archives from Object Storage - content
    "dataflow_scripts": {
        MOD_DATAFLOW: ["--applications", "--download"],
    },
    # Data Science model + job artifact bundles - content
    "datascience_artifacts": {
        MOD_DATASCIENCE: ["--models", "--jobs", "--download"],
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


# Umbrella download CATEGORIES.
# A category is a keyword that expands to a set of individual download tokens, so an
# operator can pull the LIGHT config/history layer without triggering HEAVY byte/secret
# dumps -- or vice versa -- instead of hand-listing every token:
#   --download metadata     # light: instance-agent history, API specs, ORM job logs
#   --download content       # heavy: bucket objects, vault secret plaintext, artifact
#                            #        files, ORM tfvars/templates, SDKs, IoT twins
#   --download                # bare == all == metadata | content
#   --download content --not-downloads vault_secrets   # a category minus one token
# Categories and individual tokens compose freely in --download / --not-downloads.
# The two sets PARTITION every canonical token (all == metadata | content).
DOWNLOAD_TOKEN_CATEGORIES: Dict[str, Set[str]] = {
    "metadata": {
        "compute", "api_content", "api_specs", "orm_jobs",
        "function_config", "container_env", "devops_pipeline_config",
    },
    "content": {
        "buckets", "objects", "blobs", "object_storage", "vault_secrets", "artifacts",
        "sdks", "orm_variables", "orm_templates", "iot_models", "iot_instances",
        "certificate_bundles", "dataflow_scripts", "datascience_artifacts",
    },
}

# All keywords accepted in --download / --not-downloads beyond individual tokens.
DOWNLOAD_CATEGORY_KEYWORDS: Set[str] = {"all"} | set(DOWNLOAD_TOKEN_CATEGORIES)


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
            "Run only selected service groups (CSV/space separated). Omit to run ALL.\n"
            "Accepts full tokens or short aliases (storage, compute, iam, oke, kms, lb, ...).\n"
            "Examples: --modules dns,devops  OR  --modules storage compute\n"
            "Run '--list-modules' to see every token (with aliases)."
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
    p.add_argument(
        "--list-modules",
        dest="list_modules",
        action="store_true",
        help="List every --modules service token (with aliases) and exit.",
    )
    p.add_argument(
        "--regions",
        nargs="*",
        default=None,
        help=(
            "Region scope for enumeration (CSV/space separated). Default: the session's\n"
            "CURRENT region only (today's behavior). OCI resources are regional, so a\n"
            "single-region scan misses resources in other subscribed regions.\n"
            "Examples:\n"
            "  --regions all                 # every SUBSCRIBED region\n"
            "  --regions us-ashburn-1,us-phoenix-1\n"
            "Global services (IAM/identity, tagging, compartments) run in the HOME region\n"
            "only regardless of this flag. Peak API calls scale by number of regions."
        ),
    )
    p.add_argument(
        "--find-regions", dest="find_regions", action="store_true",
        help=(
            "Discover the tenancy's subscribed regions once (list_region_subscriptions),\n"
            "persist them to the region_subscriptions store, and enumerate across ALL of\n"
            "them (shorthand for a fresh --regions all). Without this / --regions, only the\n"
            "session's current region is scanned."
        ),
    )

    # once-per-run modules
    p.add_argument("--config-check", dest="config_check", action="store_true", help="Run config_check once (after scans).")
    p.add_argument("--opengraph", action="store_true", help="Run OpenGraph once (after scans).")

    # Pass-through knobs for submodules
    p.add_argument(
        "--download",
        nargs="*",
        default=None,
        help=(
            "Enable download routing for enum_all. Accepts umbrella CATEGORIES or\n"
            "individual tokens (categories + tokens compose freely; CSV/space separated).\n"
            "Examples:\n"
            "  --download                   # all downloads (== metadata + content)\n"
            "  --download metadata          # light: instance-agent history, API specs, ORM job logs\n"
            "  --download content           # heavy: bucket objects, vault secrets, artifacts, tfvars, SDKs, IoT\n"
            "  --download buckets           # a single token (object storage content)\n"
            "  --download content --not-downloads vault_secrets   # a category minus a token\n"
            "  --download buckets,orm_variables api_content\n"
            "Categories:\n"
            f"{_format_help_list(sorted(DOWNLOAD_CATEGORY_KEYWORDS), indent='    ')}\n"
            "Tokens:\n"
            f"{_format_help_list(_canonical_download_tokens(), indent='    ')}"
        ),
    )
    p.add_argument(
        "--not-downloads",
        nargs="*",
        default=None,
        help=(
            "Exclude download categories/tokens (CSV/space separated).\n"
            "Examples:\n"
            "  --download --not-downloads content        # everything light, no heavy dumps\n"
            "  --download --not-downloads object_storage\n"
            "  --not-downloads api_specs,sdks\n"
            "Uses the same categories/tokens listed under --download."
        ),
    )
    p.add_argument("--get", action="store_true", help="Pass --get to submodules (where supported).")

    # ---- Parallelism + resume ----
    p.add_argument(
        "--parallel-services", dest="parallel_services", type=int, default=1,
        help=(
            "Enumerate (compartment, service) units CONCURRENTLY with N workers "
            "(default: 1 = sequential). Each parallel run records progress under a run "
            "token (printed at start); a plain re-run starts fresh."
        ),
    )
    p.add_argument(
        "--resume", dest="resume", default=None,
        help=(
            "Resume a prior --parallel-services run by its token: re-runs ONLY the "
            "(compartment, service) units that run left incomplete. Requires --parallel-services > 1."
        ),
    )
    p.add_argument(
        "--list-tokens", dest="list_tokens", action="store_true",
        help="List saved run tokens (interrupted/failed parallel runs) with progress, then exit.",
    )

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

    for r in rows:
        if not isinstance(r, dict):
            continue
        cid = str(r.get("compartment_id") or r.get("id") or "").strip()
        parent = str(r.get("parent_compartment_id") or "").strip()
        if not cid or not cid.startswith("ocid1."):
            continue
        if parent and parent.startswith("ocid1.") and parent != cid:
            children.setdefault(parent, []).append(cid)
        children.setdefault(cid, [])

    for parent in list(children.keys()):
        children[parent] = _normalize_cids(children[parent])

    # BFS from a virtual super-root whose children are exactly `roots`, in
    # order, so undiscovered roots are still included in the closure.
    virtual_root = "__closure_roots__"
    children[virtual_root] = roots
    return _hierarchy.descendants(children, virtual_root)


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
        ensure_fresh_creds = getattr(session, "ensure_fresh_creds", None)
        if callable(ensure_fresh_creds):
            ensure_fresh_creds(skew_seconds=600)
        module = importlib.import_module(module_name)
        return _invoke_run_module(module, user_args, session)
    except AuthError:
        raise  # session token is dead -- let the caller stop the whole sweep, not just this unit
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
    for flag in ("--get", "--download"):
        if flag in text:
            flags.add(flag)

    # Most enum modules use parse_wrapper_args(). That helper implicitly adds
    # --get by default and adds --download when include_download=True.
    # Relying only on literal "--download" text misses modules that support it
    # via include_download but don't mention the flag string directly.
    if "parse_wrapper_args(" in text:
        flags.add("--get")
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
            # Accept individual tokens AND the category keywords all/metadata/content.
            if canon in known_tokens or canon in DOWNLOAD_CATEGORY_KEYWORDS:
                if canon not in dst:
                    dst.append(canon)
            else:
                unknown.append(token)

    _resolve_many(include_raw, resolved_include)
    _resolve_many(exclude_raw, resolved_exclude)

    if unknown:
        known = sorted(list(known_tokens))
        cats = sorted(DOWNLOAD_CATEGORY_KEYWORDS)
        raise ValueError(
            f"Unknown download token(s): {', '.join(unknown)}. "
            f"Categories: {', '.join(cats)}. Tokens: {', '.join(known)}"
        )

    def _expand_category(token: str) -> Set[str]:
        """Expand a category keyword to its token set; a plain token maps to itself."""
        if token == "all":
            return set(known_tokens)
        if token in DOWNLOAD_TOKEN_CATEGORIES:
            return set(DOWNLOAD_TOKEN_CATEGORIES[token])
        return {token}

    # Base include set (bare --download == all; otherwise expand categories + tokens)
    if download_flag_set:
        if not resolved_include:
            include_set = set(known_tokens)
        else:
            include_set = set()
            for tok in resolved_include:
                include_set |= _expand_category(tok)
    elif resolved_exclude:
        # --not-downloads by itself means: all downloads except exclusions.
        include_set = set(known_tokens)
    else:
        # No explicit download controls => no download routing.
        include_set = set()

    # Exclusions (expand categories, then the object_storage-style token expansions)
    expanded_exclude: Set[str] = set()
    for tok in resolved_exclude:
        if tok == "all":
            expanded_exclude.add("all")
            continue
        if tok in DOWNLOAD_TOKEN_CATEGORIES:
            expanded_exclude |= DOWNLOAD_TOKEN_CATEGORIES[tok]
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


# Friendly short --modules aliases -> canonical service-group token. The full token name
# always works too; these are shorthands on top of it.
_MODULE_ALIASES: Dict[str, str] = {
    "compute": "core_compute", "instances": "core_compute", "vms": "core_compute",
    "network": "core_network", "vcn": "core_network",
    "blockstorage": "core_block_storage", "bv": "core_block_storage", "volumes": "core_block_storage",
    "storage": "object_storage", "oss": "object_storage", "buckets": "object_storage",
    "fss": "file_storage",
    "iam": "identity", "identitydomains": "identity",
    "kms": "vault", "secrets": "vault",
    "oke": "kubernetes", "k8s": "kubernetes",
    "lb": "load_balancer", "nlb": "network_load_balancer",
    "gguard": "cloud_guard", "guard": "cloud_guard",
    "ar": "artifact_registry", "cr": "container_registry", "ci": "container_instances",
    "db": "databases", "adb": "databases",
    "rm": "resource_manager", "orm": "resource_manager",
    "kafka": "managed_kafka", "genai": "generative_ai",
    "logs": "logging", "vss": "vulnerability_scanning", "comp": "compartments",
}


@lru_cache(maxsize=1)
def _module_selector_index() -> Dict[str, str]:
    idx: Dict[str, str] = {}
    for spec in SERVICE_GROUP_SPECS:
        service = str(spec["service"]).strip().lower()
        idx[service] = service
    # aliases resolve to canonical service tokens (only when the target still exists)
    canonical = set(idx)
    for alias, service in _MODULE_ALIASES.items():
        if service in canonical:
            idx[alias.strip().lower()] = service
    return idx


def _print_module_tokens() -> None:
    """Print every --modules service token (with aliases) and exit."""
    aliases_by_service: Dict[str, List[str]] = {}
    for alias, service in _MODULE_ALIASES.items():
        aliases_by_service.setdefault(service, []).append(alias)
    print(f"{UtilityTools.BRIGHT_CYAN}[*] --modules service tokens "
          f"(comma/space separated; omit --modules to run ALL){UtilityTools.RESET}")
    for service in _canonical_module_tokens():
        extra = sorted(aliases_by_service.get(service, []))
        suffix = f"   (aliases: {', '.join(extra)})" if extra else ""
        print(f"    {service}{suffix}")
    print("    Example:  modules run enum_all --modules storage,identity kubernetes")


def _resolve_service_run_flags(args: argparse.Namespace, *, any_once_flags: bool, should_enum_comp: bool = False, debug: bool = False) -> Dict[str, bool]:
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
    # - no selectors/flags: preserve old behavior (all unless once-only flags were requested).
    #   --comp always implies wanting a fresh enumeration pass, so it must NOT be treated as
    #   a "once-only flags were requested, skip enumeration" signal -- otherwise
    #   `enum_all --comp --config-check` (a very natural "discover + scan + audit" combo)
    #   silently skips every service enumeration and process_config_check then runs against
    #   whatever was already in the DB (often nothing), reporting a false "0 findings".
    only_once_only_flags_requested = any_once_flags and not should_enum_comp
    if include_services:
        selected = set(include_services)
    elif exclude_services:
        selected = set(all_service_set)
    else:
        selected = set() if only_once_only_flags_requested else set(all_service_set)

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


def _expand_compartments(session, roots: List[str], *, debug: bool = False) -> None:
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
        _expand_compartments(session, comp_roots, debug=debug)

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

    # Dispatch order: tenancy-scoped services (compartments/identity) first, then
    # everything else alphabetically -- sorted here rather than hand-ordered in
    # SERVICE_GROUP_SPECS so new services stay in place without manual reinsertion.
    execution_plan.sort(key=lambda spec: (spec[0] not in _GLOBAL_SERVICE_NAMES, spec[0]))

    return execution_plan


# =============================================================================
# Parallel execution + resumable run ledger
# =============================================================================

_LEDGER_TABLE = "enum_all_task_ledger"


def _unit_key(region: str, cid: str, module_name: str) -> str:
    # Region-scoped unit identity so resume tracks (region, compartment, module).
    # A blank region (single-region runs) collapses to "::cid::module".
    return f"{region or ''}::{cid}::{module_name}"


def _mint_run_token() -> str:
    return "enum_all-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _ledger_mark(session, run_id: str, region: str, cid: str, module_name: str, status: str, *, error: str = "") -> None:
    """Best-effort progress record for one (region, compartment, module) unit. Never raises.

    ``status`` is one of running/done/failed; ``error`` carries
    a one-line summary when a unit fails. A later mark REPLACES the row (PK is
    run_id+region+compartment+module+workspace), so each unit keeps only its latest state.
    """
    try:
        session.data_master.save_dict_row(
            db="service",
            table_name=_LEDGER_TABLE,
            row={
                "workspace_id": session.workspace_id,
                "run_id": run_id,
                "region": region or "",
                "compartment_id": cid,
                "module": module_name,
                "status": status,
                "error": str(error or "")[:2000],
                "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            },
            on_conflict="replace",
        )
    except Exception:
        pass


def _ledger_done_units(session, run_id: str) -> Set[str]:
    try:
        rows = session.data_master.fetch_column_from_table(
            db="service",
            table_name=_LEDGER_TABLE,
            columns=["region", "compartment_id", "module"],
            where={"workspace_id": session.workspace_id, "run_id": run_id, "status": "done"},
        )
    except Exception:
        return set()
    return {_unit_key(str(r or ""), str(c), str(m)) for (r, c, m) in rows}


def _ledger_list_tokens(session) -> List[Dict[str, Any]]:
    try:
        rows = session.data_master.fetch_column_from_table(
            db="service",
            table_name=_LEDGER_TABLE,
            columns=["run_id", "status", "updated_at"],
            where={"workspace_id": session.workspace_id},
        )
    except Exception:
        return []
    agg: Dict[str, Dict[str, Any]] = {}
    for run_id, status, updated_at in rows:
        rec = agg.setdefault(str(run_id), {"run_id": str(run_id), "done": 0, "failed": 0, "total": 0, "last": ""})
        rec["total"] += 1
        if str(status) == "done":
            rec["done"] += 1
        elif str(status) == "failed":
            rec["failed"] += 1
        if str(updated_at or "") > rec["last"]:
            rec["last"] = str(updated_at or "")
    return sorted(agg.values(), key=lambda r: r["last"], reverse=True)


def _print_run_tokens(session) -> None:
    tokens = _ledger_list_tokens(session)
    if not tokens:
        print(f"{UtilityTools.YELLOW}[!] No saved enum_all run tokens for this workspace.{UtilityTools.RESET}")
        return
    print(f"{UtilityTools.BRIGHT_CYAN}[*] Saved enum_all run tokens (resume with --parallel-services N --resume <token>):{UtilityTools.RESET}")
    for rec in tokens:
        done, total, failed = rec["done"], rec["total"], rec.get("failed", 0)
        state = "complete" if done >= total and total else f"{done}/{total} units done"
        if failed:
            state += f", {failed} failed"
        print(f"    {rec['run_id']}  [{state}]  last update {rec['last'] or 'n/a'}")


def _plan_units(
    final_targets: List[str],
    execution_plan: List[Tuple[str, bool, List[str]]],
    scan_regions: List[str],
    home_region: Optional[str],
    skip_units: Set[str],
) -> List[Tuple[str, str, str]]:
    """Expand (region, compartment, module) units, honoring the resume skip-set and
    the global-vs-regional distinction (global services run in the home region only)."""
    regions = list(scan_regions or [""])
    home = home_region or (regions[0] if regions else "")
    units: List[Tuple[str, str, str]] = []
    for region in regions:
        for cid in final_targets:
            for svc_name, should_run, modules in execution_plan:
                if not should_run:
                    continue
                # Global (tenancy-wide) services: only run once, in the home region.
                if svc_name in _GLOBAL_SERVICE_NAMES and len(regions) > 1 and region != home:
                    continue
                for module_name in modules:
                    if _unit_key(region, cid, module_name) in skip_units:
                        continue
                    units.append((region, cid, module_name))
    return units


def _run_execution_plan_parallel(
    session,
    args: argparse.Namespace,
    final_targets: List[str],
    execution_plan: List[Tuple[str, bool, List[str]]],
    *,
    download_all: bool,
    module_download_extras: Optional[Dict[str, List[str]]],
    run_id: str,
    threads: int,
    skip_units: Set[str],
    scan_regions: List[str],
    home_region: Optional[str],
    debug: bool = False,
) -> None:
    """Fan (region, compartment, service-module) units out across a bounded worker pool.

    Each worker acts on its own compartment AND region via a ``CompartmentScopedSession``
    view over the shared session, so concurrent units never fight over
    ``session.compartment_id`` / region. DB writes are safe (the DataController serializes
    every method on one process-wide lock). A single Ctrl+C sets the cooperative
    cancel flag, the pool stops launching new units, and the resume token is
    reprinted so the run can pick up exactly where it stopped.
    """
    units = _plan_units(final_targets, execution_plan, scan_regions, home_region, skip_units)
    multi_region = len([r for r in (scan_regions or []) if r]) > 1

    print(f"{UtilityTools.BRIGHT_CYAN}[*] enum_all run token: {run_id}{UtilityTools.RESET}")
    if skip_units:
        print(f"{UtilityTools.BRIGHT_CYAN}[*] Resuming: {len(skip_units)} unit(s) already complete, {len(units)} remaining.{UtilityTools.RESET}")
    if not units:
        print(f"{UtilityTools.GREEN}[+] enum_all: nothing left to run for token {run_id}.{UtilityTools.RESET}")
        return
    scope_word = "(region, compartment, service)" if multi_region else "(compartment, service)"
    if multi_region:
        print(f"{UtilityTools.YELLOW}[!] Multi-region: fanning out across {len([r for r in scan_regions if r])} region(s) "
              f"({', '.join(r for r in scan_regions if r)}). Peak API calls scale by #regions.{UtilityTools.RESET}")
    print(f"{UtilityTools.BRIGHT_CYAN}[*] Running {len(units)} {scope_word} unit(s) across {threads} worker(s).{UtilityTools.RESET}")
    print(f"{UtilityTools.YELLOW}[!] Interrupt-safe: one Ctrl+C stops the pool; resume with  enum_all --parallel-services {threads} --resume {run_id}{UtilityTools.RESET}")

    # Per-(region, compartment) (done/total) counter, mirroring the serial path's
    # "(done/total) Running <module> for <compartment>" line -- workers interleave
    # across compartments, so this is tracked per-target rather than as one global count.
    target_totals: Dict[Tuple[str, str], int] = {}
    for region, cid, _module_name in units:
        target_totals[(region, cid)] = target_totals.get((region, cid), 0) + 1
    target_progress: Dict[Tuple[str, str], int] = {}
    progress_lock = threading.Lock()

    def _worker(unit: Tuple[str, str, str]):
        region, cid, module_name = unit
        if cancel_requested():
            return None
        scoped = CompartmentScopedSession(session, cid, region or None)
        where = f"{cid}@{region}" if region else cid
        with progress_lock:
            done = target_progress[(region, cid)] = target_progress.get((region, cid), 0) + 1
        total_for_target = target_totals.get((region, cid), done)
        print(f"{UtilityTools.BRIGHT_CYAN}[*] ({done}/{total_for_target}) Running {module_name} for {UtilityTools.condense_ocid(cid)}"
              f"{(' @ ' + region) if region else ''}{UtilityTools.RESET}")
        UtilityTools._log_action("module", f"START enum_all {module_name} @ {where}", "N/A")
        _ledger_mark(session, run_id, region, cid, module_name, "running")
        try:
            _run_other_module(
                scoped,
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
            _ledger_mark(session, run_id, region, cid, module_name, "done")
        except AuthError as err:
            # Session token is dead -- stop the pool from launching further units
            # (same cooperative-cancel path as Ctrl+C) instead of grinding through
            # every remaining unit with a credential that can only keep failing.
            _ledger_mark(session, run_id, region, cid, module_name, "failed", error=str(err))
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Stopping enum_all: {err.message}{UtilityTools.RESET}")
            request_cancel()
        except Exception as err:
            # Record the failure (with a one-line summary) but don't sink the batch;
            # the unit stays non-"done" so --resume re-runs it. KeyboardInterrupt is a
            # BaseException, so one Ctrl+C still propagates and stops the pool.
            _ledger_mark(session, run_id, region, cid, module_name, "failed", error=_component_error_summary(err))
        finally:
            UtilityTools._log_action("module", f"END enum_all {module_name} @ {where}", "N/A")
        return None

    try:
        parallel_map(units, _worker, threads=threads, progress_label="enum_all", show_progress=True)
    except KeyboardInterrupt:
        request_cancel()

    if cancel_requested():
        print(f"{UtilityTools.YELLOW}[!] enum_all interrupted — resume with  enum_all --parallel-services {threads} --resume {run_id}{UtilityTools.RESET}")


def _run_execution_plan(
    session,
    args: argparse.Namespace,
    final_targets: List[str],
    execution_plan: List[Tuple[str, bool, List[str]]],
    *,
    download_all: bool,
    module_download_extras: Optional[Dict[str, List[str]]],
    scan_regions: List[str],
    home_region: Optional[str],
    debug: bool = False,
) -> None:
    regions = [r for r in (scan_regions or []) if r] or [None]
    multi_region = len(regions) > 1
    home = home_region or (regions[0] if regions and regions[0] else None)
    if multi_region:
        print(f"{UtilityTools.YELLOW}[!] Multi-region: enumerating {len(regions)} region(s) "
              f"({', '.join(str(r) for r in regions)}); peak API calls scale by #regions.{UtilityTools.RESET}")

    def _run_target(cid: str, region: Optional[str], plan: List[Tuple[str, bool, List[str]]]) -> None:
        module_names = [m for _n, run, mods in plan if run for m in mods]
        if not module_names:
            return
        label = f"{cid}@{region}" if region else cid
        UtilityTools._log_action("module", f"START enum_all target {label}", "N/A")
        old_cid = getattr(session, "compartment_id", None)
        old_region = getattr(session, "config_current_default_region", None)
        total = len(module_names)
        done = 0
        try:
            session.compartment_id = cid
            if region:
                session.config_current_default_region = region
            for svc_name, should_run, modules in plan:
                if not should_run:
                    continue
                UtilityTools.dlog(debug, "enum_all: running service group", service=svc_name, compartment_id=cid, region=region)
                for module_name in modules:
                    done += 1
                    print(f"{UtilityTools.BRIGHT_CYAN}[*] ({done}/{total}) Running {module_name} for {UtilityTools.condense_ocid(cid)}"
                          f"{(' @ ' + region) if region else ''}{UtilityTools.RESET}")
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
            session.compartment_id = old_cid
            if region:
                session.config_current_default_region = old_region
            UtilityTools._log_action("module", f"END enum_all target {label}", "N/A")

    global_plan = [spec for spec in execution_plan if spec[0] in _GLOBAL_SERVICE_NAMES]
    regional_plan = [spec for spec in execution_plan if spec[0] not in _GLOBAL_SERVICE_NAMES]

    try:
        # Global (tenancy-wide) services: once per compartment target, in the home region only --
        # no region dimension, so multi-region fan-out never revisits them.
        for cid in final_targets:
            _run_target(cid, home, global_plan)

        # Regional services: every (region, compartment) pair.
        for region in regions:
            for cid in final_targets:
                _run_target(cid, region, regional_plan)
    except AuthError as e:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Stopping enum_all: {e.message}{UtilityTools.RESET}")


def _run_once_modules(session, args: argparse.Namespace, *, run_config_check: bool, run_opengraph: bool) -> None:
    if run_config_check:
        UtilityTools._log_action("module", "START process_config_check", "N/A")
        _run_other_module(session, _module_args(args, "ocinferno.modules.everything.processing.process_config_check"), "ocinferno.modules.everything.processing.process_config_check")
        UtilityTools._log_action("module", "END process_config_check", "N/A")

    if run_opengraph:
        UtilityTools._log_action("module", "START process_oracle_cloud_hound_data", "N/A")
        _run_other_module(session, _module_args(args, "ocinferno.modules.opengraph.processing.process_oracle_cloud_hound_data"), "ocinferno.modules.opengraph.processing.process_oracle_cloud_hound_data")
        UtilityTools._log_action("module", "END process_oracle_cloud_hound_data", "N/A")


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
            auto_title=False,  # the print() above is already the section header
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
            auto_title=False,  # the print() above is already the section header
        )

    return tally_rows, detailed_rows


# =============================================================================
# Main
# =============================================================================

def run_module(user_args, session):
    args = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False))

    if getattr(args, "list_modules", False):
        _print_module_tokens()
        return 1

    if getattr(args, "list_tokens", False):
        _print_run_tokens(session)
        return 1

    parallel_services = max(1, int(getattr(args, "parallel_services", 1) or 1))
    resume_token = getattr(args, "resume", None)
    use_parallel = parallel_services > 1 or bool(resume_token)

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
        debug=debug,
    )

    try:
        service_run_flags = _resolve_service_run_flags(args, any_once_flags=any_once_flags, should_enum_comp=should_enum_comp, debug=debug)
    except ValueError as e:
        print(f"{UtilityTools.RED}[X] enum_all: {e}{UtilityTools.RESET}")
        return 0

    any_service_runs = any(service_run_flags.values())

    # If user asked for --comp and no selected service/post modules, stop after enum_comp.
    if args.comp and not (any_service_runs or any_once_flags):
        UtilityTools.dlog(debug, "enum_all: --comp only requested; stopping after enum_comp")
        return 1

    # Region scope: default is the session's current region (today's behavior);
    # --regions all | r1,r2 fans enumeration out across subscribed regions;
    # --find-regions force-discovers + persists the subscription store, then scans all.
    if bool(getattr(args, "find_regions", False)):
        found = subscribed_regions(session, refresh=True)  # live fetch + persist store
        print(f"{UtilityTools.BRIGHT_CYAN}[*] enum_all: discovered {len(found)} subscribed "
              f"region(s): {', '.join(found) or '(none)'}{UtilityTools.RESET}")
        scan_regions = resolve_regions(session, "all")
    else:
        scan_regions = resolve_regions(session, getattr(args, "regions", None))
    home = home_region(session)
    if len([r for r in scan_regions if r]) > 1:
        UtilityTools.dlog(debug, "enum_all: multi-region scope", regions=scan_regions, home=home)

    execution_plan = _build_execution_plan(service_run_flags, debug=debug)
    if use_parallel:
        clear_cancel()
        run_id = resume_token or _mint_run_token()
        skip_units = _ledger_done_units(session, run_id) if resume_token else set()
        try:
            _run_execution_plan_parallel(
                session,
                args,
                final_targets,
                execution_plan,
                download_all=download_all,
                module_download_extras=module_download_extras,
                run_id=run_id,
                threads=parallel_services,
                skip_units=skip_units,
                scan_regions=scan_regions,
                home_region=home,
                debug=debug,
            )
        except KeyboardInterrupt:
            request_cancel()
            print(f"{UtilityTools.YELLOW}[!] enum_all interrupted — resume with  enum_all --parallel-services {parallel_services} --resume {run_id}{UtilityTools.RESET}")
            return -1
        if cancel_requested():
            return -1
    else:
        _run_execution_plan(
            session,
            args,
            final_targets,
            execution_plan,
            download_all=download_all,
            module_download_extras=module_download_extras,
            scan_regions=scan_regions,
            home_region=home,
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
