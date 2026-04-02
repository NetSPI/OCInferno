from dataclasses import dataclass

import json
from pathlib import Path

from ocinferno.modules.opengraph.utilities.helpers.core_helpers import s as _s

# -----------------------------------------------------------------------------
# Shared OpenGraph node/edge labels
# -----------------------------------------------------------------------------
NODE_TYPE_OCI_USER = "OCIUser"
NODE_TYPE_OCI_GROUP = "OCIGroup"
NODE_TYPE_OCI_DYNAMIC_GROUP = "OCIDynamicGroup"
NODE_TYPE_OCI_GENERIC_RESOURCE = "OCIGenericResource"

EDGE_TYPE_OCI_GROUP_MEMBER = "OCI_GROUP_MEMBER"
EDGE_TYPE_OCI_DYNAMIC_GROUP_MEMBER = "OCI_DYNAMIC_GROUP_MEMBER"

_RESOURCE_SCOPE_MAP_PATH = Path(__file__).resolve().parent / "data" / "resource_scope_map.json"
_STATIC_CONSTANTS_PATH = Path(__file__).resolve().parent / "data" / "static_constants.json"


def _parse_resource_scope_tuple_key(raw_key):
    """
    Parses tuple-like keys from resource_scope_map.json:
      "(<resource_iam_name>,<dynamic_group_name_or_None>)"
    """
    key = str(raw_key or "").strip()
    if key.startswith("(") and key.endswith(")") and "," in key:
        left, right = key[1:-1].split(",", 1)
        resource_iam_name = left.strip().lower()
        dynamic_group_name = right.strip().lower()
        if dynamic_group_name in {"", "none", "null"}:
            dynamic_group_name = None
        return resource_iam_name, dynamic_group_name
    return "", None


def _load_resource_scope_maps():
    try:
        raw = json.loads(_RESOURCE_SCOPE_MAP_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}, {}
    if not isinstance(raw, dict):
        return {}, {}

    by_token = {}
    by_tuple = {}
    for raw_key, spec in raw.items():
        if not isinstance(spec, dict):
            continue
        resource_iam_name, dynamic_group_name = _parse_resource_scope_tuple_key(raw_key)
        if not resource_iam_name:
            continue
        by_tuple[(resource_iam_name, dynamic_group_name)] = spec
        by_token[resource_iam_name] = spec
    return by_token, by_tuple


RESOURCE_SCOPE_MAP, RESOURCE_SCOPE_MAP_TUPLE = _load_resource_scope_maps()


def _load_static_constants_payload():
    try:
        raw = json.loads(_STATIC_CONSTANTS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


_STATIC_CONSTANTS_PAYLOAD = _load_static_constants_payload()

SUPPORTED_VARIABLES = (
    _STATIC_CONSTANTS_PAYLOAD.get("SUPPORTED_VARIABLES")
    if isinstance(_STATIC_CONSTANTS_PAYLOAD.get("SUPPORTED_VARIABLES"), dict)
    else {}
)

PRINCIPAL_GROUPS = {
    'principals-group': {'group', 'group-id', 'dynamic-group', 'dynamic-group-id'}, 
    'principals-non-service': {'group', 'group-id', 'dynamic-group', 'dynamic-group-id', 'any-user', 'any-group'}, 
    'principals-service': {'service'}, 
    'principals-all': {'group', 'group-id', 'dynamic-group', 'dynamic-group-id', 'service', 'any-user', 'any-group'}
}

# Resource-family semantics used for allow-rule matching and scope expansion.
# Keys must match policy tokens (e.g. "instance-family") and values are the member resource tokens.
_DEFAULT_RESOURCE_FAMILIES_RAW = (
    _STATIC_CONSTANTS_PAYLOAD.get("DEFAULT_RESOURCE_FAMILIES")
    if isinstance(_STATIC_CONSTANTS_PAYLOAD.get("DEFAULT_RESOURCE_FAMILIES"), dict)
    else {}
)
DEFAULT_RESOURCE_FAMILIES = {
    str(k): set(v or ()) if isinstance(v, list) else set(v or ())
    for k, v in _DEFAULT_RESOURCE_FAMILIES_RAW.items()
}

# Resource types supported by OCI Dynamic Groups (normalized, lower-case).
# Keep these as canonical resource.type tokens (OCID-style). Aliases are handled
# in the evaluator table catalog, so we avoid duplicates like instance/instances.
DYNAMIC_GROUP_RESOURCE_TYPES = {
    "instance",
    "fnfunc",
    "computecontainerinstance",
    "dataflowrun",
    "resourceschedule",
    "devopsdeploypipeline",
    "devopsbuildpipeline",
    "devopsrepository",
    "devopsconnection",
}

# Resource-type alias expansion used by evaluators to bridge canonical
# dynamic-group resource.type tokens and policy/scope-map token variants.
RESOURCE_TYPE_ALIASES = {
    "instances": ("instance",),
    "fn-app": ("fnapp",),
    "fn-function": ("fnfunction", "fnfunc", "fnfnc"),
}

# Resource-scope tokens that represent resource principals for ANY-USER expansion
# and conditional request.instance.compartment.id trimming.
RESOURCE_PRINCIPAL_SCOPE_TOKENS = {
    "instances",
    "fn-function",
    "computecontainerinstance",
    "dataflowrun",
    "resourceschedule",
    "devopsdeploypipeline",
    "devopsbuildpipeline",
    "devopsrepository",
    "devopsconnection",
}

@dataclass(slots=True)
class AllowEdgeRule:
    """
    Rule for translating IAM allow statements into graph edges.

    Fields:
    - principal_group_key: restrict by subject type group (see PRINCIPAL_GROUPS)
    - match_resource_tokens: policy resource tokens to match (e.g., {"users","policies"})
    - min_verbs: ALL required verbs
    - any_verbs: ANY acceptable verbs (optional)
    - min_permissions: ALL required permissions
    - any_permissions: ANY acceptable permissions (optional)
    - edge_label: output edge type
    - edge_description: human description
    - destination_token_to_make: destination scope/resource token emitted by graph builder
    - destination_node_type_hint: override for edge destination node type
    - allow_specific_resources: allow edges to concrete resources when matched rows exist
    """
    principal_group_key: str = ""
    match_resource_tokens: frozenset = frozenset()
    min_verbs: frozenset = frozenset()
    any_verbs: frozenset = frozenset()
    min_permissions: frozenset = frozenset()
    any_permissions: frozenset = frozenset()
    edge_label: str = ""
    edge_description: str = ""
    edge_status: str = ""
    destination_token_to_make: str = ""
    destination_node_type_hint: str = ""
    allow_specific_resources: bool = True


def _allow(
    match_tokens: list[str] | tuple[str, ...] | set[str] | None,
    *,
    min_verbs=None,
    any_verbs=None,
    min_perms=None,
    any_perms=None,
    edge_label: str = "",
    edge_description: str = "",
    edge_status: str = "",
    principal_group_key: str = "principals-non-service",
    destination_token_to_make: str = "",
    destination_node_type_hint: str = "OCIResourceGroup",
    allow_specific_resources: bool = True,
) -> AllowEdgeRule:
    match_tokens = set(match_tokens or ())
    dest_token = destination_token_to_make or (next(iter(match_tokens), "") if match_tokens else "")
    return AllowEdgeRule(
        principal_group_key=principal_group_key,
        match_resource_tokens=frozenset(match_tokens),
        min_verbs=frozenset(min_verbs or ()),
        any_verbs=frozenset(any_verbs or ()),
        min_permissions=frozenset(min_perms or ()),
        any_permissions=frozenset(any_perms or ()),
        edge_label=edge_label,
        edge_description=edge_description,
        edge_status=edge_status,
        destination_token_to_make=dest_token,
        destination_node_type_hint=destination_node_type_hint,
        allow_specific_resources=bool(allow_specific_resources),
    )


# -----------------------------------------------------------------------------
# ALLOW RULES (declarative tables)
# -----------------------------------------------------------------------------
ALLOW_MANAGE_SUMMARIES = (
    _STATIC_CONSTANTS_PAYLOAD.get("ALLOW_MANAGE_SUMMARIES")
    if isinstance(_STATIC_CONSTANTS_PAYLOAD.get("ALLOW_MANAGE_SUMMARIES"), dict)
    else {}
)
ALLOW_RULE_DEFS = (
    _STATIC_CONSTANTS_PAYLOAD.get("ALLOW_RULE_DEFS")
    if isinstance(_STATIC_CONSTANTS_PAYLOAD.get("ALLOW_RULE_DEFS"), list)
    else []
)

# Generated AllowEdgeRule list
def _normalize_allow_rule_def(d: dict) -> AllowEdgeRule:
    match = d.get("match") or {}
    dest = d.get("destination") or {}
    edge = d.get("edge") or {}
    pgk = d.get("principal_group_key") or "principals-non-service"

    # Allow multiple input aliases for convenience
    resource_tokens = match.get("resource_tokens") or match.get("resources") or match.get("resource")
    if isinstance(resource_tokens, str):
        resource_tokens = [resource_tokens]
    resource_tokens = [t for t in (resource_tokens or []) if isinstance(t, str) and t.strip()]

    verbs_all = match.get("verbs_all") or match.get("verbs") or ()
    verbs_any = match.get("verbs_any") or ()
    perms_all = match.get("permissions_all") or match.get("permissions") or match.get("perms") or ()
    perms_any = match.get("permissions_any") or match.get("perms_any") or ()
    if isinstance(verbs_all, str):
        verbs_all = [verbs_all]
    if isinstance(verbs_any, str):
        verbs_any = [verbs_any]
    if isinstance(perms_all, str):
        perms_all = [perms_all]
    if isinstance(perms_any, str):
        perms_any = [perms_any]

    dest_token = _s(dest.get("token") or "")
    if not resource_tokens and dest_token:
        resource_tokens = [dest_token]
    dest_node_type = _s(dest.get("node_type") or "OCIResourceGroup")
    allow_specific = bool(dest.get("allow_specific", True))

    return _allow(
        resource_tokens,
        min_verbs=verbs_all,
        any_verbs=verbs_any,
        min_perms=perms_all,
        any_perms=perms_any,
        edge_label=_s(edge.get("label") or ""),
        edge_description=_s(edge.get("description") or ""),
        edge_status=_s(edge.get("status") or ""),
        principal_group_key=pgk,
        destination_token_to_make=dest_token,
        destination_node_type_hint=dest_node_type,
        allow_specific_resources=allow_specific,
    )


DEFAULT_ALLOW_EDGE_RULES = tuple(_normalize_allow_rule_def(d) for d in (ALLOW_RULE_DEFS or []))
_PERMISSION_MAPPING_PATH = Path(__file__).resolve().parent / "data" / "permission_mapping.json"

def _load_permission_mapping():
    try:
        raw = json.loads(_PERMISSION_MAPPING_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}

PERMISSION_MAPPING = _load_permission_mapping()


_API_OPERATION_PERMISSIONS_PATH = Path(__file__).resolve().parent / "data" / "api_operation_permissions.json"

def _load_api_operation_permissions_payload():
    try:
        raw = json.loads(_API_OPERATION_PERMISSIONS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}

_API_OPERATION_PERMISSIONS_PAYLOAD = _load_api_operation_permissions_payload()

CORE_API_OPERATION_PERMISSIONS = _API_OPERATION_PERMISSIONS_PAYLOAD.get("CORE_API_OPERATION_PERMISSIONS") or {}
DNS_API_OPERATION_PERMISSIONS = _API_OPERATION_PERMISSIONS_PAYLOAD.get("DNS_API_OPERATION_PERMISSIONS") or {}
CONTAINER_REGISTRY_API_OPERATION_PERMISSIONS = _API_OPERATION_PERMISSIONS_PAYLOAD.get("CONTAINER_REGISTRY_API_OPERATION_PERMISSIONS") or {}
NETWORK_LOAD_BALANCER_API_OPERATION_PERMISSIONS = _API_OPERATION_PERMISSIONS_PAYLOAD.get("NETWORK_LOAD_BALANCER_API_OPERATION_PERMISSIONS") or {}
NOTIFICATIONS_API_OPERATION_PERMISSIONS = _API_OPERATION_PERMISSIONS_PAYLOAD.get("NOTIFICATIONS_API_OPERATION_PERMISSIONS") or {}
FUNCTIONS_API_OPERATION_PERMISSIONS = _API_OPERATION_PERMISSIONS_PAYLOAD.get("FUNCTIONS_API_OPERATION_PERMISSIONS") or {}
FILE_STORAGE_API_OPERATION_PERMISSIONS = _API_OPERATION_PERMISSIONS_PAYLOAD.get("FILE_STORAGE_API_OPERATION_PERMISSIONS") or {}
API_GATEWAY_API_OPERATION_PERMISSIONS = _API_OPERATION_PERMISSIONS_PAYLOAD.get("API_GATEWAY_API_OPERATION_PERMISSIONS") or {}
DEVOPS_API_OPERATION_PERMISSIONS = _API_OPERATION_PERMISSIONS_PAYLOAD.get("DEVOPS_API_OPERATION_PERMISSIONS") or {}
BASTION_API_OPERATION_PERMISSIONS = _API_OPERATION_PERMISSIONS_PAYLOAD.get("BASTION_API_OPERATION_PERMISSIONS") or {}
DESKTOPS_API_OPERATION_PERMISSIONS = _API_OPERATION_PERMISSIONS_PAYLOAD.get("DESKTOPS_API_OPERATION_PERMISSIONS") or {}


# Extra operation->permission mappings (smaller, service-specific add-ons).










# Ordered sources used by the conditional engine.
API_OPERATION_PERMISSION_SOURCES = (
    CORE_API_OPERATION_PERMISSIONS,
    DNS_API_OPERATION_PERMISSIONS,
    CONTAINER_REGISTRY_API_OPERATION_PERMISSIONS,
    NETWORK_LOAD_BALANCER_API_OPERATION_PERMISSIONS,
    NOTIFICATIONS_API_OPERATION_PERMISSIONS,
    FUNCTIONS_API_OPERATION_PERMISSIONS,
    FILE_STORAGE_API_OPERATION_PERMISSIONS,
    API_GATEWAY_API_OPERATION_PERMISSIONS,
    BASTION_API_OPERATION_PERMISSIONS,
    DESKTOPS_API_OPERATION_PERMISSIONS,
    DEVOPS_API_OPERATION_PERMISSIONS,
)


def _ensure_permission_mapping_entry(*, verb: str, service: str, resource_token: str, permissions):
    if not isinstance(PERMISSION_MAPPING, dict):
        return
    v = str(verb or "").strip().lower()
    s = str(service or "").strip()
    t = str(resource_token or "").strip()
    if not (v and s and t):
        return

    svc_map = PERMISSION_MAPPING.setdefault(v, {})
    if not isinstance(svc_map, dict):
        return
    res_map = svc_map.setdefault(s, {})
    if not isinstance(res_map, dict):
        return
    cur = res_map.setdefault(t, [])
    if not isinstance(cur, list):
        return

    seen = {p for p in cur if isinstance(p, str) and p}
    for p in (permissions or []):
        if not isinstance(p, str):
            continue
        p = p.strip()
        if not p or p in seen:
            continue
        cur.append(p)
        seen.add(p)


def _augment_tag_namespace_permissions():
    # Ensure tag namespace verb statements can resolve into TAG_NAMESPACE_* permissions.
    # This powers permission-aware allow rules such as OCI_USE_TAG_NAMESPACE.
    _ensure_permission_mapping_entry(
        verb="inspect",
        service="identity_tagging",
        resource_token="tag-namespaces",
        permissions=["TAG_NAMESPACE_INSPECT"],
    )
    _ensure_permission_mapping_entry(
        verb="read",
        service="identity_tagging",
        resource_token="tag-namespaces",
        permissions=["TAG_NAMESPACE_INSPECT", "TAG_NAMESPACE_READ"],
    )
    _ensure_permission_mapping_entry(
        verb="use",
        service="identity_tagging",
        resource_token="tag-namespaces",
        permissions=["TAG_NAMESPACE_INSPECT", "TAG_NAMESPACE_READ", "TAG_NAMESPACE_USE"],
    )
    _ensure_permission_mapping_entry(
        verb="manage",
        service="identity_tagging",
        resource_token="tag-namespaces",
        permissions=[
            "TAG_NAMESPACE_INSPECT",
            "TAG_NAMESPACE_READ",
            "TAG_NAMESPACE_USE",
            "TAG_NAMESPACE_CREATE",
            "TAG_NAMESPACE_DELETE",
        ],
    )


_augment_tag_namespace_permissions()
