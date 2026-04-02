#!/usr/bin/env python3
"""
iam_policy_advanced_relation_graph_builder.py

Post-processing derived IAM edges from raw IAM statement graph.

Design intent:
  - Keep iam_policy_base_relation_graph_builder focused on raw policy semantics.
  - Derive multi-permission consequences in a separate pass.
  - Emit only evidence-backed edges (no hypothetical assumptions).
  - Consume post-conditional relation entries emitted by iam_policy_base_relation_graph_builder
    (`ctx.iam_postprocess_relation_entries`) to avoid policy re-parse/reconstruction.

Current derived edges:
  - OCI_UPDATED_ACCESS_TO_ALL_RESOURCES
    Derived shortcut emitted only when UPDATE_POLICY can be traced from
    statement -> policies@loc (or statement -> specific policy) and from
    policies@loc -> specific policy target (for scope-based updates):
      <existing_policy_ocid> -> all-resources@loc
    Edge is marked with `derived_shortcut=true`.
  - OCI_CAN_CREATE_POLICY + OCI_POLICY_CAN_GRANT_ALL_RESOURCES
    Requires OCI_CREATE_POLICY for the same principal and location and emits:
      OCIPolicyStatement -> NEW_POLICY@loc -> all-resources@loc
  - OCI_CREATE_INSTANCE scope + INSTANCE_CAN_JOIN_DG
    Requires OCI_CREATE_INSTANCE prerequisites for a location and emits:
      OCIPolicyStatement -> NEW_INSTANCE_<short>@<loc>
      NEW_INSTANCE_<short>@<loc> -> dynamic-group
    when matching_rules_engine confirms permission+location compatibility
    (`INSTANCE_CREATE`, location).
  - OCI_ADD_SELF_TO_GROUP
    Requires `USER_UPDATE` capability on self plus `GROUP_UPDATE` (or `manage groups`)
    in the same location and emits:
      principal-user -> groups@loc and/or principal-user -> specific-group
  - OCI_RUN_COMMAND
    Requires OCI_CREATE_INSTANCE_AGENT_COMMAND and emits
    statement/principal -> NEW_AGENT_COMMAND@loc.
    From NEW_AGENT_COMMAND@loc, instance-target edges are emitted only when
    Run Command plugin state is:
      - enabled/true, or
      - unknown
    and skipped when plugin state is explicitly disabled/false or known absent.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import json
import re

from ocinferno.modules.opengraph.utilities.helpers import (
    build_edge_properties as _build_edge_properties,
    dlog as _dlog,
    EDGE_CATEGORY_GROUP_MEMBERSHIP,
    EDGE_CATEGORY_PERMISSION,
    EDGE_CATEGORY_RESOURCE,
    edge_row_with_flattened_properties as _edge_row_with_flattened_properties,
    get_og_state as _og_shared,
    json_list as _json_list,
    merge_statement_entries as _merge_statement_entries,
    node_properties_from_row as _node_properties_from_row,
    scope_token_loc as _scope_token_loc,
    statement_policy_ids as _statement_policy_ids,
    statement_texts as _statement_texts,
    s as _s,
)
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    EDGE_TYPE_OCI_DYNAMIC_GROUP_MEMBER,
    EDGE_TYPE_OCI_GROUP_MEMBER,
    NODE_TYPE_OCI_GENERIC_RESOURCE,
    NODE_TYPE_OCI_DYNAMIC_GROUP,
    NODE_TYPE_OCI_GROUP,
    NODE_TYPE_OCI_USER,
)
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import (
    emit_edge as _emit_edge_shared,
    ensure_new_compute_instance_candidate_node as _ensure_new_compute_instance_candidate_node_shared,
    ensure_node as _ensure_node_shared,
    ensure_scoped_node as _ensure_scoped_node_shared,
)
from ocinferno.modules.opengraph.utilities.helpers.matching_rules_engine import (
    DynamicGroupPermissionLocationMatcher,
    DynamicGroupRuleEvaluator,
)

# -----------------------------------------------------------------------------
# Constants and edge/node taxonomy used by this derived pass
# -----------------------------------------------------------------------------
# These values define the raw edge inputs we consume and the derived edge/node
# labels this module is allowed to emit.

EDGE_UPDATE_GROUP = "OCI_UPDATE_GROUP"
EDGE_GROUP_UPDATE = "OCI_GROUP_UPDATE"
EDGE_MANAGE = "OCI_MANAGE"
EDGE_INTERNAL_USER_UPDATE = "OCI_INTERNAL_USER_UPDATE"
EDGE_INTERNAL_GROUP_UPDATE = "OCI_INTERNAL_GROUP_UPDATE"
EDGE_UPDATE_POLICY = "OCI_UPDATE_POLICY"
EDGE_CREATE_POLICY = "OCI_CREATE_POLICY"
EDGE_CREATE_INSTANCE = "OCI_CREATE_INSTANCE"
EDGE_USE_TAG_NAMESPACE = "OCI_USE_TAG_NAMESPACE"
EDGE_CREATE_INSTANCE_AGENT_COMMAND = "OCI_CREATE_INSTANCE_AGENT_COMMAND"
EDGE_READ_RUN_INPUT = "OCI_READ_RUN_INPUT"
EDGE_READ_RUN_OUTPUT = "OCI_READ_RUN_OUTPUT"
EDGE_UPDATED_ACCESS_TO_ALL_RESOURCES = "OCI_UPDATED_ACCESS_TO_ALL_RESOURCES"
EDGE_CAN_CREATE_POLICY = "OCI_CAN_CREATE_POLICY"
EDGE_POLICY_CAN_GRANT_ALL_RESOURCES = "OCI_POLICY_CAN_GRANT_ALL_RESOURCES"
# Use a single public edge label for instance-creation capability.
# Raw/base edges are statement-scoped; derived edges are principal-scoped.
EDGE_CAN_CREATE_INSTANCE = EDGE_CREATE_INSTANCE
EDGE_DYNAMIC_GROUP_MEMBER = EDGE_TYPE_OCI_DYNAMIC_GROUP_MEMBER
EDGE_INSTANCE_CAN_JOIN_DG = "INSTANCE_CAN_JOIN_DG"
EDGE_ADD_SELF_TO_GROUP = "OCI_ADD_SELF_TO_GROUP"
EDGE_RUN_COMMAND = "OCI_RUN_COMMAND"
EDGE_SCOPE_INCLUDES = "OCI_SPECIFIC_RESOURCE"
EDGE_BELONGS_TO = "OCI_BELONGS_TO"
NODE_DYNAMIC_GROUP = NODE_TYPE_OCI_DYNAMIC_GROUP
NODE_USER = NODE_TYPE_OCI_USER
NODE_GROUP = NODE_TYPE_OCI_GROUP
NODE_NEW_POLICY = "OCINewPolicy"
NODE_NEW_COMPUTE_INSTANCE = "OCINewComputeInstance"
NODE_NEW_INSTANCE_AGENT_COMMAND = "OCINewInstanceAgentCommand"
_NEW_INSTANCE_SCOPE_TOKENS = {"new-compute-instance", "new-compute-instances"}
_NEW_POLICY_SCOPE_TOKENS = {
    "new-policy",
    "new-policies",
    "new_policy",
    "new_policies",
}
CAPABILITY_EDGE_TYPES = {
    EDGE_UPDATE_GROUP,
    EDGE_GROUP_UPDATE,
    EDGE_MANAGE,
    EDGE_INTERNAL_USER_UPDATE,
    EDGE_INTERNAL_GROUP_UPDATE,
    EDGE_UPDATE_POLICY,
    EDGE_CREATE_POLICY,
    EDGE_CREATE_INSTANCE,
    EDGE_USE_TAG_NAMESPACE,
    EDGE_CREATE_INSTANCE_AGENT_COMMAND,
    EDGE_READ_RUN_INPUT,
    EDGE_READ_RUN_OUTPUT,
}
_KEEP_ORPHAN_NEW_SCOPE_EDGE_TYPES = {
    "IDD_CREATE_USER",
    "OCI_CREATE_INSTANCE",
    "OCI_CREATE_INSTANCE_AGENT_COMMAND",
}
_SPECIFIC_DEST_TYPE_FOR_LOC_INFERENCE = {
    EDGE_UPDATE_POLICY: "OCIPolicy",
    EDGE_CREATE_INSTANCE: NODE_NEW_COMPUTE_INSTANCE,
}
NODE_COLUMNS = [
    "node_id",
    "node_properties",
]

EDGE_COLUMNS = [
    "source_id",
    "destination_id",
    "edge_type",
    "edge_properties",
]

PRINCIPAL_NODE_TYPES = {
    NODE_USER,
    NODE_GROUP,
    NODE_DYNAMIC_GROUP,
    "OCIAnyUser",
    "OCIAnyGroup",
    "OCIPrincipal",
}

SKIP_PRINCIPAL_NODE_TYPES = {
    "OCIService",
}


# -----------------------------------------------------------------------------
# Capability state model
# -----------------------------------------------------------------------------
# One principal+location relation bucket accumulated from raw IAM edges.

@dataclass(slots=True)
class _RelationState:
    source_type: str = "OCIPrincipal"
    user_scope: bool = False
    user_self_specific: bool = False
    group_scope: bool = False
    update_policy_scope: bool = False
    create_policy_scope: bool = False
    create_instance_scope: bool = False
    create_instance_has_instance_create: bool = False
    create_instance_has_vnic_prereqs: bool = False
    create_instance_has_subnet_prereqs: bool = False
    create_instance_resolved_statements: list = field(default_factory=list)
    create_instance_unresolved_statements: list = field(default_factory=list)
    use_tag_namespace_scope: bool = False
    use_tag_namespace_specific_ids: set[str] = field(default_factory=set)
    use_tag_namespace_resolved_statements: list = field(default_factory=list)
    use_tag_namespace_unresolved_statements: list = field(default_factory=list)
    create_instance_agent_command_scope: bool = False
    create_instance_agent_command_resolved_statements: list = field(default_factory=list)
    create_instance_agent_command_unresolved_statements: list = field(default_factory=list)
    read_run_input_scope: bool = False
    read_run_output_scope: bool = False
    read_instance_agent_command_execution_scope: bool = False
    specific_groups: set[str] = field(default_factory=set)
    update_policy_specific_policies: set[str] = field(default_factory=set)
    update_policy_resolved_statements: list = field(default_factory=list)
    update_policy_unresolved_statements: list = field(default_factory=list)
    create_policy_resolved_statements: list = field(default_factory=list)
    create_policy_unresolved_statements: list = field(default_factory=list)

    resolved_statements: list = field(default_factory=list)
    unresolved_statements: list = field(default_factory=list)
    has_unresolved_conditionals: bool = False
    has_impossible_conditionals: bool = False
    has_inherited: bool = False
    has_direct: bool = False


# -----------------------------------------------------------------------------
# Generic parsing/merge helpers
# -----------------------------------------------------------------------------
# Small, reusable normalizers for node/edge payloads and statement metadata.

def _edge_node_type(edge_row: dict, node_type_by_id: dict, *, endpoint: str) -> str:
    node_id = _s(edge_row.get(f"{endpoint}_id") or "")
    return _s(node_type_by_id.get(node_id) or edge_row.get(f"{endpoint}_type") or "")


def _load_dynamic_group_membership_edges(session):
    """
    Load dynamic-group membership edges for existing resources.
    Used to derive principal -> dynamic-group paths from instance-agent command
    execution capability against already-matching compute instances.
    """
    try:
        rows = session.get_resource_fields(
            "opengraph_edges",
            columns=EDGE_COLUMNS,
            where_conditions={"edge_type": EDGE_DYNAMIC_GROUP_MEMBER},
        ) or []
    except Exception:
        return []
    return [_edge_row_with_flattened_properties(r) for r in rows if isinstance(r, dict)]


# -----------------------------------------------------------------------------
# Principal inventory helpers
# -----------------------------------------------------------------------------
# Resolve group/dynamic-group inventories from already-materialized OpenGraph nodes.

def _collect_group_dynamic_inventory_from_nodes(*, node_rows, node_type_by_id, node_compartment_by_id):
    """
    Returns:
      - groups_by_loc: {compartment_id -> set(group_id)}
      - dynamic_group_rows: [{"id","matching_rule","compartment_id"}, ...]
    """
    groups_by_loc = defaultdict(set)
    dynamic_group_rows = []

    for row in node_rows:
        if not isinstance(row, dict):
            continue
        nid = _s(row.get("node_id") or "")
        if not nid:
            continue
        ntype = _s(node_type_by_id.get(nid) or "")
        if ntype not in {NODE_GROUP, NODE_DYNAMIC_GROUP}:
            continue

        props = _node_properties_from_row(row)
        loc = _s(
            node_compartment_by_id.get(nid)
            or props.get("compartment_id")
            or props.get("compartment_ocid")
            or ""
        )
        if ntype == NODE_GROUP:
            if loc:
                groups_by_loc[loc].add(nid)
            continue

        dynamic_group_rows.append(
            {
                "id": nid,
                "matching_rule": _s(props.get("matching_rule") or ""),
                "compartment_id": loc,
            }
        )

    return groups_by_loc, dynamic_group_rows


def _display_loc(*, ctx, loc: str) -> str:
    return _s((getattr(ctx, "compartment_name_by_id", {}) or {}).get(loc) or loc)

# -----------------------------------------------------------------------------
# Capability extraction from raw graph edges
# -----------------------------------------------------------------------------
# Convert raw edge graph into principal+location relation buckets.

def _merge_relation_metadata(cap: _RelationState, edge_row: dict):
    resolved = _json_list(edge_row.get("resolved_statement_details"))
    unresolved = _json_list(edge_row.get("unresolved_statement_details"))
    if not resolved:
        resolved = _json_list(edge_row.get("resolved_statements"))
    if not unresolved:
        unresolved = _json_list(edge_row.get("unresolved_statements"))

    cap.resolved_statements = _merge_statement_entries(cap.resolved_statements, resolved)
    cap.unresolved_statements = _merge_statement_entries(cap.unresolved_statements, unresolved)

    cap.has_unresolved_conditionals = cap.has_unresolved_conditionals or bool(edge_row.get("has_unresolved_conditionals"))
    cap.has_impossible_conditionals = cap.has_impossible_conditionals or bool(edge_row.get("has_impossible_conditionals"))
    cap.has_inherited = cap.has_inherited or bool(edge_row.get("has_inherited"))
    cap.has_direct = cap.has_direct or bool(edge_row.get("has_direct"))


_INSTANCE_CREATE_REQUIRED_INSTANCE_PERMS = {"INSTANCE_CREATE"}
_INSTANCE_CREATE_REQUIRED_VNIC_PERMS = {"VNIC_CREATE", "VNIC_ATTACH"}
_INSTANCE_CREATE_REQUIRED_SUBNET_PERMS = {"SUBNET_READ", "SUBNET_ATTACH"}
_USER_UPDATE_PERMISSION = "USER_UPDATE"
_GROUP_UPDATE_PERMISSION = "GROUP_UPDATE"
_INSTANCE_CREATE_PERMISSION_TOKENS = (
    _INSTANCE_CREATE_REQUIRED_INSTANCE_PERMS
    | _INSTANCE_CREATE_REQUIRED_VNIC_PERMS
    | _INSTANCE_CREATE_REQUIRED_SUBNET_PERMS
)


def _extract_upper_permissions_from_statement_texts(texts, *, candidates: set[str] | None = None) -> set[str]:
    targets = set(candidates or _INSTANCE_CREATE_PERMISSION_TOKENS)
    if not targets:
        return set()
    found = set()
    for raw in (texts or []):
        txt = _s(raw).upper()
        if not txt:
            continue
        for perm in targets:
            if re.search(rf"(?<![A-Z0-9_]){perm}(?![A-Z0-9_])", txt):
                found.add(perm)
    return found


def _edge_statement_texts(edge_row: dict) -> list[str]:
    resolved_items = (
        _json_list(edge_row.get("resolved_statement_details"))
        or _json_list(edge_row.get("resolved_statements"))
        or []
    )
    unresolved_items = (
        _json_list(edge_row.get("unresolved_statement_details"))
        or _json_list(edge_row.get("unresolved_statements"))
        or []
    )
    return _statement_texts(resolved_items) + _statement_texts(unresolved_items)


def _statement_grants_permission_or_manage_resource(
    texts,
    *,
    permission: str,
    manage_resource_keyword: str,
) -> bool:
    perm = _s(permission).upper()
    res_kw = _s(manage_resource_keyword).upper()
    if not (perm and res_kw):
        return False
    perms_found = _extract_upper_permissions_from_statement_texts(texts, candidates={perm})
    if perm in perms_found:
        return True
    # Manage-verb fallback for statements like: "Allow ... to manage groups ..."
    pattern = rf"(?<![A-Z0-9_])MANAGE(?![A-Z0-9_])\s+{re.escape(res_kw)}(?![A-Z0-9_])"
    return any(re.search(pattern, _s(t).upper() or "") for t in (texts or []))


def _mark_create_instance_prereqs_from_edge(cap: _RelationState, edge_row: dict) -> None:
    stmt_texts = _edge_statement_texts(edge_row)
    perms_found = _extract_upper_permissions_from_statement_texts(stmt_texts)
    if not perms_found:
        return
    cap.create_instance_has_instance_create = (
        cap.create_instance_has_instance_create
        or _INSTANCE_CREATE_REQUIRED_INSTANCE_PERMS.issubset(perms_found)
    )
    cap.create_instance_has_vnic_prereqs = (
        cap.create_instance_has_vnic_prereqs
        or _INSTANCE_CREATE_REQUIRED_VNIC_PERMS.issubset(perms_found)
    )
    cap.create_instance_has_subnet_prereqs = (
        cap.create_instance_has_subnet_prereqs
        or _INSTANCE_CREATE_REQUIRED_SUBNET_PERMS.issubset(perms_found)
    )


def _upsert_relation_from_edge(
    *,
    relation_map: dict,
    principal_id: str,
    principal_type: str,
    edge_row: dict,
    node_type_by_id: dict,
    node_compartment_by_id: dict,
    explicit_loc: str = "",
    explicit_token: str = "",
):
    et = _s(edge_row.get("edge_type"))
    if et not in CAPABILITY_EDGE_TYPES:
        return None

    dst = _s(edge_row.get("destination_id") or "")
    dst_type = _edge_node_type(edge_row, node_type_by_id, endpoint="destination")

    token, loc = _scope_token_loc(dst)
    token = _s(token or explicit_token)
    loc = _s(loc or explicit_loc)
    if not loc:
        expected_dst_type = _SPECIFIC_DEST_TYPE_FOR_LOC_INFERENCE.get(et)
        if expected_dst_type and dst_type == expected_dst_type:
            loc = _s(node_compartment_by_id.get(dst) or "")

    if not loc:
        return None

    key = (principal_id, loc)
    cap = relation_map.get(key)
    if cap is None:
        cap = _RelationState(source_type=_s(principal_type) or "OCIPrincipal")
        relation_map[key] = cap
    elif not cap.source_type and principal_type:
        cap.source_type = principal_type

    if et in {EDGE_UPDATE_GROUP, EDGE_GROUP_UPDATE}:
        if token == "groups":
            cap.group_scope = True
        if dst_type == NODE_GROUP and _s(dst):
            cap.specific_groups.add(_s(dst))
    elif et == EDGE_INTERNAL_USER_UPDATE:
        if token == "users":
            cap.user_scope = True
        if dst_type == NODE_USER and _s(principal_type) == NODE_USER and dst == principal_id:
            cap.user_self_specific = True
    elif et == EDGE_INTERNAL_GROUP_UPDATE:
        if token == "groups":
            cap.group_scope = True
        if dst_type == NODE_GROUP and _s(dst):
            cap.specific_groups.add(_s(dst))
    elif et == EDGE_MANAGE:
        stmt_texts = _edge_statement_texts(edge_row)
        grants_user_update = _statement_grants_permission_or_manage_resource(
            stmt_texts,
            permission=_USER_UPDATE_PERMISSION,
            manage_resource_keyword="users",
        )
        grants_group_update = _statement_grants_permission_or_manage_resource(
            stmt_texts,
            permission=_GROUP_UPDATE_PERMISSION,
            manage_resource_keyword="groups",
        )

        if grants_user_update and (token == "users" or dst_type == NODE_USER):
            if token == "users":
                cap.user_scope = True
            if dst_type == NODE_USER and _s(principal_type) == NODE_USER and dst == principal_id:
                cap.user_self_specific = True

        if grants_group_update and (token == "groups" or dst_type == NODE_GROUP):
            if token == "groups":
                cap.group_scope = True
            if dst_type == NODE_GROUP and _s(dst):
                cap.specific_groups.add(_s(dst))

    elif et == EDGE_UPDATE_POLICY:
        if token == "policies" or dst_type == "OCIPolicy":
            cap.update_policy_scope = True
            if dst_type == "OCIPolicy" and _s(dst):
                cap.update_policy_specific_policies.add(_s(dst))
            cap.update_policy_resolved_statements = _merge_statement_entries(
                list(cap.update_policy_resolved_statements),
                list(
                    _json_list(edge_row.get("resolved_statement_details"))
                    or _json_list(edge_row.get("resolved_statements"))
                    or []
                ),
            )
            cap.update_policy_unresolved_statements = _merge_statement_entries(
                list(cap.update_policy_unresolved_statements),
                list(
                    _json_list(edge_row.get("unresolved_statement_details"))
                    or _json_list(edge_row.get("unresolved_statements"))
                    or []
                ),
            )
    elif et == EDGE_CREATE_POLICY:
        if (
            token in _NEW_POLICY_SCOPE_TOKENS
            or token.startswith("new-policy")
            or token.startswith("new_policy")
        ):
            cap.create_policy_scope = True
            cap.create_policy_resolved_statements = _merge_statement_entries(
                list(cap.create_policy_resolved_statements),
                list(
                    _json_list(edge_row.get("resolved_statement_details"))
                    or _json_list(edge_row.get("resolved_statements"))
                    or []
                ),
            )
            cap.create_policy_unresolved_statements = _merge_statement_entries(
                list(cap.create_policy_unresolved_statements),
                list(
                    _json_list(edge_row.get("unresolved_statement_details"))
                    or _json_list(edge_row.get("unresolved_statements"))
                    or []
                ),
            )
    elif et == EDGE_CREATE_INSTANCE:
        if token in _NEW_INSTANCE_SCOPE_TOKENS or token.startswith("new-compute-instance"):
            cap.create_instance_scope = True
            _mark_create_instance_prereqs_from_edge(cap, edge_row)
            cap.create_instance_resolved_statements = _merge_statement_entries(
                list(cap.create_instance_resolved_statements),
                list(
                    _json_list(edge_row.get("resolved_statement_details"))
                    or _json_list(edge_row.get("resolved_statements"))
                    or []
                ),
            )
            cap.create_instance_unresolved_statements = _merge_statement_entries(
                list(cap.create_instance_unresolved_statements),
                list(
                    _json_list(edge_row.get("unresolved_statement_details"))
                    or _json_list(edge_row.get("unresolved_statements"))
                    or []
                ),
            )
    elif et == EDGE_USE_TAG_NAMESPACE:
        scope_token, _scope_loc = _scope_token_loc(dst)
        is_tag_namespace_target = (
            token in {"tag-namespaces", "tag-namespace-family"}
            or scope_token in {"tag-namespaces", "tag-namespace-family"}
            or dst_type == "OCITagNamespace"
            or (dst and dst.startswith("ocid1.tagnamespace."))
        )
        if is_tag_namespace_target:
            cap.use_tag_namespace_scope = True
            cap.use_tag_namespace_resolved_statements = _merge_statement_entries(
                list(cap.use_tag_namespace_resolved_statements),
                list(
                    _json_list(edge_row.get("resolved_statement_details"))
                    or _json_list(edge_row.get("resolved_statements"))
                    or []
                ),
            )
            cap.use_tag_namespace_unresolved_statements = _merge_statement_entries(
                list(cap.use_tag_namespace_unresolved_statements),
                list(
                    _json_list(edge_row.get("unresolved_statement_details"))
                    or _json_list(edge_row.get("unresolved_statements"))
                    or []
                ),
            )
            if dst and dst.startswith("ocid1.tagnamespace."):
                cap.use_tag_namespace_specific_ids.add(dst)
    elif et == EDGE_CREATE_INSTANCE_AGENT_COMMAND:
        if token in {"instance-agent-commands", "instance-agent-command-family"}:
            cap.create_instance_agent_command_scope = True
            cap.create_instance_agent_command_resolved_statements = _merge_statement_entries(
                list(cap.create_instance_agent_command_resolved_statements),
                list(
                    _json_list(edge_row.get("resolved_statement_details"))
                    or _json_list(edge_row.get("resolved_statements"))
                    or []
                ),
            )
            cap.create_instance_agent_command_unresolved_statements = _merge_statement_entries(
                list(cap.create_instance_agent_command_unresolved_statements),
                list(
                    _json_list(edge_row.get("unresolved_statement_details"))
                    or _json_list(edge_row.get("unresolved_statements"))
                    or []
                ),
            )
    elif et in {EDGE_READ_RUN_INPUT, EDGE_READ_RUN_OUTPUT}:
        if token in {
            "instance-agent-commands",
            "instance-agent-command-family",
            "instance-agent-command-execution-family",
            "instance-agent-command-executions",
        }:
            if et == EDGE_READ_RUN_INPUT:
                cap.read_run_input_scope = True
            else:
                cap.read_run_output_scope = True
                cap.read_instance_agent_command_execution_scope = True

    _merge_relation_metadata(cap, edge_row)
    return cap


def _entry_field(entry, key: str, default=None):
    """Read a field from dict or dataclass-like relation entry."""
    if isinstance(entry, dict):
        return entry.get(key, default)
    return getattr(entry, key, default)


def _collect_relation_map_from_entries(
    *,
    relation_entries,
    node_type_by_id,
    node_compartment_by_id,
):
    """
    Build relation buckets from flattened post-conditional relation entries.

    Input shape per entry (from iam_policy_base_relation_graph_builder):
      {
        "principal_id": "...",
        "principal_type": "OCIUser|OCIGroup|...",
        "loc": "ocid1.compartment...",
        "dest_token": "users|groups|...",
        "edge_type": "OCI_*|...",
        "destination_id": "...",
        "destination_type": "...",
        "resolved_statements": [...],
        "unresolved_statements": [...],
        "resolved_statement_details": [...],
        "unresolved_statement_details": [...],
        "has_unresolved_conditionals": bool,
        "has_impossible_conditionals": bool,
        "has_inherited": bool,
        "has_direct": bool,
      }

    Output shape:
      {
        (principal_id, loc): _RelationState(...)
      }
    """
    relation_map = {}
    for entry in relation_entries:
        principal_id = _s(_entry_field(entry, "principal_id") or "")
        principal_type = _s(_entry_field(entry, "principal_type") or "")
        if not (
            principal_id
            and principal_type
            and principal_type in PRINCIPAL_NODE_TYPES
            and principal_type not in SKIP_PRINCIPAL_NODE_TYPES
        ):
            continue
        edge_row = {
            "edge_type": _s(_entry_field(entry, "edge_type") or ""),
            "destination_id": _s(_entry_field(entry, "destination_id") or ""),
            "destination_type": _s(_entry_field(entry, "destination_type") or ""),
            "resolved_statements": _entry_field(entry, "resolved_statements") or [],
            "unresolved_statements": _entry_field(entry, "unresolved_statements") or [],
            "resolved_policy": _entry_field(entry, "resolved_policy") or [],
            "unresolved_policy": _entry_field(entry, "unresolved_policy") or [],
            "resolved_statement_details": _entry_field(entry, "resolved_statement_details") or [],
            "unresolved_statement_details": _entry_field(entry, "unresolved_statement_details") or [],
            "has_unresolved_conditionals": bool(_entry_field(entry, "has_unresolved_conditionals")),
            "has_impossible_conditionals": bool(_entry_field(entry, "has_impossible_conditionals")),
            "has_inherited": bool(_entry_field(entry, "has_inherited")),
            "has_direct": bool(_entry_field(entry, "has_direct")),
        }
        _upsert_relation_from_edge(
            relation_map=relation_map,
            principal_id=principal_id,
            principal_type=principal_type,
            edge_row=edge_row,
            node_type_by_id=node_type_by_id,
            node_compartment_by_id=node_compartment_by_id,
            explicit_loc=_s(_entry_field(entry, "loc") or ""),
            explicit_token=_s(_entry_field(entry, "dest_token") or ""),
        )
    return relation_map


# -----------------------------------------------------------------------------
# Derived edge emitters
# -----------------------------------------------------------------------------
# Emit derived edges from relation buckets (email/policy/instance/pivot/group).

@dataclass(slots=True)
class _DerivedEmitContext:
    ctx: object
    existing_edges: set
    existing_nodes: set
    node_type_by_id: dict
    node_compartment_by_id: dict
    groups_by_loc: dict
    dynamic_group_rows: list
    compute_instance_name_by_id: dict
    compute_instances_by_loc: dict
    instance_agent_commands_by_loc: dict
    instance_target_ids_by_command: dict
    run_command_plugin_state_by_instance_by_loc: dict
    plugin_telemetry_present_by_loc: set
    instance_to_dynamic_groups_by_loc: dict
    dgs_with_compute_members_by_loc: dict
    dg_permission_location_matcher: object
    dg_instance_create_matches_by_loc: dict
    relation_map: dict
    policy_nodes_by_loc: dict
    policy_update_capability_by_principal_loc: set


def _collect_policy_update_capability_keys(relation_entries) -> set[tuple[str, str]]:
    """
    Build {(principal_id, loc)} keys where advanced can infer update-policy
    capability from base relation entries.
    """
    out = set()
    for entry in relation_entries or []:
        principal_id = _s(_entry_field(entry, "principal_id") or "")
        loc = _s(_entry_field(entry, "loc") or "")
        edge_type = _s(_entry_field(entry, "edge_type") or "")
        if not (principal_id and loc and edge_type == EDGE_UPDATE_POLICY):
            continue

        destination_type = _s(_entry_field(entry, "destination_type") or "")
        destination_id = _s(_entry_field(entry, "destination_id") or "")
        dest_token = _s(_entry_field(entry, "dest_token") or "").lower()
        scope_token, _scope_loc = _scope_token_loc(destination_id)
        scope_token = _s(scope_token).lower()

        if destination_type == "OCIPolicy" or dest_token == "policies" or scope_token == "policies":
            out.add((principal_id, loc))
    return out


def _collect_statement_instance_agent_caps(*, session, node_type_by_id: dict) -> dict:
    """
    Build {(statement_id, loc): _RelationState} for statement-scoped instance-agent
    command capabilities directly from raw statement->scope edges.
    This avoids dependency on subject-resolution for emitting NEW_COMMAND paths.
    """
    out = {}
    try:
        rows = session.get_resource_fields("opengraph_edges", columns=EDGE_COLUMNS) or []
    except Exception:
        return out

    for raw in rows:
        if not isinstance(raw, dict):
            continue
        row = _edge_row_with_flattened_properties(raw)
        et = _s(row.get("edge_type") or "")
        if et not in {
            EDGE_CREATE_INSTANCE_AGENT_COMMAND,
            EDGE_READ_RUN_INPUT,
            EDGE_READ_RUN_OUTPUT,
        }:
            continue

        src_id = _s(row.get("source_id") or "")
        if not src_id:
            continue
        src_type = _s(node_type_by_id.get(src_id) or row.get("source_type") or "")
        if src_type != "OCIPolicyStatement":
            continue

        dst_id = _s(row.get("destination_id") or "")
        token, loc = _scope_token_loc(dst_id)
        token_l = _s(token).lower()
        loc = _s(loc)
        if token_l not in {
            "instance-agent-commands",
            "instance-agent-command-family",
            "instance-agent-command-execution-family",
            "instance-agent-command-executions",
        }:
            continue
        if not loc:
            continue

        key = (src_id, loc)
        cap = out.get(key)
        if cap is None:
            cap = _RelationState(source_type="OCIPolicyStatement")
            out[key] = cap

        if et == EDGE_CREATE_INSTANCE_AGENT_COMMAND:
            cap.create_instance_agent_command_scope = True
            cap.create_instance_agent_command_resolved_statements = _merge_statement_entries(
                list(cap.create_instance_agent_command_resolved_statements),
                list(
                    _json_list(row.get("resolved_statement_details"))
                    or _json_list(row.get("resolved_statements"))
                    or []
                ),
            )
            cap.create_instance_agent_command_unresolved_statements = _merge_statement_entries(
                list(cap.create_instance_agent_command_unresolved_statements),
                list(
                    _json_list(row.get("unresolved_statement_details"))
                    or _json_list(row.get("unresolved_statements"))
                    or []
                ),
            )
        elif et in {EDGE_READ_RUN_INPUT, EDGE_READ_RUN_OUTPUT}:
            if et == EDGE_READ_RUN_INPUT:
                cap.read_run_input_scope = True
            else:
                cap.read_run_output_scope = True
                cap.read_instance_agent_command_execution_scope = True

        _merge_relation_metadata(cap, row)

    return out


def _base_edge_kwargs(cap: _RelationState) -> dict:
    return {
        "resolved_statements": cap.resolved_statements,
        "unresolved_statements": cap.unresolved_statements,
        "has_unresolved_conditionals": cap.has_unresolved_conditionals,
        "has_impossible_conditionals": cap.has_impossible_conditionals,
        "has_inherited": cap.has_inherited,
        "has_direct": cap.has_direct,
    }


def _merged_edge_kwargs(cap_a: _RelationState, cap_b: _RelationState) -> dict:
    return {
        "resolved_statements": _merge_statement_entries(
            list(cap_a.resolved_statements),
            list(cap_b.resolved_statements),
        ),
        "unresolved_statements": _merge_statement_entries(
            list(cap_a.unresolved_statements),
            list(cap_b.unresolved_statements),
        ),
        "has_unresolved_conditionals": (
            cap_a.has_unresolved_conditionals or cap_b.has_unresolved_conditionals
        ),
        "has_impossible_conditionals": (
            cap_a.has_impossible_conditionals or cap_b.has_impossible_conditionals
        ),
        "has_inherited": (cap_a.has_inherited or cap_b.has_inherited),
        "has_direct": (cap_a.has_direct or cap_b.has_direct),
    }


def _create_instance_prereq_state(*, cap: _RelationState) -> dict:
    return {
        "instances": bool(cap.create_instance_has_instance_create),
        "vnics": bool(cap.create_instance_has_vnic_prereqs),
        "subnets": bool(cap.create_instance_has_subnet_prereqs),
    }


def _resource_targets_for_launch_prereqs(*, loc: str) -> dict:
    loc = _s(loc)
    instances_scope = f"instances@{loc}" if loc else "instances"
    vnics_scope = f"vnics@{loc}" if loc else "vnics"
    subnets_scope = f"subnets@{loc}" if loc else "subnets"
    return {
        "INSTANCE_CREATE": instances_scope,
        "VNIC_CREATE": vnics_scope,
        "VNIC_ATTACH": vnics_scope,
        "SUBNET_READ": subnets_scope,
        "SUBNET_ATTACH": subnets_scope,
    }


def _looks_like_instance_ocid(value: str) -> bool:
    value = _s(value)
    return bool(value and value.startswith("ocid1.instance."))


def _plugin_is_run_command(props: dict) -> bool:
    if not isinstance(props, dict):
        return False
    name = _s(props.get("name") or props.get("plugin_name") or "")
    return bool(name and "RUN COMMAND" in name.upper())


def _plugin_state_from_props(props: dict) -> str:
    """
    Tri-state plugin interpretation:
      - "true"    => plugin is enabled/runnable
      - "false"   => plugin is explicitly disabled/stopped/not supported
      - "unknown" => plugin exists but enablement cannot be determined
    """
    if not isinstance(props, dict):
        return "unknown"

    # Optional explicit booleans from raw payloads.
    for key in ("is_enabled", "enabled", "isEnabled"):
        if key in props:
            v = props.get(key)
            if isinstance(v, bool):
                return "true" if v else "false"
            s = _s(v).strip().lower()
            if s in {"true", "1", "yes", "on"}:
                return "true"
            if s in {"false", "0", "no", "off"}:
                return "false"

    status = _s(props.get("status") or "").strip().upper()
    desired = _s(props.get("desired_state") or "").strip().upper()

    false_states = {"DISABLED", "STOPPED", "OFF", "NOT_SUPPORTED", "UNAVAILABLE", "INACTIVE"}
    true_states = {"RUNNING", "ENABLED", "ACTIVE"}

    if desired in false_states or status in false_states:
        return "false"
    if desired in true_states or status in true_states:
        return "true"
    return "unknown"


def _merge_plugin_state(current: str, new: str) -> str:
    current = _s(current).strip().lower()
    new = _s(new).strip().lower()
    if current == "false" or new == "false":
        return "false"
    if current == "true" or new == "true":
        return "true"
    return "unknown"


def _instance_run_command_plugin_state(*, emit_ctx: _DerivedEmitContext, loc: str, instance_id: str) -> str:
    """
    Returns one of:
      - "true"     : enabled
      - "false"    : explicitly disabled/stopped/not supported
      - "unknown"  : no telemetry for location OR telemetry indeterminate
      - "absent"   : telemetry exists for location but no run-command plugin row for this instance
    """
    loc = _s(loc)
    instance_id = _s(instance_id)
    if not (loc and instance_id):
        return "unknown"

    by_inst = emit_ctx.run_command_plugin_state_by_instance_by_loc.get(loc, {}) or {}
    state = _s(by_inst.get(instance_id) or "").strip().lower()
    if state in {"true", "false", "unknown"}:
        return state
    if loc in (emit_ctx.plugin_telemetry_present_by_loc or set()):
        return "absent"
    return "unknown"


def _collect_instance_ocids_from_obj(obj, out: set[str]):
    if obj is None:
        return
    if isinstance(obj, str):
        s = _s(obj)
        if _looks_like_instance_ocid(s):
            out.add(s)
        return
    if isinstance(obj, (list, tuple, set)):
        for item in obj:
            _collect_instance_ocids_from_obj(item, out)
        return
    if not isinstance(obj, dict):
        return

    candidate_keys = {
        "instance_id",
        "instanceid",
        "target_instance_id",
        "targetinstanceid",
        "instanceagent_id",
        "instanceagentid",
    }
    for k, v in obj.items():
        key_l = _s(k).strip().lower().replace("-", "_")
        if key_l in candidate_keys and _looks_like_instance_ocid(_s(v)):
            out.add(_s(v))
        _collect_instance_ocids_from_obj(v, out)


def _extract_instance_targets_from_command_props(props: dict) -> set[str]:
    out: set[str] = set()
    if not isinstance(props, dict):
        return out

    for k in ("instance_id", "target_instance_id", "instanceagent_id", "instanceId", "targetInstanceId"):
        v = _s(props.get(k) or "")
        if _looks_like_instance_ocid(v):
            out.add(v)

    for k in ("execution_key",):
        raw = _s(props.get(k) or "")
        if ":" in raw:
            parts = raw.split(":")
            for p in parts:
                if _looks_like_instance_ocid(_s(p)):
                    out.add(_s(p))

    for k in ("target_raw_json", "content_raw_json", "target", "targets", "content"):
        blob = props.get(k)
        parsed = blob
        if isinstance(blob, str):
            txt = blob.strip()
            if not txt:
                continue
            try:
                parsed = json.loads(txt)
            except Exception:
                parsed = None
        _collect_instance_ocids_from_obj(parsed, out)

    return out


def _upsert_new_instance_launch_context_node_metadata(
    emit_ctx: _DerivedEmitContext,
    *,
    node_id: str,
    principal_id: str,
    loc: str,
    cap: _RelationState,
) -> None:
    node_id = _s(node_id)
    principal_id = _s(principal_id)
    loc = _s(loc)
    if not (node_id and principal_id and loc):
        return

    prereq_state = _create_instance_prereq_state(cap=cap)
    tag_ns_specific = sorted(_s(x) for x in (cap.use_tag_namespace_specific_ids or set()) if _s(x))

    launch_context = {
        "principal_id": principal_id,
        "location": loc,
        "launch_prerequisite_permissions": [
            "INSTANCE_CREATE",
            "VNIC_CREATE",
            "VNIC_ATTACH",
            "SUBNET_READ",
            "SUBNET_ATTACH",
        ],
        "permission_resource_targets": _resource_targets_for_launch_prereqs(loc=loc),
        "prerequisite_sets_satisfied": prereq_state,
        "all_launch_prerequisites_satisfied": all(prereq_state.values()),
        "tag_namespace_use_available": bool(cap.use_tag_namespace_scope),
        "tag_namespace_scope_node_id": (f"tag-namespaces@{loc}" if cap.use_tag_namespace_scope else ""),
        "tag_namespace_specific_ids": tag_ns_specific,
        "tag_namespace_resolved_statements": _statement_texts(cap.use_tag_namespace_resolved_statements),
        "tag_namespace_unresolved_statements": _statement_texts(cap.use_tag_namespace_unresolved_statements),
    }

    node_type = _s(emit_ctx.node_type_by_id.get(node_id) or NODE_NEW_COMPUTE_INSTANCE)
    comp_id = _s(emit_ctx.node_compartment_by_id.get(node_id) or loc)
    tenant_id = ""
    if comp_id and hasattr(emit_ctx.ctx, "tenant_for_compartment"):
        try:
            tenant_id = _s(emit_ctx.ctx.tenant_for_compartment(comp_id) or "")
        except Exception:
            tenant_id = ""

    node_properties_patch = {
        "launch_contexts": [launch_context],
        "launch_prerequisite_permissions": launch_context["launch_prerequisite_permissions"],
        "permission_resource_targets": launch_context["permission_resource_targets"],
    }
    if cap.use_tag_namespace_scope:
        node_properties_patch["tag_namespace_use_available"] = True
        node_properties_patch["tag_namespace_scope_node_id"] = f"tag-namespaces@{loc}"
    if tag_ns_specific:
        node_properties_patch["tag_namespace_specific_ids"] = tag_ns_specific

    try:
        emit_ctx.ctx.upsert_node(
            node_id=node_id,
            node_type=node_type,
            compartment_id=comp_id,
            tenant_id=tenant_id,
            node_properties=node_properties_patch,
            commit=False,
        )
    except Exception:
        return


def _policy_statement_node_id_from_detail(item) -> str:
    if not isinstance(item, dict):
        return ""
    stmt_id = _s(item.get("stmt_id") or "")
    policy_id = _s(item.get("policy_id") or "")
    statement_index = item.get("statement_index")

    if policy_id and isinstance(statement_index, int):
        return f"policy_stmt:{policy_id}:{int(statement_index)}"

    if stmt_id and ":" in stmt_id:
        pid, idx = stmt_id.rsplit(":", 1)
        if pid and idx.isdigit():
            return f"policy_stmt:{pid}:{int(idx)}"
    return ""


def _policy_statement_node_ids_from_details(details, *, node_type_by_id) -> list[str]:
    out = []
    seen = set()
    for item in (details or []):
        nid = _policy_statement_node_id_from_detail(item)
        if not nid or nid in seen:
            continue
        ntype = _s((node_type_by_id or {}).get(nid) or "")
        if ntype and ntype != "OCIPolicyStatement":
            continue
        seen.add(nid)
        out.append(nid)
    return out


def _write_derived_edge(
    emit_ctx: _DerivedEmitContext,
    *,
    source_id: str,
    source_type: str,
    destination_id: str,
    destination_type: str,
    edge_type: str,
    description: str,
    resolved_statements: list | None = None,
    unresolved_statements: list | None = None,
    has_unresolved_conditionals: bool = False,
    has_impossible_conditionals: bool = False,
    has_inherited: bool = False,
    has_direct: bool = False,
    edge_category: str = EDGE_CATEGORY_PERMISSION,
    extra_edge_inner_properties: dict | None = None,
) -> bool:
    resolved_details = resolved_statements if isinstance(resolved_statements, list) else []
    unresolved_details = unresolved_statements if isinstance(unresolved_statements, list) else []

    if edge_category == EDGE_CATEGORY_GROUP_MEMBERSHIP:
        group_type = (
            "dynamic"
            if _s(edge_type) in {EDGE_DYNAMIC_GROUP_MEMBER, EDGE_INSTANCE_CAN_JOIN_DG}
            else "standard"
        )
        edge_props = _build_edge_properties(
            edge_category=EDGE_CATEGORY_GROUP_MEMBERSHIP,
            edge_inner_properties={
                "matching_rules": _s(description),
                "membership_id": "",
                "group_type": group_type,
            },
        )
    else:
        edge_inner = {
            "description": _s(description),
            "is_priv_escalation": True,
            "resolved_statements": _statement_texts(resolved_details),
            "unresolved_statements": _statement_texts(unresolved_details),
            "resolved_policy": _statement_policy_ids(resolved_details),
            "unresolved_policy": _statement_policy_ids(unresolved_details),
            "resolved_statement_details": resolved_details,
            "unresolved_statement_details": unresolved_details,
            "has_unresolved_conditionals": bool(has_unresolved_conditionals),
            "has_impossible_conditionals": bool(has_impossible_conditionals),
            "has_inherited": bool(has_inherited),
            "has_direct": bool(has_direct),
        }
        if isinstance(extra_edge_inner_properties, dict) and extra_edge_inner_properties:
            edge_inner.update(extra_edge_inner_properties)
        edge_props = _build_edge_properties(
            edge_category=EDGE_CATEGORY_PERMISSION,
            edge_inner_properties=edge_inner,
        )

    wrote = _emit_edge_shared(
        emit_ctx.ctx,
        src_id=source_id,
        src_type=source_type,
        dst_id=destination_id,
        dst_type=destination_type,
        edge_type=edge_type,
        edge_properties=edge_props,
        commit=False,
        on_conflict="update",
        dedupe=True,
    )
    if wrote:
        emit_ctx.existing_edges.add((source_id, edge_type, destination_id))
    return bool(wrote)


def _emit_policy_update_edges_to_all_resources(
    emit_ctx: _DerivedEmitContext,
    *,
    principal_id: str,
    principal_type: str,
    loc: str,
    cap: _RelationState,
):
    principal_id = _s(principal_id)
    loc = _s(loc)
    if not (principal_id and loc):
        return
    if (principal_id, loc) not in emit_ctx.policy_update_capability_by_principal_loc:
        return

    policy_examples = list(emit_ctx.policy_nodes_by_loc.get(loc) or [])
    if not policy_examples:
        return

    update_policy_resolved = list(cap.update_policy_resolved_statements or [])
    update_policy_unresolved = list(cap.update_policy_unresolved_statements or [])
    statement_sources = set(_policy_statement_node_ids_from_details(
        update_policy_resolved or update_policy_unresolved,
        node_type_by_id=emit_ctx.node_type_by_id,
    ))
    if not statement_sources:
        # Fallback: derive policy statements linked to this principal in graph state.
        for src_id, edge_type, dst_id in (emit_ctx.existing_edges or set()):
            if (
                _s(src_id) == principal_id
                and _s(edge_type) == "OCI_POLICY_SUBJECT"
                and _s(emit_ctx.node_type_by_id.get(dst_id) or "") == "OCIPolicyStatement"
            ):
                statement_sources.add(dst_id)

    all_resources_id = _ensure_scoped_node_shared(
        ctx=emit_ctx.ctx,
        node_id=f"all-resources@{loc}",
        node_type="OCIAllResources",
        node_display_name=f"all-resources@{_display_loc(ctx=emit_ctx.ctx, loc=loc)}",
        loc=loc,
        existing_nodes=emit_ctx.existing_nodes,
        node_type_by_id=emit_ctx.node_type_by_id,
        node_compartment_by_id=emit_ctx.node_compartment_by_id,
    )
    if not all_resources_id:
        return

    policy_ids_in_loc = {
        _s((pol or {}).get("id") or "")
        for pol in policy_examples
        if _s((pol or {}).get("id") or "")
    }

    scope_id = f"policies@{loc}"
    reachable_policy_ids = set()

    # Path A: statement -> specific policy (direct resolved target)
    for stmt_node_id in sorted(statement_sources):
        for policy_id in set(cap.update_policy_specific_policies or set()):
            if (
                policy_id
                and policy_id in policy_ids_in_loc
                and (stmt_node_id, EDGE_UPDATE_POLICY, policy_id) in emit_ctx.existing_edges
            ):
                reachable_policy_ids.add(policy_id)

    # Path B: statement -> policies@loc and policies@loc -> specific policy
    has_scope_update_path = any(
        (stmt_node_id, EDGE_UPDATE_POLICY, scope_id) in emit_ctx.existing_edges
        for stmt_node_id in statement_sources
    )
    if has_scope_update_path:
        for policy_id in policy_ids_in_loc:
            if (scope_id, "OCI_SPECIFIC_RESOURCE", policy_id) in emit_ctx.existing_edges:
                reachable_policy_ids.add(policy_id)

    if not reachable_policy_ids:
        return

    for policy_id in sorted(reachable_policy_ids):
        _write_derived_edge(
            emit_ctx,
            source_id=policy_id,
            source_type="OCIPolicy",
            destination_id=all_resources_id,
            destination_type="OCIAllResources",
            edge_type=EDGE_UPDATED_ACCESS_TO_ALL_RESOURCES,
            description=(
                "Derived shortcut: this policy is reachable via UPDATE_POLICY in this scope and can be "
                "modified to grant all-resources."
            ),
            resolved_statements=update_policy_resolved,
            unresolved_statements=update_policy_unresolved,
            has_unresolved_conditionals=cap.has_unresolved_conditionals,
            has_impossible_conditionals=cap.has_impossible_conditionals,
            has_inherited=cap.has_inherited,
            has_direct=cap.has_direct,
            extra_edge_inner_properties={
                "derived_shortcut": True,
                "requires_update_policy": True,
                "policy_update_scope_id": scope_id,
                "trace_statement_node_ids": sorted(statement_sources),
            },
        )


# -------------------------------------------------------------------------
# Derived relation: CREATE_POLICY -> synthetic NEW_POLICY node -> all-resources.
# Prefer statement-driven sources:
#   OCIPolicyStatement --OCI_CAN_CREATE_POLICY--> NEW_POLICY@loc
# Fallback to principal source only if statement-node ids cannot be resolved.
# -------------------------------------------------------------------------
def _emit_create_policy_edges_to_all_resources(
    emit_ctx: _DerivedEmitContext,
    *,
    principal_id: str,
    principal_type: str,
    loc: str,
    cap: _RelationState,
):
    if not cap.create_policy_scope:
        return
    loc = _s(loc)
    if not loc:
        return

    policy_candidate_id = _ensure_scoped_node_shared(
        ctx=emit_ctx.ctx,
        node_id=f"NEW_POLICY@{loc}",
        node_type=NODE_NEW_POLICY,
        node_display_name=f"NEW_POLICY@{_display_loc(ctx=emit_ctx.ctx, loc=loc)}",
        loc=loc,
        extra_properties={
            "synthetic": True,
            "derived_from": EDGE_CREATE_POLICY,
            "resource_type": "policy",
        },
        existing_nodes=emit_ctx.existing_nodes,
        node_type_by_id=emit_ctx.node_type_by_id,
        node_compartment_by_id=emit_ctx.node_compartment_by_id,
    )
    if not policy_candidate_id:
        return

    create_policy_resolved = list(cap.create_policy_resolved_statements or [])
    create_policy_unresolved = list(cap.create_policy_unresolved_statements or [])
    statement_sources = _policy_statement_node_ids_from_details(
        create_policy_resolved or create_policy_unresolved,
        node_type_by_id=emit_ctx.node_type_by_id,
    )

    wrote_create_policy_edge = False
    for stmt_node_id in statement_sources:
        wrote_create_policy_edge = _write_derived_edge(
            emit_ctx,
            source_id=stmt_node_id,
            source_type="OCIPolicyStatement",
            destination_id=policy_candidate_id,
            destination_type=NODE_NEW_POLICY,
            edge_type=EDGE_CAN_CREATE_POLICY,
            description=(
                "Derived from raw IAM edges: this policy statement grants CREATE_POLICY in compatible scope, "
                "enabling creation of new policy statements."
            ),
            resolved_statements=create_policy_resolved,
            unresolved_statements=create_policy_unresolved,
            has_unresolved_conditionals=cap.has_unresolved_conditionals,
            has_impossible_conditionals=cap.has_impossible_conditionals,
            has_inherited=cap.has_inherited,
            has_direct=cap.has_direct,
        ) or wrote_create_policy_edge

    if not wrote_create_policy_edge:
        _write_derived_edge(
            emit_ctx,
            source_id=principal_id,
            source_type=principal_type,
            destination_id=policy_candidate_id,
            destination_type=NODE_NEW_POLICY,
            edge_type=EDGE_CAN_CREATE_POLICY,
            description=(
                "Derived from raw IAM edges: principal can CREATE_POLICY in compatible scope, "
                "enabling creation of new policy statements."
            ),
            resolved_statements=create_policy_resolved,
            unresolved_statements=create_policy_unresolved,
            has_unresolved_conditionals=cap.has_unresolved_conditionals,
            has_impossible_conditionals=cap.has_impossible_conditionals,
            has_inherited=cap.has_inherited,
            has_direct=cap.has_direct,
            extra_edge_inner_properties={"fallback_source": "principal"},
        )

    all_resources_id = _ensure_scoped_node_shared(
        ctx=emit_ctx.ctx,
        node_id=f"all-resources@{loc}",
        node_type="OCIAllResources",
        node_display_name=f"all-resources@{_display_loc(ctx=emit_ctx.ctx, loc=loc)}",
        loc=loc,
        existing_nodes=emit_ctx.existing_nodes,
        node_type_by_id=emit_ctx.node_type_by_id,
        node_compartment_by_id=emit_ctx.node_compartment_by_id,
    )
    if not all_resources_id:
        return

    _write_derived_edge(
        emit_ctx,
        source_id=policy_candidate_id,
        source_type=NODE_NEW_POLICY,
        destination_id=all_resources_id,
        destination_type="OCIAllResources",
        edge_type=EDGE_POLICY_CAN_GRANT_ALL_RESOURCES,
        description=(
            "Derived from raw IAM edges: newly created policies in this scope can grant access to all-resources."
        ),
        resolved_statements=create_policy_resolved,
        unresolved_statements=create_policy_unresolved,
        has_unresolved_conditionals=cap.has_unresolved_conditionals,
        has_impossible_conditionals=cap.has_impossible_conditionals,
        has_inherited=cap.has_inherited,
        has_direct=cap.has_direct,
    )


# -------------------------------------------------------------------------
# Derived relation: CREATE_INSTANCE scope -> candidate NEW_INSTANCE node.
# Emits statement -> NEW_INSTANCE_<short>@<loc>, then candidate -> dynamic-group
# when matching_rules_engine confirms DG matches for (`INSTANCE_CREATE`, loc).
# -------------------------------------------------------------------------
def _emit_new_instance_and_dynamic_group_edges(
    emit_ctx: _DerivedEmitContext,
    *,
    principal_id: str,
    principal_type: str,
    loc: str,
    cap: _RelationState,
):
    if not cap.create_instance_scope:
        return
    if not (
        cap.create_instance_has_instance_create
        and cap.create_instance_has_vnic_prereqs
        and cap.create_instance_has_subnet_prereqs
    ):
        return

    candidate_id = _ensure_new_compute_instance_candidate_node_shared(
        emit_ctx.ctx,
        principal_id=principal_id,
        loc=loc,
        existing_nodes=emit_ctx.existing_nodes,
        node_type_by_id=emit_ctx.node_type_by_id,
        node_compartment_by_id=emit_ctx.node_compartment_by_id,
    )
    if not candidate_id:
        return

    _upsert_new_instance_launch_context_node_metadata(
        emit_ctx,
        node_id=candidate_id,
        principal_id=principal_id,
        loc=loc,
        cap=cap,
    )

    create_instance_resolved = list(cap.create_instance_resolved_statements or [])
    create_instance_unresolved = list(cap.create_instance_unresolved_statements or [])
    statement_sources = _policy_statement_node_ids_from_details(
        create_instance_resolved or create_instance_unresolved,
        node_type_by_id=emit_ctx.node_type_by_id,
    )

    wrote_create_instance_edge = False
    for stmt_node_id in statement_sources:
        wrote_create_instance_edge = _write_derived_edge(
            emit_ctx,
            source_id=stmt_node_id,
            source_type="OCIPolicyStatement",
            destination_id=candidate_id,
            destination_type=NODE_NEW_COMPUTE_INSTANCE,
            edge_type=EDGE_CAN_CREATE_INSTANCE,
            description=(
                "Derived from raw IAM edges: this policy statement grants the minimum "
                "instance launch prerequisites in this location."
            ),
            resolved_statements=create_instance_resolved,
            unresolved_statements=create_instance_unresolved,
            has_unresolved_conditionals=cap.has_unresolved_conditionals,
            has_impossible_conditionals=cap.has_impossible_conditionals,
            has_inherited=cap.has_inherited,
            has_direct=cap.has_direct,
            extra_edge_inner_properties={
                "launch_prerequisites": [
                    "INSTANCE_CREATE",
                    "VNIC_CREATE",
                    "VNIC_ATTACH",
                    "SUBNET_READ",
                    "SUBNET_ATTACH",
                ],
                "scope_location": loc,
            },
        ) or wrote_create_instance_edge

    if not wrote_create_instance_edge:
        _write_derived_edge(
            emit_ctx,
            source_id=principal_id,
            source_type=principal_type,
            destination_id=candidate_id,
            destination_type=NODE_NEW_COMPUTE_INSTANCE,
            edge_type=EDGE_CAN_CREATE_INSTANCE,
            description=(
                "Derived from raw IAM edges: principal can launch instances with the minimum "
                "prerequisites in this location."
            ),
            resolved_statements=create_instance_resolved,
            unresolved_statements=create_instance_unresolved,
            has_unresolved_conditionals=cap.has_unresolved_conditionals,
            has_impossible_conditionals=cap.has_impossible_conditionals,
            has_inherited=cap.has_inherited,
            has_direct=cap.has_direct,
            extra_edge_inner_properties={
                "fallback_source": "principal",
                "launch_prerequisites": [
                    "INSTANCE_CREATE",
                    "VNIC_CREATE",
                    "VNIC_ATTACH",
                    "SUBNET_READ",
                    "SUBNET_ATTACH",
                ],
                "scope_location": loc,
            },
        )

    if loc not in emit_ctx.dg_instance_create_matches_by_loc:
        candidate_dgs = [
            row for row in (emit_ctx.dynamic_group_rows or [])
            if isinstance(row, dict) and _s(row.get("compartment_id") or "") == loc
        ]
        matches = emit_ctx.dg_permission_location_matcher.match_dynamic_groups_for_permission_location(
            candidate_dgs,
            permission="INSTANCE_CREATE",
            location=loc,
        )
        emit_ctx.dg_instance_create_matches_by_loc[loc] = {
            _s(m.get("dynamic_group_id") or ""): m
            for m in (matches or [])
            if isinstance(m, dict) and _s(m.get("dynamic_group_id") or "")
        }

    dg_match_map = emit_ctx.dg_instance_create_matches_by_loc.get(loc, {}) or {}
    for dg_id in sorted(dg_match_map.keys()):
        match_meta = dg_match_map.get(dg_id) if isinstance(dg_match_map, dict) else {}
        _write_derived_edge(
            emit_ctx,
            source_id=candidate_id,
            source_type=NODE_NEW_COMPUTE_INSTANCE,
            destination_id=dg_id,
            destination_type=NODE_DYNAMIC_GROUP,
            edge_type=EDGE_INSTANCE_CAN_JOIN_DG,
            description=(
                "Derived from raw IAM edges and matching_rules_engine: this candidate "
                "NEW_INSTANCE node matches dynamic-group permission+location requirements "
                "for INSTANCE_CREATE."
            ),
            edge_category=EDGE_CATEGORY_GROUP_MEMBERSHIP,
            extra_edge_inner_properties={
                "candidate_node_id": candidate_id,
                "evaluated_permission": "INSTANCE_CREATE",
                "evaluated_location": loc,
                "hypothetical_candidate_match": bool(
                    isinstance(match_meta, dict) and match_meta.get("hypothetical_candidate_match")
                ),
                "matching_rule_match_count": int(
                    (match_meta or {}).get("match_count") if isinstance(match_meta, dict) else 0
                ),
            },
            **_base_edge_kwargs(cap),
        )


def _emit_add_self_to_group_edges(
    emit_ctx: _DerivedEmitContext,
    *,
    principal_id: str,
    principal_type: str,
    loc: str,
    cap: _RelationState,
):
    principal_type_s = _s(principal_type)
    if principal_type_s not in {NODE_USER, NODE_GROUP, "OCIAnyUser", "OCIAnyGroup", "OCIPrincipal"}:
        return

    has_self_update = bool(cap.user_scope or cap.user_self_specific)
    has_group_update = bool(cap.group_scope or cap.specific_groups)
    if not (has_self_update and has_group_update):
        return

    loc = _s(loc)
    if not loc:
        return

    def _resolve_sources() -> list[tuple[str, str]]:
        ptype = _s(principal_type)
        # Prefer concrete user sources when the capability origin is a group.
        if ptype == NODE_GROUP:
            member_ids = set()
            cache = getattr(emit_ctx.ctx, "group_member_mapping_cache", {}) or {}
            member_ids.update(_s(u) for u in (cache.get(principal_id) or set()) if _s(u))
            if not member_ids:
                for src_id, edge_type, dst_id in (emit_ctx.existing_edges or set()):
                    if _s(edge_type) != EDGE_TYPE_OCI_GROUP_MEMBER or _s(dst_id) != principal_id:
                        continue
                    member_ids.add(_s(src_id))

            out = []
            for uid in sorted(member_ids):
                if not uid:
                    continue
                uid_type = _s(emit_ctx.node_type_by_id.get(uid) or "")
                if uid_type and uid_type != NODE_USER:
                    continue
                uid_loc = _s(emit_ctx.node_compartment_by_id.get(uid) or "")
                if uid_loc and uid_loc != loc:
                    continue
                out.append((uid, NODE_USER))
            if out:
                return out

        return [(principal_id, principal_type)]

    source_principals = _resolve_sources()

    targets: list[tuple[str, str]] = []
    if cap.group_scope:
        scope_group_id = _ensure_scoped_node_shared(
            emit_ctx.ctx,
            node_id=f"groups@{loc}",
            node_type="OCIResourceGroup",
            node_display_name=f"groups@{_display_loc(ctx=emit_ctx.ctx, loc=loc)}",
            loc=loc,
            existing_nodes=emit_ctx.existing_nodes,
            node_type_by_id=emit_ctx.node_type_by_id,
            node_compartment_by_id=emit_ctx.node_compartment_by_id,
        )
        if scope_group_id:
            targets.append((scope_group_id, "OCIResourceGroup"))
            # Resource-scope expansion ran before iam_derived, so when this scope
            # node is first created here we also need to materialize
            # groups@<loc> -> <group> expansion edges.
            for gid in sorted(_s(x) for x in (emit_ctx.groups_by_loc.get(loc, set()) or set()) if _s(x)):
                if _s(emit_ctx.node_type_by_id.get(gid) or "") != NODE_GROUP:
                    continue
                edge_key = (scope_group_id, EDGE_SCOPE_INCLUDES, gid)
                if edge_key in emit_ctx.existing_edges:
                    continue
                wrote = _emit_edge_shared(
                    emit_ctx.ctx,
                    src_id=scope_group_id,
                    src_type="OCIResourceGroup",
                    dst_id=gid,
                    dst_type=NODE_GROUP,
                    edge_type=EDGE_SCOPE_INCLUDES,
                    edge_properties=_build_edge_properties(
                        edge_category=EDGE_CATEGORY_RESOURCE,
                        edge_inner_properties={
                            "description": "Scope expansion to principals.",
                            "resource_family": False,
                            "resource_used": True,
                        },
                    ),
                    commit=False,
                    on_conflict="update",
                    dedupe=True,
                )
                if wrote:
                    emit_ctx.existing_edges.add(edge_key)

    for gid in sorted(_s(x) for x in (cap.specific_groups or set()) if _s(x)):
        group_loc = _s(emit_ctx.node_compartment_by_id.get(gid) or "")
        if group_loc and group_loc != loc:
            continue
        if _s(emit_ctx.node_type_by_id.get(gid) or "") != NODE_GROUP:
            continue
        targets.append((gid, NODE_GROUP))

    seen = set()
    for source_id, source_type in source_principals:
        for destination_id, destination_type in targets:
            key = (source_id, source_type, destination_id, destination_type)
            if key in seen:
                continue
            seen.add(key)
            _write_derived_edge(
                emit_ctx,
                source_id=source_id,
                source_type=source_type,
                destination_id=destination_id,
                destination_type=destination_type,
                edge_type=EDGE_ADD_SELF_TO_GROUP,
                description=(
                    "Derived from raw IAM edges: user can update self and update/manage groups in this location, "
                    "so self-add/group-membership placement is possible for reachable group targets."
                ),
                extra_edge_inner_properties={
                    "derived_shortcut": True,
                    "requires_user_update_self": True,
                    "requires_group_update": True,
                    "derived_from_group_principal": bool(_s(principal_type) == NODE_GROUP),
                    "origin_principal_id": principal_id,
                },
                **_base_edge_kwargs(cap),
            )


def _ensure_instance_agent_scope_and_instance_expansion(
    emit_ctx: _DerivedEmitContext,
    *,
    loc: str,
):
    loc = _s(loc)
    if not loc:
        return ""

    scope_id = _ensure_scoped_node_shared(
        emit_ctx.ctx,
        node_id=f"instance-agent-commands@{loc}",
        node_type="OCIResourceGroup",
        node_display_name=f"instance-agent-commands@{_display_loc(ctx=emit_ctx.ctx, loc=loc)}",
        loc=loc,
        existing_nodes=emit_ctx.existing_nodes,
        node_type_by_id=emit_ctx.node_type_by_id,
        node_compartment_by_id=emit_ctx.node_compartment_by_id,
    )
    if not scope_id:
        return ""

    for command_id in sorted(_s(x) for x in (emit_ctx.instance_agent_commands_by_loc.get(loc, set()) or set()) if _s(x)):
        command_type = _s(emit_ctx.node_type_by_id.get(command_id) or "OCIInstanceAgentCommand")
        if command_type and command_type not in {"OCIInstanceAgentCommand", NODE_TYPE_OCI_GENERIC_RESOURCE}:
            continue
        if command_id not in emit_ctx.existing_nodes:
            _ensure_node_shared(
                emit_ctx.ctx,
                node_id=command_id,
                node_type="OCIInstanceAgentCommand",
                node_properties={
                    "name": command_id,
                    "compartment_id": loc,
                    "location": loc,
                    "synthetic": True,
                },
                commit=False,
                dedupe=True,
            )
            emit_ctx.existing_nodes.add(command_id)
            emit_ctx.node_type_by_id[command_id] = "OCIInstanceAgentCommand"
            emit_ctx.node_compartment_by_id[command_id] = loc
            command_type = "OCIInstanceAgentCommand"

        edge_key = (scope_id, EDGE_SCOPE_INCLUDES, command_id)
        if edge_key in emit_ctx.existing_edges:
            pass
        else:
            wrote = _emit_edge_shared(
                emit_ctx.ctx,
                src_id=scope_id,
                src_type="OCIResourceGroup",
                dst_id=command_id,
                dst_type=command_type or "OCIInstanceAgentCommand",
                edge_type=EDGE_SCOPE_INCLUDES,
                edge_properties=_build_edge_properties(
                    edge_category=EDGE_CATEGORY_RESOURCE,
                    edge_inner_properties={
                        "description": "Scope expansion to concrete instance-agent command resources.",
                        "resource_family": False,
                        "resource_used": True,
                    },
                ),
                commit=False,
                on_conflict="update",
                dedupe=True,
            )
            if wrote:
                emit_ctx.existing_edges.add(edge_key)

        for instance_id in sorted(_s(x) for x in (emit_ctx.instance_target_ids_by_command.get(command_id, set()) or set()) if _s(x)):
            if not _looks_like_instance_ocid(instance_id):
                continue
            instance_type = _s(emit_ctx.node_type_by_id.get(instance_id) or "")
            if not instance_type:
                _ensure_node_shared(
                    emit_ctx.ctx,
                    node_id=instance_id,
                    node_type="OCIComputeInstance",
                    node_properties={
                        "name": instance_id,
                        "compartment_id": loc,
                        "location": loc,
                        "synthetic": True,
                    },
                    commit=False,
                    dedupe=True,
                )
                emit_ctx.existing_nodes.add(instance_id)
                emit_ctx.node_type_by_id[instance_id] = "OCIComputeInstance"
                emit_ctx.node_compartment_by_id[instance_id] = loc
                instance_type = "OCIComputeInstance"

            belongs_key = (command_id, EDGE_BELONGS_TO, instance_id)
            if belongs_key in emit_ctx.existing_edges:
                continue
            wrote_belongs = _emit_edge_shared(
                emit_ctx.ctx,
                src_id=command_id,
                src_type=command_type or "OCIInstanceAgentCommand",
                dst_id=instance_id,
                dst_type=instance_type or "OCIComputeInstance",
                edge_type=EDGE_BELONGS_TO,
                edge_properties=_build_edge_properties(
                    edge_category=EDGE_CATEGORY_RESOURCE,
                    edge_inner_properties={
                        "description": "Instance-agent command targets this compute instance.",
                        "resource_family": False,
                        "resource_used": True,
                    },
                ),
                commit=False,
                on_conflict="update",
                dedupe=True,
            )
            if wrote_belongs:
                emit_ctx.existing_edges.add(belongs_key)

    return scope_id


def _ensure_new_command_candidate_node(
    emit_ctx: _DerivedEmitContext,
    *,
    loc: str,
):
    loc = _s(loc)
    if not loc:
        return ""
    return _ensure_scoped_node_shared(
        emit_ctx.ctx,
        node_id=f"NEW_AGENT_COMMAND@{loc}",
        node_type=NODE_NEW_INSTANCE_AGENT_COMMAND,
        node_display_name=f"NEW_AGENT_COMMAND@{_display_loc(ctx=emit_ctx.ctx, loc=loc)}",
        loc=loc,
        extra_properties={
            "synthetic": True,
            "derived_from": EDGE_CREATE_INSTANCE_AGENT_COMMAND,
            "resource_type": "instance-agent-command",
        },
        existing_nodes=emit_ctx.existing_nodes,
        node_type_by_id=emit_ctx.node_type_by_id,
        node_compartment_by_id=emit_ctx.node_compartment_by_id,
    )


def _ensure_compute_instance_target_node(
    emit_ctx: _DerivedEmitContext,
    *,
    instance_id: str,
    loc: str,
):
    instance_id = _s(instance_id)
    loc = _s(loc)
    if not _looks_like_instance_ocid(instance_id):
        return ""

    instance_type = _s(emit_ctx.node_type_by_id.get(instance_id) or "")
    if instance_type and instance_type not in {"OCIComputeInstance", NODE_TYPE_OCI_GENERIC_RESOURCE}:
        return ""

    plugin_state = _instance_run_command_plugin_state(
        emit_ctx=emit_ctx,
        loc=loc,
        instance_id=instance_id,
    )
    display_name = _s(emit_ctx.compute_instance_name_by_id.get(instance_id) or instance_id)

    if instance_id not in emit_ctx.existing_nodes:
        _ensure_node_shared(
            emit_ctx.ctx,
            node_id=instance_id,
            node_type="OCIComputeInstance",
            node_properties={
                "name": display_name,
                "display_name": display_name,
                "compartment_id": loc,
                "location": loc,
                "synthetic": True,
                "derived_from": EDGE_CREATE_INSTANCE_AGENT_COMMAND,
                "run_command_plugin_state": plugin_state,
            },
            commit=False,
            dedupe=True,
        )
        emit_ctx.existing_nodes.add(instance_id)

    if not instance_type:
        instance_type = "OCIComputeInstance"
    emit_ctx.node_type_by_id[instance_id] = instance_type
    if loc and not _s(emit_ctx.node_compartment_by_id.get(instance_id) or ""):
        emit_ctx.node_compartment_by_id[instance_id] = loc

    # Always stamp/refresh plugin posture for downstream graph consumers.
    comp_id = _s(emit_ctx.node_compartment_by_id.get(instance_id) or loc)
    tenant_id = ""
    if comp_id and hasattr(emit_ctx.ctx, "tenant_for_compartment"):
        try:
            tenant_id = _s(emit_ctx.ctx.tenant_for_compartment(comp_id) or "")
        except Exception:
            tenant_id = ""
    try:
        emit_ctx.ctx.upsert_node(
            node_id=instance_id,
            node_type=instance_type or "OCIComputeInstance",
            compartment_id=comp_id,
            tenant_id=tenant_id,
            node_properties={
                "name": display_name,
                "display_name": display_name,
                "run_command_plugin_state": plugin_state,
                "run_command_plugin_telemetry_present_for_location": bool(
                    loc in (emit_ctx.plugin_telemetry_present_by_loc or set())
                ),
            },
            commit=False,
        )
    except Exception:
        pass
    return instance_type


def _upsert_new_command_context_node_metadata(
    emit_ctx: _DerivedEmitContext,
    *,
    node_id: str,
    principal_id: str,
    loc: str,
    cap: _RelationState,
):
    node_id = _s(node_id)
    principal_id = _s(principal_id)
    loc = _s(loc)
    if not (node_id and principal_id and loc):
        return

    resolved_details = list(cap.create_instance_agent_command_resolved_statements or [])
    unresolved_details = list(cap.create_instance_agent_command_unresolved_statements or [])
    context = {
        "principal_id": principal_id,
        "location": loc,
        "required_permission": "INSTANCE_AGENT_COMMAND_CREATE",
        "resolved_statements": _statement_texts(resolved_details),
        "unresolved_statements": _statement_texts(unresolved_details),
        "has_unresolved_conditionals": bool(cap.has_unresolved_conditionals),
        "has_impossible_conditionals": bool(cap.has_impossible_conditionals),
    }

    node_type = _s(emit_ctx.node_type_by_id.get(node_id) or NODE_NEW_INSTANCE_AGENT_COMMAND)
    comp_id = _s(emit_ctx.node_compartment_by_id.get(node_id) or loc)
    tenant_id = ""
    if comp_id and hasattr(emit_ctx.ctx, "tenant_for_compartment"):
        try:
            tenant_id = _s(emit_ctx.ctx.tenant_for_compartment(comp_id) or "")
        except Exception:
            tenant_id = ""
    try:
        emit_ctx.ctx.upsert_node(
            node_id=node_id,
            node_type=node_type,
            compartment_id=comp_id,
            tenant_id=tenant_id,
            node_properties={
                "command_contexts": [context],
                "required_permissions": ["INSTANCE_AGENT_COMMAND_CREATE"],
                "scope_location": loc,
            },
            commit=False,
        )
    except Exception:
        return


# -------------------------------------------------------------------------
# Derived relation: instance-agent command pivot to dynamic-group context
# (tentative edge from command-create capability; confirmed edge when DG-side
# execution prerequisites are present with existing compute members).
# -------------------------------------------------------------------------
def _emit_instance_agent_run_command_edges(
    emit_ctx: _DerivedEmitContext,
    *,
    principal_id: str,
    principal_type: str,
    loc: str,
    cap: _RelationState,
):
    if not cap.create_instance_agent_command_scope:
        return

    loc = _s(loc)
    if not loc:
        return

    _ensure_instance_agent_scope_and_instance_expansion(
        emit_ctx,
        loc=loc,
    )

    candidate_id = _ensure_new_command_candidate_node(
        emit_ctx,
        loc=loc,
    )
    if not candidate_id:
        return

    _upsert_new_command_context_node_metadata(
        emit_ctx,
        node_id=candidate_id,
        principal_id=principal_id,
        loc=loc,
        cap=cap,
    )

    create_cmd_resolved = list(cap.create_instance_agent_command_resolved_statements or [])
    create_cmd_unresolved = list(cap.create_instance_agent_command_unresolved_statements or [])
    statement_sources = _policy_statement_node_ids_from_details(
        create_cmd_resolved or create_cmd_unresolved,
        node_type_by_id=emit_ctx.node_type_by_id,
    )

    wrote_create_command = False
    for stmt_node_id in statement_sources:
        wrote_create_command = _write_derived_edge(
            emit_ctx,
            source_id=stmt_node_id,
            source_type="OCIPolicyStatement",
            destination_id=candidate_id,
            destination_type=NODE_NEW_INSTANCE_AGENT_COMMAND,
            edge_type=EDGE_CREATE_INSTANCE_AGENT_COMMAND,
            description=(
                "Derived from raw IAM edges: this policy statement grants create/run command capability in this location."
            ),
            resolved_statements=create_cmd_resolved,
            unresolved_statements=create_cmd_unresolved,
            has_unresolved_conditionals=cap.has_unresolved_conditionals,
            has_impossible_conditionals=cap.has_impossible_conditionals,
            has_inherited=cap.has_inherited,
            has_direct=cap.has_direct,
            extra_edge_inner_properties={
                "derived_shortcut": True,
                "scope_location": loc,
            },
        ) or wrote_create_command

    if not wrote_create_command:
        _write_derived_edge(
            emit_ctx,
            source_id=principal_id,
            source_type=principal_type,
            destination_id=candidate_id,
            destination_type=NODE_NEW_INSTANCE_AGENT_COMMAND,
            edge_type=EDGE_CREATE_INSTANCE_AGENT_COMMAND,
            description=(
                "Derived from raw IAM edges: principal can create/run commands in this location."
            ),
            resolved_statements=create_cmd_resolved,
            unresolved_statements=create_cmd_unresolved,
            has_unresolved_conditionals=cap.has_unresolved_conditionals,
            has_impossible_conditionals=cap.has_impossible_conditionals,
            has_inherited=cap.has_inherited,
            has_direct=cap.has_direct,
            extra_edge_inner_properties={
                "derived_shortcut": True,
                "scope_location": loc,
                "fallback_source": "principal",
            },
        )

    target_instances = sorted(_s(x) for x in (emit_ctx.compute_instances_by_loc.get(loc, set()) or set()) if _s(x))
    if not target_instances:
        return

    inst_to_dgs = emit_ctx.instance_to_dynamic_groups_by_loc.get(loc, {}) or {}
    for instance_id in target_instances:
        plugin_state = _instance_run_command_plugin_state(
            emit_ctx=emit_ctx,
            loc=loc,
            instance_id=instance_id,
        )
        if plugin_state in {"false", "absent"}:
            continue

        instance_type = _ensure_compute_instance_target_node(
            emit_ctx,
            instance_id=instance_id,
            loc=loc,
        )
        if not instance_type:
            continue

        matched_dgs = []
        for dg_id in sorted(_s(x) for x in (inst_to_dgs.get(instance_id, set()) or set()) if _s(x)):
            dg_cap = emit_ctx.relation_map.get((dg_id, loc))
            if not dg_cap or not bool(dg_cap.read_run_output_scope or dg_cap.read_instance_agent_command_execution_scope):
                continue
            if _s(emit_ctx.node_type_by_id.get(dg_id) or "") != NODE_DYNAMIC_GROUP:
                continue
            matched_dgs.append(dg_id)

        description = "Derived from raw IAM edges: new command path can target this instance."

        _write_derived_edge(
            emit_ctx,
            source_id=candidate_id,
            source_type=NODE_NEW_INSTANCE_AGENT_COMMAND,
            destination_id=instance_id,
            destination_type=instance_type or "OCIComputeInstance",
            edge_type=EDGE_RUN_COMMAND,
            description=description,
            extra_edge_inner_properties={
                "derived_shortcut": True,
                "requires_create_instance_agent_command": True,
                "has_principal_execution_read": bool(cap.read_run_output_scope or cap.read_instance_agent_command_execution_scope),
                "matched_dynamic_groups": matched_dgs,
                "plugin_state": plugin_state,
                "plugin_telemetry_present": bool(loc in (emit_ctx.plugin_telemetry_present_by_loc or set())),
                "plugin_policy": "draw_when_true_or_unknown_skip_when_false_or_absent",
                "scope_location": loc,
            },
            **_base_edge_kwargs(cap),
        )


def _emit_instance_agent_run_command_edges_from_statement(
    emit_ctx: _DerivedEmitContext,
    *,
    statement_id: str,
    loc: str,
    cap: _RelationState,
):
    """
    Statement-scoped variant of run-command derivation used when subject resolution
    is unavailable. Emits:
      OCIPolicyStatement -> NEW_AGENT_COMMAND@loc (OCI_CREATE_INSTANCE_AGENT_COMMAND)
      NEW_AGENT_COMMAND@loc -> OCIComputeInstance (OCI_RUN_COMMAND).
    """
    statement_id = _s(statement_id)
    loc = _s(loc)
    if not (statement_id and loc and cap.create_instance_agent_command_scope):
        return

    _ensure_instance_agent_scope_and_instance_expansion(
        emit_ctx,
        loc=loc,
    )

    candidate_id = _ensure_new_command_candidate_node(
        emit_ctx,
        loc=loc,
    )
    if not candidate_id:
        return

    _upsert_new_command_context_node_metadata(
        emit_ctx,
        node_id=candidate_id,
        principal_id=statement_id,
        loc=loc,
        cap=cap,
    )

    create_cmd_resolved = list(cap.create_instance_agent_command_resolved_statements or [])
    create_cmd_unresolved = list(cap.create_instance_agent_command_unresolved_statements or [])
    _write_derived_edge(
        emit_ctx,
        source_id=statement_id,
        source_type="OCIPolicyStatement",
        destination_id=candidate_id,
        destination_type=NODE_NEW_INSTANCE_AGENT_COMMAND,
        edge_type=EDGE_CREATE_INSTANCE_AGENT_COMMAND,
        description=(
            "Derived from raw IAM edges: this policy statement grants create/run command capability in this location."
        ),
        resolved_statements=create_cmd_resolved,
        unresolved_statements=create_cmd_unresolved,
        has_unresolved_conditionals=cap.has_unresolved_conditionals,
        has_impossible_conditionals=cap.has_impossible_conditionals,
        has_inherited=cap.has_inherited,
        has_direct=cap.has_direct,
        extra_edge_inner_properties={
            "derived_shortcut": True,
            "scope_location": loc,
            "source_mode": "statement",
        },
    )

    target_instances = sorted(_s(x) for x in (emit_ctx.compute_instances_by_loc.get(loc, set()) or set()) if _s(x))
    if not target_instances:
        return

    inst_to_dgs = emit_ctx.instance_to_dynamic_groups_by_loc.get(loc, {}) or {}
    for instance_id in target_instances:
        plugin_state = _instance_run_command_plugin_state(
            emit_ctx=emit_ctx,
            loc=loc,
            instance_id=instance_id,
        )
        if plugin_state in {"false", "absent"}:
            continue

        instance_type = _ensure_compute_instance_target_node(
            emit_ctx,
            instance_id=instance_id,
            loc=loc,
        )
        if not instance_type:
            continue

        matched_dgs = []
        for dg_id in sorted(_s(x) for x in (inst_to_dgs.get(instance_id, set()) or set()) if _s(x)):
            dg_cap = emit_ctx.relation_map.get((dg_id, loc))
            if not dg_cap or not bool(dg_cap.read_run_output_scope or dg_cap.read_instance_agent_command_execution_scope):
                continue
            if _s(emit_ctx.node_type_by_id.get(dg_id) or "") != NODE_DYNAMIC_GROUP:
                continue
            matched_dgs.append(dg_id)

        description = "Derived from raw IAM edges: new command path can target this instance."
        _write_derived_edge(
            emit_ctx,
            source_id=candidate_id,
            source_type=NODE_NEW_INSTANCE_AGENT_COMMAND,
            destination_id=instance_id,
            destination_type=instance_type or "OCIComputeInstance",
            edge_type=EDGE_RUN_COMMAND,
            description=description,
            extra_edge_inner_properties={
                "derived_shortcut": True,
                "requires_create_instance_agent_command": True,
                "has_principal_execution_read": bool(cap.read_run_output_scope or cap.read_instance_agent_command_execution_scope),
                "matched_dynamic_groups": matched_dgs,
                "plugin_state": plugin_state,
                "plugin_telemetry_present": bool(loc in (emit_ctx.plugin_telemetry_present_by_loc or set())),
                "plugin_policy": "draw_when_true_or_unknown_skip_when_false_or_absent",
                "scope_location": loc,
            },
            **_base_edge_kwargs(cap),
        )


# -----------------------------------------------------------------------------
# Post-emit cleanup
# -----------------------------------------------------------------------------
# Keep `new-*` scope nodes only when they participate in a full chain
# (i.e., they have at least one outgoing edge). Otherwise prune the incoming
# edge(s) and remove the orphan node.

def _is_new_scope_node_id(node_id: str) -> bool:
    token, _loc = _scope_token_loc(node_id)
    token_base = token.rsplit("/", 1)[-1] if token and "/" in token else token
    return bool(token_base and token_base.startswith("new-"))


def _prune_orphan_new_scope_targets(*, session, emit_ctx: _DerivedEmitContext, debug=False) -> dict:
    existing_edges = emit_ctx.existing_edges
    existing_nodes = emit_ctx.existing_nodes

    incoming_counts = Counter()
    outgoing_counts = Counter()
    for src_id, _edge_type, dst_id in existing_edges:
        outgoing_counts[src_id] += 1
        incoming_counts[dst_id] += 1

    new_targets = {
        dst_id
        for (_src_id, _edge_type, dst_id) in existing_edges
        if _is_new_scope_node_id(dst_id)
    }
    if not new_targets:
        return {"new_scope_edges_pruned": 0, "new_scope_nodes_pruned": 0}

    nodes_with_outgoing = {
        src_id
        for (src_id, _edge_type, _dst_id) in existing_edges
        if _is_new_scope_node_id(src_id)
    }

    incoming_to_orphan = [
        (src_id, edge_type, dst_id)
        for (src_id, edge_type, dst_id) in list(existing_edges)
        # Keep selected capability edges even when no scope-member chain exists yet.
        if _is_new_scope_node_id(dst_id)
        and dst_id not in nodes_with_outgoing
        and _s(edge_type) not in _KEEP_ORPHAN_NEW_SCOPE_EDGE_TYPES
    ]

    pruned_edges = 0
    for src_id, edge_type, dst_id in incoming_to_orphan:
        try:
            session.delete_resource(
                "opengraph_edges",
                where={
                    "source_id": src_id,
                    "edge_type": edge_type,
                    "destination_id": dst_id,
                },
            )
            existing_edges.discard((src_id, edge_type, dst_id))
            pruned_edges += 1
        except Exception as e:
            _dlog(debug, "iam-derived: prune edge failed", src_id=src_id, edge_type=edge_type, dst_id=dst_id, err=f"{type(e).__name__}: {e}")

    candidate_nodes = {dst_id for (_src_id, _edge_type, dst_id) in incoming_to_orphan}
    pruned_nodes = 0
    for node_id in candidate_nodes:
        has_outgoing = outgoing_counts.get(node_id, 0) > 0
        has_incoming = incoming_counts.get(node_id, 0) > 0
        if has_outgoing or has_incoming:
            continue

        node_where = {"node_id": node_id}
        node_type = _s(emit_ctx.node_type_by_id.get(node_id) or "")
        if node_type:
            node_where["node_type"] = node_type
        try:
            session.delete_resource("opengraph_nodes", where=node_where)
            existing_nodes.discard(node_id)
            emit_ctx.node_type_by_id.pop(node_id, None)
            emit_ctx.node_compartment_by_id.pop(node_id, None)
            pruned_nodes += 1
        except Exception as e:
            _dlog(debug, "iam-derived: prune node failed", node_id=node_id, err=f"{type(e).__name__}: {e}")

    return {"new_scope_edges_pruned": pruned_edges, "new_scope_nodes_pruned": pruned_nodes}


# -----------------------------------------------------------------------------
# Main orchestration
# -----------------------------------------------------------------------------
# End-to-end runner: load graph state, derive capabilities, emit consequences.

def build_iam_policy_advanced_relation_edges_offline(*, session, ctx, debug=True, auto_commit=True, **_):
    """
    Build derived IAM consequence edges from raw IAM edges already in opengraph_* tables.
    """

    # Phase 1: Refresh OpenGraph dedupe state and establish mutable write sets.
    ctx.refresh_opengraph_state(force=False)
    og = _og_shared(ctx)

    # Phase 2: Load source graph data from OpenGraph storage plus in-memory
    # post-conditional relation entries emitted by iam_policy_base_relation_graph_builder.
    node_rows = session.get_resource_fields("opengraph_nodes", columns=NODE_COLUMNS) or []
    relation_entries = getattr(ctx, "iam_postprocess_relation_entries", [])
    if not isinstance(relation_entries, list):
        relation_entries = []
    relation_entries_seen = len(relation_entries)
    policy_update_capability_by_principal_loc = _collect_policy_update_capability_keys(relation_entries)

    # Phase 3: Build node indexes used for relation inference and scoped emits.
    # Example input row shape from `opengraph_nodes`:
    #   {
    #     "node_id": "ocid1.tagnamespace.oc1..x",
    #     "node_properties": "{\"name\":\"Finance\",\"compartment_id\":\"ocid1.compartment..a\",\"tenant_id\":\"ocid1.tenancy..t\"}"
    #   }
    #
    # Index outputs built here:
    #   node_type_by_id: {"ocid1.tagnamespace.oc1..x": "OCITagNamespace", ...}
    #   node_compartment_by_id: {"ocid1.tagnamespace.oc1..x": "ocid1.compartment..a", ...}
    # Tenancy is resolved later from ctx.tenant_for_compartment(loc) as needed.
    node_type_by_id = dict(og["existing_node_types"])
    node_compartment_by_id = {}
    compute_instance_name_by_id = {}
    policy_nodes_by_loc = defaultdict(list)
    compute_instances_by_loc = defaultdict(set)
    instance_agent_commands_by_loc = defaultdict(set)
    instance_target_ids_by_command = defaultdict(set)
    run_command_plugin_state_by_instance_by_loc = defaultdict(dict)
    plugin_telemetry_present_by_loc = set()
    for n in node_rows:
        if not isinstance(n, dict):
            continue
        nid = _s(n.get("node_id") or "")
        if not nid:
            continue
        props = _node_properties_from_row(n)
        node_type = _s(node_type_by_id.get(nid) or "")
        node_type_by_id[nid] = node_type
        comp_id = _s(props.get("compartment_id") or props.get("compartment_ocid") or "")
        node_compartment_by_id[nid] = comp_id
        if node_type == "OCIPolicy" and comp_id:
            policy_nodes_by_loc[comp_id].append(
                {
                    "id": nid,
                    "name": _s(props.get("name") or ""),
                }
            )
        if comp_id and (node_type == "OCIComputeInstance" or nid.startswith("ocid1.instance.")):
            compute_instances_by_loc[comp_id].add(nid)
            friendly = _s(props.get("display_name") or props.get("name") or "")
            if friendly:
                compute_instance_name_by_id[nid] = friendly
        if node_type == "OCIInstanceAgentCommand" and comp_id:
            instance_agent_commands_by_loc[comp_id].add(nid)
            for iid in _extract_instance_targets_from_command_props(props):
                instance_target_ids_by_command[nid].add(iid)
        if node_type == "OCIInstanceAgentCommandExecution":
            cmd_id = _s(
                props.get("instance_agent_command_id")
                or props.get("command_id")
                or ""
            )
            inst_id = _s(
                props.get("instance_id")
                or props.get("target_instance_id")
                or ""
            )
            execution_key = _s(props.get("execution_key") or "")
            if (not cmd_id or not inst_id) and ":" in execution_key:
                left, right = execution_key.split(":", 1)
                if not cmd_id and _s(left).startswith("ocid1.instanceagentcommand."):
                    cmd_id = _s(left)
                if not inst_id and _looks_like_instance_ocid(_s(right)):
                    inst_id = _s(right)
            if cmd_id and _looks_like_instance_ocid(inst_id):
                instance_target_ids_by_command[cmd_id].add(inst_id)
                if comp_id:
                    instance_agent_commands_by_loc[comp_id].add(cmd_id)
        if node_type == "OCIInstanceAgentPlugin":
            if comp_id:
                plugin_telemetry_present_by_loc.add(comp_id)
            if comp_id and _plugin_is_run_command(props):
                inst_id = _s(props.get("instance_id") or "")
                if _looks_like_instance_ocid(inst_id):
                    prior = _s(run_command_plugin_state_by_instance_by_loc[comp_id].get(inst_id) or "")
                    now = _plugin_state_from_props(props)
                    run_command_plugin_state_by_instance_by_loc[comp_id][inst_id] = _merge_plugin_state(prior, now)

    # Fallback inventory from raw service tables. This keeps derived run-command
    # edges functional even when compute/plugin nodes were filtered from opengraph.
    try:
        compute_rows = session.get_resource_fields(
            "compute_instances",
            columns=["id", "display_name", "compartment_id"],
        ) or []
    except Exception:
        compute_rows = []
    for row in compute_rows:
        if not isinstance(row, dict):
            continue
        instance_id = _s(row.get("id") or "")
        comp_id = _s(row.get("compartment_id") or "")
        if not (_looks_like_instance_ocid(instance_id) and comp_id):
            continue
        compute_instances_by_loc[comp_id].add(instance_id)
        friendly = _s(row.get("display_name") or row.get("name") or "")
        if friendly:
            compute_instance_name_by_id[instance_id] = friendly
        if not _s(node_type_by_id.get(instance_id) or ""):
            node_type_by_id[instance_id] = "OCIComputeInstance"
        if not _s(node_compartment_by_id.get(instance_id) or ""):
            node_compartment_by_id[instance_id] = comp_id

    try:
        plugin_rows = session.get_resource_fields(
            "compute_instance_agent_plugins",
            columns=["plugin_key", "instance_id", "compartment_id", "name", "status", "desired_state", "plugin_raw_json"],
        ) or []
    except Exception:
        plugin_rows = []
    for row in plugin_rows:
        if not isinstance(row, dict):
            continue
        comp_id = _s(row.get("compartment_id") or "")
        if not comp_id:
            continue
        plugin_telemetry_present_by_loc.add(comp_id)

        instance_id = _s(row.get("instance_id") or "")
        if _looks_like_instance_ocid(instance_id):
            compute_instances_by_loc[comp_id].add(instance_id)
            if not _s(node_type_by_id.get(instance_id) or ""):
                node_type_by_id[instance_id] = "OCIComputeInstance"
            if not _s(node_compartment_by_id.get(instance_id) or ""):
                node_compartment_by_id[instance_id] = comp_id

        props = {
            "name": _s(row.get("name") or ""),
            "plugin_name": _s(row.get("name") or ""),
            "status": _s(row.get("status") or ""),
            "desired_state": _s(row.get("desired_state") or ""),
            "instance_id": instance_id,
        }
        raw_json = row.get("plugin_raw_json")
        if isinstance(raw_json, str) and raw_json.strip():
            try:
                parsed = json.loads(raw_json)
                if isinstance(parsed, dict):
                    for k in ("name", "plugin_name", "status", "desired_state", "instance_id"):
                        if _s(props.get(k) or ""):
                            continue
                        props[k] = _s(parsed.get(k) or "")
            except Exception:
                pass

        resolved_instance_id = _s(props.get("instance_id") or instance_id)
        if _plugin_is_run_command(props) and _looks_like_instance_ocid(resolved_instance_id):
            prior = _s(run_command_plugin_state_by_instance_by_loc[comp_id].get(resolved_instance_id) or "")
            now = _plugin_state_from_props(props)
            run_command_plugin_state_by_instance_by_loc[comp_id][resolved_instance_id] = _merge_plugin_state(prior, now)

    # Phase 4: Build principal inventories and dynamic-group compute-member map
    # from already-materialized OpenGraph data only.
    #
    # Example outputs from `_collect_group_dynamic_inventory_from_nodes`:
    #   groups_by_loc = {
    #     "ocid1.compartment.oc1..a": {"ocid1.group.oc1..g1", "ocid1.group.oc1..g2"}
    #   }
    #   dynamic_group_rows = [
    #     {
    #       "id": "ocid1.dynamicgroup.oc1..dg1",
    #       "matching_rule": "ALL {resource.type='instance', resource.compartment.id='ocid1.compartment.oc1..a'}",
    #       "compartment_id": "ocid1.compartment.oc1..a",
    #     }
    #   ]
    groups_by_loc, dynamic_group_rows = _collect_group_dynamic_inventory_from_nodes(
        node_rows=node_rows,
        node_type_by_id=node_type_by_id,
        node_compartment_by_id=node_compartment_by_id,
    )
    dgs_with_compute_members_by_loc = defaultdict(set)
    instance_to_dynamic_groups_by_loc = defaultdict(lambda: defaultdict(set))
    # Example input row from `_load_dynamic_group_membership_edges(session)`:
    #   {
    #     "source_id": "ocid1.instance.oc1..i1",
    #     "destination_id": "ocid1.dynamicgroup.oc1..dg1",
    #     "edge_type": "OCI_DYNAMIC_GROUP_MEMBER",
    #     ...
    #   }
    # Result map built here:
    #   dgs_with_compute_members_by_loc = {
    #     "ocid1.compartment.oc1..a": {"ocid1.dynamicgroup.oc1..dg1"}
    #   }
    dg_member_edges = _load_dynamic_group_membership_edges(session)
    for e in dg_member_edges:
        if not isinstance(e, dict):
            continue
        if _s(e.get("edge_type")) != EDGE_DYNAMIC_GROUP_MEMBER:
            continue
        src_id = _s(e.get("source_id") or "")
        dg_id = _s(e.get("destination_id") or "")
        if not (src_id and dg_id):
            continue

        src_type = _s(node_type_by_id.get(src_id) or e.get("source_type") or "")
        # Compute membership edges are typically OCIComputeInstance, but keep an
        # OCID backstop in case source_type was saved as generic.
        if src_type not in {"OCIComputeInstance", NODE_TYPE_OCI_GENERIC_RESOURCE} and not src_id.startswith("ocid1.instance."):
            continue
        loc = _s(node_compartment_by_id.get(src_id) or "")
        if not loc:
            continue
        dgs_with_compute_members_by_loc[loc].add(dg_id)
        instance_to_dynamic_groups_by_loc[loc][src_id].add(dg_id)

    dg_permission_location_matcher = DynamicGroupPermissionLocationMatcher(
        DynamicGroupRuleEvaluator(session=session, debug=debug)
    )

    # Phase 5: Reduce policy output into principal+location relation buckets.
    #
    # Input (`relation_entries`) shape example from iam_policy_base_relation_graph_builder:
    #   [
    #     {
    #       "principal_id": "ocid1.group.oc1..g1",
    #       "principal_type": "OCIGroup",
    #       "loc": "ocid1.compartment.oc1..a",
    #       "edge_type": "OCI_CREATE_INSTANCE",
    #       "destination_id": "instances@ocid1.compartment.oc1..a",
    #       "destination_type": "OCIResourceGroup",
    #       "resolved_statements": [...],
    #       "unresolved_statements": [...],
    #       ...
    #     },
    #     ...
    #   ]
    #
    # Output (`relation_map`) shape:
    #   {
    #     ("ocid1.group.oc1..g1", "ocid1.compartment.oc1..a"): _RelationState(...),
    #     ...
    #   }
    # Where `_RelationState` aggregates booleans/evidence across many raw edges,
    # e.g. `create_instance_scope=True`, `create_policy_scope=False`.
    relation_map = _collect_relation_map_from_entries(
        relation_entries=relation_entries,
        node_type_by_id=node_type_by_id,
        node_compartment_by_id=node_compartment_by_id,
    )
    relation_buckets = len(relation_map)
    statement_instance_agent_caps = _collect_statement_instance_agent_caps(
        session=session,
        node_type_by_id=node_type_by_id,
    )

    # Phase 6: Emit derived consequence edges back into OpenGraph.
    emit_ctx = _DerivedEmitContext(
        ctx=ctx,
        existing_edges=og["existing_edges_set"],
        existing_nodes=og["existing_nodes_set"],
        node_type_by_id=node_type_by_id,
        node_compartment_by_id=node_compartment_by_id,
        groups_by_loc=groups_by_loc,
        dynamic_group_rows=dynamic_group_rows,
        compute_instance_name_by_id={
            _s(instance_id): _s(name)
            for instance_id, name in compute_instance_name_by_id.items()
            if _s(instance_id)
        },
        compute_instances_by_loc={
            k: set(v)
            for k, v in compute_instances_by_loc.items()
        },
        instance_agent_commands_by_loc={
            k: set(v)
            for k, v in instance_agent_commands_by_loc.items()
        },
        instance_target_ids_by_command={
            k: set(v)
            for k, v in instance_target_ids_by_command.items()
        },
        run_command_plugin_state_by_instance_by_loc={
            loc: {
                instance_id: _s(state).strip().lower()
                for instance_id, state in by_inst.items()
                if _s(instance_id)
            }
            for loc, by_inst in run_command_plugin_state_by_instance_by_loc.items()
        },
        plugin_telemetry_present_by_loc=set(plugin_telemetry_present_by_loc),
        instance_to_dynamic_groups_by_loc={
            loc: {
                instance_id: set(dg_ids)
                for instance_id, dg_ids in by_inst.items()
            }
            for loc, by_inst in instance_to_dynamic_groups_by_loc.items()
        },
        dgs_with_compute_members_by_loc=dgs_with_compute_members_by_loc,
        dg_permission_location_matcher=dg_permission_location_matcher,
        dg_instance_create_matches_by_loc={},
        relation_map=relation_map,
        policy_nodes_by_loc={
            k: sorted(list(v), key=lambda x: _s((x or {}).get("id") or ""))
            for k, v in policy_nodes_by_loc.items()
        },
        policy_update_capability_by_principal_loc=policy_update_capability_by_principal_loc,
    )

    for (principal_id, loc), cap in relation_map.items():
        principal_type = _s(cap.source_type) or _s(node_type_by_id.get(principal_id) or "OCIPrincipal")
        if not (
            principal_type
            and principal_type in PRINCIPAL_NODE_TYPES
            and principal_type not in SKIP_PRINCIPAL_NODE_TYPES
        ):
            continue

        for emitter in (
            _emit_policy_update_edges_to_all_resources,
            _emit_create_policy_edges_to_all_resources,
            _emit_new_instance_and_dynamic_group_edges,
            _emit_add_self_to_group_edges,
            _emit_instance_agent_run_command_edges,
        ):
            emitter(
                emit_ctx,
                principal_id=principal_id,
                principal_type=principal_type,
                loc=loc,
                cap=cap,
            )

    for (statement_id, loc), cap in statement_instance_agent_caps.items():
        _emit_instance_agent_run_command_edges_from_statement(
            emit_ctx,
            statement_id=statement_id,
            loc=loc,
            cap=cap,
        )

    prune_summary = _prune_orphan_new_scope_targets(
        session=session,
        emit_ctx=emit_ctx,
        debug=debug,
    )

    summary = {
        "relation_entries_seen": relation_entries_seen,
        "relation_buckets": relation_buckets,
        "statement_instance_agent_buckets": len(statement_instance_agent_caps),
        **prune_summary,
    }

    # Phase 7: Commit and summarize.
    if auto_commit:
        try:
            ctx.commit()
        except Exception as e:
            _dlog(debug, "iam-derived: commit failed", err=f"{type(e).__name__}: {e}")

    _dlog(debug, "iam-derived: done", **summary)
    return summary
