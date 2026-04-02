#!/usr/bin/env python3
"""
iam_policy_base_relation_graph_builder.py

Offline IAM policy -> OpenGraph edges builder.

Behaviors kept:
  * parse_policy_statements()
  * allowlist-driven edge labels (unless include_all=True)
  * optional conditionals filtering via StatementConditionalsEngine
  * resource-family expansion edges
  * policy-statement nodes that connect subjects -> statement -> resources

Key refactor:
  * OpenGraph dedupe state is stored on ctx.og_state and refreshed once via ctx.refresh_opengraph_state()
  * ctx.og_state uses:
        - existing_nodes_set: set(node_id)
        - existing_edges_set: set((src, edge_type, dst))
    (No edge-row caching / merging.)
  * Writes post-conditional relation entries (`ctx.iam_postprocess_relation_entries`)
    for post-processing derived builders.
  * toggles are read from ctx.iam_config (include_all/all_nodes/conditional_evaluation/expand_inheritance/etc.)
"""

from dataclasses import dataclass, field
from typing import Any, Dict

from oci_lexer_parser import parse_policy_statements
from ocinferno.modules.opengraph.utilities.helpers.iam_conditionals import StatementConditionalsEngine
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    DEFAULT_ALLOW_EDGE_RULES,
    NODE_TYPE_OCI_GENERIC_RESOURCE,
    NODE_TYPE_OCI_DYNAMIC_GROUP,
    NODE_TYPE_OCI_GROUP,
    NODE_TYPE_OCI_USER,
    PRINCIPAL_GROUPS,
    PERMISSION_MAPPING,
    RESOURCE_SCOPE_MAP,
)
from ocinferno.modules.opengraph.utilities.helpers import (
    build_edge_properties as _build_edge_properties,
    build_table_token_indexes,
    dlog as _dlog,
    EDGE_CATEGORY_PERMISSION,
    ensure_scope_node as _shared_ensure_scope_node,
    family_keys_l as _family_keys_l_shared,
    family_members_l as _family_members_l_shared,
    get_og_state as _og_shared,
    json_list as _json_list,
    l as _l,
    short_text as _short,
    synthetic_principal_id as _synthetic_principal_id,
    s as _s,
)
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import emit_edge as _emit_edge_shared
from ocinferno.modules.opengraph.utilities.helpers.policy_parser_enrichment import (
    enrich_domain_ocids_in_parsed_statements as _enrich_domain_ocids_in_parsed_statements,
)

TABLE_POLICIES = "identity_policies"
POLICY_STATEMENT_NODE = "OCIPolicyStatement"
EDGE_SUBJECT_IN_STATEMENT = "OCI_POLICY_SUBJECT"
EDGE_INTERNAL_USER_UPDATE = "OCI_INTERNAL_USER_UPDATE"
EDGE_INTERNAL_GROUP_UPDATE = "OCI_INTERNAL_GROUP_UPDATE"
ADVANCED_RELATION_EDGE_TYPES = {
    "OCI_MANAGE",
    "OCI_UPDATE_POLICY",
    "OCI_UPDATE_DYNAMIC_GROUP_RULES",
    "OCI_CREATE_POLICY",
    "OCI_CREATE_INSTANCE",
    "OCI_USE_TAG_NAMESPACE",
    "OCI_CREATE_INSTANCE_AGENT_COMMAND",
    "OCI_READ_RUN_INPUT",
    "OCI_READ_RUN_OUTPUT",
    EDGE_INTERNAL_USER_UPDATE,
    EDGE_INTERNAL_GROUP_UPDATE,
}

# table_name -> {resource_tokens}
TABLE_TO_TOKENS, _ = build_table_token_indexes(RESOURCE_SCOPE_MAP)


@dataclass(slots=True)
class StatementState:
    ctx: Any
    policy: dict
    st: dict
    statement_index: int
    statement_kind: str
    comp_id: str
    tenant_id: str
    subj_type_l: str
    subj_vals: list
    evaluate_conditionals: bool
    include_all: bool
    base_loc_pairs_all: list
    base_res_tokens: list
    base_raw_stmt: str
    stmt_id: str
    base_direct_verbs_l: set
    base_direct_perms: set
    base_effective_perms: set
    base_has_cond: bool
    base_candidate_subjects: list

    def to_engine_state(self) -> dict:
        return {
            "st": self.st,
            "base_raw_stmt": self.base_raw_stmt,
            "base_candidate_subjects": self.base_candidate_subjects,
            "base_loc_pairs_all": self.base_loc_pairs_all,
            "base_res_tokens": self.base_res_tokens,
            "base_direct_verbs_l": self.base_direct_verbs_l,
            "base_direct_perms": self.base_direct_perms,
            "base_effective_perms": self.base_effective_perms,
        }


@dataclass(slots=True)
class AllowOptionDelta:
    delta_candidate_subjects: list
    delta_loc_pairs_all: list
    delta_trimmed_verbs: set
    delta_trimmed_perms: set
    delta_option_tri: str
    delta_option_reasons: list
    delta_matched_rows_by_table: dict


@dataclass(slots=True)
class AllowEvalFlags:
    impossible_conditional: bool
    resolved_false: bool


@dataclass(slots=True)
class OptionRuntime:
    """
    Per-option runtime state used by `_handle_allow_statement`.
    Keeps branch data together so we avoid many loosely-coupled local vars.
    """
    subjects: list
    loc_pairs: list
    verbs: set
    perms: set
    rows_by_table: dict
    statement_edge_meta: dict
    subject_sources: list
    stmt_has_resource_edges: bool = False
    frame_relation_emits: list = field(default_factory=list)


@dataclass(slots=True)
class PostprocessRelationEntry:
    principal_id: str
    principal_type: str
    edge_type: str
    destination_id: str
    destination_type: str
    loc: str
    dest_token: str
    resolved_statements: list
    unresolved_statements: list
    resolved_policy: list
    unresolved_policy: list
    resolved_statement_details: list
    unresolved_statement_details: list
    has_unresolved_conditionals: bool
    has_impossible_conditionals: bool
    has_inherited: bool
    has_direct: bool

def _unwrap_policy_statements(parsed) -> list:
    if isinstance(parsed, dict):
        stmts = parsed.get("statements")
        return stmts if isinstance(stmts, list) else []
    if isinstance(parsed, list):
        return parsed
    return []


def _canon_spaces_l(x):
    if not isinstance(x, str):
        return ""
    s = " ".join(x.strip().split())
    return s.lower() if s else ""


def _rule_get(rule, k, default=None):
    if isinstance(rule, dict):
        return rule.get(k, default)
    return getattr(rule, k, default)


def _policy_statement_node_id(policy_id: str, statement_index: int) -> str:
    return f"policy_stmt:{_s(policy_id)}:{int(statement_index)}"


def _display_compartment(ctx, comp_id: str) -> str:
    comp_id = _s(comp_id)
    name_by = getattr(ctx, "compartment_name_by_id", {}) or {}
    display_loc = _s(name_by.get(comp_id) or comp_id)
    if isinstance(display_loc, str) and display_loc.startswith("ocid1."):
        prefix = "COMP_"
        if display_loc.startswith("ocid1.tenancy."):
            prefix = "TENANT_"
        token = ""
        if ".." in display_loc:
            token = display_loc.split("..", 1)[1]
        else:
            token = display_loc.rsplit(".", 1)[-1]
        token = token[:5] if token else "UNK"
        display_loc = f"{prefix}ocid1_{token}"
    return display_loc


def _policy_statement_display(ctx, policy_name: str, policy_id: str, statement_index: int, comp_id: str) -> str:
    base = _s(policy_name) or _s(policy_id) or "Policy"
    loc = _display_compartment(ctx, comp_id)
    return f"{base}:Statement_{int(statement_index) + 1}@{loc}"


def _ensure_policy_statement_node(ctx, policy: Dict[str, Any], statement_index: int, raw_stmt: str) -> str:
    og = _og_shared(ctx)
    existing_nodes = og["existing_nodes_set"]

    policy_id = _s(policy.get("id") or "")
    node_id = _policy_statement_node_id(policy_id, statement_index)
    if node_id in existing_nodes:
        return node_id

    policy_name = _s(policy.get("name") or "")
    comp_id = _s(policy.get("compartment_id") or "")
    tenant_id = _s(policy.get("_tenant_id") or "")

    ctx.upsert_node(
        node_id=node_id,
        node_type=POLICY_STATEMENT_NODE,
        node_properties={
            "name": _policy_statement_display(ctx, policy_name, policy_id, statement_index, comp_id),
            "compartment_id": comp_id,
            "tenant_id": tenant_id,
            "policy_id": policy_id,
            "policy_name": policy_name,
            "statement_index": int(statement_index),
            "statement_number": int(statement_index) + 1,
            "raw_statement": raw_stmt,
        },
        commit=False,
    )
    existing_nodes.add(node_id)
    return node_id


def _record_postprocess_relation_entries(
    *,
    ctx,
    subject_sources: list[tuple[str, str]],
    frame_relation_emits: list[dict],
    statement_edge_meta: dict,
) -> None:
    if not (frame_relation_emits and subject_sources):
        return
    store = getattr(ctx, "iam_postprocess_relation_entries", None)
    if not isinstance(store, list):
        store = []
        setattr(ctx, "iam_postprocess_relation_entries", store)

    meta = {
        "resolved_statements": list(statement_edge_meta.get("resolved_statements") or []),
        "unresolved_statements": list(statement_edge_meta.get("unresolved_statements") or []),
        "resolved_policy": list(statement_edge_meta.get("resolved_policy") or []),
        "unresolved_policy": list(statement_edge_meta.get("unresolved_policy") or []),
        "resolved_statement_details": list(statement_edge_meta.get("resolved_statement_details") or []),
        "unresolved_statement_details": list(statement_edge_meta.get("unresolved_statement_details") or []),
        "has_unresolved_conditionals": bool(statement_edge_meta.get("has_unresolved_conditionals")),
        "has_impossible_conditionals": bool(statement_edge_meta.get("has_impossible_conditionals")),
        "has_inherited": False,
        "has_direct": True,
    }
    for src_id, src_kind in (subject_sources or []):
        sid = _s(src_id)
        sk = _s(src_kind)
        if not (sid and sk):
            continue
        for emit in (frame_relation_emits or []):
            if not isinstance(emit, dict):
                continue
            et = _s(emit.get("edge_type") or "")
            if not et:
                continue
            store.append(
                PostprocessRelationEntry(
                    principal_id=sid,
                    principal_type=sk,
                    edge_type=et,
                    destination_id=_s(emit.get("destination_id") or ""),
                    destination_type=_s(emit.get("destination_type") or ""),
                    loc=_s(emit.get("loc") or ""),
                    dest_token=_s(emit.get("dest_token") or ""),
                    resolved_statements=list(meta["resolved_statements"]),
                    unresolved_statements=list(meta["unresolved_statements"]),
                    resolved_policy=list(meta["resolved_policy"]),
                    unresolved_policy=list(meta["unresolved_policy"]),
                    resolved_statement_details=list(meta["resolved_statement_details"]),
                    unresolved_statement_details=list(meta["unresolved_statement_details"]),
                    has_unresolved_conditionals=bool(meta["has_unresolved_conditionals"]),
                    has_impossible_conditionals=bool(meta["has_impossible_conditionals"]),
                    has_inherited=bool(meta["has_inherited"]),
                    has_direct=bool(meta["has_direct"]),
                )
            )


def _append_relation_emit(
    frame_relation_emits: list[dict],
    *,
    edge_kind: str,
    destination_id: str,
    destination_type: str,
    loc: str,
    dest_token: str,
) -> None:
    if edge_kind not in ADVANCED_RELATION_EDGE_TYPES:
        return
    frame_relation_emits.append(
        {
            "edge_type": edge_kind,
            "destination_id": destination_id,
            "destination_type": destination_type,
            "loc": _s(loc),
            "dest_token": _s(dest_token),
        }
    )


def _append_internal_permission_relation_hints(
    frame_relation_emits: list[dict],
    *,
    loc_pairs: list[tuple[str, bool]],
    perms: set[str],
    resource_tokens: list[str],
) -> None:
    """
    Record relation-only capability hints used by advanced derived builders.

    These are NOT emitted as graph edges; they are only stored in
    ctx.iam_postprocess_relation_entries so advanced derivation can reason over
    permission-pair statements such as:
      Allow group X to {USER_UPDATE,GROUP_UPDATE} in compartment Y
    without re-introducing standalone public privilege edges.
    """
    perms_u = {_s(p).upper() for p in (perms or set()) if _s(p)}
    tokens_l = {_l(t) for t in (resource_tokens or []) if _s(t)}

    # When parser/resource inference omits explicit resources for permission-only
    # statements, treat USER_UPDATE/GROUP_UPDATE as their canonical targets.
    grants_user_update = "USER_UPDATE" in perms_u and (not tokens_l or "users" in tokens_l)
    grants_group_update = "GROUP_UPDATE" in perms_u and (not tokens_l or "groups" in tokens_l)

    if not (grants_user_update or grants_group_update):
        return

    for loc_id, _inherited in (loc_pairs or []):
        loc = _s(loc_id)
        if not loc:
            continue
        if grants_user_update:
            _append_relation_emit(
                frame_relation_emits,
                edge_kind=EDGE_INTERNAL_USER_UPDATE,
                destination_id=f"users@{loc}",
                destination_type="OCIResourceGroup",
                loc=loc,
                dest_token="users",
            )
        if grants_group_update:
            _append_relation_emit(
                frame_relation_emits,
                edge_kind=EDGE_INTERNAL_GROUP_UPDATE,
                destination_id=f"groups@{loc}",
                destination_type="OCIResourceGroup",
                loc=loc,
                dest_token="groups",
            )


def _build_statement_edge_meta(
    *,
    state: StatementState,
    option: AllowOptionDelta,
    impossible_conditional: bool,
    resolved_false: bool,
) -> tuple[dict, bool]:
    option_tri = option.delta_option_tri or "TRUE"
    option_reasons = list(option.delta_option_reasons or ())
    has_unresolved = (option_tri.upper() == "UNKNOWN")

    stmt_info = {
        "stmt": state.base_raw_stmt,
        "stmt_id": state.stmt_id,
        "has_cond": bool(state.base_has_cond),
        "conditions": dict(state.st.get("conditions") or {}),
        "tri": option_tri,
        "policy_id": state.policy.get("id") or "",
        "policy_name": state.policy.get("name") or "",
        "statement_index": state.statement_index,
    }
    stmt_text = stmt_info["stmt"] or ""
    if has_unresolved:
        resolved_stmt_details = []
        unresolved_stmt_details = [{**stmt_info, "reasons": option_reasons}]
    else:
        resolved_stmt_details = [dict(stmt_info)]
        unresolved_stmt_details = []

    stmt_policy_id = stmt_info["policy_id"]
    return (
        {
            "resolved_statements": [stmt_text] if (stmt_text and not has_unresolved) else [],
            "unresolved_statements": [stmt_text] if (stmt_text and has_unresolved) else [],
            "resolved_policy": [stmt_policy_id] if (stmt_policy_id and not has_unresolved) else [],
            "unresolved_policy": [stmt_policy_id] if (stmt_policy_id and has_unresolved) else [],
            "resolved_statement_details": resolved_stmt_details,
            "unresolved_statement_details": unresolved_stmt_details,
            "has_unresolved_conditionals": has_unresolved,
            "has_impossible_conditionals": impossible_conditional,
            "resolved_false": resolved_false,
        },
        has_unresolved,
    )


def _build_option_runtime(
    *,
    state: StatementState,
    option: AllowOptionDelta,
    impossible_conditional: bool,
    resolved_false: bool,
    ctx,
    existing_nodes: set[str],
    skip_service_subject_edges: bool,
) -> OptionRuntime:
    """Build normalized runtime state for one conditional option branch."""
    subjects = option.delta_candidate_subjects or state.base_candidate_subjects
    loc_pairs = option.delta_loc_pairs_all or state.base_loc_pairs_all
    verbs = option.delta_trimmed_verbs or state.base_direct_verbs_l
    perms = option.delta_trimmed_perms or state.base_effective_perms
    rows_by_table = option.delta_matched_rows_by_table or {}
    statement_edge_meta, _ = _build_statement_edge_meta(
        state=state,
        option=option,
        impossible_conditional=impossible_conditional,
        resolved_false=resolved_false,
    )
    subject_sources = (
        _build_subject_sources(
            ctx,
            subjects,
            comp_id=state.comp_id,
            tenant_id=state.tenant_id,
            existing_nodes=existing_nodes,
        )
        if not skip_service_subject_edges
        else []
    )
    return OptionRuntime(
        subjects=subjects,
        loc_pairs=loc_pairs,
        verbs=verbs,
        perms=perms,
        rows_by_table=rows_by_table,
        statement_edge_meta=statement_edge_meta,
        subject_sources=subject_sources,
    )


def _flush_option_outputs(
    *,
    ctx,
    existing_edges,
    stats,
    subject_sources,
    stmt_node_id,
    stmt_node_type,
    statement_edge_meta,
    stmt_has_resource_edges,
    skip_service_subject_edges,
    frame_relation_emits,
):
    _write_subject_statement_edges(
        ctx=ctx,
        existing_edges=existing_edges,
        stats=stats,
        subject_sources=subject_sources,
        stmt_node_id=stmt_node_id,
        stmt_node_type=stmt_node_type,
        statement_edge_meta=statement_edge_meta,
        stmt_has_resource_edges=stmt_has_resource_edges,
        skip_service_subject_edges=skip_service_subject_edges,
    )
    _record_postprocess_relation_entries(
        ctx=ctx,
        subject_sources=subject_sources,
        frame_relation_emits=frame_relation_emits,
        statement_edge_meta=statement_edge_meta,
    )


# -----------------------------------------------------------------------------
# verb -> permissions map
# -----------------------------------------------------------------------------
# module-level caches
_VERB_TO_PERMS = None  # dict[str, set[str]]
_PERM_TO_RESOURCE_TOKENS = None  # dict[str, set[str]]
_PERM_TO_ALLOW_RESOURCE_TOKENS = None  # dict[str, frozenset[str]]
_PERM_TO_ALLOW_RESOURCE_TOKENS_SIG = None
_PERM_TO_RESOURCE_FALLBACK = {
    # Compute instance launch prerequisite permissions can be present in
    # permission-only policy statements even when parser resource inference is empty.
    "INSTANCE_CREATE": {"instances"},
    "VNIC_CREATE": {"vnics"},
    "VNIC_ATTACH": {"vnics"},
    "SUBNET_READ": {"subnets"},
    "SUBNET_ATTACH": {"subnets"},
    # Run-command statements are often permission-only and parse as resources=unknown.
    "INSTANCE_AGENT_COMMAND_CREATE": {"instance-agent-command-family", "instance-agent-commands"},
    "INSTANCE_AGENT_COMMAND_READ": {
        "instance-agent-command-family",
        "instance-agent-commands",
    },
    "INSTANCE_AGENT_COMMAND_EXECUTION_INSPECT": {
        "instance-agent-command-execution-family",
        "instance-agent-command-executions",
        "instance-agent-command-family",
        "instance-agent-commands",
    },
    # Secret content read can appear as a permission-only statement branch.
    "SECRET_BUNDLE_READ": {"secret-bundles", "secret-family"},
}


def actions_view(st, permission_mapping):
    """
    Return: (direct_verbs_l, direct_perms, effective_perms)

    Cascading semantics:
      inspect ⊆ read ⊆ use ⊆ manage
    """

    def canon(x):
        return x.strip().lower() if isinstance(x, str) else ""

    global _VERB_TO_PERMS, _PERM_TO_RESOURCE_TOKENS

    # -----------------------------
    # Build/cache verb->perms once
    # -----------------------------
    if _VERB_TO_PERMS is None or _PERM_TO_RESOURCE_TOKENS is None:
        v2p = {}
        p2r = {}

        pm = permission_mapping or {}
        for verb, svc_map in pm.items():
            v = canon(verb)
            if not v:
                continue

            perms = set()

            # svc_map: {service: {resource: [perms...]}}
            try:
                for res_map in (svc_map or {}).values():
                    for resource_token, plist in (res_map or {}).items():
                        resource_token_l = canon(resource_token)
                        for p in (plist or ()):
                            if isinstance(p, str):
                                p_norm = p.strip().upper()
                                if not p_norm:
                                    continue
                                perms.add(p_norm)
                                if resource_token_l:
                                    p2r.setdefault(p_norm, set()).add(resource_token_l)
            except AttributeError:
                # svc_map/res_map not dict-like -> skip
                continue

            if perms:
                v2p[v] = perms

        # cascade (cumulative)
        cumulative = set()
        for v in ("inspect", "read", "use", "manage"):
            cumulative |= v2p.get(v, set())
            v2p[v] = set(cumulative)

        _VERB_TO_PERMS = v2p
        _PERM_TO_RESOURCE_TOKENS = p2r

    # -----------------------------
    # Read statement actions
    # -----------------------------
    act = (st or {}).get("actions") or {}
    atype = canon(act.get("type"))
    vals = act.get("values") or ()

    if atype in ("permission", "permissions"):
        direct_perms = {_s(p).strip().upper() for p in vals if isinstance(p, str) and _s(p).strip()}
        return set(), direct_perms, set(direct_perms)

    if atype in ("verb", "verbs"):
        direct_verbs_l = {canon(v) for v in vals if isinstance(v, str) and v.strip()}
        effective_perms = set()
        for v in direct_verbs_l:
            effective_perms |= _VERB_TO_PERMS.get(v, set())
        return direct_verbs_l, set(), effective_perms

    return set(), set(), set()


def _perm_to_allow_resource_tokens(allow_rules_eff):
    """
    Build permission -> resource-token hints from allow-rule definitions.

    This is used for permission-only statements where parser resource inference is
    empty. By deriving from rule metadata, permission-only support automatically
    tracks all edge types encoded in ALLOW_RULE_DEFS.
    """
    global _PERM_TO_ALLOW_RESOURCE_TOKENS, _PERM_TO_ALLOW_RESOURCE_TOKENS_SIG

    rows = []
    for rule in (allow_rules_eff or ()):
        min_perms = tuple(sorted(_s(p).strip().upper() for p in (_rule_get(rule, "min_permissions", ()) or ()) if _s(p).strip()))
        any_perms = tuple(sorted(_s(p).strip().upper() for p in (_rule_get(rule, "any_permissions", ()) or ()) if _s(p).strip()))
        match_tokens = tuple(sorted(_l(t) for t in (_rule_get(rule, "match_resource_tokens", ()) or ()) if _s(t).strip()))
        dest_token = _l(_s(_rule_get(rule, "destination_token_to_make", "") or ""))
        rows.append((min_perms, any_perms, match_tokens, dest_token))

    sig = tuple(rows)
    if _PERM_TO_ALLOW_RESOURCE_TOKENS is not None and _PERM_TO_ALLOW_RESOURCE_TOKENS_SIG == sig:
        return _PERM_TO_ALLOW_RESOURCE_TOKENS

    out = {}
    for min_perms, any_perms, match_tokens, dest_token in rows:
        tokens = {t for t in match_tokens if t}
        if dest_token:
            tokens.add(dest_token)
        if not tokens:
            continue
        for perm in (*min_perms, *any_perms):
            if not perm:
                continue
            out.setdefault(perm, set()).update(tokens)

    norm = {k: frozenset(v) for k, v in out.items() if k and v}
    _PERM_TO_ALLOW_RESOURCE_TOKENS = norm
    _PERM_TO_ALLOW_RESOURCE_TOKENS_SIG = sig
    return _PERM_TO_ALLOW_RESOURCE_TOKENS


def _resource_tokens_from_permissions(perms, allow_rules_eff=None):
    """
    Best-effort token inference for permission-only statements where parser does not
    emit explicit resources (e.g., resources.type=unknown, values=[]).
    """
    global _PERM_TO_RESOURCE_TOKENS
    if _PERM_TO_RESOURCE_TOKENS is None:
        return []
    out = set()
    for p in (perms or ()):
        p_norm = _s(p).strip().upper()
        if not p_norm:
            continue
        out |= set(_PERM_TO_RESOURCE_TOKENS.get(p_norm, ()))
        out |= set(_PERM_TO_RESOURCE_FALLBACK.get(p_norm, ()))
        if allow_rules_eff:
            out |= set(_perm_to_allow_resource_tokens(allow_rules_eff).get(p_norm, ()))
    return sorted(t for t in out if t)


# -----------------------------------------------------------------------------
# parser accessors
# -----------------------------------------------------------------------------
def st_kind(st):
    return _l(st.get("kind"))


def st_subject_type(st):
    return _l((st.get("subject") or {}).get("type"))


def st_subject_values(st):
    return (st.get("subject") or {}).get("values") or []


def st_has_conditions(st):
    cond = st.get("conditions") or {}
    if not isinstance(cond, dict):
        return False
    if cond.get("clauses"):
        return True
    if cond.get("items"):
        return True
    if (cond.get("type") or "").lower() == "clause":
        return True
    return False


def st_resource_names(st):
    res = st.get("resources") or {}
    rtype = _l(res.get("type"))
    if rtype == "all-resources":
        return ["all-resources"]
    if rtype == "specific":
        return [_s(v) for v in (res.get("values") or []) if isinstance(v, str) and v.strip()]
    return []


def st_location(st):
    return st.get("location") or {}


def _family_keys_l(ctx):
    return _family_keys_l_shared(ctx)


def _family_members_l(ctx, fam):
    return _family_members_l_shared(ctx, fam)


# -----------------------------------------------------------------------------
# edge naming
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# allowlist matching
# -----------------------------------------------------------------------------
def _resource_match(ctx, rule_res_l, stmt_res_l):
    if rule_res_l == stmt_res_l:
        return True

    fam_keys = _family_keys_l(ctx)

    # If statement says "instance-family", treat it as matching "instances", etc.
    if stmt_res_l in fam_keys:
        return rule_res_l in set(_family_members_l(ctx, stmt_res_l))

    # If allow-rule says "instance-family" and stmt says "instances", match too.
    if rule_res_l in fam_keys:
        return stmt_res_l in set(_family_members_l(ctx, rule_res_l))

    return False


def _match_allow_rule(ctx, rule, res_tokens, direct_verbs_l, effective_perms, subj_type_l: str):
    """
    Return True when a normalized allow rule applies to the current statement branch.

    Typical inputs:
      rule:
        {
          "principal_group_key": "principals-non-service",
          "match_resource_tokens": {"instances"},
          "min_verbs": {"use"},
          "any_verbs": set(),
          "min_permissions": set(),
          "any_permissions": {"INSTANCE_READ"},
          ...
        }
      res_tokens: ["instances"]                      # statement resource tokens
      direct_verbs_l: {"use"}                        # statement verbs (lower-case)
      effective_perms: {"INSTANCE_READ", "..."}      # permissions implied/resolved
      subj_type_l: "group"                           # normalized subject kind

    High-level checks (all must pass):
      1) subject type gate
      2) resource token gate (with family-aware matching)
      3) verb constraints (min/all + any)
      4) permission constraints (min/all + any)
    """
    # ------------------------------------------------------------------
    # 1) Subject type gate
    # ------------------------------------------------------------------
    # Example:
    #   rule.principal_group_key = "principals-service"
    #   subj_type_l = "group"
    # -> fail (group is not a service principal)
    pgk = _s(_rule_get(rule, "principal_group_key", "") or "")
    if pgk:
        allowed = PRINCIPAL_GROUPS.get(pgk, set())
        # If subjects are allowlisted, and our subject is not in the allowlist quit
        if allowed and subj_type_l not in allowed:
            return False

    # ------------------------------------------------------------------
    # 2) Resource token gate
    # ------------------------------------------------------------------
    # `match_resource_tokens` is the normalized resource-token field.
    #
    # Example:
    #   match_tokens = {"instance-family"}
    #   res_tokens   = ["instances"]
    # `_resource_match(...)` handles family/member equivalence, so this passes.
    rule_match_tokens = set(_rule_get(rule, "match_resource_tokens", None) or ())

    if rule_match_tokens:
        has_resource_token_match = False
        for statement_resource_token in res_tokens or []:
            # Direct token hit.
            if statement_resource_token in rule_match_tokens:
                has_resource_token_match = True
                break
            # Family/member-equivalent hit (e.g., "instance-family" vs "instances").
            # `_resource_match(...)` already checks both rule<->statement directions.
            if any(
                _resource_match(ctx, rule_resource_token, statement_resource_token)
                for rule_resource_token in rule_match_tokens
            ):
                has_resource_token_match = True
                break
        if not has_resource_token_match:
            return False

    # ------------------------------------------------------------------
    # 3) Verb constraints
    # ------------------------------------------------------------------
    # min_verbs: minimum verb thresholds (hierarchical)
    # any_verbs: at least one acceptable verb threshold
    #
    # Example:
    #   min_verbs={"use"} and direct_verbs_l={"manage"} -> pass
    #   min_verbs={"read"} and direct_verbs_l={"use"} -> pass
    #   min_verbs={"manage"} and direct_verbs_l={"use"} -> fail
    #   any_verbs={"use","manage"} and direct_verbs_l={"manage"} -> pass
    verb_rank = {"inspect": 0, "read": 1, "use": 2, "manage": 3}
    statement_verbs = {_l(v) for v in (direct_verbs_l or ()) if isinstance(v, str)}
    ranked_statement_verbs = [verb_rank[v] for v in statement_verbs if v in verb_rank]
    statement_max_rank = max(ranked_statement_verbs) if ranked_statement_verbs else None

    def _satisfies_verb_threshold(required_verb: str) -> bool:
        required = _l(required_verb)
        if required in verb_rank:
            return statement_max_rank is not None and statement_max_rank >= verb_rank[required]
        return required in statement_verbs

    min_verbs = set(_rule_get(rule, "min_verbs", None) or [])
    any_verbs = set(_rule_get(rule, "any_verbs", None) or [])
    if min_verbs and not all(_satisfies_verb_threshold(v) for v in min_verbs):
        return False
    if any_verbs and not any(_satisfies_verb_threshold(v) for v in any_verbs):
        return False

    # ------------------------------------------------------------------
    # 4) Permission constraints
    # ------------------------------------------------------------------
    # min_permissions: all listed permissions must be present
    # any_permissions: at least one listed permission must be present
    #
    # Example:
    #   any_permissions={"INSTANCE_AGENT_COMMAND_EXECUTION_READ"}
    #   effective_perms={"INSTANCE_READ"} -> fail
    #   effective_perms={"INSTANCE_READ","INSTANCE_AGENT_COMMAND_EXECUTION_READ"} -> pass
    min_perms = set(_rule_get(rule, "min_permissions", None) or [])
    any_perms = set(_rule_get(rule, "any_permissions", None) or [])
    if min_perms and not min_perms.issubset(effective_perms):
        return False
    if any_perms and not (any_perms & set(effective_perms or ())):
        return False

    # All gates passed for this rule.
    return True


# -----------------------------------------------------------------------------
# location expansion (downward inheritance)
# -----------------------------------------------------------------------------
def _resolve_compartment_path(ctx, policy_compartment_id, path_value):
    raw = _s(path_value)
    if not raw or ":" not in raw:
        return ""

    segs = [s.strip() for s in raw.split(":") if s.strip()]
    if not segs:
        return ""

    parent_by = getattr(ctx, "parent_by_compartment_id", {}) or {}
    names_by = getattr(ctx, "compartment_names_l_by_id", {}) or {}

    children_by = {}
    for child_cid, parent_cid in parent_by.items():
        if parent_cid:
            children_by.setdefault(parent_cid, []).append(child_cid)

    current_root = policy_compartment_id

    for seg in segs:
        tgt = _canon_spaces_l(seg)
        resolved = ""
        for child_cid in (children_by.get(current_root, []) or []):
            names_l = names_by.get(child_cid)
            if names_l and tgt in names_l:
                resolved = child_cid
                break
        if not resolved:
            return ""
        current_root = resolved

    return current_root


def _location_tokens(ctx, st, policy_compartment_id, tenant_id, expand_inheritance, debug=False):
    loc = st_location(st) or {}
    if not isinstance(loc, dict):
        return []

    ltype = _l(loc.get("type") or loc.get("scope"))
    vals = loc.get("values") or []

    if not ltype:
        return []

    # -----------------------------------------------------------------------------
    # IMPORTANT SEMANTICS CHANGE:
    # "tenancy" scope should NOT mean "expand from tenant root".
    # We only expand from the *policy compartment* downward, because we may not
    # have a reliable tenant->root linkage (or the abstract tree at all).
    #
    # Fallback behavior:
    #   - if we cannot expand (missing graph / error / empty), default to just
    #     the current policy compartment id.
    # -----------------------------------------------------------------------------


    if ltype == "tenancy":
        base = _s(policy_compartment_id)
        if not base:
            return []
        if not expand_inheritance:
            return [(base, False)]
        try:
            expanded = ctx.descendants_including_self(base) or ()
        except Exception:
            expanded = ()
        if not expanded:
            return [(base, False)]
        return [(cid, i != 0) for i, cid in enumerate(expanded)]

    base = ""

    if ltype == "compartment_id":
        if isinstance(vals, list) and vals:
            base = _s(vals[0])

    elif ltype == "compartment_name":
        first = _s(vals[0]) if isinstance(vals, list) and vals else ""
        if ":" in first:
            base = _resolve_compartment_path(ctx, policy_compartment_id, first)
        if not base:
            tgt = _canon_spaces_l(first)
            try:
                for cid in (ctx.descendants_including_self(policy_compartment_id) or ()):
                    names_l = (getattr(ctx, "compartment_names_l_by_id", {}) or {}).get(cid)
                    if names_l and tgt in names_l:
                        base = cid
                        break
            except Exception:
                pass
        if not base:
            base = first

    elif ltype == "compartment":
        if not isinstance(vals, list) or not vals:
            return []
        out = []
        for v in vals:
            if not isinstance(v, dict):
                continue
            fmt = _l(v.get("format"))
            value = _s(v.get("value"))
            if not value:
                continue

            cid = ""
            if fmt == "ocid":
                cid = value
            elif fmt == "name":
                cid = ctx.resolve_compartment_id_by_name_near_policy(
                    policy_compartment_id=policy_compartment_id,
                    target_name=value,
                ) or ""
            elif fmt == "path":
                if ":" in value:
                    cid = _resolve_compartment_path(ctx, policy_compartment_id, value) or ""
                else:
                    cid = ctx.resolve_compartment_id_by_name_near_policy(
                        policy_compartment_id=policy_compartment_id,
                        target_name=value,
                    ) or ""
            if cid:
                out.append((cid, False))

        if expand_inheritance:
            expanded = []
            for cid, _ in out:
                try:
                    for dc in (ctx.descendants_including_self(cid) or (cid,)):
                        expanded.append((dc, dc != cid))
                except Exception:
                    expanded.append((cid, False))
            out = expanded

        seen = set()
        final = []
        for cid, inh in out:
            k = (cid, bool(inh))
            if k in seen:
                continue
            seen.add(k)
            final.append((cid, bool(inh)))
        return final

    else:
        if isinstance(vals, list) and vals:
            base = _s(vals[0])

    base = _s(base)
    if not base:
        return []

    if not expand_inheritance:
        return [(base, False)]

    try:
        expanded = ctx.descendants_including_self(base) or (base,)
    except Exception:
        expanded = (base,)

    return [(cid, i != 0) for i, cid in enumerate(expanded)]


# -----------------------------------------------------------------------------
# Small “state objects” so we stop passing 20 parallel variables around.
# -----------------------------------------------------------------------------
def _short_ocid(ocid: str, keep_head: int = 8, keep_tail: int = 6) -> str:
    """
    Shorten an OCI OCID for display: ocid1.*..TOKEN -> TOKEN[:keep_head]...TOKEN[-keep_tail:].
    Falls back safely for non-OCID strings.
    """
    s = _s(ocid)
    if not s:
        return ""

    if not s.startswith("ocid1."):
        # non-ocid: still trim if huge
        return s if len(s) <= (keep_head + keep_tail + 3) else f"{s[:keep_head]}...{s[-keep_tail:]}"

    # ocid1.<type>.<realm>..<token>
    token = ""
    if ".." in s:
        token = s.split("..", 1)[1]
    else:
        token = s.rsplit(".", 1)[-1]

    token = token or s
    if len(token) <= (keep_head + keep_tail + 3):
        return token
    return f"{token[:keep_head]}...{token[-keep_tail:]}"


def _pretty_loc(ctx, loc_id: str, tenant_id: str) -> str:
    """
    Display-friendly location:
      - TENANCY if loc_id == tenant_id
      - resolved compartment name if available
      - else shortened ocid token
    """
    loc_id = _s(loc_id)
    tenant_id = _s(tenant_id)

    if tenant_id and loc_id and loc_id == tenant_id:
        return "TENANCY"

    # Prefer resolved name if your ctx has it (your file already uses compartment_name_by_id)
    name_by = getattr(ctx, "compartment_name_by_id", {}) or {}
    friendly = _s(name_by.get(loc_id) or "")
    if friendly:
        return friendly

    return _short_ocid(loc_id)


def _service_display(raw: str) -> str:
    """
    Normalize service principal labels like:
      "SERVICE:FAAS::ocid1.tenancy..." -> "SERVICE:FAAS"
      "faas" -> "SERVICE:faas"
    """
    s = _s(raw)
    if not s:
        return ""
    if "::" in s:
        s = s.split("::", 1)[0]
    if s.lower().startswith("service:"):
        s = s.split(":", 1)[1]
    s = s.strip()
    return f"SERVICE:{s}" if s else ""


_SUBJECT_NODE_TYPE = {
    "group": NODE_TYPE_OCI_GROUP,
    "dynamic-group": NODE_TYPE_OCI_DYNAMIC_GROUP,
    "user": NODE_TYPE_OCI_USER,
    "service": "OCIService",
}


def _build_candidate_subjects(
    *,
    ctx,
    subj_type_l: str,
    subj_vals: list,
    tenant_id: str,
    loc_pairs_all: list,
):
    """
    Build candidate subject dicts for this ALLOW statement.

    Rules:
      - any-user / any-group: create a synthetic principal PER location:
          id      = ANY_USER@<loc_id>  (or ANY_GROUP@<loc_id>)
          display = ANY_USER@<pretty_loc> where pretty_loc resolves to TENANCY/name/short_ocid
          loc_id  = <loc_id>
      - normal subjects: one principal per subject value
          id      = ocid if present else canonical synthetic principal id
          display = display_name > name > label > prettified(id)
          loc_id  = None  (non-any principals are not location-scoped)
          domain_ocid / tenant_id are carried through
    """
    out = []

    subj_type_l = _l(subj_type_l)

    # -----------------------------------------
    # ANY_USER / ANY_GROUP (synthetic per loc)
    # -----------------------------------------
    if subj_type_l in {"any-user", "any-group"}:
        prefix = "ANY_USER" if subj_type_l == "any-user" else "ANY_GROUP"
        node_type = "OCIAnyUser" if prefix == "ANY_USER" else "OCIAnyGroup"

        for loc_id, _inh in (loc_pairs_all or ()):
            loc_id = _s(loc_id)
            if not loc_id:
                continue

            pretty_loc = _pretty_loc(ctx, loc_id, tenant_id)

            out.append({
                "id": f"{prefix}@{loc_id}",
                "kind": subj_type_l,
                "node_type": node_type,
                "display": f"{prefix}@{pretty_loc}",
                "domain_ocid": "",
                "tenant_id": _s(tenant_id),
                "loc_id": loc_id,
            })

        return out

    # -----------------------------------------
    # Normal subject types
    # -----------------------------------------
    node_type = _SUBJECT_NODE_TYPE.get(subj_type_l, "OCIPrincipal")
    tenant_id = _s(tenant_id)

    for sv in (subj_vals or []):
        if not isinstance(sv, dict):
            continue

        sid = _s(sv.get("ocid") or sv.get("id") or "")
        dom = _s(sv.get("identity_domain_ocid") or "")

        # If no OCID/id, use canonical synthetic principal id format.
        if not sid:
            lab = _s(sv.get("label") or sv.get("name") or sv.get("display_name") or "")
            sid = _synthetic_principal_id(
                subj_type_l,
                domain_ocid=dom,
                label=lab,
                tenant_id=tenant_id,
            )

        # display: prefer human label/name fields, else prettified id/ocid
        disp = (
            _s(sv.get("display_name") or "")
            or _s(sv.get("name") or "")
            or _s(sv.get("label") or "")
        )
        if subj_type_l == "service":
            disp = _service_display(disp or sid)
        if not disp:
            disp = _short_ocid(sid) if sid.startswith("ocid1.") else (sid or "<unknown>")

        out.append({
            "id": sid,
            "kind": subj_type_l,
            "node_type": node_type,
            "display": disp,
            "domain_ocid": dom,
            "tenant_id": tenant_id,
            "loc_id": None,  # ✅ keep None for non-any
        })

    return out


def _subject_kind_norm(subj: dict) -> str:
    k = _l(subj.get("kind") or subj.get("type") or "")
    if not k:
        nt = _l(subj.get("node_type") or "")
        if nt == "ociuser":
            k = "user"
        elif nt == "ocigroup":
            k = "group"
        elif nt == "ocidynamicgroup":
            k = "dynamic-group"
        elif nt == "ocianyuser":
            k = "any-user"
        elif nt == "ocianygroup":
            k = "any-group"
        elif nt == "ociservice":
            k = "service"
    if k in {"group-id", "group_id"}:
        return "group"
    if k in {"dynamic-group-id", "dynamic_group_id", "dynamicgroup-id"}:
        return "dynamic-group"
    if k in {"user-id", "user_id"}:
        return "user"
    return k


def _known_subject_sets(ctx):
    sig = (
        len(getattr(ctx, "idd_user_ocids", set()) or ()),
        len(getattr(ctx, "classic_user_ocids", set()) or ()),
        len(getattr(ctx, "idd_group_ocids", set()) or ()),
        len(getattr(ctx, "classic_group_ocids", set()) or ()),
        len(getattr(ctx, "idd_dynamic_group_ocids", set()) or ()),
        len(getattr(ctx, "classic_dynamic_group_ocids", set()) or ()),
    )
    cached = getattr(ctx, "_known_subject_sets_cache", None)
    cached_sig = getattr(ctx, "_known_subject_sets_cache_sig", None)
    if isinstance(cached, tuple) and len(cached) == 3 and cached_sig == sig:
        return cached
    users = set(getattr(ctx, "idd_user_ocids", set()) or ()) | set(getattr(ctx, "classic_user_ocids", set()) or ())
    groups = set(getattr(ctx, "idd_group_ocids", set()) or ()) | set(getattr(ctx, "classic_group_ocids", set()) or ())
    dgs = set(getattr(ctx, "idd_dynamic_group_ocids", set()) or ()) | set(getattr(ctx, "classic_dynamic_group_ocids", set()) or ())
    out = (users, groups, dgs)
    try:
        setattr(ctx, "_known_subject_sets_cache", out)
        setattr(ctx, "_known_subject_sets_cache_sig", sig)
    except Exception:
        pass
    return out


def _filter_known_subjects(ctx, subjects: list[dict]) -> list[dict]:
    users, groups, dgs = _known_subject_sets(ctx)
    out = []
    for subj in (subjects or []):
        if not isinstance(subj, dict):
            continue
        kind = _subject_kind_norm(subj)
        if kind in {"any-user", "any_user", "anyuser", "any-group", "any_group", "anygroup"}:
            out.append(subj)
            continue
        if kind == "service":
            continue
        sid = _s(subj.get("id") or "")
        if not sid:
            continue
        if kind == "user" and sid in users:
            out.append(subj)
            continue
        if kind == "group" and sid in groups:
            out.append(subj)
            continue
        if kind in {"dynamic-group", "dynamic_group", "dynamicgroup"} and sid in dgs:
            out.append(subj)
            continue
        if sid in users or sid in groups or sid in dgs:
            out.append(subj)
    return out


def _build_statement_state(*, ctx, policy, st, statement_index, stats, allow_rules_eff=None, debug=False):
    """
    Build base per-statement state used by statement handlers.

    Input examples:
      - policy: {"id":"ocid1.policy...", "compartment_id":"ocid1.compartment...", "statements":[...]}
      - st: parsed statement dict from oci_lexer_parser
      - statement_index: 0-based index into policy["statements"]

    Output shape example:
      {
        "statement_kind": "allow",
        "comp_id": "ocid1.compartment.oc1..xxxx",
        "tenant_id": "ocid1.tenancy.oc1..xxxx",
        "subj_type_l": "group",
        "subj_vals": [...],
        "base_loc_pairs_all": [("ocid1.compartment.oc1..xxxx", False)],
        "base_res_tokens": ["instances"],
        "base_raw_stmt": "Allow group Admins to manage instances in compartment Prod",
        "base_direct_verbs_l": {"manage"},
        "base_direct_perms": set(),
        "base_effective_perms": {"INSTANCE_READ", "..."},
        "base_has_cond": True,
        "base_candidate_subjects": [{"id":"ocid1.group...", "node_type":"OCIGroup", ...}],
      }
    """
    cfg = ctx.iam_config
    expand_inheritance = bool(cfg.get("expand_inheritance"))
    evaluate_conditionals = bool(cfg.get("conditional_evaluation"))
    include_all = bool(cfg.get("include_all"))

    comp_id = policy.get("compartment_id") or ""
    tenant_id = policy.get("_tenant_id") or ""
    statement_kind = st_kind(st)

    loc_pairs_all = _location_tokens(ctx, st, comp_id, tenant_id, expand_inheritance, debug=debug)
    if not loc_pairs_all:
        stats["skipped_missing_parts"] += 1
        return None

    direct_verbs_l, direct_perms, effective_perms = actions_view(st, PERMISSION_MAPPING)
    names = st_resource_names(st) or ()
    res_tokens = [_l(x) for x in names if isinstance(x, str) and x.strip()]
    if not res_tokens and direct_perms:
        res_tokens = _resource_tokens_from_permissions(direct_perms, allow_rules_eff=allow_rules_eff)
    if not res_tokens:
        stats["skipped_missing_parts"] += 1
        return None
    has_cond = st_has_conditions(st)
    subj_type_l = st_subject_type(st)
    subj_vals = st_subject_values(st) or []

    # Build parser-derived candidates, then keep only principals known in local caches.
    #
    # Example input:
    #   subj_type_l = "group"
    #   subj_vals = [{"label":"Admins","identity_domain_ocid":"ocid1.domain..."}]
    #   tenant_id = "ocid1.tenancy..."
    #   loc_pairs_all = [("ocid1.compartment...", False)]
    #
    # _build_candidate_subjects(...) output (pre-filter):
    #   [{"id":"ocid1.group...|synthetic::...", "kind":"group", "node_type":"OCIGroup",
    #     "display":"Admins", "domain_ocid":"ocid1.domain...", "tenant_id":"ocid1.tenancy...",
    #     "loc_id":None}]
    #
    # _filter_known_subjects(...) output (post-filter):
    #   - same list if IDs are in ctx known principal sets
    #   - [] if IDs are not known (later logic skips subject-edge emission)
    candidate_subjects = _filter_known_subjects(
        ctx,
        _build_candidate_subjects(
            ctx=ctx,
            subj_type_l=subj_type_l,
            subj_vals=subj_vals,
            tenant_id=tenant_id,
            loc_pairs_all=loc_pairs_all,
        ),
    )

    # `identity_policies.statements` is stored as JSON text in DB; decode to list
    # before indexing or we end up indexing characters from a string.
    stmts = _json_list(policy.get("statements"))
    raw_stmt = _s(stmts[statement_index]) if (0 <= statement_index < len(stmts)) else ""
    if not raw_stmt:
        raw_stmt = "<statement unavailable>"

    return StatementState(
        ctx=ctx,
        policy=policy,
        st=st,
        statement_index=int(statement_index),
        statement_kind=statement_kind,
        comp_id=comp_id,
        tenant_id=tenant_id,
        subj_type_l=subj_type_l,
        subj_vals=subj_vals,
        evaluate_conditionals=evaluate_conditionals,
        include_all=include_all,
        base_loc_pairs_all=list(loc_pairs_all),
        base_res_tokens=list(res_tokens),
        base_raw_stmt=raw_stmt,
        stmt_id=f"{policy.get('id')}:{statement_index}",
        base_direct_verbs_l=set(direct_verbs_l or ()),
        base_direct_perms=set(direct_perms or ()),
        base_effective_perms=set(effective_perms or ()),
        base_has_cond=bool(has_cond),
        base_candidate_subjects=candidate_subjects,
    )

def _rules_for_resource_tokens(ctx, *, allow_rules_eff, include_all: bool, resource_tokens: list[str], verbs_set: set[str], perms_set: set[str], subj_type_l: str):
    """
    Select allow-edge rules that apply to this statement branch.

    Example normalized rule in `DEFAULT_ALLOW_EDGE_RULES`:
      {
        "principal_group_key": "principals-non-service",
        "match_resource_tokens": frozenset({"instance-agent-commands"}),
        "min_verbs": frozenset({"use"}),
        "any_verbs": frozenset(),
        "min_permissions": frozenset(),
        "any_permissions": frozenset({"INSTANCE_AGENT_COMMAND_EXECUTION_READ"}),
        "edge_label": "OCI_READ_RUN_OUTPUT",
        "destination_token_to_make": "instance-agent-commands",
        "allow_specific_resources": True,
      }

    Input example:
      resource_tokens = ["instances"]
      verbs_set = {"use"}
      perms_set = {"INSTANCE_READ", "INSTANCE_INSPECT"}
      subj_type_l = "group"

    Comparison behavior:
      - principal group check: `subj_type_l` must fit `principal_group_key`
      - resource check: statement `resource_tokens` must match rule token(s)
      - action check: verbs/perms must satisfy rule min/any constraints

    Return:
      - list[(rule_dict, matched_tokens)] when one or more rules match
      - None when no rules match and include_all is False (hard stop branch)
      - [] when no rules match and include_all is True (allow downstream fallback)
    """
    matches = []
    for rule in allow_rules_eff:
        # Full rule gate: subject type + action set + resource token compatibility. If our statement aligns with
        # this rule, then we proceed else move onto the next rule
        if not _match_allow_rule(ctx, rule, resource_tokens, verbs_set, perms_set, subj_type_l):
            continue

        # Build `matched_tokens` for this rule.
        #
        # Why this exists:
        # - `_match_allow_rule(...)` only answers "does the rule apply at all?".
        # - Here we compute the exact statement resource token(s) that matched this rule.
        # - We retain this match detail with each rule tuple for traceability/debugging.
        #
        # Example:
        #   statement resource_tokens = ["instance-agent-command-family", "instances"]
        #   rule.match_resource_tokens = {"instance-agent-command-family", "instance-agent-commands"}
        # Result:
        #   matched_tokens = ["instance-agent-command-family"]
        # and later emit can stay scoped to that matched token.
        match_tokens = set(_rule_get(rule, "match_resource_tokens", ()) or ())
        if not match_tokens:
            # Rule did not constrain resource tokens -> keep all statement tokens.
            matched_tokens = list(resource_tokens or ())
        else:
            matched_tokens = []
            for statement_resource_token in (resource_tokens or []):
                if statement_resource_token in match_tokens:
                    matched_tokens.append(statement_resource_token)
                    continue
                # Family/member-equivalent match
                # (e.g., statement token "instances" vs rule token "instance-family").
                if any(
                    _resource_match(ctx, rule_resource_token, statement_resource_token)
                    for rule_resource_token in match_tokens
                ):
                    matched_tokens.append(statement_resource_token)

        # If rule explicitly requests token matching but none matched, drop it.
        if not matched_tokens and match_tokens:
            continue

        # Keep both the matched rule and the exact statement tokens it matched.
        matches.append((rule, matched_tokens))

    # Distinguish "no matches" modes for callers:
    # - None => do not emit anything for this branch (strict mode)
    # - []   => caller may emit include-all fallback edges
    if not matches and not include_all:
        return None
    return matches


def _emit_defs_from_matches(*, matches, default_dst_type: str, include_all: bool, resource_tokens: list[str]):
    emit = []
    seen = set()
    if matches:
        for rule, _matched_tokens in matches:
            edge_kind = _s(_rule_get(rule, "edge_label", ""))
            if not edge_kind:
                continue
            dst_hint = _s(_rule_get(rule, "destination_node_type_hint", "")) or default_dst_type
            # Normalized allow rules always set destination_token_to_make.
            dest_token = _s(_rule_get(rule, "destination_token_to_make", ""))
            allow_specific = bool(_rule_get(rule, "allow_specific_resources", True))
            edge_description = _s(_rule_get(rule, "edge_description", "")).strip()
            edge_status = _s(_rule_get(rule, "edge_status", "")).strip()
            key = (edge_kind, dest_token, dst_hint, allow_specific, edge_description, edge_status)
            if key in seen:
                continue
            seen.add(key)
            emit.append(key)
    # include_all fallback: if no allow-rule emits were produced, emit generic
    # POLICY_BUNDLE defs for each input resource token.
    if not emit and include_all:
        for tok in (resource_tokens or ()):
            key = ("POLICY_BUNDLE", tok, default_dst_type, False, "", "")
            if key in seen:
                continue
            seen.add(key)
            emit.append(key)
    return emit


def _evaluate_allow_statement_options(*, state: StatementState, cond_engine, stats):
    """
    Evaluate ALLOW-statement conditionals and return per-option deltas.

    Input:
      - `state`: baseline statement context from `_build_statement_state`

    Output:
      - `option_deltas`: list[AllowOptionDelta]
          Each item overrides ONLY keys changed by conditional evaluation, e.g.:
            {
              "delta_candidate_subjects": [...],            # trimmed subjects
              "delta_loc_pairs_all": [...],                 # trimmed locations
              "delta_trimmed_verbs": {...},                 # trimmed verbs
              "delta_trimmed_perms": {...},                 # trimmed perms
              "delta_option_tri": "TRUE|FALSE|UNKNOWN",
              "delta_option_reasons": [...],
              "delta_matched_rows_by_table": {
                  ("compute_instances", "instances"): [...],
                  ("buckets", "buckets"): [...],
              },
            }
          Keys not present should be read from baseline `state`.
      - `eval_flags`: AllowEvalFlags
      - `dropped`: bool
    """

    # Fast path: conditional evaluation disabled or statement has no conditionals.
    if (not state.evaluate_conditionals) or (not state.base_has_cond):
        return [
            AllowOptionDelta(
                delta_candidate_subjects=list(state.base_candidate_subjects),
                delta_loc_pairs_all=list(state.base_loc_pairs_all),
                delta_trimmed_verbs=set(state.base_direct_verbs_l),
                delta_trimmed_perms=set(state.base_effective_perms),
                delta_option_tri="TRUE",
                delta_option_reasons=[],
                delta_matched_rows_by_table={},
            )
        ], AllowEvalFlags(impossible_conditional=False, resolved_false=False), False

    ctx = state.ctx
    base_subjects = list(state.base_candidate_subjects)
    base_verbs = set(state.base_direct_verbs_l)
    base_effective_perms = set(state.base_direct_perms or state.base_effective_perms)
    base_locs = list(state.base_loc_pairs_all)

    drop_failed_conditionals = bool(
        getattr(ctx, "iam_config", {}).get("drop_all_no_effective_permissions")
    )

    # Engine evaluates condition tree and returns per-branch delta options.
    cond_result = cond_engine.evaluate_candidates(state=state.to_engine_state())

    # Engine requested statement drop.
    if getattr(cond_result, "drop_statement", False):
        stats["dropped_by_conditionals"] += 1
        return [], AllowEvalFlags(
            impossible_conditional=False,
            resolved_false=bool(getattr(cond_result, "resolved_false", False)),
        ), True

    # Respect drop-all-no-effective-permissions behavior for resolved-false branches.
    resolved_false = bool(getattr(cond_result, "resolved_false", False))
    impossible_conditional = bool(getattr(cond_result, "impossible_conditional", False))
    if resolved_false and drop_failed_conditionals:
        stats["dropped_by_conditionals"] += 1
        return [], AllowEvalFlags(
            impossible_conditional=impossible_conditional,
            resolved_false=True,
        ), True

    # Per-branch delta options from conditionals; fallback to one baseline branch.
    raw_options = [opt for opt in (getattr(cond_result, "options", None) or ()) if isinstance(opt, dict)] or [
        {
            "delta_candidate_subjects": base_subjects,
            "delta_loc_pairs_all": base_locs,
            "delta_trimmed_verbs": base_verbs,
            "delta_trimmed_perms": base_effective_perms,
            "delta_option_tri": "TRUE",
            "delta_option_reasons": [],
            "delta_matched_rows_by_table": {},
        }
    ]

    option_deltas: list[AllowOptionDelta] = []
    for opt in raw_options:
        # Finalize each branch with local policy-graph constraints:
        # 1) Keep only known principals.
        #    Example input:
        #      opt["delta_candidate_subjects"] = [{"id":"ocid1.group...A"}, {"id":"synthetic::missing"}]
        #    Example output:
        #      allowed_subjects = [{"id":"ocid1.group...A"}]
        # 2) Enforce non-empty location scope.
        #    Example input:
        #      opt["delta_loc_pairs_all"] = []
        #    Impact:
        #      branch is skipped (no reachable resource scope for edge emission).
        # 3) Normalize action/permission sets.
        #    Case A (verb-based statement):
        #      opt["delta_trimmed_verbs"] = {"use"}
        #      opt["delta_trimmed_perms"] = {"INSTANCE_READ"}
        #    -> trimmed_verbs={"use"}, trimmed_perms={"INSTANCE_READ"}
        #
        #    Case B (permission-based statement):
        #      opt["delta_trimmed_perms"] = {"INSTANCE_READ"}
        #    -> trimmed_perms={"INSTANCE_READ"}
        #
        #    Case C (option omits action fields):
        #      opt has no delta_trimmed_verbs / delta_trimmed_perms
        #    -> fallback to baseline sets:
        #       trimmed_verbs=base_verbs, trimmed_perms=base_effective_perms
        allowed_subjects = _filter_known_subjects(
            ctx,
            [dict(s) for s in (opt.get("delta_candidate_subjects") or base_subjects) if isinstance(s, dict)],
        )

        loc_pairs = list(opt.get("delta_loc_pairs_all") or [])
        if not loc_pairs:
            continue

        raw_rows_by_table = dict(opt.get("delta_matched_rows_by_table") or {})
        rows_by_table = {}
        for tname, trows in raw_rows_by_table.items():
            table_name = _s(tname)
            if not table_name:
                continue
            token = next(iter(TABLE_TO_TOKENS.get(table_name) or ()), "")
            if not token:
                continue
            rows_by_table[(table_name, token)] = list(trows or [])

        option_deltas.append(
            AllowOptionDelta(
                delta_candidate_subjects=allowed_subjects,
                delta_loc_pairs_all=loc_pairs,
                delta_trimmed_verbs=set(opt.get("delta_trimmed_verbs") or base_verbs),
                delta_trimmed_perms=set(opt.get("delta_trimmed_perms") or base_effective_perms),
                delta_option_tri=_s(opt.get("delta_option_tri") or "TRUE"),
                delta_option_reasons=list(opt.get("delta_option_reasons") or ()),
                delta_matched_rows_by_table=rows_by_table,
            )
        )

    return option_deltas, AllowEvalFlags(
        impossible_conditional=impossible_conditional,
        resolved_false=resolved_false,
    ), False


def _ensure_subject_node(ctx, subject_dict, *, comp_id: str, tenant_id: str, existing_nodes: set[str]):
    node_id = _s(subject_dict.get("id") or "")
    if not node_id:
        return
    if node_id in existing_nodes:
        return

    node_type = _s(subject_dict.get("node_type") or "OCIPrincipal")
    disp = _s(subject_dict.get("display") or subject_dict.get("name") or "")
    kind = _l(subject_dict.get("kind") or subject_dict.get("type") or "")
    if kind == "service":
        disp = _service_display(disp or node_id)
    if not disp:
        disp = _short_ocid(node_id) if node_id.startswith("ocid1.") else node_id

    loc_id = _s(subject_dict.get("loc_id") or "")
    node_comp = loc_id or _s(comp_id) or None

    ctx.upsert_node(
        node_id=node_id,
        node_type=node_type,
        node_properties={
            "name": disp,
            "compartment_id": node_comp,
            "tenant_id": _s(tenant_id) or None,
            **({"principal_kind": kind} if kind else {}),
        },
        commit=False,
    )
    existing_nodes.add(node_id)


def _build_subject_sources(ctx, candidate_subjects, *, comp_id: str, tenant_id: str, existing_nodes: set[str]):
    """
    Build reusable (source_id, source_type) tuples for the statement option and
    ensure subject nodes exactly once for this option.
    """
    out = []
    for subject_dict in (candidate_subjects or []):
        if not isinstance(subject_dict, dict):
            continue
        src_id = _s(subject_dict.get("id"))
        if not src_id:
            continue
        src_kind = subject_dict.get("node_type") or "OCIPrincipal"
        _ensure_subject_node(
            ctx,
            subject_dict,
            comp_id=comp_id,
            tenant_id=tenant_id,
            existing_nodes=existing_nodes,
        )
        out.append((src_id, src_kind))
    return out


# -------------------------------------------------------------------------
# Reusable statement-edge writers
# Used by ALLOW now; intended for ADMIN/ENDORSE handlers later.
# -------------------------------------------------------------------------
def _build_statement_permission_edge_props(
    *,
    description: str,
    statement_edge_meta: dict,
    edge_status: str = "",
    has_inherited: bool = False,
    has_direct: bool = False,
):
    status_norm = _s(edge_status or "").strip().upper()
    return _build_edge_properties(
        edge_category=EDGE_CATEGORY_PERMISSION,
        edge_inner_properties={
            "description": description,
            "is_priv_escalation": False,
            **({"status": status_norm, "is_pending": (status_norm == "PENDING")} if status_norm else {}),
            "resolved_statements": statement_edge_meta.get("resolved_statements", []),
            "unresolved_statements": statement_edge_meta.get("unresolved_statements", []),
            "resolved_policy": statement_edge_meta.get("resolved_policy", []),
            "unresolved_policy": statement_edge_meta.get("unresolved_policy", []),
            "resolved_statement_details": statement_edge_meta.get("resolved_statement_details", []),
            "unresolved_statement_details": statement_edge_meta.get("unresolved_statement_details", []),
            "has_unresolved_conditionals": bool(statement_edge_meta.get("has_unresolved_conditionals")),
            "has_impossible_conditionals": bool(statement_edge_meta.get("has_impossible_conditionals")),
            "resolved_false": bool(statement_edge_meta.get("resolved_false")),
            "has_inherited": has_inherited,
            "has_direct": has_direct,
        },
    )


def _write_statement_policy_edge(
    *,
    ctx,
    existing_edges: set[tuple[str, str, str]],
    src_id: str,
    src_kind: str,
    dst_id: str,
    dst_type: str,
    edge_kind: str,
    description: str,
    statement_edge_meta: dict,
    edge_status: str = "",
    has_inherited: bool = False,
    has_direct: bool = False,
) -> bool:
    edge_props = _build_statement_permission_edge_props(
        description=description,
        statement_edge_meta=statement_edge_meta,
        edge_status=edge_status,
        has_inherited=has_inherited,
        has_direct=has_direct,
    )
    wrote = _emit_edge_shared(
        ctx,
        src_id=src_id,
        src_type=src_kind,
        dst_id=dst_id,
        dst_type=dst_type,
        edge_type=edge_kind,
        edge_properties=edge_props,
        commit=False,
        on_conflict="update",
        dedupe=True,
    )
    if not wrote:
        return False
    existing_edges.add((src_id, edge_kind, dst_id))
    return True


def _write_subject_statement_edges(
    *,
    ctx,
    existing_edges: set[tuple[str, str, str]],
    stats: dict,
    subject_sources: list[tuple[str, str]],
    stmt_node_id: str,
    stmt_node_type: str,
    statement_edge_meta: dict,
    stmt_has_resource_edges: bool,
    skip_service_subject_edges: bool,
) -> None:
    if not (stmt_has_resource_edges and not skip_service_subject_edges):
        return
    for src_id, src_kind in subject_sources:
        if _write_statement_policy_edge(
            ctx=ctx,
            existing_edges=existing_edges,
            src_id=src_id,
            src_kind=src_kind,
            dst_id=stmt_node_id,
            dst_type=stmt_node_type,
            edge_kind=EDGE_SUBJECT_IN_STATEMENT,
            description="Subject included in IAM policy statement.",
            statement_edge_meta=statement_edge_meta,
            has_direct=True,
        ):
            stats["subject_statement_edges_written"] += 1


def _write_statement_resource_edge(
    *,
    ctx,
    existing_edges: set[tuple[str, str, str]],
    stats: dict,
    stmt_node_id: str,
    stmt_node_type: str,
    dst_id: str,
    dst_type: str,
    edge_kind: str,
    statement_edge_meta: dict,
    inherited: bool = False,
    description: str = "Derived from OCI IAM policy ALLOW statement.",
    edge_status: str = "",
) -> bool:
    if not _write_statement_policy_edge(
        ctx=ctx,
        existing_edges=existing_edges,
        src_id=stmt_node_id,
        src_kind=stmt_node_type,
        dst_id=dst_id,
        dst_type=dst_type,
        edge_kind=edge_kind,
        description=description,
        statement_edge_meta=statement_edge_meta,
        edge_status=edge_status,
        has_inherited=bool(inherited),
        has_direct=not bool(inherited),
    ):
        return False
    stats["statement_resource_edges_written"] += 1
    stats["statements_kept"] += 1
    return True


def _dest_matches_token(ctx, dest_token: str, token: str) -> bool:
    dt = _l(dest_token)
    tt = _l(token)
    if not dt:
        return True
    if dt in {"all-resources", "all_resources"}:
        return False
    if dt == tt:
        return True
    return _resource_match(ctx, dt, tt) or _resource_match(ctx, tt, dt)


def _emit_specific_row_matches(
    *,
    ctx,
    existing_edges,
    stats,
    stmt_node_id: str,
    stmt_node_type: str,
    allow_rules_eff,
    include_all: bool,
    subj_type_l: str,
    runtime: OptionRuntime,
) -> bool:
    """
    Phase B1:
    Emit statement->resource edges from concrete matched rows.
    Returns True when at least one concrete edge was emitted.
    """
    used_row_matches = False
    for table_key, rows in runtime.rows_by_table.items():
        if isinstance(table_key, tuple) and len(table_key) >= 2:
            table_name = _s(table_key[0])
            table_token = _l(table_key[1])
        else:
            table_name = _s(table_key)
            table_token = ""
        if not rows or table_name == "resource_compartments" or not table_token:
            continue

        matches = _rules_for_resource_tokens(
            ctx,
            allow_rules_eff=allow_rules_eff,
            include_all=include_all,
            resource_tokens=[table_token],
            verbs_set=runtime.verbs,
            perms_set=runtime.perms,
            subj_type_l=subj_type_l,
        )
        if matches is None:
            continue
        emit_defs = _emit_defs_from_matches(
            matches=matches,
            default_dst_type="",
            include_all=include_all,
            resource_tokens=[table_token],
        )
        if not emit_defs:
            continue

        for row in rows:
            dst_id = ctx.write_specific_resource_node(
                row,
                None,
                commit=False,
                table_name=table_name,
                resource_token=table_token,
            )
            if not dst_id:
                continue

            for edge_kind, dest_token, dst_type_hint, allow_specific, edge_description, edge_status in emit_defs:
                if not allow_specific:
                    continue
                if not _dest_matches_token(ctx, dest_token, table_token):
                    continue
                dst_type = dst_type_hint or _s(row.get("resource_type")) or NODE_TYPE_OCI_GENERIC_RESOURCE
                if _write_statement_resource_edge(
                    ctx=ctx,
                    existing_edges=existing_edges,
                    stats=stats,
                    stmt_node_id=stmt_node_id,
                    stmt_node_type=stmt_node_type,
                    dst_id=dst_id,
                    dst_type=dst_type,
                    edge_kind=edge_kind,
                    statement_edge_meta=runtime.statement_edge_meta,
                    inherited=False,
                    description=edge_description or "Derived from OCI IAM policy ALLOW statement.",
                    edge_status=edge_status,
                ):
                    used_row_matches = True
                    runtime.stmt_has_resource_edges = True
                    _append_relation_emit(
                        runtime.frame_relation_emits,
                        edge_kind=edge_kind,
                        destination_id=dst_id,
                        destination_type=dst_type,
                        loc=_s(row.get("compartment_id") or row.get("compartment_ocid") or ""),
                        dest_token=table_token,
                    )
    return used_row_matches


def _emit_scope_fallback(
    *,
    ctx,
    existing_edges,
    stats,
    stmt_node_id: str,
    stmt_node_type: str,
    allow_rules_eff,
    state: StatementState,
    runtime: OptionRuntime,
) -> None:
    """Phase B2: emit scope-level fallback edges when Phase B1 had no concrete rows."""
    matches = _rules_for_resource_tokens(
        ctx,
        allow_rules_eff=allow_rules_eff,
        include_all=state.include_all,
        resource_tokens=state.base_res_tokens,
        verbs_set=runtime.verbs,
        perms_set=runtime.perms,
        subj_type_l=state.subj_type_l,
    )
    if matches is None:
        return
    emit_defs = _emit_defs_from_matches(
        matches=matches,
        default_dst_type="",
        include_all=state.include_all,
        resource_tokens=state.base_res_tokens,
    )
    if not emit_defs:
        return

    for loc_id, inherited in runtime.loc_pairs:
        for edge_kind, dest_token, dst_type, _allow_specific, edge_description, edge_status in emit_defs:
            if not dest_token:
                continue
            scope_token = _s(dest_token)
            # IAM USER_CREATE can target any identity domain in-scope.
            # Keep this node distinct from IDD-scoped create-user nodes.
            if edge_kind == "OCI_CREATE_USER" and scope_token in {"new-users", "new_users", "new-user", "new_user"}:
                scope_token = "ANYDOMAIN/new_user"

            scope_id, scope_type, _ = _shared_ensure_scope_node(
                ctx,
                token=scope_token,
                loc=loc_id,
                tenant_id=state.tenant_id,
                compartment_id=state.comp_id,
                commit=False,
                dedupe=True,
            )
            edge_dst_type = dst_type or scope_type
            if _write_statement_resource_edge(
                ctx=ctx,
                existing_edges=existing_edges,
                stats=stats,
                stmt_node_id=stmt_node_id,
                stmt_node_type=stmt_node_type,
                dst_id=scope_id,
                dst_type=edge_dst_type,
                edge_kind=edge_kind,
                statement_edge_meta=runtime.statement_edge_meta,
                inherited=bool(inherited),
                description=edge_description or "Derived from OCI IAM policy ALLOW statement.",
                edge_status=edge_status,
            ):
                runtime.stmt_has_resource_edges = True
                _append_relation_emit(
                    runtime.frame_relation_emits,
                    edge_kind=edge_kind,
                    destination_id=scope_id,
                    destination_type=edge_dst_type,
                    loc=_s(loc_id),
                    dest_token=scope_token,
                )


def _handle_allow_statement(
    ctx,
    og_state,
    policy,
    st,
    statement_index,
    cond_engine,
    stats,
    debug=False,
):
    # Flow:
    # 1) Build normalized statement state
    # 2) Apply conditional trimming to get per-option deltas
    # 3) Emit statement->resource edges (specific rows first, scope fallback second)
    # 4) Emit subject->statement edges + postprocess relation entries
    allow_rules_eff = list(DEFAULT_ALLOW_EDGE_RULES or ())

    state = _build_statement_state(
        ctx=ctx,
        policy=policy,
        st=st,
        statement_index=statement_index,
        stats=stats,
        allow_rules_eff=allow_rules_eff,
        debug=debug,
    )
    if not state:
        return

    existing_edges, existing_nodes = og_state["existing_edges_set"], og_state["existing_nodes_set"]

    option_deltas, eval_flags, dropped = _evaluate_allow_statement_options(
        state=state,
        cond_engine=cond_engine,
        stats=stats,
    )
    if dropped or not option_deltas:
        return

    s = state

    impossible_conditional = eval_flags.impossible_conditional
    resolved_false = eval_flags.resolved_false

    stmt_node_type = POLICY_STATEMENT_NODE
    stmt_node_id = _ensure_policy_statement_node(
        ctx,
        policy,
        statement_index,
        s.base_raw_stmt,
    )
    skip_service_subject_edges = (s.subj_type_l == "service" and not s.include_all)
    if skip_service_subject_edges:
        stats["skipped_service_subjects"] = stats.get("skipped_service_subjects", 0) + 1

    # Emit edges for each conditional option (or one untrimmed option).
    for option in option_deltas:
        runtime = _build_option_runtime(
            state=s,
            option=option,
            impossible_conditional=impossible_conditional,
            resolved_false=resolved_false,
            ctx=ctx,
            existing_nodes=existing_nodes,
            skip_service_subject_edges=skip_service_subject_edges,
        )
        used_row_matches = _emit_specific_row_matches(
            ctx=ctx,
            existing_edges=existing_edges,
            stats=stats,
            stmt_node_id=stmt_node_id,
            stmt_node_type=stmt_node_type,
            allow_rules_eff=allow_rules_eff,
            include_all=s.include_all,
            subj_type_l=s.subj_type_l,
            runtime=runtime,
        )
        if not used_row_matches:
            _emit_scope_fallback(
                ctx=ctx,
                existing_edges=existing_edges,
                stats=stats,
                stmt_node_id=stmt_node_id,
                stmt_node_type=stmt_node_type,
                allow_rules_eff=allow_rules_eff,
                state=s,
                runtime=runtime,
            )

        _append_internal_permission_relation_hints(
            runtime.frame_relation_emits,
            loc_pairs=runtime.loc_pairs,
            perms=set(runtime.perms or ()),
            resource_tokens=list(s.base_res_tokens or ()),
        )

        _flush_option_outputs(
            ctx=ctx,
            existing_edges=existing_edges,
            stats=stats,
            subject_sources=runtime.subject_sources,
            stmt_node_id=stmt_node_id,
            stmt_node_type=stmt_node_type,
            statement_edge_meta=runtime.statement_edge_meta,
            stmt_has_resource_edges=runtime.stmt_has_resource_edges,
            skip_service_subject_edges=skip_service_subject_edges,
            frame_relation_emits=runtime.frame_relation_emits,
        )


def build_iam_policy_base_relation_edges_offline(*, session, ctx, debug=True, auto_commit=True, **_):
    # -------------------------------------------------------------------------
    # Phase 0: Initialize OG state, per-run caches, and config toggles
    # -------------------------------------------------------------------------
    # refresh OG dedupe sets
    ctx.refresh_opengraph_state(force=False)
    og = _og_shared(ctx)
    # Fresh per-run post-conditional relation handoff for advanced fast-path.
    setattr(ctx, "iam_postprocess_relation_entries", [])

    expand_inheritance = ctx.iam_config.get("expand_inheritance")
    conditional_evaluation = ctx.iam_config.get("conditional_evaluation")
    include_all = ctx.iam_config.get("include_all")
    infer_domain = ctx.iam_config.get("infer_domain")
    define_subs = ctx.iam_config.get("parse_define_subs")
    drop_time_no_perms = bool(ctx.iam_config.get("drop_time_based_no_effective_permissions"))
    drop_all_no_perms = bool(ctx.iam_config.get("drop_all_no_effective_permissions"))

    _dlog(debug, "iam: start build", table=TABLE_POLICIES)

    # quick visibility into domain resolution capability
    try:
        ctx.get_or_create_domain_ocid("Default")
    except Exception as e:
        _dlog(debug, "iam: get_or_create_domain_ocid(Default) failed", err=f"{type(e).__name__}: {e}")

    # -------------------------------------------------------------------------
    # Phase 1: Load active IAM policies and construct statement evaluator state
    # -------------------------------------------------------------------------
    policies = session.get_resource_fields(
        TABLE_POLICIES,
        where_conditions={"lifecycle_state": "ACTIVE"},
    ) or []

    cond_engine = StatementConditionalsEngine(
        session=session,
        ctx=ctx,
        debug=debug,
    )

    stats = {
        "policies_total": len(policies),
        "statements_total": sum(len(_json_list(p.get("statements"))) for p in policies if isinstance(p, dict)),
        "policies_parsed": 0,
        "parse_failures": [],
        "statements_seen": 0,
        "statements_kept": 0,
        "nodes_start": len(og["existing_nodes_set"]),
        "edges_start": len(og["existing_edges_set"]),
        "skipped_missing_parts": 0,
        "skipped_other_kinds": 0,
        "skipped_service_subjects": 0,
        "dropped_by_conditionals": 0,
        "include_all": bool(include_all),
        "expand_inheritance": bool(expand_inheritance),
        "evaluate_conditionals": bool(conditional_evaluation),
        "infer_domain": bool(infer_domain),
        "drop_time_based_no_effective_permissions": drop_time_no_perms,
        "drop_all_no_effective_permissions": drop_all_no_perms,
        "subject_statement_edges_written": 0,
        "statement_resource_edges_written": 0,
        "parse_diagnostics": [],
        "parse_diagnostics_error_count": 0,
    }

    failures = []

    # -------------------------------------------------------------------------
    # Phase 2: Parse each policy and normalize parsed statements
    # -------------------------------------------------------------------------
    for p in policies:

        policy_statements = _json_list(p.get("statements"))
        policy_id = p.get("id") or ""
        policy_name = p.get("name") or ""
        policy_compartment_id = p.get("compartment_id") or ""
        tenant_id = ctx.tenant_for_compartment(policy_compartment_id) or ""
        p["_tenant_id"] = tenant_id

        try:
            # Note tenant ID passed is for any tenancy NOT for tenant at the subject/domain level
            default_domain = _s(getattr(ctx, "default_domain_arg", "") or "") if infer_domain else ""
            
            payload, diagnostics = parse_policy_statements(
                policy_statements,
                define_subs=bool(define_subs),
                nested_simplify=True,
                error_mode="report", # Always use report mode so parser syntax errors are non-fatal.
                default_tenancy_alias=_s(tenant_id) or None,
                default_identity_domain=default_domain or None,
            )

            parsed = _unwrap_policy_statements(payload)

            # add identity_domain_ocid if identity_domain is present
            _enrich_domain_ocids_in_parsed_statements(ctx, parsed)
            stats["policies_parsed"] += 1

            diag_errors = diagnostics.get("errors") or []
            if diag_errors:
                diag_entry = {
                    "policy_id": policy_id,
                    "policy_name": policy_name,
                    "error_count": int(diagnostics.get("error_count") or len(diag_errors)),
                    "errors": [],
                }
                for e in diag_errors:
                    stmt_text = _short(_s(e.get("line_text") or ""), 240)
                    rule_index = e.get("rule_index")
                    if isinstance(rule_index, int) and 0 <= rule_index < len(policy_statements):
                        stmt_text = _short(policy_statements[rule_index], 240)
                    diag_entry["errors"].append({
                        "rule_index": rule_index,
                        "line": e.get("line"),
                        "column": e.get("column"),
                        "message": _s(e.get("message") or ""),
                        "statement": stmt_text,
                    })
                stats["parse_diagnostics"].append(diag_entry)
                stats["parse_diagnostics_error_count"] += diag_entry["error_count"]

        except Exception as e:
            failures.append({
                "policy_id": policy_id,
                "compartment_id": policy_compartment_id,
                "err": f"{type(e).__name__}: {e}",
            })
            parsed = []
            continue

        # ---------------------------------------------------------------------
        # Phase 3: Dispatch statement handlers
        # ---------------------------------------------------------------------
        for idx, st in enumerate(parsed or []):
            
            stats["statements_seen"] += 1
            
            if st_kind(st) == "allow":

                _handle_allow_statement(
                    ctx,
                    og,
                    policy=p,
                    st=st,
                    statement_index=idx,
                    cond_engine=cond_engine,
                    stats=stats,
                    debug=debug,
                )

            else:
                
                stats["skipped_other_kinds"] += 1
                continue

    # -------------------------------------------------------------------------
    # Phase 4: Finalize stats, record metrics, commit, and emit summary log
    # -------------------------------------------------------------------------
    stats["parse_failures"] = failures
    stats["nodes_created"] = len(og["existing_nodes_set"]) - stats["nodes_start"]
    stats["edges_created"] = len(og["existing_edges_set"]) - stats["edges_start"]
    stats["offline_context_stats"] = getattr(ctx, "stats", {}) or {}

    try:
        ctx.record_iam_stats(stats)
    except Exception:
        pass

    if auto_commit:
        try:
            ctx.commit()
        except Exception as e:
            _dlog(debug, "iam: ctx commit failed", err=f"{type(e).__name__}: {e}")

    _dlog(
        debug,
        "iam: done build",
        policies_parsed=stats["policies_parsed"],
        statements_seen=stats["statements_seen"],
        statements_kept=stats["statements_kept"],
        nodes_created=stats["nodes_created"],
        edges_created=stats["edges_created"],
        dropped_by_conditionals=stats["dropped_by_conditionals"],
        parse_diagnostics_error_count=stats.get("parse_diagnostics_error_count", 0),
    )

    return stats
