#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
resource_scope_graph_builder.py

Expands *scope nodes* in opengraph_nodes that look like:

    <resource_token>@<compartment_ocid>

into:

1) Resource-family expansion edges (policy semantics):

    <family_scope> --FAMILY_INCLUDES--> <member_scope>

2) Concrete resource expansion edges (enumeration-backed):

    <scope_node> --OCI_SPECIFIC_RESOURCE--> <resource_ocid>

3) Wildcard principal expansion (IAM semantics):

    <user_ocid> --OCI_ANY_USER_MEMBER_OF--> ANY_USER@<loc>

    <group_or_dg_ocid> --OCI_ANY_GROUP_MEMBER_OF--> ANY_GROUP@<loc>

Notes:
- Uses ctx.og_state dedupe sets:
    existing_nodes_set: set(node_id)
    existing_edges_set: set((src, edge_type, dst))
- Assumes ctx.refresh_opengraph_state(force=False) is available.
- Does NOT expand "all-resources" (too broad).
"""
from ocinferno.modules.opengraph.utilities.helpers.context import _dlog
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    NODE_TYPE_OCI_GENERIC_RESOURCE,
    NODE_TYPE_OCI_DYNAMIC_GROUP,
    NODE_TYPE_OCI_GROUP,
    NODE_TYPE_OCI_USER,
    RESOURCE_SCOPE_MAP,
)
from ocinferno.modules.opengraph.utilities.helpers import (
    build_edge_properties as _build_edge_properties,
    EDGE_CATEGORY_GROUP_MEMBERSHIP,
    EDGE_CATEGORY_RESOURCE,
    family_keys_l as _family_keys_l,
    family_members_l as _family_members_l,
    get_og_state as _og,
    is_family as _is_family,
    iter_scope_specs as _iter_scope_specs,
    l as _l,
    row_get as _shared_row_get,
    s as _s,
)
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import emit_edge as _emit_edge_shared
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import ensure_principal_node as _ensure_principal_node_shared
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import ensure_scope_node as _shared_ensure_scope_node
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import fetch_rows_cached as _fetch_rows_cached
from collections import defaultdict, deque

# Edges
EDGE_SCOPE_INCLUDES = "OCI_SPECIFIC_RESOURCE"
EDGE_FAMILY_INCLUDES = "FAMILY_INCLUDES"
EDGE_ANY_USER_MEMBER_OF = "OCI_ANY_USER_MEMBER_OF"
EDGE_ANY_GROUP_MEMBER_OF = "OCI_ANY_GROUP_MEMBER_OF"
EDGE_SCOPE_MEMBER_OF = "OCI_SCOPE_MEMBER_OF"
EDGE_BELONGS_TO = "OCI_BELONGS_TO"
EDGE_INCLUDES = "OCI_INCLUDES"
NEW_USER_SCOPE_TOKENS = {"new-users", "new_users", "new-user", "new_user"}

# ANY_USER resource-principal expansion:
# Keep this intentionally narrow for now (Functions only) to avoid overly broad
# wildcard principal expansion. Add more targets later as:
#   "<OpenGraphNodeType>"
# Example future adds: "OCIComputeInstance", "OCIContainerInstance".
ANY_USER_RESOURCE_PRINCIPAL_SCOPE_TOKENS = ("OCIFunctionFunction",)

def _is_scope_node_id(node_id):
    if not isinstance(node_id, str) or "@" not in node_id:
        return False
    name, loc = node_id.split("@", 1)
    return bool(_s(name) and _s(loc))


def _infer_scope_node_type(token_l: str, family_keys_l: set[str]) -> str:
    if token_l == "any_user":
        return "OCIAnyUser"
    if token_l == "any_group":
        return "OCIAnyGroup"
    if token_l == "all-resources":
        return "OCIAllResources"
    if token_l in family_keys_l:
        return "OCIResourceFamily"
    return "OCIResourceGroup"

def _ensure_family_edges(ctx, family_scope_id, family_scope_type, loc, stats, debug=False):
    """
    Given family scope node "<fam>@<loc>", ensure:
      <fam>@<loc> --FAMILY_INCLUDES--> <member>@<loc>

    Also ensures member scope nodes exist.
    Returns list of member scope ids created/ensured (for later concrete expansion).
    """
    og = _og(ctx)
    existing_edges = og["existing_edges_set"]

    fam_name = family_scope_id.split("@", 1)[0].lower()
    if fam_name not in _family_keys_l(ctx):
        return []

    members = []
    made = 0

    for mem_token_l in _family_members_l(ctx, fam_name):
        try:
            mem_scope_id, mem_scope_type, _ = _shared_ensure_scope_node(
                ctx,
                token=mem_token_l,
                loc=loc,
                commit=False,
                dedupe=True,
            )
        except Exception as e:
            if debug:
                _dlog(debug, "resource-scope: upsert scope node failed", token=mem_token_l, loc=loc, err=f"{type(e).__name__}: {e}")
            continue
        if not mem_scope_id:
            continue

        members.append(mem_scope_id)

        ek = (family_scope_id, EDGE_FAMILY_INCLUDES, mem_scope_id)
        if ek in existing_edges:
            continue

        try:
            wrote = _emit_edge_shared(
                ctx,
                src_id=family_scope_id,
                src_type=family_scope_type or "OCIResourceFamily",
                dst_id=mem_scope_id,
                dst_type=mem_scope_type or "OCIResourceGroup",
                edge_type=EDGE_FAMILY_INCLUDES,
                edge_properties=_build_edge_properties(
                    edge_category=EDGE_CATEGORY_RESOURCE,
                    edge_inner_properties={
                        "description": "Resource family membership expansion (policy semantics).",
                        "resource_family": True,
                        "resource_used": True,
                    },
                ),
                commit=False,
                on_conflict="update",
                dedupe=True,
            )
            if wrote:
                existing_edges.add(ek)
                made += 1
        except Exception as e:
            if debug:
                _dlog(debug, "resource-scope: family edge write failed",
                      family_scope_id=family_scope_id, mem_scope_id=mem_scope_id,
                      err=f"{type(e).__name__}: {e}")

    if made:
        stats["family_include_edges_created"] += made
        if debug:
            _dlog(debug, "resource-scope: family expansion", family=fam_name, loc=loc, made=made)

    return members


def _build_compartment_lookup(session, lookup_spec, cache, debug=False):
    if not isinstance(lookup_spec, dict):
        return {}
    table = lookup_spec.get("table")
    id_col = lookup_spec.get("id_col")
    comp_col = lookup_spec.get("compartment_col")
    if not (table and id_col and comp_col):
        return {}
    cache_key = (table, str(id_col), str(comp_col))
    if cache_key in cache:
        return cache[cache_key]
    try:
        rows = session.get_resource_fields(table, columns=[id_col, comp_col]) or []
    except Exception as e:
        if debug:
            _dlog(debug, "resource-scope: lookup query failed", table=table, err=f"{type(e).__name__}: {e}")
        cache[cache_key] = {}
        return {}
    mapping = {}
    for row in rows:
        rid = _shared_row_get(row, id_col)
        cid = _shared_row_get(row, comp_col)
        if isinstance(rid, str) and rid and isinstance(cid, str) and cid:
            mapping[rid] = cid
    cache[cache_key] = mapping
    return mapping


def _build_id_name_lookup(session, *, table: str, id_col: str, name_col: str, cache: dict, debug=False):
    """
    Build cached lookup: id -> name for fallback display synthesis.
    """
    if not (table and id_col and name_col):
        return {}
    cache_key = ("id_name_lookup", table, str(id_col), str(name_col))
    if cache_key in cache:
        return cache[cache_key]
    try:
        rows = session.get_resource_fields(table, columns=[id_col, name_col]) or []
    except Exception as e:
        if debug:
            _dlog(debug, "resource-scope: id/name lookup query failed", table=table, err=f"{type(e).__name__}: {e}")
        cache[cache_key] = {}
        return {}
    mapping = {}
    for row in rows:
        rid = _shared_row_get(row, id_col)
        name = _shared_row_get(row, name_col)
        if isinstance(rid, str) and rid and isinstance(name, str) and name.strip():
            mapping[rid] = name.strip()
    cache[cache_key] = mapping
    return mapping


def _fetch_scope_rows(session, query_cache, *, table: str, comp_col: str | None, loc: str, stats: dict, debug: bool, log_tag: str):
    """
    Cached row fetch helper for scope expansion.
    - If comp_col is provided, query with where_conditions {comp_col: loc}
    - If comp_col is empty, fetch all rows
    """
    try:
        cache_key = (table, comp_col or "", loc if comp_col else "")
        if cache_key in query_cache:
            return query_cache.get(cache_key) or []
        rows = _fetch_rows_cached(
            session,
            query_cache,
            table=table,
            where_conditions={comp_col: loc} if comp_col else None,
            cache_key=cache_key,
        ) or []
        query_cache[cache_key] = rows
        return rows
    except Exception as e:
        stats["query_failures"] += 1
        if debug:
            _dlog(debug, log_tag, table=table, loc=loc, err=f"{type(e).__name__}: {e}")
        return []


def _resolve_display_name(row: dict, *, display_col: str | None, name_col: str | None, fallback: str) -> str:
    display = _shared_row_get(row, display_col) if display_col else None
    if not (isinstance(display, str) and display.strip()) and name_col:
        display = _shared_row_get(row, name_col)
    if isinstance(display, str) and display.strip():
        return display
    return fallback


def _build_principal_scope_index(ctx):
    """
    Build and cache principal rows keyed by scope token + compartment:
      index[token][compartment_id] -> [(node_id, node_type, is_idd, row), ...]

    This avoids repeated full scans of ctx principal lists for each scope node.
    """
    og = _og(ctx)
    cached = og.get("principal_scope_index")
    if isinstance(cached, dict) and cached:
        return cached

    index = {
        "users": defaultdict(list),
        "groups": defaultdict(list),
        "dynamic-groups": defaultdict(list),
        "any-user": defaultdict(list),
        "any-group": defaultdict(list),
    }
    seen = {k: defaultdict(set) for k in index}

    def _add(token, node_id, node_type, comp_id, is_idd, row):
        nid = _s(node_id)
        loc = _s(comp_id)
        if not (nid and loc):
            return
        bucket_seen = seen[token][loc]
        if nid in bucket_seen:
            return
        bucket_seen.add(nid)
        index[token][loc].append((nid, node_type, bool(is_idd), row if isinstance(row, dict) else {}))

    sources = (
        ("users", getattr(ctx, "idd_users", []) or [], NODE_TYPE_OCI_USER, True, "ocid"),
        ("users", getattr(ctx, "classic_users", []) or [], NODE_TYPE_OCI_USER, False, "id"),
        ("groups", getattr(ctx, "idd_groups", []) or [], NODE_TYPE_OCI_GROUP, True, "ocid"),
        ("groups", getattr(ctx, "classic_groups", []) or [], NODE_TYPE_OCI_GROUP, False, "id"),
        ("dynamic-groups", getattr(ctx, "idd_dynamic_groups", []) or [], NODE_TYPE_OCI_DYNAMIC_GROUP, True, "ocid"),
        ("dynamic-groups", getattr(ctx, "classic_dynamic_groups", []) or [], NODE_TYPE_OCI_DYNAMIC_GROUP, False, "id"),
    )

    for token, rows, node_type, is_idd, id_key in sources:
        for row in rows:
            if not isinstance(row, dict):
                continue
            comp_id = _s(row.get("compartment_id") or row.get("compartment_ocid") or "")
            node_id = _s(row.get(id_key) or row.get("ocid") or row.get("id") or "")
            if not (node_id and comp_id):
                continue

            _add(token, node_id, node_type, comp_id, is_idd, row)
            if token == "users":
                _add("any-user", node_id, node_type, comp_id, is_idd, row)
            else:
                _add("any-group", node_id, node_type, comp_id, is_idd, row)

    og["principal_scope_index"] = index
    return index


def _write_any_edge(ctx, *, src_id: str, src_type: str, dst_id: str, dst_type: str, edge_type: str, existing_edges: set, stats: dict, debug: bool):
    if not src_id or not dst_id:
        return
    ek = (src_id, edge_type, dst_id)
    if ek in existing_edges:
        return
    try:
        desc = "Synthetic scope inclusion link." if edge_type == EDGE_SCOPE_MEMBER_OF else "Wildcard principal expansion."
        if edge_type in (EDGE_ANY_USER_MEMBER_OF, EDGE_ANY_GROUP_MEMBER_OF):
            edge_props = _build_edge_properties(
                edge_category=EDGE_CATEGORY_GROUP_MEMBERSHIP,
                edge_inner_properties={
                    "matching_rules": desc,
                    "membership_id": "",
                    "group_type": "standard",
                },
            )
        else:
            edge_props = _build_edge_properties(
                edge_category=EDGE_CATEGORY_RESOURCE,
                edge_inner_properties={
                    "description": desc,
                    "resource_family": False,
                    "resource_used": False,
                },
            )
        wrote = _emit_edge_shared(
            ctx,
            src_id=src_id,
            src_type=src_type,
            dst_id=dst_id,
            dst_type=dst_type,
            edge_type=edge_type,
            edge_properties=edge_props,
            commit=False,
            on_conflict="update",
            dedupe=True,
        )
        if wrote:
            existing_edges.add(ek)
            if edge_type == EDGE_ANY_USER_MEMBER_OF:
                stats["any_user_member_edges_created"] += 1
            elif edge_type == EDGE_ANY_GROUP_MEMBER_OF:
                stats["any_group_member_edges_created"] += 1
            elif edge_type == EDGE_SCOPE_MEMBER_OF:
                stats["scope_member_of_edges_created"] += 1
    except Exception as e:
        if debug:
            _dlog(debug, "resource-scope: wildcard edge write failed", src_id=src_id, dst_id=dst_id, err=f"{type(e).__name__}: {e}")


def _emit_any_scope_members(
    *,
    ctx,
    scope_id: str,
    scope_type: str,
    entries: list,
    edge_type: str,
    existing_edges: set,
    existing_nodes: set,
    stats: dict,
    debug: bool,
):
    for node_id, node_type, is_idd, row in entries:
        _ensure_principal_node_shared(
            ctx,
            node_id=node_id,
            node_type=node_type,
            identity_domain=bool(is_idd),
            row=row,
            existing_nodes=existing_nodes,
            debug=debug,
        )
        _write_any_edge(
            ctx,
            src_id=node_id,
            src_type=node_type,
            dst_id=scope_id,
            dst_type=scope_type,
            edge_type=edge_type,
            existing_edges=existing_edges,
            stats=stats,
            debug=debug,
        )


def _expand_principal_scope(ctx, scope_id, scope_type, res_token_l, loc, principal_index, stats, debug=False) -> bool:
    if res_token_l not in {"users", "groups", "dynamic-groups"}:
        return False

    og = _og(ctx)
    existing_edges = og["existing_edges_set"]
    existing_nodes = og["existing_nodes_set"]
    entries = (principal_index.get(res_token_l) or {}).get(loc) or []
    for node_id, node_type, is_idd, row in entries:
        _ensure_principal_node_shared(
            ctx,
            node_id=node_id,
            node_type=node_type,
            identity_domain=bool(is_idd),
            row=row,
            existing_nodes=existing_nodes,
            debug=debug,
        )
        ek = (scope_id, EDGE_SCOPE_INCLUDES, node_id)
        if ek in existing_edges:
            continue
        try:
            wrote = _emit_edge_shared(
                ctx,
                src_id=scope_id,
                src_type=scope_type,
                dst_id=node_id,
                dst_type=node_type,
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
                existing_edges.add(ek)
                stats["scope_include_edges_created"] += 1
        except Exception as e:
            if debug:
                _dlog(debug, "resource-scope: principal edge write failed", scope_id=scope_id, node_id=node_id, err=f"{type(e).__name__}: {e}")

    return True


def _expand_any_user_to_resource_principals(session, ctx, scope_id, scope_type, loc, stats, debug=False):
    """
    For ANY_USER scope nodes, emit MEMBER_OF edges from resource principals in the compartment.
    Resource-principal candidates come from RESOURCE_SCOPE_MAP.
    """
    og = _og(ctx)
    existing_edges = og["existing_edges_set"]
    existing_nodes = og["existing_nodes_set"]
    query_cache = og.setdefault("any_user_resource_query_cache", {})

    allowed_node_types = set(ANY_USER_RESOURCE_PRINCIPAL_SCOPE_TOKENS or ())
    for raw_spec in RESOURCE_SCOPE_MAP.values():
        for spec in _iter_scope_specs(raw_spec):

            table = spec.get("table")
            id_col = spec.get("id_col")
            comp_col = spec.get("compartment_col")
            node_type = _s(spec.get("node_type") or "OCIResource")
            tenant_col = spec.get("tenant_col")
            display_col = spec.get("display_col")
            name_col = spec.get("name_col")

            if node_type not in allowed_node_types:
                continue
            if not (table and id_col and comp_col):
                continue

            rows = _fetch_scope_rows(
                session,
                query_cache,
                table=table,
                comp_col=comp_col,
                loc=loc,
                stats=stats,
                debug=debug,
                log_tag="resource-scope: any-user resource query failed",
            )
            if not rows:
                continue

            for row in rows:
                if not isinstance(row, dict):
                    continue
                rid = _shared_row_get(row, id_col)
                if not (isinstance(rid, str) and rid):
                    continue

                display = _resolve_display_name(
                    row,
                    display_col=display_col,
                    name_col=name_col,
                    fallback=rid,
                )
                tenant_id = _shared_row_get(row, tenant_col) if tenant_col else None

                raw = dict(row)
                raw["id"] = rid
                raw["display_name"] = display
                raw["compartment_id"] = loc
                if isinstance(tenant_id, str) and tenant_id:
                    raw["tenant_id"] = tenant_id

                if rid not in existing_nodes:
                    try:
                        ctx.write_specific_resource_node(raw, node_type, commit=False)
                        existing_nodes.add(rid)
                    except Exception as e:
                        if debug:
                            _dlog(debug, "resource-scope: any-user resource node write failed", id=rid, node_type=node_type, err=f"{type(e).__name__}: {e}")
                        continue

                _write_any_edge(
                    ctx,
                    src_id=rid,
                    src_type=node_type,
                    dst_id=scope_id,
                    dst_type=scope_type or "OCIAnyUser",
                    edge_type=EDGE_ANY_USER_MEMBER_OF,
                    existing_edges=existing_edges,
                    stats=stats,
                    debug=debug,
                )


def _expand_scope_to_resources(session, ctx, scope_id, scope_type, res_token_l, loc, stats, debug=False):
    """
    Expand a non-family scope node (e.g. instances@loc) to concrete resources using RESOURCE_SCOPE_MAP.
    """
    spec = RESOURCE_SCOPE_MAP.get(_l(res_token_l))
    specs = _iter_scope_specs(spec)
    if not specs:
        stats["scope_nodes_skipped_unknown_resource"] += 1
        return

    og = _og(ctx)
    existing_edges = og["existing_edges_set"]
    lookup_cache = og.setdefault("compartment_lookup_cache", {})
    query_cache = og.setdefault("scope_resource_query_cache", {})

    for spec in specs:
        if not isinstance(spec, dict):
            continue
        table = spec.get("table")
        id_col = spec.get("id_col")
        comp_col = spec.get("compartment_col")
        node_type = spec.get("node_type") or NODE_TYPE_OCI_GENERIC_RESOURCE
        tenant_col = spec.get("tenant_col")
        display_col = spec.get("display_col")
        name_col = spec.get("name_col")
        lookup_spec = spec.get("compartment_lookup") if not comp_col else None
        is_secret_bundle_like = table in {"vault_secret_bundle", "vault_secret_versions"}

        if not (table and id_col and (comp_col or lookup_spec)):
            stats["scope_nodes_skipped_unknown_resource"] += 1
            continue

        rows = _fetch_scope_rows(
            session,
            query_cache,
            table=table,
            comp_col=comp_col if comp_col else None,
            loc=loc,
            stats=stats,
            debug=debug,
            log_tag="resource-scope: query failed",
        )

        if not rows:
            continue

        lookup_map = {}
        fk_col = None
        if not comp_col and lookup_spec:
            fk_col = lookup_spec.get("fk_col")
            lookup_map = _build_compartment_lookup(session, lookup_spec, lookup_cache, debug=debug)

        stats["scope_nodes_mapped"] += 1

        for row in rows:
            if not isinstance(row, dict):
                continue
            stats["rows_seen"] += 1

            rid = _shared_row_get(row, id_col)
            if not (isinstance(rid, str) and rid):
                stats["rows_missing_required_fields"] += 1
                continue

            cid = None
            if comp_col:
                cid = _shared_row_get(row, comp_col) or loc
            else:
                fk_val = _shared_row_get(row, fk_col) if fk_col else None
                cid = lookup_map.get(fk_val)

            if not (isinstance(cid, str) and cid):
                stats["rows_missing_required_fields"] += 1
                continue
            if cid != loc:
                continue

            display = _resolve_display_name(
                row,
                display_col=display_col,
                name_col=name_col,
                fallback=rid,
            )
            if is_secret_bundle_like:
                sid_for_display = _shared_row_get(row, "secret_id")
                vn_for_display = _shared_row_get(row, "version_number")
                if (
                    isinstance(sid_for_display, str)
                    and sid_for_display
                    and vn_for_display not in (None, "")
                    and display == rid
                ):
                    secret_name_by_id = _build_id_name_lookup(
                        session,
                        table="vault_secret",
                        id_col="id",
                        name_col="secret_name",
                        cache=lookup_cache,
                        debug=debug,
                    )
                    sname = secret_name_by_id.get(sid_for_display)
                    if isinstance(sname, str) and sname:
                        display = f"{sname}:v{vn_for_display}"
            tenant_id = _shared_row_get(row, tenant_col) if tenant_col else None

            raw = dict(row)
            raw["id"] = rid
            raw["display_name"] = display
            if is_secret_bundle_like:
                vname = _shared_row_get(row, "version_name")
                if not (isinstance(vname, str) and vname.strip()):
                    raw["version_name"] = display
            raw["compartment_id"] = cid
            if isinstance(tenant_id, str) and tenant_id:
                raw["tenant_id"] = tenant_id

            try:
                rid2 = ctx.write_specific_resource_node(raw, node_type, commit=False) or rid
                stats["specific_nodes_written"] += 1
            except Exception as e:
                if debug:
                    _dlog(debug, "resource-scope: node write failed", id=rid, node_type=node_type, err=f"{type(e).__name__}: {e}")
                continue

            ek = (scope_id, EDGE_SCOPE_INCLUDES, rid2)
            if ek in existing_edges:
                continue

            try:
                wrote = _emit_edge_shared(
                    ctx,
                    src_id=scope_id,
                    src_type=scope_type,
                    dst_id=rid2,
                    dst_type=node_type,
                    edge_type=EDGE_SCOPE_INCLUDES,
                    edge_properties=_build_edge_properties(
                        edge_category=EDGE_CATEGORY_RESOURCE,
                        edge_inner_properties={
                            "description": "Scope expansion to concrete resources.",
                            "resource_family": False,
                            "resource_used": True,
                        },
                    ),
                    commit=False,
                    on_conflict="update",
                    dedupe=True,
                )
                if wrote:
                    existing_edges.add(ek)
                    stats["scope_include_edges_created"] += 1
            except Exception as e:
                if debug:
                    _dlog(debug, "resource-scope: edge write failed", scope_id=scope_id, rid=rid2, err=f"{type(e).__name__}: {e}")


def _emit_tag_definition_namespace_edges(session, ctx, stats, debug=False):
    """
    Emit OCITagNamespace -> OCITagDefinition edges via OCI_INCLUDES.

    This relationship is inventory-derived (not policy-derived) and helps
    graph consumers pivot from namespace controls to concrete tag keys.
    """
    og = _og(ctx)
    existing_nodes = og["existing_nodes_set"]
    existing_edges = og["existing_edges_set"]

    try:
        definitions = session.get_resource_fields("tag_definitions") or []
    except Exception as e:
        if debug:
            _dlog(debug, "resource-scope: tag definitions query failed", err=f"{type(e).__name__}: {e}")
        return

    if not definitions:
        return

    try:
        namespaces = session.get_resource_fields("tag_namespaces") or []
    except Exception:
        namespaces = []
    ns_by_id = {
        _s(r.get("id") or ""): r
        for r in (namespaces or [])
        if isinstance(r, dict) and _s(r.get("id") or "")
    }

    for row in definitions:
        if not isinstance(row, dict):
            continue
        def_id = _s(row.get("id") or "")
        ns_id = _s(row.get("tag_namespace_id") or "")
        if not (def_id and ns_id):
            continue

        ns_row = ns_by_id.get(ns_id) or {}
        comp_id = _s(row.get("compartment_id") or ns_row.get("compartment_id") or "")

        if ns_id not in existing_nodes:
            raw_ns = dict(ns_row) if isinstance(ns_row, dict) else {}
            raw_ns.setdefault("id", ns_id)
            raw_ns.setdefault("name", _s(raw_ns.get("name") or row.get("tag_namespace_name") or ns_id))
            raw_ns.setdefault("display_name", _s(raw_ns.get("display_name") or raw_ns.get("name") or ns_id))
            raw_ns.setdefault("compartment_id", comp_id)
            try:
                ctx.write_specific_resource_node(raw_ns, "OCITagNamespace", commit=False)
                existing_nodes.add(ns_id)
                stats["specific_nodes_written"] += 1
            except Exception as e:
                if debug:
                    _dlog(debug, "resource-scope: tag namespace node write failed", id=ns_id, err=f"{type(e).__name__}: {e}")
                continue

        raw_def = dict(row)
        raw_def.setdefault("id", def_id)
        raw_def.setdefault("name", _s(raw_def.get("name") or def_id))
        raw_def.setdefault("display_name", _s(raw_def.get("display_name") or raw_def.get("name") or def_id))
        raw_def.setdefault("compartment_id", comp_id)
        try:
            def_node_id = ctx.write_specific_resource_node(raw_def, "OCITagDefinition", commit=False) or def_id
            existing_nodes.add(def_node_id)
            stats["specific_nodes_written"] += 1
        except Exception as e:
            if debug:
                _dlog(debug, "resource-scope: tag definition node write failed", id=def_id, err=f"{type(e).__name__}: {e}")
            continue

        ek = (ns_id, EDGE_INCLUDES, def_node_id)
        if ek in existing_edges:
            continue
        try:
            wrote = _emit_edge_shared(
                ctx,
                src_id=ns_id,
                src_type="OCITagNamespace",
                dst_id=def_node_id,
                dst_type="OCITagDefinition",
                edge_type=EDGE_INCLUDES,
                edge_properties=_build_edge_properties(
                    edge_category=EDGE_CATEGORY_RESOURCE,
                    edge_inner_properties={
                        "description": "Tag namespace includes this tag definition.",
                        "resource_family": False,
                        "resource_used": True,
                    },
                ),
                commit=False,
                on_conflict="update",
                dedupe=True,
            )
            if wrote:
                existing_edges.add(ek)
                stats["tag_namespace_includes_definition_edges_created"] = int(
                    stats.get("tag_namespace_includes_definition_edges_created", 0)
                ) + 1
        except Exception as e:
            if debug:
                _dlog(
                    debug,
                    "resource-scope: tag namespace includes edge write failed",
                    src=ns_id,
                    dst=def_node_id,
                    err=f"{type(e).__name__}: {e}",
                )


def build_resource_scope_expansion_edges_offline(
    *,
    session,
    ctx,  # OfflineIamContext
    debug=False,
    auto_commit=True,
    **_,
):
    """
    Expand scope nodes into:
      - FAMILY_INCLUDES edges (family scopes -> member scopes)
      - OCI_SPECIFIC_RESOURCE edges (member scopes -> concrete resources)
    """

    # ---------------------------------------------------------------------
    # Phase 0: Load current OpenGraph state and prepare dedupe/stats context
    # ---------------------------------------------------------------------
    # Refresh OG dedupe sets once, then use ctx.og_state everywhere
    try:
        ctx.refresh_opengraph_state(force=False)
    except Exception:
        pass

    og = _og(ctx)
    existing_nodes = og["existing_nodes_set"]
    existing_edges = og["existing_edges_set"]
    existing_node_types = og.get("existing_node_types") if isinstance(og.get("existing_node_types"), dict) else {}

    stats = {
        "scope_nodes_seen": 0,
        "scope_nodes_mapped": 0,
        "scope_nodes_skipped_all_resources": 0,
        "scope_nodes_skipped_unknown_resource": 0,
        "family_scope_nodes_seen": 0,
        "family_include_edges_created": 0,
        "member_scope_nodes_enqueued": 0,
        "query_failures": 0,
        "rows_seen": 0,
        "rows_missing_required_fields": 0,
        "specific_nodes_written": 0,
        "scope_include_edges_created": 0,
        "any_user_nodes_seen": 0,
        "any_group_nodes_seen": 0,
        "any_user_member_edges_created": 0,
        "any_group_member_edges_created": 0,
        "new_user_scope_nodes_seen": 0,
        "scope_member_of_edges_created": 0,
        "tag_definition_belongs_to_edges_created": 0,
    }

    # ---------------------------------------------------------------------
    # Phase 1: Seed work queue with existing scope nodes (<resource>@<location>)
    # ---------------------------------------------------------------------
    queue = deque()
    queued = set()
    processed = set()
    fam_keys_l = _family_keys_l(ctx)

    for sid in existing_nodes:

        # Only look for scope nodes which have @ in name
        if not _is_scope_node_id(sid):
            continue

        # Grab the resource name (ex. instances@compA --> instances)
        token = sid.split("@", 1)[0]
        inferred_type = _infer_scope_node_type(_l(token), fam_keys_l)
        scope_type = _s(existing_node_types.get(sid) or inferred_type)
        if sid in queued:
            continue
        queued.add(sid)
        queue.append((sid, scope_type or "OCIResourceGroup"))

    # Snapshot of known scope node ids. Used for synthetic links like:
    #   new-users@<loc> --> ANY_USER@<loc>
    known_scope_ids = set(queued)
    principal_index = _build_principal_scope_index(ctx)

    # ---------------------------------------------------------------------
    # Phase 2: Process each scope node and emit expansion edges
    # ---------------------------------------------------------------------
    # queue is the pending list of scope nodes to process, not all resources (ex. instances@<compartment>).
    while queue:
        scope_id, scope_type = queue.popleft()
        if scope_id in processed:
            continue
        processed.add(scope_id)

        if not _is_scope_node_id(scope_id):
            continue

        res_token, loc = scope_id.split("@", 1)
        res_l = _l(res_token)
        # Support qualified scope tokens like:
        #   ANYDOMAIN/new_user@<loc>
        #   <IdentityDomain>/new_user@<loc>
        res_l_base = res_l.rsplit("/", 1)[-1] if "/" in res_l else res_l
        loc = _s(loc)

        # -----------------------------------------------------------------
        # 2A: Special synthetic scope mapping
        # Creates: new-users@<loc> --OCI_SCOPE_MEMBER_OF--> ANY_USER@<loc>
        # -----------------------------------------------------------------
        if res_l in NEW_USER_SCOPE_TOKENS or res_l_base in NEW_USER_SCOPE_TOKENS:
            stats["new_user_scope_nodes_seen"] += 1

            # Destination scope ID for the synthetic mapping above.
            any_user_scope_id = f"ANY_USER@{loc}" if loc else ""
            
            if any_user_scope_id and any_user_scope_id in known_scope_ids:
                _write_any_edge(
                    ctx,
                    src_id=scope_id,
                    src_type=scope_type or "OCIResourceGroup",
                    dst_id=any_user_scope_id,
                    dst_type="OCIAnyUser",
                    edge_type=EDGE_SCOPE_MEMBER_OF,
                    existing_edges=existing_edges,
                    stats=stats,
                    debug=debug,
                )
            continue

        # -----------------------------------------------------------------
        # 2B: Wildcard principal expansion for ANY_USER
        # Creates:
        #   <user_or_instance_principal> --OCI_ANY_USER_MEMBER_OF--> ANY_USER@<loc>
        #   <function_resource_principal> --OCI_ANY_USER_MEMBER_OF--> ANY_USER@<loc>
        # -----------------------------------------------------------------
        # Wildcard principal expansion (ANY_USER)
        # ANY_USER goes to users, instance principals, and resource principals
        # for now resource principals are just functions but will add more in the future if needed
        if res_l == "any_user":
            stats["any_user_nodes_seen"] += 1
            users = (principal_index.get("any-user") or {}).get(loc) or []
            _emit_any_scope_members(
                ctx=ctx,
                scope_id=scope_id,
                scope_type=scope_type or "OCIAnyUser",
                entries=users,
                edge_type=EDGE_ANY_USER_MEMBER_OF,
                existing_edges=existing_edges,
                existing_nodes=existing_nodes,
                stats=stats,
                debug=debug,
            )
            _expand_any_user_to_resource_principals(
                session,
                ctx,
                scope_id=scope_id,
                scope_type=scope_type,
                loc=loc,
                stats=stats,
                debug=debug,
            )
            continue

        # -----------------------------------------------------------------
        # 2C: Wildcard principal expansion for ANY_GROUP
        # Creates:
        #   <group_or_dynamic_group> --OCI_ANY_GROUP_MEMBER_OF--> ANY_GROUP@<loc>
        # -----------------------------------------------------------------
        if res_l == "any_group":
            stats["any_group_nodes_seen"] += 1
            groups = (principal_index.get("any-group") or {}).get(loc) or []
            _emit_any_scope_members(
                ctx=ctx,
                scope_id=scope_id,
                scope_type="OCIAnyGroup",
                entries=groups,
                edge_type=EDGE_ANY_GROUP_MEMBER_OF,
                existing_edges=existing_edges,
                existing_nodes=existing_nodes,
                stats=stats,
                debug=debug,
            )
            continue

        # -----------------------------------------------------------------
        # 2D: Explicit no-op for all-resources scope
        # -----------------------------------------------------------------
        # Skip all-resources (too broad). We just have an "all-resources" node that is a good final destination
        if res_l == "all-resources":
            stats["scope_nodes_skipped_all_resources"] += 1
            continue

        stats["scope_nodes_seen"] += 1

        # Ensure this node is in og_state nodes set (some flows may not have refreshed nodes)
        if scope_id not in existing_nodes:
            existing_nodes.add(scope_id)

        # -----------------------------------------------------------------
        # 2E: Resource-family expansion
        # Creates:
        #   <family>@<loc> --FAMILY_INCLUDES--> <member_scope>@<loc>
        # and enqueues member scopes for later concrete expansion.
        # -----------------------------------------------------------------
        # FAMILY: family@loc -> member@loc, enqueue members for concrete expansion
        if res_l in fam_keys_l:
            stats["family_scope_nodes_seen"] += 1

            members = _ensure_family_edges(ctx, scope_id, scope_type, loc, stats, debug=debug) or []
            for mem_scope_id in members:
                if mem_scope_id and mem_scope_id not in queued:
                    queued.add(mem_scope_id)
                    known_scope_ids.add(mem_scope_id)
                    queue.append((mem_scope_id, "OCIResourceGroup"))
                    stats["member_scope_nodes_enqueued"] += 1
            continue

        # -----------------------------------------------------------------
        # 2F: Non-family expansion path
        # Step 1: principal scope expansion (users/groups/dynamic-groups tokens)
        # Step 2: concrete resource expansion via RESOURCE_SCOPE_MAP
        # -----------------------------------------------------------------
        # NON-FAMILY: expand to concrete resources (if mapped)
        if _expand_principal_scope(ctx, scope_id, scope_type, res_l, loc, principal_index, stats, debug=debug):
            continue
        _expand_scope_to_resources(
            session,
            ctx,
            scope_id=scope_id,
            scope_type=scope_type or "OCIResourceGroup",
            res_token_l=res_l,
            loc=loc,
            stats=stats,
            debug=debug,
        )

    # ---------------------------------------------------------------------
    # Phase 3: Inventory relationships not represented by scope nodes.
    # ---------------------------------------------------------------------
    _emit_tag_definition_namespace_edges(session, ctx, stats, debug=debug)

    if auto_commit:
        try:
            ctx.commit()
        except Exception:
            pass

    if debug:
        _dlog(debug, "resource-scope: done", **stats)

    return stats


if __name__ == "__main__":
    print("resource_scope_graph_builder.py is intended to be imported (needs session + OfflineIamContext).")
