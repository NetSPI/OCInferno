from __future__ import annotations

from collections import defaultdict

from ocinferno.modules.opengraph.utilities.helpers.core_helpers import (
    dlog as _dlog,
    l as _l,
    s as _s,
    short_hash as _short_hash,
)
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    DEFAULT_RESOURCE_FAMILIES,
)


# -----------------------------------------------------------------------------
# OpenGraph in-memory state helpers
# -----------------------------------------------------------------------------
# These functions centralize dedupe/index state used by OpenGraph builders.

def get_og_state(ctx):
    st = getattr(ctx, "og_state", None)
    if not isinstance(st, dict):
        st = {}
        try:
            ctx.og_state = st
        except Exception:
            pass
    st.setdefault("existing_nodes_set", set())
    st.setdefault("existing_edges_set", set())
    st.setdefault("existing_node_types", {})
    return st


# -----------------------------------------------------------------------------
# Core ensure_* writers (node / edge)
# -----------------------------------------------------------------------------
# These are the canonical wrappers all builders should use for OpenGraph writes.

def ensure_node(
    ctx,
    *,
    node_id: str,
    node_type: str,
    display_name: str = "",
    compartment_id: str = "",
    tenant_id: str = "",
    node_properties=None,
    commit=False,
    dedupe=True,
):
    nid = _s(node_id)
    if not nid:
        return ""
    st = get_og_state(ctx)
    existing_nodes = st["existing_nodes_set"]
    node_types = st["existing_node_types"]
    if dedupe and nid in existing_nodes:
        return nid

    ctx.upsert_node(
        node_id=nid,
        node_type=node_type,
        display_name=display_name,
        compartment_id=compartment_id,
        tenant_id=tenant_id,
        node_properties=node_properties,
        commit=bool(commit),
    )
    existing_nodes.add(nid)
    if isinstance(node_types, dict):
        node_types[nid] = node_type
    return nid


def _tenant_for_loc(ctx, loc: str) -> str:
    loc = _s(loc)
    if not loc:
        return ""
    try:
        return _s(ctx.tenant_for_compartment(loc) or "")
    except Exception:
        return ""


def _display_loc(ctx, loc: str) -> str:
    return _s((getattr(ctx, "compartment_name_by_id", {}) or {}).get(loc) or loc)


def ensure_scoped_node(
    ctx,
    *,
    node_id: str,
    node_type: str,
    node_display_name: str,
    loc: str,
    tenant_id: str = "",
    extra_properties: dict | None = None,
    existing_nodes: set | None = None,
    node_type_by_id: dict | None = None,
    node_compartment_by_id: dict | None = None,
):
    """
    Ensure a location-scoped node exists and keep optional caller caches in sync.
    """
    loc = _s(loc)
    node_id = _s(node_id)
    if not (loc and node_id):
        return ""

    st = get_og_state(ctx)
    nodes = existing_nodes if isinstance(existing_nodes, set) else st["existing_nodes_set"]
    if node_id in nodes or node_id in st["existing_nodes_set"]:
        nodes.add(node_id)
        if isinstance(node_type_by_id, dict) and node_id not in node_type_by_id:
            node_type_by_id[node_id] = node_type
        if isinstance(node_compartment_by_id, dict) and node_id not in node_compartment_by_id:
            node_compartment_by_id[node_id] = loc
        return node_id

    resolved_tenant = _s(tenant_id) or _tenant_for_loc(ctx, loc)
    props = {
        "name": _s(node_display_name) or node_id,
        "compartment_id": loc,
        "tenant_id": resolved_tenant or "",
        "location": loc,
    }
    if isinstance(extra_properties, dict) and extra_properties:
        props.update(extra_properties)

    ensure_node(
        ctx,
        node_id=node_id,
        node_type=node_type,
        node_properties=props,
        commit=False,
        dedupe=True,
    )
    nodes.add(node_id)
    if isinstance(node_type_by_id, dict):
        node_type_by_id[node_id] = node_type
    if isinstance(node_compartment_by_id, dict):
        node_compartment_by_id[node_id] = loc
    return node_id


def ensure_new_compute_instance_candidate_node(
    ctx,
    *,
    principal_id: str,
    loc: str,
    existing_nodes: set | None = None,
    node_type_by_id: dict | None = None,
    node_compartment_by_id: dict | None = None,
):
    """
    Ensure the synthetic candidate node used by advanced IAM relation derivation.
    """
    loc = _s(loc)
    principal_id = _s(principal_id)
    if not (loc and principal_id):
        return ""

    short = _short_hash(principal_id, 10)
    node_id = f"NEW_INSTANCE_{short}@{loc}"
    return ensure_scoped_node(
        ctx,
        node_id=node_id,
        node_type="OCINewComputeInstance",
        node_display_name=f"NEW_INSTANCE_{short}@{_display_loc(ctx, loc)}",
        loc=loc,
        extra_properties={
            "synthetic": True,
            "derived_from": "OCI_CREATE_INSTANCE",
            "principal_id": principal_id,
            "resource_type": "instance",
        },
        existing_nodes=existing_nodes,
        node_type_by_id=node_type_by_id,
        node_compartment_by_id=node_compartment_by_id,
    )


def ensure_principal_node(
    ctx,
    *,
    node_id: str,
    node_type: str,
    identity_domain: bool,
    row: dict | None = None,
    existing_nodes: set | None = None,
    node_type_by_id: dict | None = None,
    debug=False,
):
    """
    Ensure a principal node exists via context.write_principal_node.
    """
    node_id = _s(node_id)
    if not node_id:
        return ""
    st = get_og_state(ctx)
    nodes = existing_nodes if isinstance(existing_nodes, set) else st["existing_nodes_set"]
    if node_id in nodes or node_id in st["existing_nodes_set"]:
        nodes.add(node_id)
        if isinstance(node_type_by_id, dict) and node_id not in node_type_by_id:
            node_type_by_id[node_id] = node_type
        return node_id

    payload = row if isinstance(row, dict) and row else ({"ocid": node_id} if identity_domain else {"id": node_id})
    try:
        out = _s(
            ctx.write_principal_node(
                payload,
                node_type,
                identity_domain=bool(identity_domain),
                commit=False,
            )
            or ""
        )
    except Exception as e:
        _dlog(debug, "graph-utils: ensure_principal_node failed", node_id=node_id, err=f"{type(e).__name__}: {e}")
        return ""

    if not out:
        return ""
    nodes.add(out)
    if isinstance(node_type_by_id, dict):
        node_type_by_id[out] = node_type
    return out


def ensure_edge(
    ctx,
    *,
    src_id: str,
    src_type: str,
    dst_id: str,
    dst_type: str,
    edge_type: str,
    edge_properties: dict | None = None,
    commit=False,
    on_conflict="ignore",
    dedupe=True,
):
    sid = _s(src_id)
    did = _s(dst_id)
    et = _s(edge_type)
    if not (sid and did and et):
        return False
    st = get_og_state(ctx)
    existing_edges = st["existing_edges_set"]
    key = (sid, et, did)
    if dedupe and key in existing_edges:
        return False
    ctx.write_edge(
        sid,
        src_type,
        did,
        dst_type,
        et,
        edge_properties=edge_properties if isinstance(edge_properties, dict) else None,
        commit=bool(commit),
        on_conflict=on_conflict,
    )
    existing_edges.add(key)
    return True


def emit_edge(
    ctx,
    *,
    src_id: str,
    src_type: str,
    dst_id: str,
    dst_type: str,
    edge_type: str,
    edge_properties: dict | None = None,
    commit: bool = False,
    on_conflict: str = "update",
    dedupe: bool = True,
    stats: dict | None = None,
    stat_written: str = "",
    stat_skipped: str = "",
):
    """
    Shared edge emitter with optional stats updates.

    Returns True when a new edge row was written, else False.
    """
    wrote = ensure_edge(
        ctx,
        src_id=src_id,
        src_type=src_type,
        dst_id=dst_id,
        dst_type=dst_type,
        edge_type=edge_type,
        edge_properties=edge_properties if isinstance(edge_properties, dict) else {},
        commit=bool(commit),
        on_conflict=on_conflict,
        dedupe=bool(dedupe),
    )
    if isinstance(stats, dict):
        if wrote and stat_written:
            stats[stat_written] = int(stats.get(stat_written, 0) or 0) + 1
        elif (not wrote) and stat_skipped:
            stats[stat_skipped] = int(stats.get(stat_skipped, 0) or 0) + 1
    return wrote


# -----------------------------------------------------------------------------
# Query/scope/resource helper utilities
# -----------------------------------------------------------------------------
# These are non-writer helpers shared by builders for table/spec handling.

def fetch_rows_cached(
    session,
    cache: dict,
    *,
    table: str,
    where_conditions: dict | None = None,
    columns=None,
    cache_key=None,
):
    """
    Cached wrapper over session.get_resource_fields().
    """
    if cache is None:
        cache = {}
    key = cache_key
    if key is None:
        where = where_conditions or {}
        norm_where = tuple(sorted((str(k), str(v)) for k, v in where.items()))
        if columns is None:
            norm_cols = None
        else:
            norm_cols = tuple(columns)
        key = (str(table), norm_where, norm_cols)
    if key in cache:
        return cache.get(key) or []

    rows = session.get_resource_fields(
        table,
        where_conditions=where_conditions if where_conditions else None,
        columns=columns,
    ) or []
    cache[key] = rows
    return rows


def iter_scope_specs(spec):
    if not isinstance(spec, dict):
        return ()
    tables = spec.get("tables")
    if isinstance(tables, (list, tuple)):
        base = {k: v for k, v in spec.items() if k != "tables"}
        out = []
        for entry in tables:
            if not isinstance(entry, dict):
                continue
            merged = dict(base)
            merged.update(entry)
            out.append(merged)
        return tuple(out)
    return (spec,)


def family_map(ctx):
    fam = getattr(ctx, "resource_families", None)
    return fam if isinstance(fam, dict) and fam else (DEFAULT_RESOURCE_FAMILIES or {})


def family_keys_l(ctx):
    fm = family_map(ctx)
    return {k.lower() for k in fm.keys() if isinstance(k, str) and k}


def family_members_l(ctx, fam):
    fm = family_map(ctx)
    v = fm.get(fam) or fm.get(_l(fam))
    if not isinstance(v, (set, list, tuple)):
        return ()
    out = []
    for x in v:
        if isinstance(x, str) and x.strip():
            out.append(x.strip().lower())
    return tuple(sorted(set(out)))


def is_family(ctx, token):
    return _l(token) in family_keys_l(ctx)


def scope_node_type(ctx, token: str):
    tok = _s(token)
    tok_l = _l(tok)
    fam = is_family(ctx, tok_l)
    if tok_l == "all-resources":
        return "OCIAllResources", fam
    if fam:
        return "OCIResourceFamily", fam
    return "OCIResourceGroup", fam


def ensure_scope_node(
    ctx,
    *,
    token: str,
    loc: str,
    tenant_id: str = "",
    compartment_id: str = "",
    display_prefix: str = "",
    commit=False,
    dedupe=True,
):
    token_s = _s(token)
    loc_s = _s(loc)
    if not (token_s and loc_s):
        return "", "", False
    nid = f"{token_s}@{loc_s}"
    ntype, is_fam = scope_node_type(ctx, token_s)
    st = get_og_state(ctx)
    if dedupe and nid in st["existing_nodes_set"]:
        return nid, ntype, is_fam

    disp_loc = _s((getattr(ctx, "compartment_name_by_id", {}) or {}).get(loc_s) or loc_s)
    if display_prefix:
        display_name = f"{display_prefix}{token_s}@{disp_loc}"
    else:
        display_name = f"{token_s}@{disp_loc}"
    node_comp = _s(loc_s) or _s(compartment_id) or None
    node_tenant = _s(tenant_id)
    if not node_tenant and node_comp and hasattr(ctx, "tenant_for_compartment"):
        try:
            node_tenant = _s(ctx.tenant_for_compartment(node_comp) or "")
        except Exception:
            node_tenant = ""

    ensure_node(
        ctx,
        node_id=nid,
        node_type=ntype,
        node_properties={
            "name": display_name,
            "compartment_id": node_comp or "",
            "tenant_id": node_tenant or "",
            "location": loc_s,
            "is_known_family": bool(is_fam),
        },
        commit=commit,
        dedupe=False,
    )
    return nid, ntype, is_fam


def build_table_token_indexes(resource_scope_map: dict):
    table_to_tokens = defaultdict(set)
    token_to_specs = defaultdict(list)
    for token, info in (resource_scope_map or {}).items():
        tok = _l(token)
        if not tok:
            continue
        for spec in iter_scope_specs(info):
            if not isinstance(spec, dict):
                continue
            table = _s(spec.get("table"))
            if not table:
                continue
            token_to_specs[tok].append(spec)
            table_to_tokens[table].add(tok)
    return {k: set(v) for k, v in table_to_tokens.items()}, {k: list(v) for k, v in token_to_specs.items()}


def select_scope_specs(resource_scope_map: dict, token: str):
    tok = _l(token)
    if not tok:
        return ()
    return iter_scope_specs((resource_scope_map or {}).get(tok) or {})


def table_specs_for_token(resource_scope_map: dict, token: str, table_name: str):
    table = _s(table_name)
    out = []
    for spec in select_scope_specs(resource_scope_map, token):
        if _s(spec.get("table")) == table:
            out.append(spec)
    return tuple(out)


def row_get(row, key):
    if not isinstance(row, dict):
        return None
    if isinstance(key, (list, tuple)):
        parts = []
        for k in key:
            v = row.get(k)
            if v is None:
                return None
            parts.append(str(v))
        return "::".join(parts)
    return row.get(key)


def canonical_resource_row_from_spec(row: dict, spec: dict):
    if not isinstance(row, dict) or not isinstance(spec, dict):
        return {}
    id_col = spec.get("id_col") or "id"
    comp_col = spec.get("compartment_col") or "compartment_id"
    display_col = _s(spec.get("display_col") or "")
    name_col = _s(spec.get("name_col") or "")
    tenant_col = _s(spec.get("tenant_col") or "")

    rid = _s(row_get(row, id_col))
    cid = _s(row_get(row, comp_col))
    if not (rid and cid):
        return {}

    display = ""
    if display_col:
        display = _s(row.get(display_col))
    if not display and name_col:
        display = _s(row.get(name_col))
    if not display:
        display = rid

    out = dict(row)
    out["id"] = rid
    out["display_name"] = display
    out["compartment_id"] = cid
    if tenant_col:
        tid = _s(row.get(tenant_col))
        if tid:
            out["tenant_id"] = tid
    return out
