# group_membership_graph_builder.py
from ocinferno.modules.opengraph.utilities.helpers import (
    build_edge_properties as _build_edge_properties,
    EDGE_CATEGORY_GROUP_MEMBERSHIP,
    merge_value as _merge_value,
)
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    EDGE_TYPE_OCI_GROUP_MEMBER as EDGE_GROUP_MEMBER,
    NODE_TYPE_OCI_GROUP as NODE_GROUP,
    NODE_TYPE_OCI_USER as NODE_USER,
)
from ocinferno.modules.opengraph.utilities.helpers.context import _dlog, _json_load
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import emit_edge as _emit_edge_shared

_SOURCE_LABELS = {
    "idd_user_groups": "Identity Domains: user.groups expansion",
    "idd_group_users": "Identity Domains: group.users expansion",
    "membership_table": "User-group-memberships table",
}

# Order in preference of showing where relationships came from
_SOURCE_ORDER = ("membership_table", "idd_user_groups", "idd_group_users")

def _stmt(membership_id, sources):
    mid = str(membership_id).strip() if membership_id is not None else ""

    if isinstance(sources, str):
        src_keys = {sources.strip()} if sources.strip() else set()
    else:
        src_keys = {str(k).strip() for k in (sources or ()) if str(k).strip()}

    src_text = "; ".join(_SOURCE_LABELS.get(k, k) for k in _SOURCE_ORDER if k in src_keys) or "Unknown source"
    mid_text = f" (membership_id={mid})" if mid else ""
    return (
        f"Group membership edge derived from: {src_text}{mid_text}. "
        "Impact: group membership grants the group's IAM permissions."
    )

# Check users/groups/dynamic_groups from identity domain API
# Check users/groups/dynamic_groups from old non-idd APIs
# Check membership user/group ID combos
def build_group_membership_edges_offline(*, session, ctx, debug=False, auto_commit=True):
    """
    Build OCIUser/OCIGroup nodes and OCI_GROUP_MEMBER edges.

    Correctness rule:
      - Collect nodes/edges in-memory, prefer richer data when seen later
      - Upsert nodes + edges once at the end
      - commit once at the end

    Notes:
      - We do NOT force “IDD vs classic” globally.
      - Some nodes may have no domain info (that’s okay).
      - Domain hint / domain-cast is now stored on ctx (OfflineIamContext) and NOT passed here.
    """

    stats = {
        "user_nodes_written": 0,
        "group_nodes_written": 0,
        "edges_written": 0,
        "edges_skipped": 0,
        "edges_seen": 0,
        "membership_rows_seen": 0,
        "idd_json_edges_seen": 0,
    }

    # -------------------------------------------------------------------------
    # In-memory aggregators (prefer richer data - write final nodes/edges at the end)
    # -------------------------------------------------------------------------
    node_cache: dict[tuple[str, str, bool], dict] = {}  # (node_id, node_type, identity_domain) -> principal dict
    edge_cache: dict[tuple[str, str], dict] = {}        # (uid, gid) -> {"membership_id": str, "sources": set[str]}

    def _queue_principal(principal: dict, node_type: str, identity_domain: bool) -> None:
        # Example:
        #   input principal = {"ocid": "ocid1.user...", "display_name": "Alice", "domain_ocid": "ocid1.domain..."}
        #   node_type = NODE_USER, identity_domain = True
        #   key = ("ocid1.user...", "OCIUser", True)
        #
        #   first call:
        #     node_cache[key] does not exist -> {}
        #     after merge -> {"ocid": "...", "display_name": "Alice", "domain_ocid": "..."}
        #
        #   later call with richer data:
        #     input principal = {"ocid": "ocid1.user...", "email": "alice@example.com"}
        #     after merge -> {"ocid": "...", "display_name": "Alice", "domain_ocid": "...", "email": "alice@example.com"}
        #
        # Net effect: one canonical node per (id, type, idd/classic), enriched across sightings.
        node_id = principal.get("ocid" if identity_domain else "id")
        if not node_id:
            return
        key = (node_id, node_type, identity_domain)
        node_cache[key] = _merge_value(node_cache.get(key) or {}, principal or {})

    def _queue_edge(uid: str, gid: str, membership_id, source: str) -> None:
        uid, gid = str(uid or "").strip(), str(gid or "").strip()
        if not uid or not gid:
            return

        stats["edges_seen"] += 1
        # edge_cache is keyed by (user_id, group_id) so repeated evidence collapses to one edge row.
        # setdefault returns the existing row if present, otherwise creates:
        #   {"membership_id": "", "sources": set()}
        edge_row = edge_cache.setdefault((uid, gid), {"membership_id": "", "sources": set()})
        # Keep the first non-empty membership_id we see for this edge pair.
        # (Later sightings without an id, or duplicate ids, do not overwrite it.)
        if (mid := str(membership_id or "").strip()) and not edge_row["membership_id"]:
            edge_row["membership_id"] = mid
        # Track all distinct provenance labels (membership_table / idd_* expansions).
        # Using a set dedupes repeated source labels automatically.
        if source := str(source or "").strip():
            edge_row["sources"].add(source)

    def _is_idd_cached(node_id: str, node_type: str, default: bool = False) -> bool:
        """
        Resolve node identity-domain mode from what we've already queued.
        This avoids Phase B creating duplicate (same node_id/node_type) writes
        with conflicting IDD/classic modes.
        """
        key_idd = (node_id, node_type, True)
        key_classic = (node_id, node_type, False)
        if key_idd in node_cache:
            return True
        if key_classic in node_cache:
            return False
        return default

    # -------------------------------------------------------------------------
    # Phase 0: seed all known principals
    # -------------------------------------------------------------------------
    for row in (ctx.idd_users or ()):
        _queue_principal(row, NODE_USER, identity_domain=True)
    for row in (ctx.classic_users or ()):
        _queue_principal(row, NODE_USER, identity_domain=False)
    for row in (ctx.idd_groups or ()):
        _queue_principal(row, NODE_GROUP, identity_domain=True)
    for row in (ctx.classic_groups or ()):
        _queue_principal(row, NODE_GROUP, identity_domain=False)

    # -------------------------------------------------------------------------
    # Phase A: IDD expansions embedded in user.groups / group.users fields
    # -------------------------------------------------------------------------
    for u in (ctx.idd_users or []):
        user_id, dom_ocid, comp_ocid = u.get("ocid"), u.get("domain_ocid"), u.get("compartment_ocid")
        if not user_id:
            continue

        for gref in _json_load(u.get("groups"), list):
            gid = gref.get("ocid")
            if not gid:
                continue

            row = dict(gref)
            row.setdefault("compartment_ocid", comp_ocid)
            if dom_ocid:
                row.setdefault("domain_ocid", dom_ocid)

            _queue_principal(row, NODE_GROUP, identity_domain=True)
            _queue_edge(user_id, row.get("ocid"), row.get("membership_ocid"), "idd_user_groups")
            stats["idd_json_edges_seen"] += 1

    for g in (ctx.idd_groups or []):
        group_id, dom_ocid, comp_ocid = g.get("ocid"), g.get("domain_ocid"), g.get("compartment_ocid")
        if not group_id:
            continue

        member_refs = []
        member_refs.extend(_json_load(g.get("users"), list))
        member_refs.extend(_json_load(g.get("members"), list))

        for uref in member_refs:
            uid = uref.get("ocid")
            if not uid:
                continue

            row = dict(uref)
            row.setdefault("compartment_ocid", comp_ocid)
            if dom_ocid:
                row.setdefault("domain_ocid", dom_ocid)

            _queue_principal(row, NODE_USER, identity_domain=True)
            _queue_edge(row.get("ocid"), group_id, row.get("membership_ocid"), "idd_group_users")
            stats["idd_json_edges_seen"] += 1

    # -------------------------------------------------------------------------
    # Phase B: Normalized memberships (classic + IDD)
    # -------------------------------------------------------------------------
    for m in (ctx.memberships or []):

        uid, gid = m.get("user_id"), m.get("group_id")
        mid = m.get("membership_ocid") or m.get("membership_id") or m.get("id")
 
        if not uid or not gid:
            continue
        stats["membership_rows_seen"] += 1

        # Determine IDD from membership row first, then fallback to cache.
        # IDD rows should carry membership_ocid and/or domain_ocid.
        row_domain_ocid = str(m.get("domain_ocid") or m.get("identity_domain_ocid") or "").strip()
        row_membership_ocid = str(m.get("membership_ocid") or "").strip()
        row_membership_id = str(m.get("membership_id") or "").strip()
        row_is_idd = bool(row_domain_ocid or (row_membership_ocid and not row_membership_id))

        user_is_idd = row_is_idd or _is_idd_cached(uid, NODE_USER, default=False)
        group_is_idd = row_is_idd or _is_idd_cached(gid, NODE_GROUP, default=False)

        # Save to both ocid and id; identity_domain flag selects which field is consumed.
        comp_id = m.get("compartment_id") or m.get("compartment_ocid")
        tenancy = m.get("tenancy_ocid") or m.get("tenant_id")
        inactive = m.get("inactive_status")
        urow = {
            "ocid": uid,
            "id": uid,
            "name": m.get("user_name") or uid,
            "compartment_id": comp_id,
            "compartment_ocid": comp_id,
            "tenancy_ocid": tenancy,
            "tenant_id": tenancy,
            "domain_ocid": row_domain_ocid,
            "inactive_status": inactive,
        }
        grow = {
            "ocid": gid,
            "id": gid,
            "name": m.get("group_name") or gid,
            "compartment_id": comp_id,
            "compartment_ocid": comp_id,
            "tenancy_ocid": tenancy,
            "tenant_id": tenancy,
            "domain_ocid": row_domain_ocid,
            "inactive_status": inactive,
        }

        _queue_principal(urow, NODE_USER, identity_domain=user_is_idd)
        _queue_principal(grow, NODE_GROUP, identity_domain=group_is_idd)
        _queue_edge(uid, gid, mid, "membership_table")

    # Build group->user membership cache once from deduped edges.
    for uid, gid in edge_cache.keys():
        ctx.group_member_mapping_cache.setdefault(gid, set()).add(uid)

    # -------------------------------------------------------------------------
    # Phase C: write once per unique node/edge
    # -------------------------------------------------------------------------
    for (_node_id, node_type, identity_domain), principal in node_cache.items():
        ctx.write_principal_node(principal, node_type, identity_domain=identity_domain, commit=False)
        if node_type == NODE_USER:
            stats["user_nodes_written"] += 1
        elif node_type == NODE_GROUP:
            stats["group_nodes_written"] += 1

    for (uid, gid), meta in edge_cache.items():
        _emit_edge_shared(
            ctx,
            src_id=uid,
            src_type=NODE_USER,
            dst_id=gid,
            dst_type=NODE_GROUP,
            edge_type=EDGE_GROUP_MEMBER, 
            edge_properties=_build_edge_properties(
                edge_category=EDGE_CATEGORY_GROUP_MEMBERSHIP, # Used to put edges in permission, group, or resource buckets
                edge_inner_properties={
                    "matching_rules": _stmt(meta.get("membership_id"), meta.get("sources") or set()),
                    "membership_id": (meta.get("membership_id") or "").strip(),
                    "group_type": "standard",
                },
            ),
            commit=False,
            on_conflict="update",
            dedupe=True,
        )

    stats["edges_written"] = len(edge_cache)
    stats["edges_skipped"] = max(stats["edges_seen"] - stats["edges_written"], 0)

    if auto_commit:
        ctx.commit()
    _dlog(debug, "groups: done", **stats)
    return stats
