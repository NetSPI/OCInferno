# dynamic_group_membership_graph_builder.py
from ocinferno.modules.opengraph.utilities.helpers import (
    build_edge_properties as _build_edge_properties,
    EDGE_CATEGORY_GROUP_MEMBERSHIP,
    merge_value as _merge_value,
)
from ocinferno.modules.opengraph.utilities.helpers.context import _dlog
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    EDGE_TYPE_OCI_DYNAMIC_GROUP_MEMBER as EDGE_DYNAMIC_GROUP_MEMBER,
    NODE_TYPE_OCI_DYNAMIC_GROUP as DYNAMIC_GROUP_NODE,
    NODE_TYPE_OCI_GENERIC_RESOURCE as GENERIC_RESOURCE,
)
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import emit_edge as _emit_edge_shared
from ocinferno.modules.opengraph.utilities.helpers.matching_rules_engine import DynamicGroupRuleEvaluator

def build_dynamic_group_membership_edges_offline(*, session, ctx, debug: bool = False, auto_commit=True) -> dict:
    """Evaluate dynamic-group matching rules and create edges resource -> dynamic-group."""
    evaluator = DynamicGroupRuleEvaluator(
        session=session,
        debug=debug,
    )

    domain_dgs, classic_dgs = ctx.idd_dynamic_groups, ctx.classic_dynamic_groups
    og_state = ctx.refresh_opengraph_state(force=False)
    existing_nodes = og_state["existing_nodes_set"]

    totals = {
        "domain_dynamic_groups_total": len(domain_dgs),
        "domain_dynamic_groups_processed": 0,
        "classic_dynamic_groups_total": len(classic_dgs),
        "classic_leftovers_processed": 0,
        "groups_rule_errors": 0,
        "groups_no_rule": 0,
        "groups_zero_matches": 0,
        "matches_skipped_missing_resource_id": 0,
        "matched_nodes_written": 0,
        "edges_written": 0,
        "edges_skipped": 0,
        "edges_seen": 0,
        "matches_seen": 0,
    }

    # In-memory edge aggregation for dedupe/merge.
    edge_cache: dict[tuple[str, str], dict] = {}  # (src_id, dg_id) -> {"matching_rule": str, "src_node_type": str, "tables_matching_rules": set[str]}
    # In-memory node aggregation for dedupe/merge before DB writes.
    node_cache: dict[str, dict] = {}  # src_id -> merged candidate_row

    def _queue_node(candidate_row: dict) -> None:
        src_id = str(candidate_row.get("id") or "").strip()
        if not src_id:
            return
        incoming_type = str(candidate_row.get("node_type") or GENERIC_RESOURCE).strip() or GENERIC_RESOURCE
        cur = node_cache.get(src_id)
        if cur is None:
            node_cache[src_id] = dict(candidate_row)
            return

        current_type = str(cur.get("node_type") or GENERIC_RESOURCE).strip() or GENERIC_RESOURCE
        merged = _merge_value(cur, candidate_row)
        if current_type == GENERIC_RESOURCE and incoming_type != GENERIC_RESOURCE:
            merged["node_type"] = incoming_type
        node_cache[src_id] = merged

    def _queue_edge(src_id: str, dg_id: str, *, rule: str, source_type: str, table_names: set[str] | None = None) -> None:
        if not src_id or not dg_id:
            return
        totals["edges_seen"] += 1
        key = (src_id, dg_id)
        edge_row = edge_cache.setdefault(
            key,
            {
                "matching_rule": rule or "",
                "src_node_type": source_type or GENERIC_RESOURCE,
                "tables_matching_rules": set(),
            },
        )
        if (edge_row.get("src_node_type") or GENERIC_RESOURCE) == GENERIC_RESOURCE and source_type and source_type != GENERIC_RESOURCE:
            edge_row["src_node_type"] = source_type
        edge_row["tables_matching_rules"].update(t for t in (table_names or set()) if isinstance(t, str) and t)

    def _proc(dg: dict, *, is_idd: bool) -> None:
        ctx.write_principal_node(dg, DYNAMIC_GROUP_NODE, identity_domain=is_idd, commit=False)

        dg_id = dg.get("ocid") if is_idd else dg.get("id")
        if not dg_id:
            return

        dg_comp_id = str(dg.get("compartment_ocid") or dg.get("compartment_id") or "").strip()

        rule = str(dg.get("matching_rule") or "").strip()
        if not rule:
            totals["groups_no_rule"] += 1
            return

        matched_any = False

        # Match row shape from evaluator.match_iter(...):
        # {
        #   "id": str,
        #   "node_type": str,
        #   "by_table": {
        #     "<table_name>": {
        #       "rows": list[dict]
        #     }
        #   },
        # }
        try:
            for m in evaluator.match_iter(rule, compartment_id=dg_comp_id or None):
                matched_any = True
                totals["matches_seen"] += 1
                src_id = str(m.get("id") or "").strip()
                if not src_id:
                    totals["matches_skipped_missing_resource_id"] += 1
                    continue

                src_type = str(m.get("node_type") or GENERIC_RESOURCE).strip() or GENERIC_RESOURCE
                merged_row = {}
                matched_tables = set()
                by_table = m.get("by_table")
                if isinstance(by_table, dict):
                    for table_name, meta in by_table.items():
                        if not isinstance(table_name, str) or not table_name or not isinstance(meta, dict):
                            continue
                        rows = meta.get("rows")
                        if not isinstance(rows, list):
                            continue
                        matched_tables.add(table_name)
                        for row in rows:
                            if isinstance(row, dict):
                                merged_row = _merge_value(merged_row, row)

                source_row = merged_row if isinstance(merged_row, dict) else {}
                m_comp = source_row.get("compartment_id") or source_row.get("compartment_ocid") or ""
                if not (isinstance(m_comp, str) and m_comp):
                    continue

                # Keep merged match data so additional discovered attributes can flow into node properties.
                candidate_row = {
                    **source_row,
                    "id": src_id,
                    "display_name": source_row.get("display_name") or source_row.get("name") or src_id,
                    "compartment_id": m_comp,
                    "tenant_id": source_row.get("tenant_id") or source_row.get("tenancy_ocid") or "",
                    "node_type": src_type,
                }

                _queue_node(candidate_row)

                _queue_edge(src_id, dg_id, rule=rule, source_type=src_type, table_names=matched_tables)

                # Cache merged member metadata per (dynamic_group_id, member_id) for downstream conditional expansion.
                dg_members = ctx.dynamic_group_member_mapping_cache.setdefault(dg_id, {})
                incoming_member = _merge_value({"node_type": src_type or GENERIC_RESOURCE}, candidate_row)
                dg_members[src_id] = _merge_value(dg_members.get(src_id) or {}, incoming_member)
        except Exception as e:
            totals["groups_rule_errors"] += 1
            _dlog(debug, "dg: matching-rule evaluate failed", dynamic_group_id=dg_id, err=f"{type(e).__name__}: {e}")
            return

        if not matched_any:
            totals["groups_zero_matches"] += 1

    # _proc runs evaluator and records membership edges per matching rule.
    for groups, is_idd, counter_key in (
        (domain_dgs, True, "domain_dynamic_groups_processed"),
        (classic_dgs, False, "classic_leftovers_processed"),
    ):
        for dg in groups:
            _proc(dg, is_idd=is_idd)
            totals[counter_key] += 1

    for src_id, candidate_row in node_cache.items():
        node_type = str(candidate_row.get("node_type") or GENERIC_RESOURCE).strip() or GENERIC_RESOURCE
        wrote = ctx.write_specific_resource_node(candidate_row, node_type, commit=False)
        if wrote and src_id not in existing_nodes:
            totals["matched_nodes_written"] += 1
            existing_nodes.add(src_id)

    for (src_id, dg_id), meta in edge_cache.items():
        _emit_edge_shared(
            ctx,
            src_id=src_id,
            src_type=meta.get("src_node_type") or GENERIC_RESOURCE,
            dst_id=dg_id,
            dst_type=DYNAMIC_GROUP_NODE,
            edge_type=EDGE_DYNAMIC_GROUP_MEMBER,
            edge_properties=_build_edge_properties(
                edge_category=EDGE_CATEGORY_GROUP_MEMBERSHIP,
                edge_inner_properties={
                    "matching_rule": str(meta.get("matching_rule") or ""),
                    "tables_matching_rules": sorted(meta.get("tables_matching_rules") or []),
                    "group_type": "dynamic",
                },
            ),
            commit=False,
            on_conflict="update",
            dedupe=True,
        )

    totals["edges_written"] = len(edge_cache)
    totals["edges_skipped"] = max(totals["edges_seen"] - totals["edges_written"], 0)

    if auto_commit:
        ctx.commit()
    _dlog(debug, "dg: done", **totals)
    return totals
