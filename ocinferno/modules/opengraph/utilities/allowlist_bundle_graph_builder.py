# allowlist_bundle_graph_builder.py
"""Multi-permission BUNDLE edges from ALLOW_RULE_DEFS (cross-resource-token AND).

The base allowlist matches ONE statement at a time (permissions on one resource token),
so a true multi-permission route -- an edge that should fire only when a principal holds
ALL of several (permissions, resource-token) requirements at the SAME location -- used to
require hand-written AND logic in iam_policy_advanced_relation_graph_builder.py (the
`_RelationState` boolean flags). A ``bundle`` rule expresses that AND purely in JSON, so
multi-permission privesc routes are authorable without Python.

A bundle rule lives alongside the normal rules in ``ALLOW_RULE_DEFS`` (static_constants.json):

    {
      "id": "SOME_MULTI_ROUTE",
      "edge": {"label": "OCI_SOME_EDGE", "description": "..."},
      "destination": {"token": "<scope-token>", "node_type": "OCIResourceGroup"},
      "bundle": {
        "requires_all": [
          {"permissions_all": ["PERM_A"], "resource_tokens": ["token-a"]},
          {"permissions_all": ["PERM_B", "PERM_C"], "resource_tokens": ["token-b"]}
        ]
      }
    }

The edge fires for a (principal, location) only when EVERY ``requires_all`` requirement is
satisfied there (each requirement = the principal holds all ``permissions_all`` on at least
one of its ``resource_tokens``). Additive: rules without a ``bundle`` field are ignored here,
so when no bundle rules exist this step is a no-op and the graph is unchanged.

NOTE: each bundle permission must be a GRAPHED permission (have a single-permission
allow-rule, or be a known capability) so it is surfaced into the relation data this reads.
"""
import json
from pathlib import Path

from ocinferno.modules.opengraph.utilities.helpers import (
    build_edge_properties as _build_edge_properties,
    EDGE_CATEGORY_PERMISSION,
)
from ocinferno.modules.opengraph.utilities.helpers.context import _dlog
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import emit_edge as _emit_edge_shared
from ocinferno.modules.opengraph.utilities.iam_policy_advanced_relation_graph_builder import (
    _edge_statement_texts,
    _entry_field,
    _extract_upper_permissions_from_statement_texts,
    _s,
)

_STATIC_CONSTANTS_PATH = (
    Path(__file__).resolve().parent / "helpers" / "data" / "static_constants.json"
)


def _load_bundle_rules() -> list:
    """ALLOW_RULE_DEFS entries that carry a ``bundle.requires_all`` block."""
    try:
        payload = json.loads(_STATIC_CONSTANTS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []
    out = []
    for r in (payload.get("ALLOW_RULE_DEFS") or []):
        if not isinstance(r, dict):
            continue
        bundle = r.get("bundle") or {}
        raw_reqs = bundle.get("requires_all") or []
        reqs = []
        for req in raw_reqs:
            if not isinstance(req, dict):
                continue
            perms = {str(p).strip().upper() for p in (req.get("permissions_all") or []) if str(p).strip()}
            toks = {str(t).strip() for t in (req.get("resource_tokens") or []) if str(t).strip()}
            if perms and toks:
                reqs.append({"permissions_all": perms, "resource_tokens": toks})
        if not reqs:
            continue
        dest = r.get("destination") or {}
        edge = r.get("edge") or {}
        out.append({
            "id": _s(r.get("id") or ""),
            "requires_all": reqs,
            "edge_label": _s(edge.get("label") or ""),
            "edge_description": _s(edge.get("description") or ""),
            "dest_token": _s(dest.get("token") or r.get("id") or "bundle-target"),
            "dest_node_type": _s(dest.get("node_type") or "") or "OCIResourceGroup",
        })
    return out


def _requirement_satisfied(req: dict, perms_by_token: dict) -> bool:
    """A requirement holds if the principal has ALL permissions_all on at least one
    of the requirement's resource_tokens (exact token match)."""
    need = req["permissions_all"]
    for token in req["resource_tokens"]:
        if need.issubset(perms_by_token.get(token, frozenset())):
            return True
    return False


def bundle_rule_matches(rule: dict, perms_by_token: dict) -> bool:
    """Pure, testable core: does a (principal, location)'s per-token permission map
    satisfy EVERY requirement of a bundle rule?"""
    reqs = rule.get("requires_all") or []
    return bool(reqs) and all(_requirement_satisfied(req, perms_by_token) for req in reqs)


def build_allowlist_bundle_edges_offline(*, session, ctx, debug: bool = False, auto_commit: bool = False) -> dict:
    stats = {"bundle_rules": 0, "relation_entries_seen": 0, "principals_matched": 0, "edges_written": 0}
    rules = _load_bundle_rules()
    stats["bundle_rules"] = len(rules)
    if not rules:
        if auto_commit:
            ctx.commit()
        _dlog(debug, "allowlist-bundle: no bundle rules", **stats)
        return stats

    candidate_perms: set = set()
    for r in rules:
        for req in r["requires_all"]:
            candidate_perms |= req["permissions_all"]

    entries = getattr(ctx, "iam_postprocess_relation_entries", None) or []
    stats["relation_entries_seen"] = len(entries)

    # (principal_id, principal_type, loc) -> {resource_token: set(permissions)}
    grants: dict = {}
    for entry in entries:
        pid = _s(_entry_field(entry, "principal_id") or "")
        ptype = _s(_entry_field(entry, "principal_type") or "")
        loc = _s(_entry_field(entry, "loc") or "")
        token = _s(_entry_field(entry, "dest_token") or "")
        if not (pid and ptype and loc and token):
            continue
        edge_row = {
            "resolved_statement_details": _entry_field(entry, "resolved_statement_details") or [],
            "resolved_statements": _entry_field(entry, "resolved_statements") or [],
            "unresolved_statement_details": _entry_field(entry, "unresolved_statement_details") or [],
            "unresolved_statements": _entry_field(entry, "unresolved_statements") or [],
        }
        perms = _extract_upper_permissions_from_statement_texts(_edge_statement_texts(edge_row), candidates=candidate_perms)
        if perms:
            grants.setdefault((pid, ptype, loc), {}).setdefault(token, set()).update(perms)

    for (pid, ptype, loc), perms_by_token in grants.items():
        matched = False
        for rule in rules:
            if not bundle_rule_matches(rule, perms_by_token):
                continue
            matched = True
            dst_id = f"{rule['dest_token']}@{loc}"
            ctx.upsert_node(
                node_id=dst_id, node_type=rule["dest_node_type"], compartment_id=loc,
                node_properties={"scope_token": rule["dest_token"], "bundle_rule_id": rule["id"],
                                 "description": rule["edge_description"]},
                commit=False,
            )
            wrote = _emit_edge_shared(
                ctx, src_id=pid, src_type=ptype, dst_id=dst_id, dst_type=rule["dest_node_type"],
                edge_type=rule["edge_label"],
                edge_properties=_build_edge_properties(
                    edge_category=EDGE_CATEGORY_PERMISSION,
                    edge_inner_properties={
                        "bundle_rule_id": rule["id"], "evaluated_location": loc,
                        "requires_all": [sorted(req["permissions_all"]) for req in rule["requires_all"]],
                        "description": rule["edge_description"], "source": "ALLOW_RULE_DEFS.bundle",
                    },
                ),
                commit=False, on_conflict="update", dedupe=True,
            )
            if wrote:
                stats["edges_written"] += 1
        if matched:
            stats["principals_matched"] += 1

    if auto_commit:
        ctx.commit()
    _dlog(debug, "allowlist-bundle: done", **stats)
    return stats
