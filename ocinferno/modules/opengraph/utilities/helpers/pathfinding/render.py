"""
Rendering: convert raw node-ID paths into human-readable text or JSON.

OCI paths typically look like:
  principal -> [OCI_GROUP_MEMBER] -> group -> [OCI_POLICY_SUBJECT] -> policy_stmt
           -> [OCI_MANAGE / OCI_CREATE_*] -> resource_or_capability_node

Collapsing rules:
  - OCIPolicyStatement nodes are folded into the hop that terminates at them,
    so the display shows: principal --[verb on resource in scope]--> resource
  - OCIResourceGroup nodes are kept as destinations (they describe what you can
    access, e.g. "all-resources@tenancy:xxx")
  - OCINew* nodes (synthetic RPST targets) are shown as the final destination
"""
from __future__ import annotations

import io
import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import AttackGraph


# ---------------------------------------------------------------------------
# OCID display helpers
# ---------------------------------------------------------------------------

_OCID_RE = re.compile(r"^ocid1\.[a-z][a-z0-9]*\.oc[0-9]+\.\.")

def _elide_mid(text: str, limit: int) -> str:
    """Keep both ends, elide the middle — tail gets the larger share since
    the resource-type suffix identifies the OCID better than the prefix."""
    if len(text) <= limit:
        return text
    budget = limit - 1  # one char for '…'
    tail = (budget * 2) // 3
    head = budget - tail
    return f"{text[:head]}…{text[-tail:]}"


def _short_node(nid: str, display: str) -> str:
    """Prefer the display name; fall back to middle-elided OCID."""
    if display and display != nid:
        return display
    if _OCID_RE.match(nid) and len(nid) > 50:
        return _elide_mid(nid, 48)
    return nid


# ---------------------------------------------------------------------------
# Edge-kind friendly descriptions
# ---------------------------------------------------------------------------

_EDGE_FRIENDLY: dict[str, str] = {
    "OCI_MANAGE":                    "manage",
    "OCI_GROUP_MEMBER":              "member of",
    "OCI_DYNAMIC_GROUP_MEMBER":      "matched by dynamic group",
    "OCI_POLICY_SUBJECT":            "policy subject",
    "OCI_CAN_CREATE_POLICY":         "can create policy",
    "OCI_CREATE_POLICY":             "create policy",
    "OCI_UPDATE_POLICY":             "update policy",
    "OCI_UPDATE_GROUP":              "update group",
    "OCI_GROUP_UPDATE":              "update group",
    "OCI_INTERNAL_USER_UPDATE":      "update user",
    "OCI_INTERNAL_GROUP_UPDATE":     "update group",
    "OCI_ADD_SELF_TO_GROUP":         "add self to group",
    "OCI_POLICY_CAN_GRANT_ALL_RESOURCES": "can grant all resources",
    "OCI_UPDATED_ACCESS_TO_ALL_RESOURCES": "granted all-resources access",
    "IDD_CREATE_USER":               "create user in IDD domain",
    "IDD_ADD_SELF_TO_GROUP":         "add self to IDD group",
    "IDD_USER_ADMIN":                "user admin (IDD)",
    "IDD_USER_MANAGER":              "user manager (IDD)",
    "IDD_IDENTITY_ADMIN_USER":       "identity domain admin",
    "APP_ROLE_GRANTED":              "app role granted",
    "ROLE_IN_APPLICATION":           "role in IDD application",
    "USER_API_KEY":                  "has API key for",
    "OCI_RUN_COMMAND":               "run command on instance",
    "OCI_CREATE_INSTANCE_AGENT_COMMAND": "create instance agent command",
    "OCI_READ_RUN_INPUT":            "read run input",
    "OCI_READ_RUN_OUTPUT":           "read run output",
    "OCI_INCLUDES":                  "scope includes",
    "OCI_SPECIFIC_RESOURCE":         "specific resource",
    "OCI_SCOPE_MEMBER_OF":           "in scope",
    "OCI_BELONGS_TO":                "belongs to",
    "FAMILY_INCLUDES":               "family includes",
    "INSTALL_KEY_CAN_JOIN_DG":       "install key can join dynamic group",
    "OCI_CREATE_INSTANCE":           "create compute instance as SA",
    "OCI_CREATE_FN_FUNCTION":        "create function as SA",
    "OCI_CREATE_CONTAINER_INSTANCE": "create container instance as SA",
    "OCI_CREATE_OKE_CLUSTER":        "create OKE cluster as SA",
}


def _edge_description(edge_kind: str) -> str | None:
    return _EDGE_FRIENDLY.get(edge_kind)


# ---------------------------------------------------------------------------
# Hop dataclass
# ---------------------------------------------------------------------------

@dataclass
class Hop:
    src: str
    dst: str
    edge_kind: str
    # Metadata from collapsed intermediaries
    scope: str | None = None
    verb: str | None = None
    resource_tokens: str | None = None
    is_priv_escalation: bool = False
    conditional: bool = False
    policy_ids: list[str] = field(default_factory=list)


def _edge_between(graph: "AttackGraph", src: str, dst: str) -> tuple[str, dict]:
    """Return (kind, props) of the first edge from src to dst."""
    for d, eidx in graph.adj.get(src) or []:
        if d == dst:
            e = graph.edges[eidx]
            return e.kind, e.props
    return "", {}


def _extract_edge_meta(props: dict) -> dict:
    """Pull useful display metadata from edge properties."""
    inner = props.get("edge_inner_properties") or {}
    if isinstance(inner, str):
        try:
            inner = json.loads(inner)
        except Exception:
            inner = {}
    return {
        "is_priv_escalation": bool(inner.get("is_priv_escalation") or props.get("is_priv_escalation")),
        "conditional": bool(inner.get("conditional") or props.get("conditional")),
        "policy_ids": list(inner.get("resolved_policy") or []),
        "verb": str(inner.get("verb") or "").strip() or None,
        "resource_tokens": str(inner.get("resource_tokens") or "").strip() or None,
        "scope": str(inner.get("scope_display") or inner.get("scope") or "").strip() or None,
    }


# ---------------------------------------------------------------------------
# Path collapsing
# ---------------------------------------------------------------------------

def collapse_path(graph: "AttackGraph", path: list[str]) -> list[Hop]:
    """
    Convert a raw node-ID path into a list of display Hops, folding
    OCIPolicyStatement intermediaries into their adjacent hops.
    """
    if len(path) < 2:
        return []

    hops: list[Hop] = []
    i = 0
    while i < len(path) - 1:
        src = path[i]
        dst = path[i + 1]
        kind, props = _edge_between(graph, src, dst)
        meta = _extract_edge_meta(props)

        # If dst is a binding/policy-statement node and there's a next hop,
        # fold it: skip the binding node and use the outgoing capability edge
        if (graph.is_binding(dst) and i + 2 < len(path)):
            next_dst = path[i + 2]
            cap_kind, cap_props = _edge_between(graph, dst, next_dst)
            cap_meta = _extract_edge_meta(cap_props)

            # Merge metadata from both edges
            merged_meta = {
                "is_priv_escalation": meta["is_priv_escalation"] or cap_meta["is_priv_escalation"],
                "conditional": meta["conditional"] or cap_meta["conditional"],
                "policy_ids": (meta["policy_ids"] or []) + (cap_meta["policy_ids"] or []),
                "verb": cap_meta["verb"] or meta["verb"],
                "resource_tokens": cap_meta["resource_tokens"] or meta["resource_tokens"],
                "scope": cap_meta["scope"] or meta["scope"],
            }
            hops.append(Hop(
                src=src,
                dst=next_dst,
                edge_kind=cap_kind or kind,
                scope=merged_meta["scope"],
                verb=merged_meta["verb"],
                resource_tokens=merged_meta["resource_tokens"],
                is_priv_escalation=merged_meta["is_priv_escalation"],
                conditional=merged_meta["conditional"],
                policy_ids=merged_meta["policy_ids"],
            ))
            i += 2  # consumed src, binding_node, next_dst
        else:
            hops.append(Hop(
                src=src,
                dst=dst,
                edge_kind=kind,
                scope=meta["scope"],
                verb=meta["verb"],
                resource_tokens=meta["resource_tokens"],
                is_priv_escalation=meta["is_priv_escalation"],
                conditional=meta["conditional"],
                policy_ids=meta["policy_ids"],
            ))
            i += 1

    return hops


def _hop_count(hops: list[Hop]) -> int:
    return len(hops)


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------

def _node_label(graph: "AttackGraph", nid: str) -> str:
    return _short_node(nid, graph.node_display(nid))


def _hop_annotation(hop: Hop) -> str:
    """Build the parenthetical annotation for a hop line.

    Policy-based hops (OCI_MANAGE, OCI_CREATE_*) carry verb/resource/scope
    from collapsed OCIPolicyStatement metadata — show those directly.
    Membership/IAM-control hops fall back to the friendly edge description.
    """
    parts = []
    if hop.verb:
        parts.append(hop.verb)
    if hop.resource_tokens:
        parts.append(hop.resource_tokens)
    if hop.scope:
        parts.append(f"in {hop.scope}")

    # For hops with no policy metadata, show the friendly edge description
    # so the reader knows what kind of privilege the edge represents.
    if not parts:
        desc = _edge_description(hop.edge_kind)
        if desc:
            parts.append(desc)

    if hop.conditional:
        parts.append("conditional")

    return f"  ({', '.join(parts)})" if parts else ""


def render_path_text(graph: "AttackGraph", path: list[str], *, expanded: bool = False) -> str:
    """Render a single path as indented text."""
    out = io.StringIO()
    hops = collapse_path(graph, path) if not expanded else None

    if expanded:
        # Raw mode: show every node and edge
        src_label = _node_label(graph, path[0])
        out.write(f"  {src_label}\n")
        for i in range(len(path) - 1):
            kind, props = _edge_between(graph, path[i], path[i + 1])
            dst_label = _node_label(graph, path[i + 1])
            cond = " [conditional]" if props.get("conditional") else ""
            out.write(f"    └─[{kind}]─> {dst_label}{cond}\n")
    else:
        assert hops is not None
        src_label = _node_label(graph, path[0])
        hop_n = _hop_count(hops)
        out.write(f"  [{hop_n} hop{'s' if hop_n != 1 else ''}] {src_label}\n")
        for hop in hops:
            dst_label = _node_label(graph, hop.dst)
            annotation = _hop_annotation(hop)
            out.write(f"      └─[{hop.edge_kind}]─> {dst_label}{annotation}\n")

    return out.getvalue()


def _shortest_hop_count(graph: "AttackGraph", paths: list[list[str]]) -> int:
    """Minimum collapsed hop count across a set of paths to the same target."""
    if not paths:
        return 0
    return min(_hop_count(collapse_path(graph, p)) for p in paths)


def render_report(
    graph: "AttackGraph",
    paths_by_target: dict[str, list[list[str]]],
    *,
    expanded: bool = False,
    summary_only: bool = False,
    target_ids: set[str],
) -> str:
    out = io.StringIO()

    all_paths = [p for pp in paths_by_target.values() for p in pp]
    total_principals = len({p[0] for p in all_paths})

    # Header
    out.write("=" * 70 + "\n")
    out.write(" OCI OPENGRAPH ATTACK PATH ANALYSIS\n")
    out.write("=" * 70 + "\n")
    out.write(f"  Graph:      {graph.n_nodes:,} nodes  {graph.n_edges:,} edges\n")
    out.write(f"  Principals: {graph.n_principals:,}\n")
    out.write(f"  Targets:    {len(target_ids):,}\n")
    if all_paths:
        out.write(f"  Paths:      {len(all_paths):,}  |  {total_principals} distinct principal(s)\n")
    out.write("\n")

    if not all_paths:
        out.write("  No attack paths found.\n")
        return out.getvalue()

    # Summary table — order by most reachable (highest path count), then shortest
    sorted_targets = sorted(
        paths_by_target.items(),
        key=lambda x: (-len(x[1]), _shortest_hop_count(graph, x[1])),
    )

    out.write(" TARGET SUMMARY\n")
    out.write(" " + "-" * 68 + "\n")
    out.write(f"  {'PATHS':>6}  {'PRINCIPALS':>10}  {'SHORTEST':>8}  TARGET\n")
    out.write(" " + "-" * 68 + "\n")

    for tid, tpaths in sorted_targets:
        principals = {p[0] for p in tpaths}
        label = _node_label(graph, tid)
        shortest = _shortest_hop_count(graph, tpaths)
        out.write(f"  {len(tpaths):>6}  {len(principals):>10}  {shortest:>8}  {label}\n")

    out.write("\n")

    if summary_only:
        return out.getvalue()

    # Per-target path detail
    for tid, tpaths in sorted_targets:
        if not tpaths:
            continue
        label = _node_label(graph, tid)
        kinds = graph.node_kinds(tid)
        principals = {p[0] for p in tpaths}
        shortest = _shortest_hop_count(graph, tpaths)

        out.write("─" * 70 + "\n")
        out.write(f" TARGET: {label}\n")
        if kinds:
            out.write(f"         kinds: {', '.join(kinds)}\n")
        # Show full OCID only when the display label is different
        if label != tid:
            out.write(f"         node:  {tid}\n")
        out.write(
            f"         {len(principals)} principal(s)  |  {len(tpaths)} path(s)  |  shortest = {shortest} hop(s)\n"
        )
        out.write("\n")

        for path in sorted(tpaths, key=lambda p: (_hop_count(collapse_path(graph, p)), p[0])):
            out.write(render_path_text(graph, path, expanded=expanded))

        out.write("\n")

    return out.getvalue()


def paths_to_json(
    graph: "AttackGraph",
    paths_by_target: dict[str, list[list[str]]],
    *,
    target_ids: set[str],
    truncated: bool = False,
) -> dict:
    all_paths = [p for pp in paths_by_target.values() for p in pp]
    serialized = []
    for tid, tpaths in paths_by_target.items():
        for path in tpaths:
            hops = collapse_path(graph, path)
            serialized.append({
                "source": path[0],
                "source_label": graph.node_display(path[0]),
                "target": tid,
                "target_label": graph.node_display(tid),
                "hop_count": _hop_count(hops),
                "raw_nodes": path,
                "hops": [
                    {
                        "src": h.src,
                        "src_label": graph.node_display(h.src),
                        "dst": h.dst,
                        "dst_label": graph.node_display(h.dst),
                        "edge_kind": h.edge_kind,
                        "edge_description": _edge_description(h.edge_kind),
                        "verb": h.verb,
                        "resource_tokens": h.resource_tokens,
                        "scope": h.scope,
                        "is_priv_escalation": h.is_priv_escalation,
                        "conditional": h.conditional,
                        "policy_ids": h.policy_ids,
                    }
                    for h in hops
                ],
            })

    return {
        "graph": {
            "nodes": graph.n_nodes,
            "edges": graph.n_edges,
            "principals": graph.n_principals,
        },
        "targets": len(target_ids),
        "paths_total": len(all_paths),
        "paths_truncated": truncated,
        "paths": serialized,
    }
