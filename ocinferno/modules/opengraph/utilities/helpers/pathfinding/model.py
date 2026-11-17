"""
OCI attack-graph model: loads the OpenGraph JSON export and builds adjacency
indices for path-finding. Pure-Python, no OCI SDK dependency.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# OCI-specific node/edge constants
# ---------------------------------------------------------------------------

PRINCIPAL_KINDS = frozenset({
    "OCIUser",
    "OCIGroup",
    "OCIDynamicGroup",
    "OCIAnyUser",
    "OCIAnyGroup",
    "OCIService",
})

# Short type names usable with --from-type user,group,dg,...
FROM_TYPE_ALIASES: dict[str, str] = {
    "user": "OCIUser",
    "group": "OCIGroup",
    "dynamic_group": "OCIDynamicGroup",
    "dg": "OCIDynamicGroup",
    "any_user": "OCIAnyUser",
    "any_group": "OCIAnyGroup",
    "service": "OCIService",
}

# Synthetic / intermediary node kinds that are collapsed in path display
BINDING_KINDS = frozenset({
    "OCIPolicyStatement",
    "OCIResourceGroup",
    "OCIIDDApplication",
})

# Edges that traverse membership / containment hierarchy
MEMBERSHIP_EDGE_KINDS = frozenset({
    "OCI_GROUP_MEMBER",
    "OCI_DYNAMIC_GROUP_MEMBER",
    "OCI_ANY_GROUP_MEMBER_OF",
    "OCI_ANY_USER_MEMBER_OF",
    "APP_ROLE_GRANTED",
    "ROLE_IN_APPLICATION",
    "INSTALL_KEY_CAN_JOIN_DG",
})

# Node kinds that represent groups / dynamic groups (used by --no-default-admin-group-hop filter).
GROUP_NODE_KINDS = frozenset({
    "OCIGroup",
    "OCIDynamicGroup",
    "OCIAnyGroup",
    "OCIIDDAppRole",
})

# OCI_POLICY_SUBJECT: principal → policy statement
GRANT_EDGE_KIND = "OCI_POLICY_SUBJECT"

CONTAINMENT_EDGE_KINDS = frozenset({
    "OCI_SCOPE_MEMBER_OF",
    "FAMILY_INCLUDES",
    "OCI_INCLUDES",
    "OCI_BELONGS_TO",
    "OCI_SPECIFIC_RESOURCE",
})

# All *_CAN_JOIN_DG edge kinds (match by suffix at load time)
_JOIN_DG_SUFFIX = "_CAN_JOIN_DG"

# High-privilege IAM-control capability edge kinds
IAM_CONTROL_EDGE_KINDS = frozenset({
    "OCI_CAN_CREATE_POLICY",
    "OCI_CREATE_POLICY",
    "OCI_UPDATE_POLICY",
    "OCI_UPDATE_GROUP",
    "OCI_GROUP_UPDATE",
    "OCI_INTERNAL_USER_UPDATE",
    "OCI_INTERNAL_GROUP_UPDATE",
    "OCI_ADD_SELF_TO_GROUP",
    "OCI_POLICY_CAN_GRANT_ALL_RESOURCES",
    "OCI_UPDATED_ACCESS_TO_ALL_RESOURCES",
    "IDD_CREATE_USER",
})

# Identity-domain admin app-roles. Unlike the edges above (where reaching the DESTINATION is
# the goal), these edges run app-role -> administered user/group, so the privileged thing is
# their SOURCE node -- the admin app-role itself (Identity Domain Administrator / User
# Administrator / User Manager). A principal reaching that app-role (e.g. via APP_ROLE_GRANTED)
# gains identity-domain admin, so these are targeted by SOURCE (see iter_admin_role_targets).
IDD_ADMIN_ROLE_EDGE_KINDS = frozenset({
    "IDD_IDENTITY_ADMIN_USER",
    "IDD_USER_ADMIN",
    "IDD_USER_MANAGER",
    "IDD_ADD_SELF_TO_GROUP",
})

# Dynamic-group injection: a principal can make a resource a member of the DG -- by rewriting
# the DG's matching rule (manage dynamic-groups). Like the *_CAN_JOIN_DG membership edges, the
# DG the edge points at is the escalation endpoint (its grants are inherited), so these are
# traversable and targeted (reaching the DG) under --to-any / --to-kind OCIDynamicGroup.
DG_INJECTION_EDGE_KINDS = frozenset({"OCI_CAN_MODIFY_DG_RULES"})

# RPST resource-creation edge kinds (can exec code as new resource principal)
RPST_CREATE_EDGE_KINDS = frozenset({
    "OCI_CREATE_INSTANCE",
    "OCI_CREATE_FN_FUNCTION",
    "OCI_CREATE_CONTAINER_INSTANCE",
    "OCI_CREATE_OKE_CLUSTER",
    "OCI_CREATE_BDS_INSTANCE",
    "OCI_CREATE_DIS_WORKSPACE",
    "OCI_CREATE_AUTONOMOUS_DATABASE",
    "OCI_CREATE_MYSQL_INSTANCE",
    "OCI_CREATE_OIC_INSTANCE",
    "OCI_CREATE_GG_DEPLOYMENT",
    "OCI_CREATE_API_GATEWAY",
    "OCI_CREATE_RESOURCE_SCHEDULE",
    "OCI_CREATE_DS_NOTEBOOK_SESSION",
    "OCI_CREATE_DS_MODEL_DEPLOYMENT",
    "OCI_CREATE_GENAI_AGENT",
    "OCI_CREATE_GENAI_INGESTION_JOB",
    "OCI_CREATE_CERTIFICATE_AUTHORITY",
    "OCI_CREATE_ODA_INSTANCE",
    "OCI_CREATE_DATA_CATALOG",
    "OCI_CREATE_DB_TOOLS_CONNECTION",
    "OCI_CREATE_DR_PROTECTION_GROUP",
    "OCI_CREATE_ANALYTICS_INSTANCE",
    "OCI_CREATE_RESOURCE_ANALYTICS",
})

# Execution-on-existing-resource capability edges
EXEC_EDGE_KINDS = frozenset({
    "OCI_RUN_COMMAND",
    "OCI_CREATE_INSTANCE_AGENT_COMMAND",
    "OCI_READ_RUN_INPUT",
    "OCI_READ_RUN_OUTPUT",
})

# Full manage verb
MANAGE_EDGE_KIND = "OCI_MANAGE"

# Default high-impact priv-esc terminal destinations.
# Only OCI_MANAGE (all-resources) + policy create/update.
# The other IAM_CONTROL_EDGE_KINDS (group/user updates, add-self-to-group,
# IDD_CREATE_USER, etc.) remain as traversal edges — the BFS goes THROUGH
# them to reach these high-value destinations — but they are not surfaced
# as terminal targets themselves by default.
DEFAULT_PRIV_EDGE_KINDS = frozenset({
    MANAGE_EDGE_KIND,
    "OCI_CAN_CREATE_POLICY",
    "OCI_CREATE_POLICY",
    "OCI_UPDATE_POLICY",
})

# IDD admin role edges included in the default target set.
# Only full Identity Domain Administrator (IDD_IDENTITY_ADMIN_USER).
# Use IDD_ADMIN_ROLE_EDGE_KINDS for all roles (opt-in via --include-idd-all).
DEFAULT_IDD_ADMIN_EDGE_KINDS = frozenset({"IDD_IDENTITY_ADMIN_USER"})


def edge_is_conditional(props: dict) -> bool:
    """True when an edge's IAM grant carries any ``where`` condition.

    The graph builder records condition state inside ``edge_inner_properties``
    (``has_unresolved_conditionals``, ``unresolved_statements``, and the full
    ``resolved_statements`` text) rather than a flat top-level ``conditional`` flag.
    Derive the flag here so ``--exclude-conditional`` and the ``[conditional]`` label
    reflect conditions the builder actually captured -- whether it resolved them
    (region/tag) or left them unresolved (time-based/dynamic).
    """
    if not isinstance(props, dict):
        return False
    inner = props.get("edge_inner_properties") or {}
    if isinstance(inner, str):
        try:
            inner = json.loads(inner)
        except Exception:
            inner = {}
    # Condition state may sit at the top level of properties or inside
    # edge_inner_properties depending on the builder, so check both.
    def _get(key):
        return props.get(key) or (inner.get(key) if isinstance(inner, dict) else None)

    if _get("conditional"):
        return True
    if _get("has_unresolved_conditionals") or _get("has_impossible_conditionals"):
        return True
    if _get("unresolved_statements") or _get("unresolved_statement_details"):
        return True
    for stmt in (_get("resolved_statements") or []):
        if " where " in f" {str(stmt).lower()} ":
            return True
    return False


# ---------------------------------------------------------------------------
# Graph model
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class EdgeInfo:
    idx: int
    src: str
    dst: str
    kind: str
    props: dict


@dataclass
class AttackGraph:
    nodes: dict[str, dict]           # node_id -> {kinds, properties, ...}
    edges: list[EdgeInfo]            # all edges
    adj: dict[str, list[tuple[str, int]]]   # src -> [(dst, edge_idx)]
    radj: dict[str, list[tuple[str, int]]]  # dst -> [(src, edge_idx)]
    # statistics
    n_nodes: int = 0
    n_edges: int = 0
    n_principals: int = 0

    # ---------------------------------------------------------------------------
    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        exclude_conditional: bool = False,
        debug: bool = False,
    ) -> "AttackGraph":
        path = Path(path)
        if path.is_dir():
            raw_edges: list[dict] = []
            raw_nodes: list[dict] = []
            # Load all JSON parts in a directory
            for f in sorted(path.iterdir()):
                if f.suffix != ".json" or "manifest" in f.name:
                    continue
                data = json.loads(f.read_text(encoding="utf-8"))
                g = data.get("graph") or {}
                raw_nodes.extend(g.get("nodes") or [])
                raw_edges.extend(g.get("edges") or [])
        else:
            data = json.loads(path.read_text(encoding="utf-8"))
            g = data.get("graph") or {}
            raw_nodes = g.get("nodes") or []
            raw_edges = g.get("edges") or []

        return cls._build(
            raw_nodes,
            raw_edges,
            exclude_conditional=exclude_conditional,
            debug=debug,
        )

    @classmethod
    def _build(
        cls,
        raw_nodes: list[dict],
        raw_edges: list[dict],
        *,
        exclude_conditional: bool,
        debug: bool,
    ) -> "AttackGraph":
        nodes: dict[str, dict] = {}
        for n in raw_nodes:
            if not isinstance(n, dict):
                continue
            nid = str(n.get("id") or "").strip()
            if not nid:
                continue
            # strip heavy unused props to save memory
            props = dict(n.get("properties") or {})
            props.pop("module_command", None)
            props.pop("example_command", None)
            nodes[nid] = {
                "id": nid,
                "kinds": list(n.get("kinds") or []),
                "properties": props,
            }

        edges: list[EdgeInfo] = []
        adj: dict[str, list[tuple[str, int]]] = {}
        radj: dict[str, list[tuple[str, int]]] = {}

        for raw in raw_edges:
            if not isinstance(raw, dict):
                continue
            src = str((raw.get("start") or {}).get("value") or "").strip()
            dst = str((raw.get("end") or {}).get("value") or "").strip()
            kind = str(raw.get("kind") or "").strip()
            if not (src and dst and kind):
                continue

            props = dict(raw.get("properties") or {})

            # Skip conditional edges if requested
            if exclude_conditional and edge_is_conditional(props):
                continue

            # Treat any *_CAN_JOIN_DG edge as a membership edge
            # (normalize for display but keep original kind)

            idx = len(edges)
            ei = EdgeInfo(idx=idx, src=src, dst=dst, kind=kind, props=props)
            edges.append(ei)
            adj.setdefault(src, []).append((dst, idx))
            radj.setdefault(dst, []).append((src, idx))

        n_principals = sum(
            1 for n in nodes.values()
            if any(k in PRINCIPAL_KINDS for k in n.get("kinds") or [])
        )

        if debug:
            from collections import Counter
            kind_counts = Counter(e.kind for e in edges)
            print(f"[model] nodes={len(nodes)} edges={len(edges)} principals={n_principals}")
            for ek, cnt in kind_counts.most_common(20):
                print(f"  {cnt:6d}  {ek}")

        return cls(
            nodes=nodes,
            edges=edges,
            adj=adj,
            radj=radj,
            n_nodes=len(nodes),
            n_edges=len(edges),
            n_principals=n_principals,
        )

    # ---------------------------------------------------------------------------
    def node_display(self, nid: str) -> str:
        """Human-readable label for a node."""
        n = self.nodes.get(nid)
        if not n:
            return nid
        props = n.get("properties") or {}
        name = str(props.get("name") or props.get("display_name") or "").strip()
        if name and name != nid:
            return name
        return nid

    def node_kinds(self, nid: str) -> list[str]:
        n = self.nodes.get(nid)
        return list(n.get("kinds") or []) if n else []

    def is_principal(self, nid: str) -> bool:
        return any(k in PRINCIPAL_KINDS for k in self.node_kinds(nid))

    def is_binding(self, nid: str) -> bool:
        return any(k in BINDING_KINDS for k in self.node_kinds(nid))

    def edge_kind_histogram(self) -> dict[str, int]:
        from collections import Counter
        return dict(Counter(e.kind for e in self.edges).most_common())

    def iter_priv_targets(self, edge_kinds: frozenset[str] | None = None) -> Iterator[str]:
        """Yield all destination node IDs that are reached by privilege-escalation edges."""
        wanted = edge_kinds if edge_kinds is not None else DEFAULT_PRIV_EDGE_KINDS
        seen: set[str] = set()
        for e in self.edges:
            if e.kind in wanted or (e.kind.endswith(_JOIN_DG_SUFFIX) and MANAGE_EDGE_KIND not in wanted):
                # CAN_JOIN_DG edges are always traversable membership edges; don't treat
                # them as priv-esc targets unless explicitly requested
                pass
            if e.kind in wanted:
                dst = e.dst
                if dst not in seen:
                    seen.add(dst)
                    yield dst

    def iter_secret_read_targets(self) -> Iterator[str]:
        """Yield destination nodes of OCI_READ edges that relate to vault secrets."""
        seen: set[str] = set()
        for e in self.edges:
            if e.kind != "OCI_READ":
                continue
            dst = e.dst
            if dst in seen:
                continue
            n = self.nodes.get(dst, {})
            props = n.get("properties") or {}
            node_text = " ".join(str(v) for v in [dst] + list(props.values())).lower()
            if "secret" in node_text:
                seen.add(dst)
                yield dst

    def iter_admin_role_targets(
        self, edge_kinds: frozenset[str] = IDD_ADMIN_ROLE_EDGE_KINDS
    ) -> Iterator[str]:
        """Yield SOURCE node IDs of identity-domain admin-role edges -- the privileged app-role
        nodes. Reaching such a node (via APP_ROLE_GRANTED) is the escalation; it can administer
        users/groups. Targeted by source because the edges point role -> administered principal."""
        seen: set[str] = set()
        for e in self.edges:
            if e.kind in edge_kinds and e.src not in seen:
                seen.add(e.src)
                yield e.src
