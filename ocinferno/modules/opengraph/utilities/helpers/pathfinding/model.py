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
    "OCI_ROLE_OF_APP",
    "OCI_IDD_GROUP_MEMBER",
    "INSTALL_KEY_CAN_JOIN_DG",
})

# OCI_POLICY_SUBJECT: principal → policy statement
GRANT_EDGE_KIND = "OCI_POLICY_SUBJECT"

# Structural scope/containment edges (skipped unless --include-containment)
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

# All "default priv-escalation" target edge kinds
DEFAULT_PRIV_EDGE_KINDS = (
    frozenset({MANAGE_EDGE_KIND})
    | IAM_CONTROL_EDGE_KINDS
    | RPST_CREATE_EDGE_KINDS
    | EXEC_EDGE_KINDS
)


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
        include_containment: bool = False,
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
            include_containment=include_containment,
            exclude_conditional=exclude_conditional,
            debug=debug,
        )

    @classmethod
    def _build(
        cls,
        raw_nodes: list[dict],
        raw_edges: list[dict],
        *,
        include_containment: bool,
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

            # Skip containment edges unless requested
            if not include_containment and kind in CONTAINMENT_EDGE_KINDS:
                continue

            props = dict(raw.get("properties") or {})

            # Skip conditional edges if requested
            if exclude_conditional and props.get("conditional"):
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
