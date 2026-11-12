"""
process_og_attack_paths — text-based attack path analysis over OCI OpenGraph JSON.

Reads the JSON produced by process_oracle_cloud_hound_data and finds privilege-
escalation paths without requiring BloodHound.  Two search modes:

  default   — one shortest path per reachable principal (fast, BFS)
  --all-paths — enumerate every simple path up to --max-paths (best-first)

Usage:
  modules run process_og_attack_paths --graph-json /path/to/oracle_cloud_hound.json
  modules run process_og_attack_paths --graph-json /path/to/file.json --to-manage
  modules run process_og_attack_paths --graph-json /path/to/file.json --to-kind OCIGroup
  modules run process_og_attack_paths --graph-json /path/to/file.json --summary
  modules run process_og_attack_paths --graph-json /path/to/file.json --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ocinferno.modules.opengraph.utilities.helpers.pathfinding.model import (
    _JOIN_DG_SUFFIX,
    DEFAULT_PRIV_EDGE_KINDS,
    IAM_CONTROL_EDGE_KINDS,
    MANAGE_EDGE_KIND,
    RPST_CREATE_EDGE_KINDS,
    AttackGraph,
)
from ocinferno.modules.opengraph.utilities.helpers.pathfinding.render import (
    paths_to_json,
    render_report,
)
from ocinferno.modules.opengraph.utilities.helpers.pathfinding.search import (
    enumerate_paths,
    shortest_paths,
)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(user_args: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="process_og_attack_paths",
        description="Text-based OCI OpenGraph attack path analysis (no BloodHound needed).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Find all priv-esc paths (default: manage + IAM-control + RPST creation)
  --graph-json /path/to/oracle_cloud_hound.json

  # Find paths to any OCI_MANAGE destination only
  --graph-json /path/to/file.json --to-manage

  # Find paths to a specific node
  --graph-json /path/to/file.json --to-node ocid1.group.oc1..aaa...

  # Find paths to all nodes of a kind
  --graph-json /path/to/file.json --to-kind OCIDynamicGroup

  # Enumerate all paths (not just shortest per principal)
  --graph-json /path/to/file.json --all-paths --max-paths 200

  # Only show summary counts, no path detail
  --graph-json /path/to/file.json --summary

  # Machine-readable JSON output
  --graph-json /path/to/file.json --json
""",
    )

    # Required
    p.add_argument(
        "--graph-json", required=True, metavar="PATH",
        help="Path to oracle_cloud_hound.json (or a directory of split-JSON parts).",
    )

    # Target selection
    tg = p.add_argument_group("Target selection (default: all OCI_MANAGE + IAM-control + RPST-create targets)")
    tg.add_argument(
        "--to-priv", action="store_true", default=False,
        help="Target all privilege-escalation edge destinations (default when no other --to-* given).",
    )
    tg.add_argument(
        "--to-manage", action="store_true", default=False,
        help="Target all OCI_MANAGE edge destinations.",
    )
    tg.add_argument(
        "--to-iam", action="store_true", default=False,
        help="Target all IAM-control edge destinations (create/update policy/group).",
    )
    tg.add_argument(
        "--to-rpst", action="store_true", default=False,
        help="Target all RPST resource-creation edge destinations.",
    )
    tg.add_argument(
        "--to-kind", metavar="KIND", action="append", default=[],
        help="Target all nodes of this kind (e.g. OCIDynamicGroup). Repeatable.",
    )
    tg.add_argument(
        "--to-node", metavar="NODE_ID", action="append", default=[],
        help="Target an exact node id. Repeatable.",
    )
    tg.add_argument(
        "--to-any", action="store_true", default=False,
        help="Target every capability edge destination (very broad).",
    )

    # Source selection
    p.add_argument(
        "--from", metavar="SUBSTR", action="append", default=[], dest="from_filter",
        help="Only start paths at principals whose id/name contains this substring. Repeatable.",
    )

    # Search options
    sg = p.add_argument_group("Search options")
    sg.add_argument(
        "--all-paths", action="store_true", default=False,
        help="Enumerate all simple paths (not just shortest per principal).",
    )
    sg.add_argument(
        "--max-depth", type=int, default=None, metavar="N",
        help="Maximum path length in hops (default: 10 for shortest, 7 for all-paths).",
    )
    sg.add_argument(
        "--max-paths", type=int, default=500, metavar="N",
        help="Maximum paths returned in --all-paths mode (default: 500).",
    )
    sg.add_argument(
        "--max-expansions", type=int, default=400_000, metavar="N",
        help="Search budget for --all-paths mode (default: 400,000 heap pops).",
    )
    sg.add_argument(
        "--include-containment", action="store_true", default=False,
        help="Follow scope/containment edges (OCI_SCOPE_MEMBER_OF, FAMILY_INCLUDES, etc.).",
    )
    sg.add_argument(
        "--exclude-conditional", action="store_true", default=False,
        help="Skip edges that require conditions to be met.",
    )
    sg.add_argument(
        "--exclude-service-agents", action="store_true", default=False,
        help="Exclude OCI service-agent principals as path sources.",
    )
    sg.add_argument(
        "--no-direct", action="store_true", default=False,
        help="Exclude trivial paths where the principal directly holds the target edge.",
    )
    sg.add_argument(
        "--exclude-node", metavar="SUBSTR", action="append", default=[],
        help="Exclude paths that include nodes matching this substring. Repeatable.",
    )

    # Output
    og = p.add_argument_group("Output")
    og.add_argument(
        "--expanded", action="store_true", default=False,
        help="Show every raw node/edge (no collapsing of OCIPolicyStatement nodes).",
    )
    og.add_argument(
        "--summary", action="store_true", default=False,
        help="Print only the summary table, no individual paths.",
    )
    og.add_argument(
        "--json", action="store_true", default=False,
        help="Emit machine-readable JSON to stdout.",
    )
    og.add_argument(
        "--output", metavar="FILE", default=None,
        help="Write report to this file instead of stdout.",
    )
    og.add_argument(
        "--list-targets", action="store_true", default=False,
        help="List the nodes matched by the target selector, then exit.",
    )
    og.add_argument(
        "--stats", action="store_true", default=False,
        help="Print edge-kind histogram and exit.",
    )
    og.add_argument(
        "-v", "--debug", action="store_true", default=False,
    )

    return p.parse_args(user_args)


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

def _resolve_targets(
    graph: AttackGraph,
    args: argparse.Namespace,
) -> set[str]:
    any_explicit = (
        args.to_manage or args.to_iam or args.to_rpst
        or args.to_kind or args.to_node or args.to_any
    )

    target_edge_kinds: frozenset[str] = frozenset()

    if args.to_any:
        # Every capability edge destination
        all_cap = DEFAULT_PRIV_EDGE_KINDS | frozenset({
            e.kind for e in graph.edges
            if e.kind.endswith(_JOIN_DG_SUFFIX)
        })
        target_edge_kinds = all_cap
    elif any_explicit:
        combined: set[str] = set()
        if args.to_manage:
            combined.add(MANAGE_EDGE_KIND)
        if args.to_iam:
            combined |= IAM_CONTROL_EDGE_KINDS
        if args.to_rpst:
            combined |= RPST_CREATE_EDGE_KINDS
        target_edge_kinds = frozenset(combined)
    else:
        # Default: all privilege-escalation edges
        target_edge_kinds = DEFAULT_PRIV_EDGE_KINDS

    # Collect from edges
    targets: set[str] = set(graph.iter_priv_targets(target_edge_kinds))

    # Add explicitly named nodes
    for nid in args.to_node:
        if nid in graph.nodes:
            targets.add(nid)
        else:
            # Try substring match
            for gid in graph.nodes:
                if nid.lower() in gid.lower():
                    targets.add(gid)

    # Add nodes by kind
    for kind in args.to_kind:
        for nid, n in graph.nodes.items():
            if kind in (n.get("kinds") or []):
                targets.add(nid)

    return targets


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_module(user_args: list[str], session) -> dict:
    args = _parse_args(user_args)

    # Load graph
    graph_path = Path(args.graph_json)
    if not graph_path.exists():
        print(f"[attack_paths] ERROR: graph file not found: {graph_path}", file=sys.stderr)
        return {"ok": False, "error": "graph file not found"}

    if args.debug:
        print(f"[attack_paths] Loading graph from {graph_path} ...", file=sys.stderr)

    graph = AttackGraph.from_path(
        graph_path,
        include_containment=args.include_containment,
        exclude_conditional=args.exclude_conditional,
        debug=args.debug,
    )

    # Stats mode
    if args.stats:
        print(f"Nodes: {graph.n_nodes:,}  Edges: {graph.n_edges:,}  Principals: {graph.n_principals:,}\n")
        print("Edge-kind histogram:")
        for ek, cnt in sorted(graph.edge_kind_histogram().items(), key=lambda x: -x[1]):
            print(f"  {cnt:7,}  {ek}")
        return {"ok": True}

    # Resolve targets
    targets = _resolve_targets(graph, args)

    # List targets mode
    if args.list_targets:
        print(f"Targets ({len(targets)}):")
        for tid in sorted(targets):
            label = graph.node_display(tid)
            kinds = graph.node_kinds(tid)
            print(f"  {label}  [{', '.join(kinds)}]")
            if label != tid:
                print(f"    id: {tid}")
        return {"ok": True}

    if not targets:
        print("[attack_paths] No target nodes matched the selector.", file=sys.stderr)
        return {"ok": False, "error": "no targets"}

    # Resolve excluded nodes
    excluded: set[str] = set()
    for substr in (args.exclude_node or []):
        for nid in graph.nodes:
            if substr.lower() in nid.lower():
                excluded.add(nid)

    # Resolve source filter
    source_filter: set[str] | None = None
    if args.from_filter:
        source_filter = set()
        for substr in args.from_filter:
            for nid, n in graph.nodes.items():
                label = graph.node_display(nid)
                if substr.lower() in nid.lower() or substr.lower() in label.lower():
                    if graph.is_principal(nid):
                        source_filter.add(nid)

    if args.all_paths:
        max_depth = args.max_depth if args.max_depth is not None else 7
        if args.debug:
            print(f"[attack_paths] enumerate_paths mode, max_depth={max_depth}, targets={len(targets)}", file=sys.stderr)
        paths = enumerate_paths(
            graph, targets,
            max_depth=max_depth,
            max_paths=args.max_paths,
            max_expansions=args.max_expansions,
            source_filter=source_filter,
            excluded_nodes=excluded,
            exclude_service_agents=args.exclude_service_agents,
            no_direct=args.no_direct,
        )
        truncated = len(paths) >= args.max_paths
    else:
        max_depth = args.max_depth if args.max_depth is not None else 10
        if args.debug:
            print(f"[attack_paths] shortest_paths mode, max_depth={max_depth}, targets={len(targets)}", file=sys.stderr)
        paths = shortest_paths(
            graph, targets,
            max_depth=max_depth,
            source_filter=source_filter,
            excluded_nodes=excluded,
            exclude_service_agents=args.exclude_service_agents,
            no_direct=args.no_direct,
        )
        truncated = False

    if args.debug:
        print(f"[attack_paths] Found {len(paths)} paths", file=sys.stderr)

    # Group paths by target
    paths_by_target: dict[str, list[list[str]]] = {}
    for path in paths:
        tid = path[-1]
        paths_by_target.setdefault(tid, []).append(path)

    # Output
    if args.json:
        result = paths_to_json(graph, paths_by_target, target_ids=targets, truncated=truncated)
        output = json.dumps(result, indent=2)
    else:
        output = render_report(
            graph,
            paths_by_target,
            expanded=args.expanded,
            summary_only=args.summary,
            target_ids=targets,
        )
        if truncated:
            output += f"\n[Truncated: showing first {args.max_paths} paths. Use --max-paths to increase.]\n"

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"[attack_paths] Report written to {args.output}")
    else:
        print(output)

    return {
        "ok": True,
        "components": [
            {
                "name": "attack_paths",
                "count": len(paths),
                "targets": len(targets),
            }
        ],
    }
