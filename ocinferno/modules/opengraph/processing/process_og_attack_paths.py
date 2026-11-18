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
    DEFAULT_IDD_ADMIN_EDGE_KINDS,
    DEFAULT_MANAGE_TARGET_KINDS,
    DEFAULT_PRIV_EDGE_KINDS,
    DG_INJECTION_EDGE_KINDS,
    EXEC_EDGE_KINDS,
    FROM_TYPE_ALIASES,
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
  # Find all priv-esc paths (default: manage + IAM-control + IDD identity domain admin)
  --graph-json /path/to/oracle_cloud_hound.json

  # Only users and groups as starting principals
  --graph-json /path/to/file.json --from-type user,group

  # Only paths whose target is at the tenancy level (skip child-compartment grants)
  --graph-json /path/to/file.json --to-scope ocid1.tenancy

  # Specific starting user, all paths including IDD admin compound chains
  --graph-json /path/to/file.json --from someuser --all-paths --max-paths 50

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
    tg = p.add_argument_group("Target selection (default: OCI_MANAGE + IAM-control + IDD identity domain admin)")
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
    tg.add_argument(
        "--include-secret-read", action="store_true", default=False,
        help=(
            "Also target OCI_READ destinations that relate to vault secrets. "
            "Shows all principals that can read secret contents."
        ),
    )
    # Source selection
    p.add_argument(
        "--from", metavar="SUBSTR", action="append", default=[], dest="from_filter",
        help="Only start paths at principals whose id/name contains this substring. Repeatable.",
    )
    p.add_argument(
        "--from-type", metavar="TYPE", action="append", default=[], dest="from_types",
        help=(
            "Only start paths at principals of these kinds. Comma-separated or repeatable. "
            "Choices: user, group, dg (dynamic_group), any_user, any_group, service. "
            "Example: --from-type user,group"
        ),
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
        "--exclude-conditional", action="store_true", default=False,
        help="Skip edges that require conditions to be met.",
    )
    sg.add_argument(
        "--no-direct", action="store_true", default=False,
        help="Exclude trivial paths where the principal directly holds the target edge.",
    )
    sg.add_argument(
        "--no-default-admin-group-hop", action="store_true", default=False,
        help=(
            "Exclude single-hop paths through the default Administrators group "
            "(any group whose name contains 'administrator', case-insensitive). "
            "Longer chains (User→Group1→Group2→priv) are kept. "
            "Targets the OCI built-in Administrators group in the Default identity domain."
        ),
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
        "--to-scope", "--target-scope", metavar="OCID_OR_NAME", default=None, dest="target_scope",
        help=(
            "Filter computed targets to only nodes whose id contains this substring — "
            "limits results to paths that land at exactly this compartment/tenancy scope. "
            "Example: --to-scope ocid1.tenancy (only tenancy-level priv-esc, skip child compartments). "
            "Accepts an OCID or a unique name fragment."
        ),
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
# IDD compound path generation
# ---------------------------------------------------------------------------

def _idd_compound_paths(
    graph: "AttackGraph",
    primary_targets: set[str],
    source_filter: set[str] | None,
    excluded: set[str],
    max_depth: int = 10,
    idd_edge_kinds: frozenset[str] = DEFAULT_IDD_ADMIN_EDGE_KINDS,
) -> list[list[str]]:
    """Generate compound IDD admin attack chains.

    When an attacker holds an identity-domain admin role (Identity Domain
    Administrator / User Administrator / User Manager) and a victim user in
    that domain has their own privilege-escalation paths, the attacker can
    reset the victim's credentials and exploit those paths.

    Shape: attacker --[APP_ROLE_GRANTED]--> admin_role
                    --[IDD_*_USER/MANAGER]--> victim
                    --[victim's PE path]--> target

    This cannot be found by the base BFS because:
    - In shortest_paths, the attacker's min-dist path is the shorter
      IDD_CREATE_USER/admin-role-as-target route.
    - In enumerate_paths, the backward BFS stops at victim (a principal).
    """
    # Build admin_role -> victim map from IDD admin edges
    admin_role_victims: dict[str, set[str]] = {}
    for e in graph.edges:
        if e.kind in idd_edge_kinds:
            admin_role_victims.setdefault(e.src, set()).add(e.dst)
    if not admin_role_victims:
        return []

    # Collect all victim user IDs (users targeted by IDD admin roles)
    all_victim_ids: set[str] = set()
    for victim_ids in admin_role_victims.values():
        all_victim_ids.update(victim_ids)
    all_victim_ids -= excluded

    if not all_victim_ids:
        return []

    # Find PE paths for victim users (run shortest_paths with victims as source filter)
    victim_paths_list = shortest_paths(
        graph, primary_targets,
        max_depth=max_depth,
        source_filter=all_victim_ids,
        excluded_nodes=excluded,
    )
    if not victim_paths_list:
        return []

    # Index victim paths by victim user ID
    victim_base_paths: dict[str, list[list[str]]] = {}
    for p in victim_paths_list:
        victim_base_paths.setdefault(p[0], []).append(p)

    compound: list[list[str]] = []
    for admin_role_id, victim_ids in admin_role_victims.items():
        if admin_role_id in excluded:
            continue
        # Find direct APP_ROLE_GRANTED holders of this admin role
        attackers: list[str] = []
        for src, eidx in graph.radj.get(admin_role_id) or []:
            e = graph.edges[eidx]
            if e.kind != "APP_ROLE_GRANTED":
                continue
            if src in excluded:
                continue
            if source_filter is not None and src not in source_filter:
                continue
            if not graph.is_principal(src):
                continue
            attackers.append(src)

        if not attackers:
            continue

        for victim_id in victim_ids:
            if victim_id in excluded:
                continue
            vpaths = victim_base_paths.get(victim_id)
            if not vpaths:
                continue
            for attacker in attackers:
                for vpath in vpaths:
                    if attacker == victim_id or admin_role_id == victim_id:
                        continue
                    full = [attacker, admin_role_id] + vpath
                    if len(set(full)) < len(full):
                        continue  # cycle — node appears twice
                    compound.append(full)

    return compound


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

def _resolve_targets(
    graph: AttackGraph,
    args: argparse.Namespace,
) -> tuple[set[str], set[str], set[str]]:
    """Return (primary_targets, admin_role_targets, manage_only_targets).

    primary_targets — priv-esc edge destinations (OCI_MANAGE, IAM-control, etc.)
    admin_role_targets — IDD admin role SOURCE nodes (targeted by source, not destination).
    manage_only_targets — subset of primary_targets that are OCIAllResources nodes reached
        via OCI_MANAGE in the default mode.  Paths terminating at these nodes are filtered
        to only those whose final hop is an OCI_MANAGE edge (not OCI_READ/OCI_USE/etc.).

    Keeping admin_role_targets separate lets the two-pass BFS in run_module find paths that
    traverse *through* an admin role node toward a downstream priv-esc target
    (e.g. UserA → AdminRole → UserB → manage tenancy) rather than stopping at
    the admin role as the terminal target.
    """
    any_explicit = (
        args.to_manage or args.to_iam or args.to_rpst
        or args.to_kind or args.to_node or args.to_any
    )

    target_edge_kinds: frozenset[str] = frozenset()
    manage_only_targets: set[str] = set()

    if args.to_any:
        all_cap = DEFAULT_PRIV_EDGE_KINDS | frozenset({MANAGE_EDGE_KIND}) | RPST_CREATE_EDGE_KINDS | EXEC_EDGE_KINDS | DG_INJECTION_EDGE_KINDS | frozenset({
            e.kind for e in graph.edges
            if e.kind.endswith(_JOIN_DG_SUFFIX)
        })
        primary_targets = set(graph.iter_priv_targets(all_cap))
    elif any_explicit:
        combined: set[str] = set()
        if args.to_manage:
            combined.add(MANAGE_EDGE_KIND)
        if args.to_iam:
            combined |= IAM_CONTROL_EDGE_KINDS
        if args.to_rpst:
            combined |= RPST_CREATE_EDGE_KINDS | EXEC_EDGE_KINDS
        primary_targets = set(graph.iter_priv_targets(frozenset(combined)))
    else:
        # Default: policy-creation targets (all scopes) + OCI_MANAGE filtered to
        # all-resources nodes only (not family-specific groups@/users@/etc.)
        primary_targets = set(graph.iter_priv_targets(DEFAULT_PRIV_EDGE_KINDS))
        manage_targets = set(graph.iter_priv_targets(
            frozenset({MANAGE_EDGE_KIND}),
            node_kind_filter=DEFAULT_MANAGE_TARGET_KINDS,
        ))
        primary_targets.update(manage_targets)
        # Track these separately: BFS finds all paths TO these nodes, including via
        # OCI_READ/OCI_USE/OCI_INSPECT.  Post-filter keeps only OCI_MANAGE final hops.
        manage_only_targets = manage_targets

    # Secret-read targets (opt-in)
    if args.include_secret_read:
        primary_targets.update(graph.iter_secret_read_targets())

    # Add explicitly named nodes and kind-matched nodes to primary targets
    for nid in args.to_node:
        if nid in graph.nodes:
            primary_targets.add(nid)
        else:
            for gid in graph.nodes:
                if nid.lower() in gid.lower():
                    primary_targets.add(gid)

    for kind in args.to_kind:
        for nid, n in graph.nodes.items():
            if kind in (n.get("kinds") or []):
                primary_targets.add(nid)

    # IDD admin role SOURCE nodes — kept separate so the main BFS can traverse
    # through them as intermediate steps toward downstream priv-esc targets.
    # Default: only full Identity Domain Administrator (IDD_IDENTITY_ADMIN_USER).
    # --include-idd-all: also User Administrator, User Manager, etc.
    admin_role_targets: set[str] = set()
    if args.to_any or args.to_iam or not any_explicit:
        admin_role_targets = set(graph.iter_admin_role_targets(DEFAULT_IDD_ADMIN_EDGE_KINDS))

    return primary_targets, admin_role_targets, manage_only_targets


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

    # Resolve targets (three separate sets — see docstring)
    primary_targets, admin_role_targets, manage_only_targets = _resolve_targets(graph, args)
    all_targets = primary_targets | admin_role_targets

    # Apply --target-scope filter to narrow results to a specific compartment/tenancy
    if args.target_scope:
        scope_lc = args.target_scope.lower()
        all_targets = {t for t in all_targets if scope_lc in t.lower()}
        # Keep admin role targets only if still in the filtered set
        admin_role_targets &= all_targets
        primary_targets &= all_targets

    # List targets mode
    if args.list_targets:
        print(f"Targets ({len(all_targets)}) — primary: {len(primary_targets)}, admin-role: {len(admin_role_targets)}:")
        for tid in sorted(all_targets):
            label = graph.node_display(tid)
            kinds = graph.node_kinds(tid)
            tag = "  [admin-role]" if tid in admin_role_targets else ""
            print(f"  {label}  [{', '.join(kinds)}]{tag}")
            if label != tid:
                print(f"    id: {tid}")
        return {"ok": True}

    if not all_targets:
        print("[attack_paths] No target nodes matched the selector.", file=sys.stderr)
        return {"ok": False, "error": "no targets"}

    # Resolve excluded nodes
    excluded: set[str] = set()
    for substr in (args.exclude_node or []):
        for nid in graph.nodes:
            if substr.lower() in nid.lower():
                excluded.add(nid)

    # Resolve source filter — substring match
    source_filter: set[str] | None = None
    if args.from_filter:
        source_filter = set()
        for substr in args.from_filter:
            for nid, n in graph.nodes.items():
                label = graph.node_display(nid)
                if substr.lower() in nid.lower() or substr.lower() in label.lower():
                    if graph.is_principal(nid):
                        source_filter.add(nid)

    # Resolve --from-type kind filter and intersect with substring filter
    if args.from_types:
        wanted_kinds: set[str] = set()
        for raw in args.from_types:
            for tok in raw.split(","):
                tok = tok.strip().lower()
                if tok in FROM_TYPE_ALIASES:
                    wanted_kinds.add(FROM_TYPE_ALIASES[tok])
                else:
                    print(f"[attack_paths] WARNING: unknown --from-type value {tok!r}. Valid: {', '.join(sorted(FROM_TYPE_ALIASES))}", file=sys.stderr)
        if wanted_kinds:
            type_matched = {
                nid for nid, n in graph.nodes.items()
                if graph.is_principal(nid) and any(k in wanted_kinds for k in (n.get("kinds") or []))
            }
            source_filter = type_matched if source_filter is None else (source_filter & type_matched)

    # -----------------------------------------------------------------
    # Two-pass BFS:
    #   Pass 1 — primary priv-esc targets only (IDD admin roles are
    #            intermediate steps, so full chains are found, e.g.
    #            UserA → AdminRole → UserB → manage tenancy)
    #   Pass 2 — admin role SOURCE targets only, for principals that
    #            had no path in pass 1 (catches "has admin role, no
    #            downstream PE found" cases)
    # -----------------------------------------------------------------

    if args.all_paths:
        max_depth = args.max_depth if args.max_depth is not None else 7
        if args.debug:
            print(f"[attack_paths] enumerate_paths mode, max_depth={max_depth}", file=sys.stderr)

        paths: list = []
        if primary_targets:
            paths = enumerate_paths(
                graph, primary_targets,
                max_depth=max_depth,
                max_paths=args.max_paths,
                max_expansions=args.max_expansions,
                source_filter=source_filter,
                excluded_nodes=excluded,
                no_direct=args.no_direct,
                no_default_admin_group_hop=args.no_default_admin_group_hop,
            )

        # Pass 2: admin role targets for principals not already in pass 1
        if admin_role_targets and len(paths) < args.max_paths:
            found_sources = {p[0] for p in paths}
            if source_filter is not None:
                pass2_filter = source_filter - found_sources
            else:
                pass2_filter = {
                    nid for nid in graph.nodes
                    if graph.is_principal(nid) and nid not in found_sources
                }
            if pass2_filter:
                remaining_budget = args.max_paths - len(paths)
                p2 = enumerate_paths(
                    graph, admin_role_targets,
                    max_depth=max_depth,
                    max_paths=remaining_budget,
                    max_expansions=args.max_expansions,
                    source_filter=pass2_filter,
                    excluded_nodes=excluded,
                    no_direct=args.no_direct,
                    no_default_admin_group_hop=args.no_default_admin_group_hop,
                )
                paths.extend(p2)
        truncated = len(paths) >= args.max_paths
    else:
        max_depth = args.max_depth if args.max_depth is not None else 10
        if args.debug:
            print(f"[attack_paths] shortest_paths mode, max_depth={max_depth}", file=sys.stderr)

        paths = []
        if primary_targets:
            paths = shortest_paths(
                graph, primary_targets,
                max_depth=max_depth,
                source_filter=source_filter,
                excluded_nodes=excluded,
                no_direct=args.no_direct,
                no_default_admin_group_hop=args.no_default_admin_group_hop,
            )

        # Pass 2: admin role targets for principals without a primary-target path
        if admin_role_targets:
            found_sources = {p[0] for p in paths}
            if source_filter is not None:
                pass2_filter = source_filter - found_sources
            else:
                pass2_filter = {
                    nid for nid in graph.nodes
                    if graph.is_principal(nid) and nid not in found_sources
                }
            if pass2_filter:
                p2 = shortest_paths(
                    graph, admin_role_targets,
                    max_depth=max_depth,
                    source_filter=pass2_filter,
                    excluded_nodes=excluded,
                    no_direct=args.no_direct,
                    no_default_admin_group_hop=args.no_default_admin_group_hop,
                )
                paths.extend(p2)
        truncated = False

    # -----------------------------------------------------------------
    # Pass 3: IDD compound paths
    #   attacker --[APP_ROLE_GRANTED]--> admin_role
    #            --[IDD_*_USER/MANAGER]--> victim --[victim's PE path]--> target
    # These cannot be found by the BFS (the victim is an intermediate
    # principal, so the BFS terminates at the victim, not the attacker).
    # -----------------------------------------------------------------
    compound = _idd_compound_paths(
        graph,
        primary_targets=primary_targets,
        source_filter=source_filter,
        excluded=excluded,
        max_depth=max_depth,
    )
    if compound:
        # Add only compound paths whose (attacker, target) pair isn't already covered
        existing_pairs = {(p[0], p[-1]) for p in paths}
        for cp in compound:
            pair = (cp[0], cp[-1])
            if pair not in existing_pairs:
                paths.append(cp)
                existing_pairs.add(pair)
        if args.debug:
            print(f"[attack_paths] IDD compound paths: {len(compound)} generated", file=sys.stderr)

    # Drop any path where a node appears twice (cycles / trivially redundant chains)
    paths = [p for p in paths if len(set(p)) == len(p)]

    # For OCIAllResources targets added via OCI_MANAGE, drop paths whose final
    # edge is not OCI_MANAGE (e.g. OCI_READ/OCI_USE/OCI_INSPECT to same node).
    # The BFS targets those nodes correctly, but it traverses ALL edges into them.
    if manage_only_targets:
        def _final_edge_is_manage(path: list[str]) -> bool:
            if path[-1] not in manage_only_targets:
                return True
            if len(path) < 2:
                return True
            for dst, eidx in graph.adj.get(path[-2], []):
                if dst == path[-1] and graph.edges[eidx].kind == MANAGE_EDGE_KIND:
                    return True
            return False
        paths = [p for p in paths if _final_edge_is_manage(p)]

    if args.debug:
        print(f"[attack_paths] Found {len(paths)} paths (incl. compound, post-dedup)", file=sys.stderr)

    # Group paths by target
    paths_by_target: dict[str, list[list[str]]] = {}
    for path in paths:
        tid = path[-1]
        paths_by_target.setdefault(tid, []).append(path)

    # Output
    if args.json:
        result = paths_to_json(graph, paths_by_target, target_ids=all_targets, truncated=truncated)
        output = json.dumps(result, indent=2)
    else:
        output = render_report(
            graph,
            paths_by_target,
            expanded=args.expanded,
            summary_only=args.summary,
            target_ids=all_targets,
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
                "targets": len(all_targets),
            }
        ],
    }
