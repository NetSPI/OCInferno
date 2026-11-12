"""
Path-finding algorithms over an AttackGraph.

Two modes:
  shortest_paths  — single multi-source reverse BFS; O(V+E), yields one
                    shortest path per reachable principal.
  enumerate_paths — best-first search guided by the BFS heuristic; yields
                    up to max_paths paths in nondecreasing-length order.
"""
from __future__ import annotations

import heapq
from collections import deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import AttackGraph

# ---------------------------------------------------------------------------

def reverse_distances(
    graph: "AttackGraph",
    target_ids: set[str],
    max_depth: int,
    *,
    excluded_nodes: set[str] | None = None,
) -> dict[str, int]:
    """
    BFS from target_ids over the REVERSE graph.
    Returns dist[n] = minimum number of edges from n to any target.
    """
    exc = excluded_nodes or set()
    dist: dict[str, int] = {}
    q: deque[str] = deque()

    for tid in target_ids:
        if tid not in exc:
            dist[tid] = 0
            q.append(tid)

    while q:
        cur = q.popleft()
        d = dist[cur]
        if d >= max_depth:
            continue
        for src, _eidx in graph.radj.get(cur) or []:
            if src in dist or src in exc:
                continue
            dist[src] = d + 1
            q.append(src)

    return dist


def shortest_paths(
    graph: "AttackGraph",
    target_ids: set[str],
    *,
    max_depth: int = 10,
    source_filter: set[str] | None = None,
    excluded_nodes: set[str] | None = None,
    exclude_service_agents: bool = False,
    no_direct: bool = False,
) -> list[list[str]]:
    """
    Multi-source reverse BFS from target_ids.  Returns one shortest path per
    reachable principal as a list of node IDs (source first, target last).
    """
    exc = excluded_nodes or set()
    dist: dict[str, int] = {}
    succ: dict[str, tuple[str, int]] = {}  # node -> (next_hop, edge_idx)
    q: deque[str] = deque()

    for tid in target_ids:
        if tid not in exc:
            dist[tid] = 0
            q.append(tid)

    while q:
        cur = q.popleft()
        d = dist[cur]
        if d >= max_depth:
            continue
        for src, eidx in graph.radj.get(cur) or []:
            if src in dist or src in exc:
                continue
            dist[src] = d + 1
            succ[src] = (cur, eidx)
            q.append(src)

    paths: list[list[str]] = []
    for nid, n in graph.nodes.items():
        if not graph.is_principal(nid):
            continue
        if nid not in dist:
            continue
        if source_filter and nid not in source_filter:
            continue
        if exc and nid in exc:
            continue
        if exclude_service_agents:
            props = n.get("properties") or {}
            if props.get("is_service_agent"):
                continue

        # Reconstruct path
        path: list[str] = [nid]
        seen: set[str] = {nid}
        cur = nid
        ok = True
        while cur not in target_ids:
            nxt, _eidx = succ.get(cur, (None, None))
            if nxt is None or nxt in seen:
                ok = False
                break
            seen.add(nxt)
            path.append(nxt)
            cur = nxt
        if not ok:
            continue

        # "Direct" = principal already holds the binding (0 hops to target)
        if no_direct and len(path) <= 2 and path[-1] in target_ids:
            continue

        paths.append(path)

    return paths


def enumerate_paths(
    graph: "AttackGraph",
    target_ids: set[str],
    *,
    max_depth: int = 8,
    max_paths: int = 500,
    max_expansions: int = 400_000,
    source_filter: set[str] | None = None,
    excluded_nodes: set[str] | None = None,
    exclude_service_agents: bool = False,
    no_direct: bool = False,
) -> list[list[str]]:
    """
    Best-first enumeration of all simple paths from any principal to any target.
    Uses reverse_distances as the A* heuristic (exact on the raw graph).
    """
    exc = excluded_nodes or set()
    h = reverse_distances(graph, target_ids, max_depth, excluded_nodes=exc)

    # heap entries: (priority, path_so_far)
    heap: list[tuple[int, list[str]]] = []

    for tid in target_ids:
        if tid in exc:
            continue
        heapq.heappush(heap, (0, [tid]))

    # Walk backwards from targets
    paths: list[list[str]] = []
    expansions = 0

    while heap and len(paths) < max_paths and expansions < max_expansions:
        prio, path = heapq.heappop(heap)
        expansions += 1
        cur = path[-1]  # we build path in reverse

        # If cur is a principal, we have a complete path
        if graph.is_principal(cur):
            if source_filter and cur not in source_filter:
                continue
            if exclude_service_agents:
                props = (graph.nodes.get(cur) or {}).get("properties") or {}
                if props.get("is_service_agent"):
                    continue
            if no_direct and len(path) <= 2:
                continue
            paths.append(list(reversed(path)))
            continue

        if len(path) >= max_depth + 1:
            continue

        visited = set(path)
        for src, eidx in graph.radj.get(cur) or []:
            if src in visited or src in exc:
                continue
            if src not in h:
                continue
            new_path = path + [src]
            priority = len(new_path) + h[src]
            heapq.heappush(heap, (priority, new_path))

    return paths
