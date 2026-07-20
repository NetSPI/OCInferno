"""Compartment-hierarchy graph traversal shared across OCInferno.

The tenancy/compartment tree is walked in several places -- enum_all's
``--cids`` subtree scoping, OpenGraph's compartment-scoped condition/DG
matching, and the CLI's tree-printing commands. They all reduce to the same
two primitives operating over a ``{parent_id: [child_id, ...]}`` adjacency
map: expand a root into its descendants, and render a forest as an ASCII
tree. This module is the single home for both walks (and the ancestor-chain
walk used to include ancestors for display) so the algorithm lives in
exactly one place.
"""

from __future__ import annotations

from collections import deque
from typing import Callable, Dict, List, Optional


def descendants(children_by_parent: Dict[str, List[str]], root: str) -> List[str]:
    """BFS all descendant ids under ``root`` (excludes root), cycle-safe.

    Used to expand a compartment into its subtree for scoping (enum_all
    ``--cids``, OpenGraph compartment-scoped matching). The ``seen`` set
    guards against malformed cyclic hierarchy data. Returns descendants in
    breadth-first order; an empty/blank root yields ``[]``.
    """
    root_id = str(root or "").strip()
    if not root_id:
        return []
    out: List[str] = []
    seen = {root_id}
    queue: deque[str] = deque(children_by_parent.get(root_id, []))
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        out.append(current)
        for child in children_by_parent.get(current, []):
            if child not in seen:
                queue.append(child)
    return out


def ancestor_chain(parent_by_id: Dict[str, str], cid: str, *, max_hops: int = 64) -> List[str]:
    """Walk ``parent_by_id`` upward from ``cid``, cycle- and depth-safe.

    Returns the chain of ancestor ids starting with ``cid``'s immediate
    parent and ending at the root (excludes ``cid`` itself). Stops at the
    first falsy parent, a parent already visited (cycle guard), or after
    ``max_hops`` steps -- whichever comes first.
    """
    chain: List[str] = []
    cur = str(cid or "").strip()
    if not cur:
        return chain
    seen = {cur}
    for _ in range(max_hops):
        parent = str(parent_by_id.get(cur) or "").strip()
        if not parent or parent in seen:
            break
        chain.append(parent)
        seen.add(parent)
        cur = parent
    return chain


def render_tree_lines(
    roots: List[str],
    children_by_parent: Dict[str, List[str]],
    label_of: Callable[[str], str],
) -> List[str]:
    """Render an ASCII tree from a ``{parent_id: [child_id, ...]}`` adjacency map.

    Roots are emitted flush-left with no branch glyph; every other node gets
    a ``├─ ``/``└─ `` branch and its subtree is indented by ``│  ``/``   ``.
    ``label_of`` turns a node id into its display string (a colorized label,
    a name+ocid pair, ...), so each caller keeps its own labeling/highlighting
    while sharing this one tree walk. A node revisited within its own root's
    walk (malformed/cyclic data) is emitted once as ``(cycle) <label>`` and
    not expanded further. Children are rendered in the order the adjacency
    map already holds them (callers sort upstream). Returns the lines in
    pre-order for the caller to print or collect.
    """
    lines: List[str] = []

    def _walk(node_id: str, prefix: str, is_last: bool, seen: set) -> None:
        branch = "└─ " if is_last else "├─ "
        if node_id in seen:
            lines.append(f"{prefix}{branch}(cycle) {label_of(node_id)}")
            return
        seen.add(node_id)
        lines.append(f"{prefix}{branch}{label_of(node_id)}")
        kids = children_by_parent.get(node_id, [])
        child_prefix = prefix + ("   " if is_last else "│  ")
        for index, kid in enumerate(kids):
            _walk(kid, child_prefix, index == len(kids) - 1, seen)

    for root in roots:
        lines.append(label_of(root))
        kids = children_by_parent.get(root, [])
        seen = {root}
        for index, kid in enumerate(kids):
            _walk(kid, "", index == len(kids) - 1, seen)

    return lines


def children_map_from_parent_map(parent_by_id: Dict[str, Optional[str]]) -> Dict[str, List[str]]:
    """Invert a ``{id: parent_id}`` map into ``{parent_id: [child_id, ...]}``.

    Every id in ``parent_by_id`` also gets an entry (possibly empty) so
    leaf lookups via ``.get(id, [])`` never need a default at the call site.
    """
    children: Dict[str, List[str]] = {}
    for cid, parent in (parent_by_id or {}).items():
        children.setdefault(cid, [])
        if parent and parent != cid:
            children.setdefault(parent, []).append(cid)
    return children
