"""Characterization tests for core/utils/hierarchy.py.

The compartment-tree walk logic is consolidated onto three shared primitives:
``descendants``, ``ancestor_chain``, and ``render_tree_lines``, used by
enum_all.py, enum_all_summary.py, workspace_instructions.py, and OpenGraph's
context.py / iam_conditionals.py. These tests pin those primitives' behavior
against verbatim copies of the walks they replaced so the consolidation stays
output-preserving.
"""
from __future__ import annotations

import random

import pytest

from ocinferno.core.utils.hierarchy import (
    ancestor_chain,
    children_map_from_parent_map,
    descendants,
    render_tree_lines,
)


# ---------------------------------------------------------------------------
# render_tree_lines
# ---------------------------------------------------------------------------

def _old_enum_all_summary_walk(roots, children, label_of):
    """Verbatim copy of the pre-refactor enum_all_summary.print_compartment_tree dfs."""
    lines = []

    def dfs(cid, prefix="", is_last=True, seen=None):
        if seen is None:
            seen = set()
        if cid in seen:
            lines.append(prefix + ("└─ " if is_last else "├─ ") + f"(cycle) {label_of(cid)}")
            return
        seen.add(cid)
        lines.append(prefix + ("└─ " if is_last else "├─ ") + label_of(cid))
        kids = children.get(cid, [])
        for i, kid in enumerate(kids):
            last = i == (len(kids) - 1)
            new_prefix = prefix + ("   " if is_last else "│  ")
            dfs(kid, new_prefix, last, seen)

    for ri, root in enumerate(roots):
        lines.append(label_of(root))
        kids = children.get(root, [])
        for i, kid in enumerate(kids):
            last = i == (len(kids) - 1)
            dfs(kid, "", last)
    return lines


def _random_tree(rng, n_nodes):
    """Build a random forest as a {parent_id: [child_id, ...]} adjacency map (acyclic)."""
    names = [f"n{i}" for i in range(n_nodes)]
    children: dict = {}
    roots = []
    for i, name in enumerate(names):
        parent = None if i == 0 or rng.random() < 0.3 else names[rng.randrange(0, i)]
        if parent is None:
            roots.append(name)
        else:
            children.setdefault(parent, []).append(name)
    label_of = lambda cid: f"<{cid}:{len(children.get(cid, []))}>"  # noqa: E731
    return roots, children, label_of


def test_render_tree_lines_matches_old_walk_randomized():
    rng = random.Random(1337)
    for _ in range(400):
        roots, children, label_of = _random_tree(rng, rng.randint(1, 40))
        new = render_tree_lines(roots, children, label_of)
        assert new == _old_enum_all_summary_walk(roots, children, label_of)


def test_render_tree_lines_edge_cases():
    label_of = lambda cid: cid  # noqa: E731
    assert render_tree_lines([], {}, label_of) == []
    assert render_tree_lines(["r"], {}, label_of) == ["r"]
    lines = render_tree_lines(["r"], {"r": ["a", "b"]}, label_of)
    assert lines == ["r", "├─ a", "└─ b"]
    lines = render_tree_lines(["r"], {"r": ["a"], "a": ["b"]}, label_of)
    assert lines == ["r", "└─ a", "   └─ b"]
    lines = render_tree_lines(["r"], {"r": ["a", "c"], "a": ["b"]}, label_of)
    assert lines == ["r", "├─ a", "│  └─ b", "└─ c"]
    assert render_tree_lines(["r1", "r2"], {}, label_of) == ["r1", "r2"]


def test_render_tree_lines_cycle_guard():
    label_of = lambda cid: cid  # noqa: E731
    # malformed data: "b"'s child list wrongly points back at "r" (its own ancestor)
    lines = render_tree_lines(["r"], {"r": ["a"], "a": ["b"], "b": ["r"]}, label_of)
    assert lines == ["r", "└─ a", "   └─ b", "      └─ (cycle) r"]
    # root itself reachable as its own descendant is also caught
    lines = render_tree_lines(["r"], {"r": ["r"]}, label_of)
    assert lines == ["r", "└─ (cycle) r"]


# ---------------------------------------------------------------------------
# descendants
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "children, root, expected",
    [
        ({"root": ["a", "b"], "a": ["c"], "b": ["c"]}, "root", ["a", "b", "c"]),
        ({"root": ["a", "b"], "a": ["a1", "a2"], "b": ["b1"]}, "root", ["a", "b", "a1", "a2", "b1"]),
        ({"root": ["a"], "a": ["root"]}, "root", ["a"]),
        ({"root": ["a"]}, "", []),
        ({}, "missing", []),
    ],
    ids=["excludes-root-and-dedupes", "breadth-first-order", "cycle-safe", "blank-root", "missing-root"],
)
def test_descendants(children, root, expected):
    assert descendants(children, root) == expected


def test_descendants_multi_root_union_matches_old_enum_all_closure():
    """Old enum_all._descendant_compartment_closure BFS'd a shared queue seeded
    with every root; the virtual-super-root trick reproduces that ordering."""
    children = {"r1": ["a", "b"], "r2": ["c"], "a": ["d"]}
    roots = ["r1", "r2"]
    children_with_virtual = dict(children)
    children_with_virtual["__virtual__"] = roots
    assert descendants(children_with_virtual, "__virtual__") == ["r1", "r2", "a", "b", "c", "d"]


# ---------------------------------------------------------------------------
# ancestor_chain
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "parent_by_id, cid, expected",
    [
        ({"c": "b", "b": "a", "a": ""}, "c", ["b", "a"]),
        ({"c": "b"}, "c", ["b"]),
        ({"c": "b"}, "unknown", []),
        ({"a": "b", "b": "a"}, "a", ["b"]),
        ({"a": "b"}, "", []),
    ],
    ids=["walks-to-root", "excludes-self", "missing-parent", "cycle-safe", "blank-cid"],
)
def test_ancestor_chain(parent_by_id, cid, expected):
    assert ancestor_chain(parent_by_id, cid) == expected


def test_ancestor_chain_max_hops():
    parent_by_id = {f"n{i}": f"n{i + 1}" for i in range(200)}
    assert len(ancestor_chain(parent_by_id, "n0", max_hops=5)) == 5


# ---------------------------------------------------------------------------
# children_map_from_parent_map
# ---------------------------------------------------------------------------

def test_children_map_from_parent_map_inverts_and_seeds_leaves():
    parent_by_id = {"root": "", "a": "root", "b": "root", "c": "a"}
    children = children_map_from_parent_map(parent_by_id)
    assert children["root"] == ["a", "b"]
    assert children["a"] == ["c"]
    assert children["b"] == []
    assert children["c"] == []


def test_children_map_from_parent_map_ignores_self_parent():
    parent_by_id = {"root": "root"}
    children = children_map_from_parent_map(parent_by_id)
    assert children["root"] == []
