"""Large-graph export: streaming single-file writer (bounded memory + progress) and the
size-bounded splitter that emits self-contained OpenGraph parts + a manifest."""
from __future__ import annotations

import json
import pathlib
import tempfile

from ocinferno.modules.opengraph.utilities.helpers.graph_export import (
    write_graph_json_with_progress,
    write_split_outputs,
)


def _payload(n_nodes=8, n_edges=6):
    nodes = [{"id": f"n{i}", "kinds": ["OCIUser"], "properties": {"pad": "x" * 40}} for i in range(n_nodes)]
    edges = [{"kind": "E", "start": {"value": f"n{i}"}, "end": {"value": f"n{i+1}"}} for i in range(n_edges)]
    return {"metadata": {"m": 1}, "graph": {"nodes": nodes, "edges": edges},
            "summary": {"nodes": n_nodes, "edges": n_edges}}


def test_streaming_write_matches_payload():
    tmp = pathlib.Path(tempfile.mkdtemp())
    out = tmp / "g.json"
    write_graph_json_with_progress(out, _payload())
    d = json.loads(out.read_text())
    assert len(d["graph"]["nodes"]) == 8 and len(d["graph"]["edges"]) == 6
    assert d["metadata"] == {"m": 1} and "summary" in d


def test_split_produces_self_contained_parts_and_manifest():
    tmp = pathlib.Path(tempfile.mkdtemp())
    # ~500 bytes cap forces multiple parts
    res = write_split_outputs(tmp / "g.json", _payload(), max_size_mb=0.0005)
    assert res["part_count"] >= 2
    seen_edges = 0
    for pf in res["parts"]:
        pd = json.loads(pathlib.Path(pf).read_text())
        ids = {n["id"] for n in pd["graph"]["nodes"]}
        for e in pd["graph"]["edges"]:
            # every edge endpoint is present IN THE SAME PART (self-contained)
            assert e["start"]["value"] in ids and e["end"]["value"] in ids
            seen_edges += 1
    assert seen_edges == 6  # all edges distributed exactly once
    man = json.loads(pathlib.Path(res["manifest"]).read_text())
    assert man["part_count"] == res["part_count"] and man["total_edges"] == 6


def test_split_single_part_when_small():
    tmp = pathlib.Path(tempfile.mkdtemp())
    res = write_split_outputs(tmp / "g.json", _payload(), max_size_mb=90.0)
    assert res["part_count"] == 1
