# graph_export.py
"""Large-graph export helpers for OpenGraph JSON: a streaming single-file writer with
progress (bounded memory), and a size-bounded splitter that emits multiple self-contained
OpenGraph part files + a manifest (BloodHound has upload-size limits, so massive graphs
must be split). Section-agnostic (pure size-based chunking), so it works for any
OpenGraph payload.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _json_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _edge_endpoint_ids(edge: dict) -> list:
    """The node ids an edge references (BloodHound OpenGraph edge shape: start/end -> value)."""
    out = []
    for key in ("start", "end"):
        end = edge.get(key)
        if isinstance(end, dict):
            val = end.get("value") or end.get("match_by") or ""
        else:
            val = end or ""
        val = str(val or "").strip()
        if val:
            out.append(val)
    return out


def _progress(label: str, done: int, total: int, *, force: bool = False) -> None:
    if total <= 0:
        return
    if force or done == total or done % max(1, total // 50) == 0:
        pct = int(done * 100 / total)
        sys.stdout.write(f"\r[*] {label}: {done}/{total} ({pct}%)")
        sys.stdout.flush()
        if force or done == total:
            sys.stdout.write("\n")


def write_graph_json_with_progress(out_path: Path, payload: dict) -> None:
    """Stream a single OpenGraph JSON to disk node-by-node / edge-by-edge with a progress
    line, so very large graphs don't hold a giant serialized string in memory at once. The
    file shape matches the in-memory payload (metadata / graph{nodes,edges} / summary)."""
    graph = dict(payload.get("graph") or {})
    nodes = [n for n in (graph.get("nodes") or []) if isinstance(n, dict)]
    edges = [e for e in (graph.get("edges") or []) if isinstance(e, dict)]
    metadata = payload.get("metadata")
    summary = payload.get("summary") or {"nodes": len(nodes), "edges": len(edges)}
    total = len(nodes) + len(edges)
    print(f"[*] streaming graph: nodes={len(nodes)}, edges={len(edges)}, total={total}")

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write("{\n")
        if metadata is not None:
            fh.write('  "metadata": ')
            json.dump(metadata, fh, ensure_ascii=False, separators=(",", ":"))
            fh.write(",\n")
        fh.write('  "graph": {\n    "nodes": [')
        for i, node in enumerate(nodes, start=1):
            if i > 1:
                fh.write(",")
            json.dump(node, fh, ensure_ascii=False, separators=(",", ":"))
            _progress("write nodes", i, len(nodes))
        _progress("write nodes", len(nodes), len(nodes), force=True)
        fh.write("],\n    \"edges\": [")
        for i, edge in enumerate(edges, start=1):
            if i > 1:
                fh.write(",")
            json.dump(edge, fh, ensure_ascii=False, separators=(",", ":"))
            _progress("write edges", i, len(edges))
        _progress("write edges", len(edges), len(edges), force=True)
        fh.write("]\n  },\n  \"summary\": ")
        json.dump(summary, fh, ensure_ascii=False, separators=(",", ":"))
        fh.write("\n}\n")


def write_split_outputs(base_out_path: Path, payload: dict, *, max_size_mb: float = 90.0, debug: bool = False) -> dict:
    """Split ``payload`` into size-bounded, SELF-CONTAINED OpenGraph part files + a manifest.

    Each part packs edges (and the nodes they reference) until its serialized size nears
    ``max_size_mb``, then starts a new part; a node referenced across parts is re-emitted in
    each (so every part imports independently). Orphan nodes (no edges) are packed into
    parts too. Returns ``{"parts": [paths], "manifest": path, "part_count": n}``.
    """
    graph = dict(payload.get("graph") or {})
    nodes = [n for n in (graph.get("nodes") or []) if isinstance(n, dict)]
    edges = [e for e in (graph.get("edges") or []) if isinstance(e, dict)]
    node_by_id = {str(n.get("id") or "").strip(): n for n in nodes if str(n.get("id") or "").strip()}
    node_size = {nid: _json_size(n) for nid, n in node_by_id.items()}
    max_bytes = max(1, int(float(max_size_mb) * 1024 * 1024))
    metadata = payload.get("metadata")

    parts: list = []            # list of {"edges": [...], "node_ids": set(), "size": int}
    cur = {"edges": [], "node_ids": set(), "size": 256}

    def _flush():
        nonlocal cur
        if cur["edges"] or cur["node_ids"]:
            parts.append(cur)
            cur = {"edges": [], "node_ids": set(), "size": 256}

    for edge in edges:
        eids = [i for i in _edge_endpoint_ids(edge) if i in node_by_id]
        add = _json_size(edge) + sum(node_size.get(i, 0) for i in eids if i not in cur["node_ids"])
        if cur["size"] + add > max_bytes and (cur["edges"] or cur["node_ids"]):
            _flush()
        cur["edges"].append(edge)
        cur["node_ids"].update(eids)
        cur["size"] += add
    _flush()

    # Orphan nodes (never referenced by an edge) -> pack into parts up to size.
    referenced = set().union(*[p["node_ids"] for p in parts]) if parts else set()
    orphans = [nid for nid in node_by_id if nid not in referenced]
    if orphans and not parts:
        parts.append({"edges": [], "node_ids": set(), "size": 256})
    oi = 0
    for nid in orphans:
        p = parts[oi % len(parts)]
        if p["size"] + node_size.get(nid, 0) > max_bytes and len(p["node_ids"]) > 0:
            parts.append({"edges": [], "node_ids": set(), "size": 256})
            p = parts[-1]
        p["node_ids"].add(nid)
        p["size"] += node_size.get(nid, 0)
        oi += 1

    stem = base_out_path.with_suffix("")
    written: list = []
    for idx, p in enumerate(parts, start=1):
        part_nodes = [node_by_id[i] for i in sorted(p["node_ids"]) if i in node_by_id]
        part_payload: dict = {"graph": {"nodes": part_nodes, "edges": p["edges"]}}
        if metadata is not None:
            part_payload["metadata"] = metadata
        part_path = Path(f"{stem}_part{idx:03d}.json")
        part_path.write_text(json.dumps(part_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        written.append(str(part_path))
        _progress("write parts", idx, len(parts), force=(idx == len(parts)))

    manifest_path = Path(f"{stem}_manifest.json")
    manifest = {
        "part_count": len(written),
        "max_size_mb": float(max_size_mb),
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "parts": [
            {"file": Path(f).name, "nodes": len(pp["node_ids"]), "edges": len(pp["edges"])}
            for f, pp in zip(written, parts)
        ],
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"parts": written, "manifest": str(manifest_path), "part_count": len(written)}
