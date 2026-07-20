#!/usr/bin/env python3
"""Export post-pass: annotate edges with a runnable ``module run`` example.

Instead of threading node lookups through every builder, this single pass runs at
export time (after the builders + collapse passes) and, for every edge KIND listed in
``data/edge_module_commands.json``, fills that entry's template from the edge's own
endpoint NODE data and writes the resolved string into the edge's ``example_command``
property. It also folds any ``includes_edges`` into the edge's ``includes_other_edges``
(the "collapsed edges" list) so a capability like IDD_CREATE_USER_API_KEY can be listed
on the broad admin edge that subsumes it.

Everything it needs is already in the graph (e.g. an IDD user node's id IS the user OCID
and its properties carry ``domain_url``), so no builder has to know about module commands.
"""
from __future__ import annotations

import json
import re
from importlib import resources
from typing import Any, Dict, List, Tuple

from ocinferno.core.utils.selection_helpers import _s
from ocinferno.modules.opengraph.utilities.helpers import dlog as _dlog
from ocinferno.modules.opengraph.utilities.helpers import json_load as _json_load

_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


def _load_command_specs() -> Dict[str, Dict[str, Any]]:
    try:
        text = resources.files("ocinferno.modules.opengraph.utilities.helpers.data").joinpath(
            "edge_module_commands.json"
        ).read_text(encoding="utf-8")
        data = json.loads(text)
        cmds = data.get("commands") if isinstance(data, dict) else None
        return cmds if isinstance(cmds, dict) else {}
    except Exception:
        return {}


def _node_props_by_id(node_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for r in (node_rows or []):
        if not isinstance(r, dict):
            continue
        nid = _s(r.get("node_id"))
        if nid:
            out[nid] = _json_load(r.get("node_properties"), dict) or {}
    return out


def _placeholder_context(edge: Dict[str, Any], node_props: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    src_id = _s(edge.get("source_id"))
    dst_id = _s(edge.get("destination_id"))
    dprops = node_props.get(dst_id, {}) if isinstance(node_props.get(dst_id), dict) else {}

    # Destination compartment: explicit property, else the token after "@" in a
    # resource-group node id (e.g. "users@ocid1.compartment.oc1..aaaa").
    dest_comp = _s(dprops.get("compartment_id") or dprops.get("compartment_ocid"))
    if not dest_comp and "@" in dst_id:
        dest_comp = dst_id.rsplit("@", 1)[-1]

    return {
        "source_id": src_id,
        "destination_id": dst_id,
        "dest_ocid": _s(dprops.get("ocid")) or dst_id,
        "dest_domain_url": _s(dprops.get("domain_url")),
        "dest_compartment": dest_comp or "<COMPARTMENT>",
        "dest_name": _s(dprops.get("name") or dprops.get("display_name")),
    }


def _fill(template: str, ctx: Dict[str, str]) -> str:
    def _sub(m: "re.Match[str]") -> str:
        key = m.group(1)
        val = ctx.get(key, "")
        return val if val else f"<{key.upper()}>"
    return _PLACEHOLDER.sub(_sub, template)


def annotate_edge_module_commands(
    edge_rows: List[Dict[str, Any]], node_rows: List[Dict[str, Any]], *, debug: bool = False
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Add ``example_command`` (+ collapsed ``includes_other_edges``) to configured edges.

    Returns ``(edge_rows, stats)``. Edge rows whose kind has no config entry are untouched.
    """
    specs = _load_command_specs()
    stats = {"annotated": 0, "kinds": len(specs)}
    if not specs or not edge_rows:
        return (edge_rows or []), stats

    node_props = _node_props_by_id(node_rows)

    for edge in edge_rows:
        if not isinstance(edge, dict):
            continue
        spec = specs.get(_s(edge.get("edge_type")))
        if not spec:
            continue

        # Edge properties are nested {edge_category, edge_inner_properties:{...}}; the
        # exporter flattens ONLY edge_inner_properties, so all new keys must live there.
        payload = _json_load(edge.get("edge_properties"), dict) or {}
        inner = payload.get("edge_inner_properties")
        if not isinstance(inner, dict):
            inner = {}
        ctx = _placeholder_context(edge, node_props)

        template = _s(spec.get("template"))
        if template:
            inner["example_command"] = _fill(template, ctx)
        if spec.get("authz"):
            inner["authz_source"] = _s(spec.get("authz"))

        includes = spec.get("includes_edges")
        if isinstance(includes, list) and includes:
            merged = set(inner.get("includes_other_edges") or [])
            merged.update(_s(x) for x in includes if _s(x))
            inner["includes_other_edges"] = sorted(merged)

        payload["edge_inner_properties"] = inner
        edge["edge_properties"] = json.dumps(payload, sort_keys=False)
        stats["annotated"] += 1

    _dlog(debug, "edge-command annotator: done", **stats)
    return edge_rows, stats
