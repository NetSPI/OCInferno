#!/usr/bin/env python3
"""get_network_resources: sweep every saved service table and surface all network
identifiers (IPs, CIDRs, URLs, FQDNs, and subnet/VCN/NSG references).

A *process* module -- it reads the workspace's SQLite tables that prior enumeration
populated (no OCI API calls) and produces a consolidated network inventory: exactly
what an operator wants after ``enum_all`` to answer "what are all the IPs and URLs in
this tenancy, and which resource does each belong to?". Results print grouped by kind
and persist to the ``network_inventory`` table for querying/attack-path use.
"""
from __future__ import annotations

import argparse
import json
from importlib import resources
from typing import List, Optional

from ocinferno.core.console import UtilityTools
from ocinferno.modules.everything.utilities import network_inventory as ni

# Tables that never hold enumerable resource network data (creds, graph, run-state, self).
_EXCLUDED_TABLES = frozenset({
    "workspace_index", "sessions", "user_permissions",
    "opengraph_nodes", "opengraph_edges", "enum_all_task_ledger",
    "network_inventory",
})

_OUTPUT_TABLE = "network_inventory"


def _all_service_tables() -> List[str]:
    try:
        text = resources.files("ocinferno.mappings").joinpath("database_info.json").read_text(encoding="utf-8")
        schema = json.loads(text)
        tables = schema.get("tables")
        if tables is None:  # tolerate legacy nested shape
            tables = [t for db in schema.get("databases", []) for t in db.get("tables", [])]
        names = [t["table_name"] for t in tables]
    except Exception:
        return []
    return [n for n in names if n not in _EXCLUDED_TABLES]


def _parse_args(user_args) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Aggregate all network identifiers (IPs/CIDRs/URLs/FQDNs/subnet refs) from saved resources",
        allow_abbrev=False,
    )
    p.add_argument(
        "--kinds", default=None,
        help=f"Comma-separated kinds to include (default: all). Options: {','.join(ni.ALL_KINDS)}",
    )
    p.add_argument("--table", default=None, help="Only sweep this one source table (e.g. compute_instances).")
    p.add_argument("--value-contains", default=None, help="Only report values containing this substring.")
    p.add_argument("--json-out", default=None, help="Write the full inventory JSON to a file path.")
    p.add_argument("--quiet", action="store_true", help="Do not print the tables (still persists + reports counts).")
    return p.parse_args(user_args)


def run_module(user_args, session):
    args = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False) or getattr(session, "individual_run_debug", False))

    kinds: Optional[set] = None
    if args.kinds:
        kinds = {k.strip().lower() for k in str(args.kinds).split(",") if k.strip()}

    tables = [args.table] if args.table else _all_service_tables()

    records = []
    for table_name in tables:
        try:
            rows = session.get_resource_fields(table_name) or []
        except Exception as e:
            UtilityTools.dlog(debug, "get_network_resources: table read failed", table=table_name, err=str(e))
            continue
        if not rows:
            continue
        records.extend(ni.extract_from_rows(table_name, rows))

    records = ni.dedupe(records)
    if kinds:
        records = [r for r in records if r["kind"] in kinds]
    if args.value_contains:
        needle = str(args.value_contains).lower()
        records = [r for r in records if needle in r["value"].lower()]

    summary = ni.summarize(records)

    # Persist for querying / attack-path reuse (always, no --save opt-in).
    saved = 0
    for r in records:
        try:
            session.data_master.save_dict_row(
                db="service",
                table_name=_OUTPUT_TABLE,
                row={"workspace_id": session.workspace_id, **r},
                on_conflict="replace",
            )
            saved += 1
        except Exception:
            pass

    if not args.quiet:
        _print_report(records, summary)

    out_path = session.resolve_output_path(
        requested_path=args.json_out,
        service_name="everything",
        filename="network_resources.json",
        compartment_id=getattr(session, "compartment_id", None),
        subdirs=["reports"],
        target="export",
    )
    try:
        out_path.write_text(json.dumps({"summary": summary, "records": records}, indent=2), encoding="utf-8")
        print(f"[*] Wrote network inventory JSON: {out_path}")
    except Exception as e:
        print(f"{UtilityTools.RED}[X] Failed writing network inventory JSON:{UtilityTools.RESET} {type(e).__name__}: {e}")

    return {"ok": True, "records": len(records), "saved": saved, "summary": summary}


def _print_report(records, summary) -> None:
    if not records:
        print(f"{UtilityTools.YELLOW}[!] No network identifiers found. Run enum_all first to populate resource tables.{UtilityTools.RESET}")
        return
    order = {ni.KIND_IP: 0, ni.KIND_CIDR: 1, ni.KIND_FQDN: 2, ni.KIND_URL: 3, ni.KIND_NET_REF: 4}
    for kind in sorted({r["kind"] for r in records}, key=lambda k: order.get(k, 9)):
        subset = sorted([r for r in records if r["kind"] == kind], key=lambda r: r["value"])
        print(f"\n{UtilityTools.BRIGHT_CYAN}[*] {kind.upper()} ({len(subset)} rows, {len({r['value'] for r in subset})} distinct){UtilityTools.RESET}")
        rows = [
            {"value": r["value"], "resource": r["resource_name"] or r["resource_id"],
             "source_table": r["source_table"], "column": r["column_name"], "compartment_id": r["compartment_id"]}
            for r in subset
        ]
        UtilityTools.print_limited_table(rows, ["value", "resource", "source_table", "column", "compartment_id"])
    distinct_counts = ", ".join(f"{k}={summary.get(f'{k}_distinct', 0)}" for k in ni.ALL_KINDS)
    print(f"\n{UtilityTools.GREEN}[+] Network inventory (distinct): {distinct_counts}{UtilityTools.RESET}")
