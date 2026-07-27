#!/usr/bin/env python3
"""process_network_resources: two-step saved-data network analysis.

Step 1 (inventory): sweep every saved service table and surface all network
identifiers (IPs, CIDRs, URLs, FQDNs, and subnet/VCN/NSG references), persisting
results to the ``network_inventory`` table.

Step 2 (denormalize): invert the subnet→security-list and subnet→route-table
relationships, backfilling ``attached_subnet_ids`` onto each security-list and
route-table row so cross-referencing which subnets a rule governs requires no
manual OCID chasing.

Both steps are **Process** (no OCI API calls) — run ``enum_all`` /
``enum_core_network`` first to populate the source tables.
"""
from __future__ import annotations

import argparse
import json
from importlib import resources
from typing import Any, Dict, List, Optional

from ocinferno.core.console import UtilityTools
from ocinferno.modules.everything.utilities import network_inventory as ni

# ── inventory constants ────────────────────────────────────────────────────────

_EXCLUDED_TABLES = frozenset({
    "workspace_index", "sessions", "user_permissions",
    "opengraph_nodes", "opengraph_edges", "enum_all_task_ledger",
    "network_inventory",
})

_OUTPUT_TABLE = "network_inventory"


# ── helpers ────────────────────────────────────────────────────────────────────

def _all_service_tables() -> List[str]:
    try:
        text = resources.files("ocinferno.mappings").joinpath("database_info.json").read_text(encoding="utf-8")
        schema = json.loads(text)
        tables = schema.get("tables")
        if tables is None:
            tables = [t for db in schema.get("databases", []) for t in db.get("tables", [])]
        names = [t["table_name"] for t in tables]
    except Exception:
        return []
    return [n for n in names if n not in _EXCLUDED_TABLES]


def _safe_lifecycle(val: Any) -> str:
    return (val or "").upper().strip()


def _load_subnet_rows(session) -> list:
    return session.get_resource_fields(
        "virtual_network_subnets",
        columns=["id", "security_list_ids", "route_table_id", "lifecycle_state"],
    ) or []


def _backfill_sl_attachments(session, subnet_rows: list) -> int:
    sl_to_subnets: Dict[str, list] = {}
    for sn in subnet_rows:
        if _safe_lifecycle(sn.get("lifecycle_state")) in ("TERMINATED", "TERMINATING"):
            continue
        sn_id = sn.get("id") or ""
        raw = sn.get("security_list_ids") or "[]"
        try:
            ids = json.loads(raw) if isinstance(raw, str) else (raw if isinstance(raw, list) else [])
        except Exception:
            ids = []
        for sid in ids:
            sid = str(sid).strip()
            if sid:
                sl_to_subnets.setdefault(sid, []).append(sn_id)

    sl_rows = session.get_resource_fields("virtual_network_security_lists") or []
    if not sl_rows:
        return 0
    for sl in sl_rows:
        sl["attached_subnet_ids"] = json.dumps(sl_to_subnets.get(sl.get("id") or "", []))
    session.save_resources(sl_rows, "virtual_network_security_lists")
    return len(sl_rows)


def _backfill_rt_attachments(session, subnet_rows: list) -> int:
    rt_to_subnets: Dict[str, list] = {}
    for sn in subnet_rows:
        if _safe_lifecycle(sn.get("lifecycle_state")) in ("TERMINATED", "TERMINATING"):
            continue
        sn_id = sn.get("id") or ""
        rt_id = (sn.get("route_table_id") or "").strip()
        if rt_id:
            rt_to_subnets.setdefault(rt_id, []).append(sn_id)

    rt_rows = session.get_resource_fields("virtual_network_route_tables") or []
    if not rt_rows:
        return 0
    for rt in rt_rows:
        rt["attached_subnet_ids"] = json.dumps(rt_to_subnets.get(rt.get("id") or "", []))
    session.save_resources(rt_rows, "virtual_network_route_tables")
    return len(rt_rows)


def _print_inventory_report(records, summary) -> None:
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
        UtilityTools.print_limited_table(
            rows,
            ["value", "resource", "source_table", "column", "compartment_id"],
            title=f"Network Resources - {kind.replace('_', ' ').title()}",
        )
    distinct_counts = ", ".join(f"{k}={summary.get(f'{k}_distinct', 0)}" for k in ni.ALL_KINDS)
    print(f"\n{UtilityTools.GREEN}[+] Network inventory (distinct): {distinct_counts}{UtilityTools.RESET}")


# ── parser ─────────────────────────────────────────────────────────────────────

def _parse_args(user_args) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Two-step saved-data network analysis: "
            "(1) inventory — aggregate all network identifiers from every resource table; "
            "(2) denormalize — backfill attached_subnet_ids onto security lists and route tables."
        ),
        allow_abbrev=False,
    )

    # step control
    p.add_argument("--no-inventory", dest="inventory", action="store_false", default=True,
                   help="Skip the network-identifier inventory sweep (step 1).")
    p.add_argument("--no-denormalize", dest="denormalize", action="store_false", default=True,
                   help="Skip the subnet denormalization backfill (step 2).")

    # inventory flags
    p.add_argument("--kinds", default=None,
                   help=f"Comma-separated identifier kinds to include (default: all). Options: {','.join(ni.ALL_KINDS)}")
    p.add_argument("--table", default=None,
                   help="Inventory: only sweep this one source table (e.g. compute_instances).")
    p.add_argument("--value-contains", default=None,
                   help="Inventory: only report values containing this substring.")
    p.add_argument("--json-out", default=None,
                   help="Inventory: write the full inventory JSON to a file path.")
    p.add_argument("--quiet", action="store_true",
                   help="Inventory: do not print the identifier tables (still persists and reports counts).")

    # denormalize flags
    p.add_argument("--no-security-lists", dest="security_lists", action="store_false", default=True,
                   help="Denormalize: skip security-list backfill.")
    p.add_argument("--no-route-tables", dest="route_tables", action="store_false", default=True,
                   help="Denormalize: skip route-table backfill.")

    return p.parse_args(list(user_args) if user_args else [])


# ── entry point ────────────────────────────────────────────────────────────────

def run_module(user_args, session) -> Dict[str, Any]:
    args = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False) or getattr(session, "individual_run_debug", False))
    result: Dict[str, Any] = {"ok": True}

    # ── step 1: inventory ──────────────────────────────────────────────────────
    if args.inventory:
        kinds: Optional[set] = None
        if args.kinds:
            kinds = {k.strip().lower() for k in str(args.kinds).split(",") if k.strip()}

        tables = [args.table] if args.table else _all_service_tables()
        records = []
        for table_name in tables:
            try:
                rows = session.get_resource_fields(table_name) or []
            except Exception as e:
                UtilityTools.dlog(debug, "process_network_resources: table read failed",
                                  table=table_name, err=str(e))
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
            _print_inventory_report(records, summary)

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

        result.update({"inventory_records": len(records), "inventory_saved": saved, "inventory_summary": summary})

    # ── step 2: denormalize ────────────────────────────────────────────────────
    if args.denormalize:
        subnet_rows = _load_subnet_rows(session)
        if not subnet_rows:
            print(f"{UtilityTools.YELLOW}[!] No subnet rows found — run enum_core_network first.{UtilityTools.RESET}")
            result.update({"security_lists_updated": 0, "route_tables_updated": 0})
        else:
            sl_count = rt_count = 0
            if args.security_lists:
                sl_count = _backfill_sl_attachments(session, subnet_rows)
                if sl_count:
                    print(f"{UtilityTools.GREEN}[+] Security lists: backfilled attached_subnet_ids on {sl_count} rows.{UtilityTools.RESET}")
                else:
                    print(f"{UtilityTools.YELLOW}[!] Security lists: no rows found.{UtilityTools.RESET}")
            if args.route_tables:
                rt_count = _backfill_rt_attachments(session, subnet_rows)
                if rt_count:
                    print(f"{UtilityTools.GREEN}[+] Route tables: backfilled attached_subnet_ids on {rt_count} rows.{UtilityTools.RESET}")
                else:
                    print(f"{UtilityTools.YELLOW}[!] Route tables: no rows found.{UtilityTools.RESET}")
            result.update({"security_lists_updated": sl_count, "route_tables_updated": rt_count})

    return result
