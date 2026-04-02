#!/usr/bin/env python3
from __future__ import annotations

# =============================================================================
# NOTICE - LLM GENERATED FOUNDATION
# =============================================================================
# This module was initially generated with assistance from a Large Language
# Model (LLM). It is actively being manually reviewed, verified, and expanded
# by maintainers. 
# =============================================================================

import argparse
import json
from typing import List, Optional

from ocinferno.core.console import UtilityTools
from ocinferno.modules.everything.utilities.config_audit import (
    run_audit,
    print_audit_report,
    DEFAULT_SERVICE_AUDITORS,
)

def _parse_args(user_args) -> argparse.Namespace:
    service_hint = ",".join(cls.service for cls in DEFAULT_SERVICE_AUDITORS)
    p = argparse.ArgumentParser(
        description="Run config audit across all saved service tables",
        allow_abbrev=False,
    )
    p.add_argument(
        "--services",
        default=None,
        help=f"Comma-separated services to audit (default: all). Example: {service_hint}",
    )
    p.add_argument("--save", action="store_true", help="Pass-through flag for module-runner consistency (unused here).")
    p.add_argument("--json-out", default=None, help="Write findings JSON to a file path.")
    p.add_argument("--quiet", action="store_true", help="Do not print report (still stores on session).")
    return p.parse_args(user_args)


def run_module(user_args, session):
    """
    Everything/Enumeration entry point: load saved DB rows via session.get_resource_fields(),
    run service-oriented audits, store results on session for later output, and optionally
    write JSON to disk.
    """
    args = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False) or getattr(session, "individual_run_debug", False))

    include_services: Optional[List[str]] = None
    if args.services:
        include_services = [s.strip() for s in str(args.services).split(",") if s.strip()]

    report = run_audit(session=session, debug=debug, include_services=include_services)

    # Store for later printing/exporting
    try:
        session.config_audit_report = report
    except Exception:
        pass

    if not args.quiet:
        print_audit_report(report)

    out_path = session.resolve_output_path(
        requested_path=args.json_out,
        service_name="everything",
        filename="config_audit.json",
        compartment_id=getattr(session, "compartment_id", None),
        subdirs=["reports"],
        target="export",
    )
    try:
        out_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=False), encoding="utf-8")
        print(f"[*] Wrote config audit JSON: {out_path}")
    except Exception as e:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed writing JSON report:{UtilityTools.RESET} {type(e).__name__}: {e}")

    return report.to_dict()
