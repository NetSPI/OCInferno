#!/usr/bin/env python3
from __future__ import annotations

import argparse
from typing import Any, Dict, List

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.modules.networkloadbalancer.utilities.helpers import (
    NetworkLoadBalancersResource,
    fill_missing,
)


def _parse_args(user_args):
    parser = argparse.ArgumentParser(description="Enumerate OCI Network Load Balancers", allow_abbrev=False)
    parser.add_argument("--nlb-id", default="", help="Get a specific NLB by OCID")
    # --get/--save are runner-level common flags; parse module-specific args only.
    args, _ = parser.parse_known_args(list(user_args))
    raw_args = {str(x) for x in (list(user_args) if user_args is not None else [])}
    args.get = "--get" in raw_args
    args.save = "--save" in raw_args
    return args


def run_module(user_args, session) -> Dict[str, Any]:
    args = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False) or getattr(session, "individual_run_debug", False))
    comp_id = getattr(session, "compartment_id", None)
    nlb_id = (args.nlb_id or "").strip()
    if not comp_id and not nlb_id:
        raise ValueError("Need session.compartment_id unless --nlb-id is provided")

    load_balancers_resource = NetworkLoadBalancersResource(session=session)
    try:
        # Resource loop: either single NLB by ID or all NLBs in the compartment.
        if nlb_id:
            item = load_balancers_resource.get(nlb_id=nlb_id) or {}
            rows: List[Dict[str, Any]] = [item] if item else []
        else:
            rows = load_balancers_resource.list(compartment_id=comp_id) or []
    except oci.exceptions.ServiceError as e:
        UtilityTools.dlog(True, "list_network_load_balancers failed", status=getattr(e, "status", None), code=getattr(e, "code", None))
        return {"ok": False, "load_balancers": 0}
    except Exception as e:
        UtilityTools.dlog(True, "list_network_load_balancers failed", err=f"{type(e).__name__}: {e}")
        return {"ok": False, "load_balancers": 0}

    if not rows:
        UtilityTools.dlog(debug, "No network load balancers found", compartment_id=comp_id, nlb_id=nlb_id or None)
        return {"ok": True, "load_balancers": 0, "saved": False}

    for r in rows:
        if isinstance(r, dict):
            r.setdefault("compartment_id", comp_id)

    enriched = 0
    if args.get:
        for r in rows:
            if not isinstance(r, dict):
                continue
            rid = r.get("id")
            if not isinstance(rid, str) or not rid:
                continue
            try:
                meta = load_balancers_resource.get(nlb_id=rid) or {}
            except Exception as e:
                UtilityTools.dlog(debug, "get_network_load_balancer failed", nlb_id=rid, err=f"{type(e).__name__}: {e}")
                continue
            if fill_missing(r, meta):
                enriched += 1

    UtilityTools.print_limited_table(rows, load_balancers_resource.COLUMNS)

    if args.save:
        load_balancers_resource.save(rows)

    return {
        "ok": True,
        "load_balancers": len(rows),
        "saved": bool(args.save),
        "get": bool(args.get),
        "enriched": int(enriched),
    }
