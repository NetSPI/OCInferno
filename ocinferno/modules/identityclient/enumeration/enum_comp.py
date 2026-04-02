#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import deque
from typing import Any, Optional

from ocinferno.core.console import UtilityTools
from ocinferno.modules.identityclient.utilities.helpers import IdentityResourceClient
from ocinferno.core.utils.module_helpers import print_results_table


def _parse_args(user_args):
    parser = argparse.ArgumentParser(
        description="Enumerate OCI compartments.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help=(
            "Recursively enumerate sub-compartments.\n"
            "- Tenancy root: uses ListCompartments(subtree=True)\n"
            "- Non-tenancy root: walks recursively via repeated ListCompartments(subtree=False)"
        ),
    )
    parser.add_argument(
        "--lifecycle",
        choices=("ACTIVE", "INACTIVE", "ALL"),
        default="ACTIVE",
        help="Compartment lifecycle state filter (default: ACTIVE).",
    )
    parser.add_argument(
        "--get-root-only",
        action="store_true",
        help="Only run GetCompartment on current/root compartment. Do not run ListCompartments.",
    )
    parser.add_argument(
        "--get-root",
        action="store_true",
        help="Run GetCompartment on root, then run list calls according to recursive mode.",
    )
    parser.add_argument(
        "--get-all-comps",
        action="store_true",
        help=(
            "Run GetCompartment on root and on every discovered compartment from list calls.\n"
            "Useful when you want full GetCompartment metadata across the discovered set."
        ),
    )
    # --save is a runner-level common flag; parse module-specific args only.
    args, _ = parser.parse_known_args(list(user_args))
    raw_args = {str(x) for x in (list(user_args) if user_args is not None else [])}
    args.save = "--save" in raw_args
    return args


def run_module(user_args, session):
    args = _parse_args(user_args)

    debug = bool(getattr(session, "debug", False))
    ops = IdentityResourceClient(session=session)

    root = getattr(session, "compartment_id", None)
    if not root:
        print(f"{UtilityTools.RED}[X] session.compartment_id is not set.{UtilityTools.RESET}")
        return -1
        
    lifecycle: Optional[str] = None if args.lifecycle == "ALL" else args.lifecycle

    discovered: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _maybe_save(row: dict[str, Any]) -> None:
        if args.save:
            ops.save_compartment(row)

    def _add_row(row: Any) -> Optional[str]:
        """
        Normalize minimum contract:
        - Expect dict-like row from IdentityResourceClient that includes 'id' for the compartment OCID.
        - Dedup by 'id'.
        Returns the compartment id if newly added, else None.
        """
        if not isinstance(row, dict):
            return None
        cid = row.get("id")
        if not isinstance(cid, str) or not cid:
            return None
        if cid in seen:
            return None

        seen.add(cid)
        discovered.append(row)
        _maybe_save(row)
        return cid

    def _safe_get_compartment(cid: str, *, context: str) -> Optional[dict[str, Any]]:
        try:
            row = ops.get_compartment(compartment_id=cid)
        except Exception as e:
            if getattr(e, "__class__", type(e)).__name__ == "ServiceError":
                service = str(getattr(e, "target_service", "") or "").strip()
                op = str(getattr(e, "operation_name", "") or "").strip()
                status = str(getattr(e, "status", "") or "").strip()
                code = str(getattr(e, "code", "") or "").strip()
                msg = str(getattr(e, "message", "") or "").strip() or str(e)
                err_brief = (
                    f"ServiceError(service={service or 'identity'}, operation={op or 'get_compartment'}, "
                    f"status={status or '?'}, code={code or '?'}, message={msg})"
                )
            else:
                err_brief = f"{type(e).__name__}: {e}"

            print(
                f"{UtilityTools.YELLOW}[!] enum_comp: GetCompartment failed for {cid} "
                f"({context}); continuing with list traversal. "
                f"{err_brief}{UtilityTools.RESET}"
            )
            UtilityTools.dlog(
                debug,
                "enum_comp: get_compartment failed; continuing",
                cid=cid,
                context=context,
                err=err_brief,
            )
            return None
        return row if isinstance(row, dict) else None

    if args.get_root_only and (args.recursive or args.get_root or args.get_all_comps):
        print(
            f"{UtilityTools.RED}[X] --get-root-only cannot be combined with "
            f"--recursive/--get-root/--get-all-comps.{UtilityTools.RESET}"
        )
        return -1

    get_root = bool(args.get_root or args.get_all_comps or args.get_root_only)
    get_all_discovered = bool(args.get_all_comps)
    list_enabled = not bool(args.get_root_only)

    # Root GET mode: trivial short-circuit when list is disabled
    if args.get_root_only:
        root_row = _safe_get_compartment(root, context="root-only")
        if root_row:
            _add_row(root_row)
        print_results_table(
            discovered,
            columns=["id", "name", "time_created", "lifecycle_state"],
            sort_key="name",
            empty_message="[*] No compartments discovered.",
            summary_message="[*] enum_comp complete. Discovered: {count} compartment(s).",
            summary_count=len(seen),
        )
        return 0

    # -------------------------
    # Determine tenancy-ness for THIS root
    # -------------------------
    try:
        root_is_tenancy = ops.is_tenancy_root(root)
    except Exception as e:
        UtilityTools.dlog(debug, "enum_comp: is_tenancy_root failed; assuming non-root", root=root, err=str(e))
        root_is_tenancy = False

    lifecycle: Optional[str] = None if args.lifecycle == "ALL" else args.lifecycle

    UtilityTools.dlog(
        debug,
        "enum_comp: start",
        root=root,
        root_is_tenancy=root_is_tenancy,
        recursive=args.recursive,
        lifecycle=args.lifecycle,
        get_root=get_root,
        get_all_discovered=get_all_discovered,
    )

    # Optional root GET
    # Resource check: root compartment metadata.
    if get_root:
        root_row = _safe_get_compartment(root, context="root")
        if root_row:
            _add_row(root_row)

    if list_enabled:
        # Resource loop: discovered compartments from list APIs (with optional recursive walk).
        # Recursive mode
        if args.recursive and root_is_tenancy:
            rows = ops.list_compartments(compartment_id=root, lifecycle_state=lifecycle, subtree=True) or []
            for r in rows:
                _add_row(r)
                rid = r.get("id") if isinstance(r, dict) else None
                if get_all_discovered and isinstance(rid, str) and rid:
                    got = _safe_get_compartment(rid, context="discovered")
                    if got:
                        _add_row(got)

        elif args.recursive:
            # Non-tenancy recursive walk via repeated non-subtree list calls.
            q = deque([root])
            enqueued = {root}

            while q:
                cid = q.popleft()

                try:
                    rows = ops.list_compartments(compartment_id=cid, lifecycle_state=lifecycle, subtree=False) or []
                except Exception as e:
                    UtilityTools.dlog(debug, "enum_comp: recursive list failed", root=cid, err=str(e))
                    continue

                for r in rows:
                    new_id = _add_row(r)
                    rid = r.get("id") if isinstance(r, dict) else None
                    if get_all_discovered and isinstance(rid, str) and rid:
                        got = _safe_get_compartment(rid, context="discovered")
                        if got:
                            _add_row(got)
                    if isinstance(new_id, str) and new_id and new_id not in enqueued:
                        enqueued.add(new_id)
                        q.append(new_id)
        else:
            # Single list from root
            rows = ops.list_compartments(compartment_id=root, lifecycle_state=lifecycle, subtree=False) or []
            for r in rows:
                _add_row(r)
                rid = r.get("id") if isinstance(r, dict) else None
                if get_all_discovered and isinstance(rid, str) and rid:
                    got = _safe_get_compartment(rid, context="discovered")
                    if got:
                        _add_row(got)

    print_results_table(
        discovered,
        columns=["id", "name", "time_created", "lifecycle_state"],
        sort_key="name",
        empty_message="[*] No compartments discovered.",
        summary_message="[*] enum_comp complete. Discovered: {count} compartment(s).",
        summary_count=len(seen),
    )
    return 0
