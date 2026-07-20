#!/usr/bin/env python3
"""Enumerate the tenancy's SUBSCRIBED regions and persist them per-tenant.

OCI resources are regional and a tenancy is only reachable in the regions it's
subscribed to (``list_region_subscriptions``). This tenancy-global module discovers
those regions once, records them in the workspace-scoped ``region_subscriptions``
store (so ``data`` / later runs see valid regions without another API call), and
prints them with the home-region flag. ``enum_all --find-regions`` performs the same
discovery inline before a multi-region scan.
"""
from __future__ import annotations

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.regions import home_region, subscribed_regions

COLUMNS = ["region_name", "region_key", "status", "is_home_region"]


def run_module(user_args, session):
    args = list(user_args or [])
    # Default: live-discover + persist. --cached reuses the stored/session set.
    refresh = "--cached" not in args
    subscribed_regions(session, refresh=refresh)
    home = home_region(session)

    rows = []
    data_master = getattr(session, "data_master", None)
    workspace_id = getattr(session, "workspace_id", None)
    if data_master is not None and workspace_id is not None:
        try:
            for name, key, status, is_home in (data_master.fetch_column_from_table(
                db="service", table_name="region_subscriptions",
                columns=COLUMNS, where={"workspace_id": workspace_id}) or []):
                rows.append({
                    "region_name": name,
                    "region_key": key,
                    "status": status,
                    "is_home_region": "yes" if str(is_home) in ("1", "True", "true") else "",
                })
        except Exception:
            pass

    if not rows:
        print(f"{UtilityTools.YELLOW}[-] enum_regions: no subscribed regions found "
              f"(list_region_subscriptions returned nothing or was denied).{UtilityTools.RESET}")
        return {"ok": True, "regions": []}

    UtilityTools.print_limited_table(rows, COLUMNS, title="Subscribed Regions")
    print(f"{UtilityTools.GREEN}[+] enum_regions: {len(rows)} subscribed region(s); "
          f"home region = {home}.{UtilityTools.RESET}")
    return {"ok": True, "regions": [r["region_name"] for r in rows], "home_region": home}
