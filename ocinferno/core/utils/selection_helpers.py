from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence

from ocinferno.core.console import UtilityTools

TABLE_IDENTITY_DOMAINS = "identity_domains"


def _s(value: Any) -> str:
    if value is None:
        return ""
    return value.strip() if isinstance(value, str) else str(value)


def _row_label(row: Dict[str, Any], *, display_keys: Sequence[str]) -> str:
    display = ""
    for key in display_keys:
        display = _s(row.get(key))
        if display:
            break
    if not display:
        display = _s(row.get("ocid") or row.get("id") or "<unknown>")

    ocid = _s(row.get("ocid"))
    row_id = _s(row.get("id"))
    if ocid:
        return f"{display} | ocid={ocid}"
    if row_id:
        return f"{display} | id={row_id}"
    return display


def load_identity_domains_from_db(session, *, compartment_id: str | None = None) -> list[dict[str, Any]]:
    if not compartment_id:
        return session.get_resource_fields(TABLE_IDENTITY_DOMAINS) or []
    rows = session.get_resource_fields(
        TABLE_IDENTITY_DOMAINS,
        where_conditions={"compartment_id": compartment_id},
    ) or []
    if rows:
        return rows
    return session.get_resource_fields(TABLE_IDENTITY_DOMAINS) or []


def choose_identity_domain(
    session,
    *,
    domain_ocid: str = "",
    domain_url: str = "",
    all_saved_domains: bool = False,
    no_prompt: bool = False,
    prompt_title: str = "Identity Domains",
    missing_hint: str = "modules run enum_identity --domains --save",
) -> Optional[Dict[str, Any]]:
    domains = load_identity_domains_from_db(
        session,
        compartment_id=None if all_saved_domains else getattr(session, "compartment_id", None),
    ) or []
    domains = [d for d in domains if isinstance(d, dict)]
    if not domains:
        print(f"{UtilityTools.RED}[X] No saved identity domains found. Run: {missing_hint}{UtilityTools.RESET}")
        return None

    domain_ocid = _s(domain_ocid)
    domain_url = _s(domain_url)
    if domain_ocid or domain_url:
        for d in domains:
            if domain_ocid and _s(d.get("id")) == domain_ocid:
                return d
            if domain_url and _s(d.get("url")) == domain_url:
                return d
            if domain_url and _s(d.get("home_region_url")) == domain_url:
                return d

        if domain_ocid:
            print(f"{UtilityTools.RED}[X] Domain OCID not found in saved domains: {domain_ocid}{UtilityTools.RESET}")
        else:
            print(f"{UtilityTools.RED}[X] Domain URL not found in saved domains: {domain_url}{UtilityTools.RESET}")
        return None

    if no_prompt:
        print(f"{UtilityTools.RED}[X] --no-prompt requires --domain-ocid (or a known domain selector).{UtilityTools.RESET}")
        return None

    return UtilityTools._choose_from_list(
        prompt_title,
        domains,
        lambda d: f"{_s(d.get('display_name') or d.get('name') or d.get('id'))} | {_s(d.get('id'))}",
    )


def get_domain_rows(
    session,
    *,
    table_name: str,
    domain_ocid: str,
) -> List[Dict[str, Any]]:
    rows = session.get_resource_fields(table_name, where_conditions={"domain_ocid": _s(domain_ocid)}) or []
    return [r for r in rows if isinstance(r, dict)]


def find_row_by_ocid_or_id(
    rows: List[Dict[str, Any]],
    *,
    target_ocid: str = "",
    target_id: str = "",
) -> Optional[Dict[str, Any]]:
    target_ocid = _s(target_ocid)
    target_id = _s(target_id)
    if target_ocid:
        for row in rows:
            if _s(row.get("ocid")) == target_ocid:
                return row
    if target_id:
        for row in rows:
            if _s(row.get("id")) == target_id:
                return row
    return None


def choose_domain_row(
    session,
    *,
    table_name: str,
    domain_ocid: str,
    target_ocid: str = "",
    target_id: str = "",
    no_prompt: bool = False,
    prompt_title: str = "Identity Domain Resources",
    entity_plural: str = "resources",
    missing_hint: str = "modules run enum_identity --principals --save",
    display_keys: Sequence[str] = ("display_name", "name", "ocid", "id"),
) -> Optional[Dict[str, Any]]:
    rows = get_domain_rows(session, table_name=table_name, domain_ocid=domain_ocid)
    if not rows:
        print(
            f"{UtilityTools.RED}[X] No saved {entity_plural} for domain {domain_ocid}. "
            f"Run: {missing_hint}{UtilityTools.RESET}"
        )
        return None

    selected = find_row_by_ocid_or_id(rows, target_ocid=target_ocid, target_id=target_id)
    if selected:
        return selected

    if _s(target_ocid) or _s(target_id):
        print(
            f"{UtilityTools.RED}[X] Requested {entity_plural.rstrip('s')} was not found in cached {entity_plural} "
            f"for this domain.{UtilityTools.RESET}"
        )
        return None

    if no_prompt:
        print(
            f"{UtilityTools.RED}[X] --no-prompt requires explicit target for {entity_plural.rstrip('s')} selection."
            f"{UtilityTools.RESET}"
        )
        return None

    return UtilityTools._choose_from_list(
        prompt_title,
        rows,
        lambda row: _row_label(row, display_keys=display_keys),
    )


def extract_active_cred_user_ocid(session) -> str:
    creds = getattr(session, "credentials", None)
    if isinstance(creds, dict):
        direct_user = _s(creds.get("user"))
        if direct_user.startswith("ocid1.user"):
            return direct_user
        cfg_user = _s((creds.get("config") or {}).get("user"))
        if cfg_user.startswith("ocid1.user"):
            return cfg_user

    active_credname = _s(getattr(session, "credname", ""))
    if not active_credname:
        return ""

    for row in (session.get_all_creds() or []):
        if not isinstance(row, dict):
            continue
        if _s(row.get("credname")) != active_credname:
            continue
        try:
            stored = json.loads(_s(row.get("session_creds")) or "{}")
        except Exception:
            stored = {}
        user = _s(stored.get("user"))
        if user.startswith("ocid1.user"):
            return user
        break
    return ""
