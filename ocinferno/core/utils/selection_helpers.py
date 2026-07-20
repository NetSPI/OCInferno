from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence

from ocinferno.core.console import UtilityTools

TABLE_IDENTITY_DOMAINS = "identity_domains"


def _s(value: Any) -> str:
    if value is None:
        return ""
    return value.strip() if isinstance(value, str) else str(value)


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
    missing_hint: str = "modules run enum_identity --domains",
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


def paged_search_select(
    items: Sequence[Any],
    *,
    title: str,
    label_fn,
    page_size: int = 20,
):
    """Interactively pick one item from a (possibly large) list.

    Renders one page at a time and accepts: a number to select, ``n``/``p`` to page,
    ``/<term>`` to filter by label substring, ``c`` to clear the filter, ``ENTER`` to
    cancel. Returns the selected item or ``None``. Small lists (<= page_size) behave
    like a plain numbered menu.
    """
    view = [it for it in items]
    if not view:
        print(f"{UtilityTools.RED}[X] Nothing to choose from.{UtilityTools.RESET}")
        return None

    page = 0
    filt = ""
    while True:
        shown = [it for it in view if filt.lower() in label_fn(it).lower()] if filt else view
        if not shown:
            print(f"{UtilityTools.YELLOW}[!] No matches for '/{filt}'.{UtilityTools.RESET}")
            filt = ""
            continue
        pages = max(1, (len(shown) + page_size - 1) // page_size)
        page = max(0, min(page, pages - 1))
        start = page * page_size
        chunk = shown[start:start + page_size]

        hdr = f"{UtilityTools.BOLD}{UtilityTools.BRIGHT_GREEN}[*] {title}{UtilityTools.RESET}"
        state = f" (page {page + 1}/{pages}, {len(shown)} match" + ("" if len(shown) == 1 else "es")
        state += f", filter='{filt}'" if filt else ""
        state += ")"
        print(f"{hdr}{UtilityTools.BRIGHT_BLACK}{state}{UtilityTools.RESET}")
        for i, it in enumerate(chunk, start + 1):
            print(f"  [{i}] {label_fn(it)}")
        hint = "Select # | 'n'ext | 'p'rev | '/term' filter | 'c'lear | ENTER cancel" if pages > 1 or filt \
            else "Select a number (or ENTER to cancel)"
        choice = input(f"{hint}: ").strip()

        if choice == "":
            print("[*] Cancelled.")
            return None
        low = choice.lower()
        if low in ("n", "next"):
            page += 1
            continue
        if low in ("p", "prev"):
            page -= 1
            continue
        if low in ("c", "clear"):
            filt = ""
            page = 0
            continue
        if choice.startswith("/"):
            filt = choice[1:].strip()
            page = 0
            continue
        if choice.isdigit():
            idx = int(choice)
            if start + 1 <= idx <= start + len(chunk):
                return chunk[idx - start - 1]
            # allow selecting any absolute index within the current filtered view
            if 1 <= idx <= len(shown):
                return shown[idx - 1]
            print(f"{UtilityTools.RED}[X] Out of range.{UtilityTools.RESET}")
            continue
        print(f"{UtilityTools.RED}[X] Unrecognized input.{UtilityTools.RESET}")


def select_from_db_or_manual(
    *,
    rows: Sequence[Dict[str, Any]],
    entity: str,
    label_fn,
    manual_prompt: str,
    manual_validate=None,
    page_size: int = 20,
    empty_hint: str = "",
):
    """Top-level interactive picker: choose a saved row from the workspace DB, or enter a
    value manually. Returns ``("row", row)`` | ``("manual", value)`` | ``None`` (cancel).

    When ``rows`` is empty it goes straight to manual entry (showing ``empty_hint``).
    Large ``rows`` are handled by :func:`paged_search_select` (search + paging).
    ``manual_validate(value) -> bool`` gates manual input (re-prompts on False).
    """
    usable = [r for r in rows if isinstance(r, dict)]

    def _manual():
        while True:
            val = _s(input(f"{manual_prompt}: "))
            if not val:
                print("[*] Cancelled.")
                return None
            if manual_validate and not manual_validate(val):
                print(f"{UtilityTools.RED}[X] Invalid value, try again (ENTER to cancel).{UtilityTools.RESET}")
                continue
            return ("manual", val)

    if not usable:
        if empty_hint:
            print(f"{UtilityTools.YELLOW}[!] No saved {entity} in the workspace DB. {empty_hint}{UtilityTools.RESET}")
        return _manual()

    print(f"{UtilityTools.BOLD}{UtilityTools.BRIGHT_GREEN}[*] Select {entity}:{UtilityTools.RESET}")
    print(f"  [1] Choose from {len(usable)} {entity} saved in the workspace DB")
    print("  [2] Enter a value manually")
    choice = _s(input("Select 1 or 2 (ENTER to cancel): "))
    if choice == "":
        print("[*] Cancelled.")
        return None
    if choice == "2":
        return _manual()
    if choice == "1":
        picked = paged_search_select(usable, title=f"{entity.title()} (workspace DB)", label_fn=label_fn, page_size=page_size)
        return ("row", picked) if picked is not None else None
    print(f"{UtilityTools.RED}[X] Enter 1 or 2.{UtilityTools.RESET}")
    return select_from_db_or_manual(
        rows=rows, entity=entity, label_fn=label_fn, manual_prompt=manual_prompt,
        manual_validate=manual_validate, page_size=page_size, empty_hint=empty_hint,
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
