"""Region-subscription awareness for OCI tenancies.

An OCI tenancy starts subscribed to a single *home* region and pays to add more.
Enumerating a region the tenancy isn't subscribed to fails (the region-scoped
endpoint 404s / can't be reached), so blindly fanning out across every OCI region
wastes calls and prints noisy errors.

This module gives the framework two things, cached on the ``session``:

1. The **authoritative** subscribed-region set, fetched once via
   ``list_region_subscriptions`` (``subscribed_regions`` / ``is_region_subscribed``).
2. A **runtime skip-cache** — when an API call trips a "region not subscribed"
   error, ``mark_region_unavailable`` records it so later calls skip it instead
   of re-erroring (``region_unavailable`` / ``should_skip_region``).

Everything is best-effort and fail-open: if the subscription list can't be
fetched, nothing is blocked (an empty/unknown set never filters a region out).
"""
from __future__ import annotations

from typing import Any, List, Optional

try:  # oci is a hard runtime dep, but keep imports defensive for stubbed test envs.
    import oci  # type: ignore
except Exception:  # pragma: no cover - exercised only when the SDK is stubbed out
    oci = None  # type: ignore


def is_region_not_subscribed_error(exc: Exception) -> bool:
    """True when ``exc`` is OCI signalling the tenancy isn't subscribed to a region.

    Conservative on purpose: a plain 404 on some resource must NOT be mistaken for
    a region-subscription problem, so we require either an explicit region-support
    error code or subscription language in the message.
    """
    code = getattr(exc, "code", None)
    if code in {"RegionNotSupported", "RegionNotSubscribed"}:
        return True
    message = str(getattr(exc, "message", "") or exc).lower()
    return (
        "not subscribed" in message
        or "region is not enabled" in message
        or "not authorized to subscribe" in message
        or "region is not supported" in message
    )


def _cache(session: Any) -> dict:
    cache = getattr(session, "_region_cache", None)
    if not isinstance(cache, dict):
        cache = {"subscribed": None, "unavailable": set()}
        try:
            setattr(session, "_region_cache", cache)
        except Exception:
            pass
    return cache


def fetch_subscribed_regions(session: Any, *, proxy: Optional[str] = None) -> List[str]:
    """Best-effort: query ``list_region_subscriptions`` and return region names.

    Returns ``[]`` on any failure (missing SDK, bad creds, denied) — callers treat
    an empty set as "unknown, don't filter".
    """
    if oci is None:
        return []
    creds = getattr(session, "credentials", None)
    # ``session.credentials`` is the {"config": <dict>, "signer": <object|None>} wrapper;
    # IdentityClient takes the CONFIG dict (+ signer), NOT the wrapper.
    if not (isinstance(creds, dict) and isinstance(creds.get("config"), dict)):
        return []
    cfg = creds.get("config") or {}
    signer = creds.get("signer")
    try:
        if signer is None:
            identity = oci.identity.IdentityClient(cfg, retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY)
        else:
            identity = oci.identity.IdentityClient(cfg, signer=signer, retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY)
        add_proxy = getattr(session, "add_proxy_config", None)
        if callable(add_proxy):
            add_proxy(identity, proxy_address=proxy)
        # The full tenancy OCID lives in the config (and on session.tenant_id); a
        # subscription list is always tenancy-rooted.
        tenancy_id = (
            cfg.get("tenancy")
            or getattr(session, "tenant_id", None)
            or getattr(session, "tenancy_id", None)
        )
        resp = oci.pagination.list_call_get_all_results(identity.list_region_subscriptions, tenancy_id)
        out: List[str] = []
        home: Optional[str] = None
        records: List[dict] = []
        for r in resp.data or []:
            rn = getattr(r, "region_name", None)
            if rn:
                out.append(rn)
                is_home = bool(getattr(r, "is_home_region", False))
                if is_home:
                    home = rn
                records.append({
                    "region_name": rn,
                    "region_key": getattr(r, "region_key", "") or "",
                    "status": getattr(r, "status", "") or "",
                    "is_home_region": is_home,
                })
        if home:
            _cache(session)["home"] = home
        # Persist the per-tenant region store (best-effort; workspace-scoped).
        persist_region_subscriptions(session, records)
        return out
    except Exception:
        return []


def persist_region_subscriptions(session: Any, records: List[dict]) -> None:
    """Save the tenancy's subscribed-region records to the workspace-scoped
    ``region_subscriptions`` table (a durable per-tenant store, so later runs and the
    ``data`` command can see valid regions without re-calling the API). Never raises."""
    data_master = getattr(session, "data_master", None)
    workspace_id = getattr(session, "workspace_id", None)
    if data_master is None or workspace_id is None or not records:
        return
    for rec in records:
        try:
            data_master.save_dict_row(
                db="service",
                table_name="region_subscriptions",
                row={
                    "workspace_id": workspace_id,
                    "region_name": rec.get("region_name", ""),
                    "region_key": rec.get("region_key", ""),
                    "status": rec.get("status", ""),
                    "is_home_region": "1" if rec.get("is_home_region") else "0",
                },
                on_conflict="replace",
            )
        except Exception:
            pass


def stored_subscribed_regions(session: Any) -> List[str]:
    """Region names from the persisted ``region_subscriptions`` store (empty if none).
    Also repopulates the in-memory home-region cache from the stored home flag."""
    data_master = getattr(session, "data_master", None)
    workspace_id = getattr(session, "workspace_id", None)
    if data_master is None or workspace_id is None:
        return []
    try:
        rows = data_master.fetch_column_from_table(
            db="service",
            table_name="region_subscriptions",
            columns=["region_name", "is_home_region"],
            where={"workspace_id": workspace_id},
        )
    except Exception:
        return []
    out: List[str] = []
    for name, is_home in rows or []:
        if name:
            out.append(str(name))
            if str(is_home) in ("1", "True", "true"):
                _cache(session)["home"] = str(name)
    return out


def home_region(session: Any, *, proxy: Optional[str] = None) -> Optional[str]:
    """The tenancy's HOME region (where global services -- IAM/tagging/budget -- live).

    Falls back to the session's current default region when the subscription list
    doesn't flag a home region (best-effort)."""
    subscribed_regions(session, proxy=proxy)  # populates cache["home"] as a side effect
    cached = _cache(session).get("home")
    if cached:
        return cached
    return getattr(session, "config_current_default_region", None) or getattr(session, "region", None)


def resolve_regions(session: Any, selector: Any = None, *, proxy: Optional[str] = None) -> List[str]:
    """Resolve a ``--regions`` selector to a concrete, subscription-validated list.

    ``selector`` accepts ``None``/``"current"`` (the session's current region -- the
    DEFAULT, preserving today's single-region behaviour), ``"all"`` (every subscribed
    region), or an explicit CSV/space/list of region names (validated against the
    subscription list; unsubscribed names are dropped with a warning). Always returns
    at least the current region when nothing else resolves (fail-open)."""
    current = getattr(session, "config_current_default_region", None) or getattr(session, "region", None)
    subs = subscribed_regions(session, proxy=proxy)

    if selector is None:
        tokens: List[str] = []
    elif isinstance(selector, (list, tuple)):
        tokens = [str(t).strip() for t in selector if str(t).strip()]
    else:
        tokens = [t.strip() for t in str(selector).replace(",", " ").split() if t.strip()]
    low = [t.lower() for t in tokens]

    if not tokens or low == ["current"]:
        return [current] if current else list(subs[:1])
    if "all" in low:
        return list(subs) if subs else ([current] if current else [])

    out: List[str] = []
    for r in tokens:
        if r.lower() in ("current", "all"):
            continue
        if subs and r not in subs:
            print(f"[!] Region '{r}' is not in the tenancy's subscribed regions "
                  f"({', '.join(subs)}); skipping.")
            continue
        if r not in out:
            out.append(r)
    return out or ([current] if current else [])


def subscribed_regions(session: Any, *, refresh: bool = False, proxy: Optional[str] = None) -> List[str]:
    """Cached authoritative subscribed-region list for this session's tenancy.

    Resolution order: in-memory session cache -> the persisted ``region_subscriptions``
    store (populated by a prior discovery, so no API call) -> a live
    ``list_region_subscriptions`` fetch (which persists the store). ``refresh=True``
    skips both caches and forces a live re-fetch (what ``--find-regions`` uses)."""
    cache = _cache(session)
    if refresh or cache.get("subscribed") is None:
        stored = [] if refresh else stored_subscribed_regions(session)
        cache["subscribed"] = stored or fetch_subscribed_regions(session, proxy=proxy)
    return list(cache.get("subscribed") or [])


def is_region_subscribed(session: Any, region: str, *, proxy: Optional[str] = None) -> bool:
    """True if ``region`` is in the subscribed set. Unknown/empty set → True (fail-open)."""
    if not region:
        return True
    subs = subscribed_regions(session, proxy=proxy)
    if not subs:
        return True
    return region in subs


def mark_region_unavailable(session: Any, region: str) -> None:
    """Record a region that tripped a not-subscribed error so later calls skip it."""
    if not region:
        return
    _cache(session)["unavailable"].add(region)


def region_unavailable(session: Any, region: str) -> bool:
    if not region:
        return False
    return region in _cache(session).get("unavailable", set())


def should_skip_region(session: Any, region: str, *, proxy: Optional[str] = None) -> bool:
    """True when ``region`` should be skipped: already known-unavailable at runtime,
    or absent from the authoritative subscription list."""
    if region_unavailable(session, region):
        return True
    return not is_region_subscribed(session, region, proxy=proxy)
