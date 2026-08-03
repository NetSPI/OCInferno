"""Declarative enumeration framework.

Every standard ``enum_<service>`` module describes its resources as a list of
``Component`` specs and hands them to :func:`run_components`, which provides one
uniform enumeration loop shared across ~28 modules:

    parse args -> resolve selected components -> require a compartment
      -> for each selected component: list -> (--get) enrich -> print -> save
         (soft-skipping 401/403/404 for services often disabled per compartment)
      -> append cached counts for the unselected components

Built atop the config-driven :class:`~ocinferno.core.resource.OciListResource`
base: modules become declarations, the shared behavior lives in one place. A
module with a plain list/get/save shape collapses to::

    COMPONENTS = [Component("redis_clusters", RedisClustersResource, cache_table="redis_clusters")]
    def run_module(user_args, session):
        return run_components(user_args, session, COMPONENTS,
                              module_name="enum_redis", description="Enumerate OCI Cache (Redis) resources")

Per-service quirks (ID-input scoping, a get that needs the compartment, no ``--get``)
are expressed via the Component's ``list_fn``/``get_row_fn``/``supports_get`` knobs
rather than a hand-rolled ``run_module``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Sequence

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.service_runtime import (
    SOFT_SKIP_STATUSES,
    append_cached_component_counts,
    concise_display_columns,
    parse_wrapper_args,
    resolve_selected_components,
    run_standard_enum_component,
)


@dataclass
class Component:
    """Declarative spec for one enumerable resource type within an enum module.

    Fields beyond the obvious:
      cache_table     Table used for the "cached count" line when the component is NOT
                      selected (None => no cached-count entry).
      supports_get    False => never call get() even with --get (list-only resources).
      soft_skip       True (default) => treat 401/403/404 on list as an empty result
                      (service disabled/unauthorized per compartment) instead of an error.
      list_fn         Override the default ``lambda cid: resource.list(compartment_id=cid)``.
                      Signature: ``list_fn(session, args, resource) -> callable(cid) -> rows``
                      (lets a component read manual --X-ids flags for ID-scoped listing).
      get_row_fn      Override the default ``lambda row: resource.get(resource_id=row["id"])``.
                      Signature: ``get_row_fn(session, args, resource) -> callable(row) -> dict``
                      (e.g. NoSQL's get needs the compartment id too).
      print_columns   Override the printed columns (None => resource.COLUMNS).
      resource_kwargs Extra kwargs for the Resource constructor (e.g. region=...).
      download_fn     Enables ``--download`` for this component. Factory:
                      ``download_fn(session, args, resource) -> callable(rows) -> int``
                      run after save when ``--download`` is set; returns the number of
                      files written. Use ``service_runtime.field_dump_download(...)`` for
                      metadata field dumps (env vars/config/user-data), or a custom
                      factory calling a resource content-download method.
    """

    key: str
    resource_cls: type
    help_text: str = ""
    title: str = ""
    cache_table: Optional[str] = None
    compartment_field: str = "compartment_id"
    print_columns: Optional[Sequence[str]] = None
    supports_get: bool = True
    soft_skip: bool = True
    require_compartment: bool = True   # False => a list_fn that can run from manual --X-ids without a compartment
    list_fn: Optional[Callable] = None
    get_row_fn: Optional[Callable] = None
    download_fn: Optional[Callable] = None
    resource_kwargs: Dict[str, Any] = field(default_factory=dict)


def component_arg_specs(components: Sequence[Component]):
    """The (key, key, help) triples ``parse_wrapper_args`` expects."""
    return [(c.key, c.key, c.help_text or f"Enumerate {c.title or c.key.replace('_', '-')}") for c in components]


def _split_ids(raw) -> list:
    """Normalize a manual-id value (str, or an argparse ``append`` list) to a flat
    list of ids, splitting on commas and whitespace."""
    parts = raw if isinstance(raw, (list, tuple)) else [raw]
    out = []
    for part in parts:
        out.extend(x.strip() for x in str(part or "").replace(",", " ").split() if x.strip())
    return out


def nested_list_fn(
    *,
    parent_resource_cls: type,
    parent_id_field: str,
    parent_id_column: str = "id",
    manual_parent_arg: Optional[str] = None,
    manual_parent_ids: Optional[Sequence[str]] = None,
    child_takes_compartment: bool = True,
):
    """Build a ``list_fn`` for a NESTED (per-parent fan-out) component.

    Resolves the parent OCIDs, then lists the child under each parent. Parents
    come from (1) the manual ``--<manual_parent_arg>`` flag
    if given, else (2) a fresh list of the parent resource in the current compartment.
    Each child row is stamped with ``{parent_id_field: <parent id>}`` and the real
    ``compartment_id``.

    ``manual_parent_ids``: an already-resolved list of parent ids, bypassing BOTH the
    ``manual_parent_arg`` flag and the live parent-list fallback entirely. For a module
    with a richer parent-id resolution (e.g. a DB-cache tier before falling back to a
    live list) that must be shared -- computed once -- across several Components, resolve
    it once in ``run_module`` and pass the result here so every dependent component's
    ``list_fn`` reuses it instead of each independently re-resolving (and, without a
    manual arg, re-listing live) the same parents.

    ``child_takes_compartment``:
      True  (default) -> the child SDK list takes BOTH ``compartment_id`` and the parent
                         id (e.g. ``list_container_images(compartment_id, repository_id)``).
      False           -> the child SDK list is scoped by the parent id ALONE (e.g.
                         ``list_functions(application_id)`` / ``list_sessions(bastion_id)``).
                         The child Resource must set ``LIST_SCOPE_KWARG = parent_id_field``;
                         the parent id is passed as the single scope kwarg.
    """
    def _make(session, args, resource):
        def _inner(compartment_id):
            if manual_parent_ids is not None:
                parent_ids = list(manual_parent_ids)
            else:
                manual = getattr(args, manual_parent_arg, "") if manual_parent_arg else ""
                if manual:
                    parent_ids = _split_ids(manual)
                else:
                    parents = parent_resource_cls(session).list(compartment_id=compartment_id) or []
                    parent_ids = [p.get(parent_id_column) for p in parents
                                  if isinstance(p, dict) and p.get(parent_id_column)]
            rows = []
            for pid in parent_ids:
                try:
                    if child_takes_compartment:
                        listed = resource.list(compartment_id=compartment_id, **{parent_id_field: pid}) or []
                    else:
                        # Parent-id is the sole scope; child's LIST_SCOPE_KWARG == parent_id_field
                        # remaps this positional arg onto the parent kwarg.
                        listed = resource.list(compartment_id=pid) or []
                except Exception:
                    continue
                for row in listed:
                    if isinstance(row, dict):
                        row.setdefault(parent_id_field, pid)
                        if compartment_id:
                            row.setdefault("compartment_id", compartment_id)
                        rows.append(row)
            return rows
        return _inner

    return _make


def tenancy_root_list_fn(session, args, resource):
    """``list_fn`` for a component whose SDK list call rejects any compartment_id
    other than the tenancy root (some OCI services enforce this server-side even
    though the SDK's own docstring doesn't say so). Runs once, only when the current
    scan target IS the tenancy root; skips (rather than re-querying the same root
    data) for every other compartment in a --comp sweep."""
    def _inner(compartment_id):
        root = getattr(session, "tenant_id", None)
        if root and compartment_id != root:
            print(f"{UtilityTools.YELLOW}[-] {resource.TABLE_NAME}: skipped "
                  f"(tenancy-root-only resource; this compartment isn't the tenancy root).{UtilityTools.RESET}")
            return []
        return resource.list(compartment_id=root or compartment_id) or []
    return _inner


def run_components(
    user_args,
    session,
    components: Sequence[Component],
    *,
    module_name: str,
    description: str,
    add_extra_args: Optional[Callable] = None,
    require_compartment: bool = True,
) -> Dict[str, Any]:
    """Run the standard per-component enumeration loop for ``components``.

    Returns ``{"ok": True, "components": [...], "args": <parsed args>}`` (the parsed
    args are returned so a module with custom flags can post-process if needed).
    """
    has_download = any(getattr(c, "download_fn", None) for c in components)
    args, _ = parse_wrapper_args(
        user_args,
        description=description,
        components=component_arg_specs(components),
        add_extra_args=add_extra_args,
        include_download=has_download,
    )
    if has_download:
        # Per-unit wall-clock cap consumed by DownloadBudget in the download_fn.
        session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)

    order = [c.key for c in components]
    selected = resolve_selected_components(args, order)

    if require_compartment and not getattr(session, "compartment_id", None):
        raise ValueError("session.compartment_id is not set")

    cache_tables = {c.key: (c.cache_table, c.compartment_field) for c in components if c.cache_table}

    # --regions: explicit region list; if absent, use a single-item list with None
    # so the inner loop runs once with the session's default region.
    region_list: Sequence[Optional[str]] = getattr(args, "regions", None) or [None]

    results = []
    for region_override in region_list:
        for c in components:
            if not selected.get(c.key, False):
                continue
            resource_kwargs = dict(c.resource_kwargs)
            if region_override and "region" not in resource_kwargs:
                resource_kwargs["region"] = region_override
            resource = c.resource_cls(session=session, **resource_kwargs)

            if c.list_fn is not None:
                list_rows = c.list_fn(session, args, resource)
            else:
                list_rows = lambda cid, _r=resource: _r.list(compartment_id=cid)

            get_row = None
            if c.supports_get:
                if c.get_row_fn is not None:
                    get_row = c.get_row_fn(session, args, resource)
                else:
                    get_row = lambda row, _r=resource: _r.get(resource_id=row.get("id"))

            download_rows_fn = c.download_fn(session, args, resource) if c.download_fn is not None else None

            # Storage always uses the full COLUMNS (via resource.save); stdout shows a
            # concise subset unless --wide. Precedence: Component.print_columns override
            # -> resource.DISPLAY_COLUMNS -> auto-derived concise subset.
            full_columns = getattr(resource, "COLUMNS", [])
            if getattr(args, "wide", False):
                print_columns = list(c.print_columns) if c.print_columns else list(full_columns)
            elif c.print_columns:
                print_columns = list(c.print_columns)
            else:
                print_columns = list(getattr(resource, "DISPLAY_COLUMNS", []) or concise_display_columns(full_columns))

            results.append(run_standard_enum_component(
                user_args=args,
                session=session,
                component_key=c.key,
                list_rows=list_rows,
                get_row=get_row,
                save_rows_fn=resource.save,
                print_columns=print_columns,
                module_name=module_name,
                soft_skip_statuses=SOFT_SKIP_STATUSES if c.soft_skip else (),
                require_compartment=c.require_compartment,
                download_rows_fn=download_rows_fn,
            ))

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=order,
        cache_tables=cache_tables,
    )

    return {"ok": True, "components": results, "args": args}
