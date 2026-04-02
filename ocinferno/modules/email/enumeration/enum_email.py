#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List

from ocinferno.core.console import UtilityTools
from ocinferno.modules.email.utilities.helpers import (
    EmailConfigurationResource,
    EmailDkimsResource,
    EmailDomainsResource,
    EmailReturnPathsResource,
    EmailSendersResource,
    EmailSpfsResource,
    EmailSuppressionsResource,
)
from ocinferno.core.utils.service_runtime import (
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("senders", "senders", "Enumerate email senders"),
    ("domains", "domains", "Enumerate email domains"),
    ("dkims", "dkims", "Enumerate DKIM records for domains"),
    ("spfs", "spfs", "Enumerate SPF records for domains"),
    ("return_paths", "return_paths", "Enumerate email return paths"),
    ("suppressions", "suppressions", "Enumerate suppressions"),
    ("email_configuration", "email_configuration", "Fetch email configuration (submit endpoints)"),
]


def _parse_args(user_args):
    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate OCI Email Delivery resources",
        components=COMPONENTS,
        include_get=False,
    )


def run_module(user_args, session) -> Dict[str, Any]:
    args, _ = _parse_args(user_args)
    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    debug = bool(getattr(session, "debug", False) or getattr(session, "individual_run_debug", False))

    if not getattr(session, "compartment_id", None):
        raise ValueError(
            "session.compartment_id is not set."
            "\nSelect a compartment in the module runner (or run via module_actions prompt)."
        )

    comp_id = session.compartment_id
    senders_resource = EmailSendersResource(session=session)
    domains_resource = EmailDomainsResource(session=session)
    dkims_resource = EmailDkimsResource(session=session)
    spfs_resource = EmailSpfsResource(session=session)
    return_paths_resource = EmailReturnPathsResource(session=session)
    suppressions_resource = EmailSuppressionsResource(session=session)
    email_configuration_resource = EmailConfigurationResource(session=session)

    results: Dict[str, Any] = {"ok": True}
    domains: List[Dict[str, Any]] = []

    if selected["senders"]:
        try:
            senders = senders_resource.list(compartment_id=comp_id)
        except Exception as e:
            UtilityTools.dlog(True, "list_senders failed", err=f"{type(e).__name__}: {e}")
            senders = []
        for row in senders:
            if isinstance(row, dict):
                row.setdefault("compartment_id", comp_id)
        UtilityTools.print_limited_table(senders, senders_resource.COLUMNS)
        if args.save:
            senders_resource.save(senders)
        results["senders"] = len(senders)

    if selected["domains"] or selected["dkims"] or selected["spfs"]:
        try:
            domains = domains_resource.list(compartment_id=comp_id)
        except Exception as e:
            UtilityTools.dlog(True, "list_email_domains failed", err=f"{type(e).__name__}: {e}")
            domains = []
        for row in domains:
            if isinstance(row, dict):
                row.setdefault("compartment_id", comp_id)
        if selected["domains"]:
            UtilityTools.print_limited_table(domains, domains_resource.COLUMNS)
            if args.save:
                domains_resource.save(domains)
        results["domains"] = len(domains)

    if selected["dkims"] and domains:
        dkims: List[Dict[str, Any]] = []
        for domain in domains:
            domain_id = str((domain or {}).get("id") or "").strip()
            if not domain_id:
                continue
            try:
                rows = dkims_resource.list_for_domain(email_domain_id=domain_id)
            except Exception as e:
                UtilityTools.dlog(debug, "list_dkims failed", email_domain_id=domain_id, err=f"{type(e).__name__}: {e}")
                continue
            for row in rows:
                if isinstance(row, dict):
                    row.setdefault("compartment_id", comp_id)
                    row.setdefault("email_domain_id", domain_id)
            dkims.extend(rows)
        UtilityTools.print_limited_table(dkims, dkims_resource.COLUMNS)
        if args.save:
            dkims_resource.save(dkims)
        results["dkims"] = len(dkims)

    if selected["spfs"] and domains:
        spfs: List[Dict[str, Any]] = []
        for domain in domains:
            domain_id = str((domain or {}).get("id") or "").strip()
            if not domain_id:
                continue
            try:
                rows = spfs_resource.list_for_domain(email_domain_id=domain_id)
            except Exception as e:
                UtilityTools.dlog(debug, "list_spfs failed", email_domain_id=domain_id, err=f"{type(e).__name__}: {e}")
                continue
            for row in rows:
                if isinstance(row, dict):
                    row.setdefault("compartment_id", comp_id)
                    row.setdefault("email_domain_id", domain_id)
            spfs.extend(rows)
        UtilityTools.print_limited_table(spfs, spfs_resource.COLUMNS)
        if args.save:
            spfs_resource.save(spfs)
        results["spfs"] = len(spfs)

    if selected["return_paths"]:
        try:
            return_paths = return_paths_resource.list(compartment_id=comp_id)
        except Exception as e:
            UtilityTools.dlog(True, "list_return_paths failed", err=f"{type(e).__name__}: {e}")
            return_paths = []
        for row in return_paths:
            if isinstance(row, dict):
                row.setdefault("compartment_id", comp_id)
        UtilityTools.print_limited_table(return_paths, return_paths_resource.COLUMNS)
        if args.save:
            return_paths_resource.save(return_paths)
        results["return_paths"] = len(return_paths)

    if selected["suppressions"]:
        try:
            suppressions = suppressions_resource.list(compartment_id=comp_id)
        except Exception as e:
            UtilityTools.dlog(True, "list_suppressions failed", err=f"{type(e).__name__}: {e}")
            suppressions = []
        for row in suppressions:
            if isinstance(row, dict):
                row.setdefault("compartment_id", comp_id)
        UtilityTools.print_limited_table(suppressions, suppressions_resource.COLUMNS)
        if args.save:
            suppressions_resource.save(suppressions)
        results["suppressions"] = len(suppressions)

    if selected["email_configuration"]:
        try:
            cfg_row = email_configuration_resource.get(compartment_id=comp_id)
        except Exception as e:
            UtilityTools.dlog(True, "get_email_configuration failed", err=f"{type(e).__name__}: {e}")
            cfg_row = {}
        if cfg_row:
            cfg_row.setdefault("compartment_id", comp_id)
            UtilityTools.print_limited_table(
                [cfg_row],
                email_configuration_resource.COLUMNS,
            )
            if args.save:
                email_configuration_resource.save([cfg_row])
            results["email_configuration"] = 1
        else:
            results["email_configuration"] = 0

    if not any(k in results for k in ("senders", "domains", "dkims", "spfs", "return_paths", "suppressions", "email_configuration")):
        UtilityTools.dlog(debug, "No email resources returned")

    return results
