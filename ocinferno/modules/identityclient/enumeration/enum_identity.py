#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.modules.identityclient.utilities.helpers import (
    IdentityDomainsResource,
    IdentityIamResource,
    IdentityIddApiKeysResource,
    IdentityIddAppRolesResource,
    IdentityIddAppsResource,
    IdentityIddAuthTokensResource,
    IdentityIddGrantsResource,
    IdentityIddPasswordPoliciesResource,
    IdentityPrincipalsResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("domains", "domains", "Enumerate identity domains"),
    ("iam", "iam", "Enumerate classic IAM policies"),
    ("principals", "principals", "Enumerate principals"),
    ("idd_apps", "idd_apps", "Enumerate identity domain applications"),
    ("idd_app_roles", "idd_app_roles", "Enumerate identity domain app roles"),
    ("idd_api_keys", "idd_api_keys", "Enumerate identity domain API keys"),
    ("idd_auth_tokens", "idd_auth_tokens", "Enumerate identity domain auth tokens"),
    ("idd_grants", "idd_grants", "Enumerate identity domain grants"),
    ("idd_password_policies", "idd_password_policies", "Enumerate identity domain password policies"),
]


CACHE_TABLES = {
    "domains": ("identity_domains", "compartment_id"),
    "iam": ("identity_policies", "compartment_id"),
    "principals": None,
    "idd_apps": ("identity_domain_apps", None),
    "idd_app_roles": ("identity_domain_app_roles", None),
    "idd_api_keys": ("identity_domain_user_api_keys", None),
    "idd_auth_tokens": ("identity_domain_user_auth_tokens", None),
    "idd_grants": ("identity_domain_grants", None),
    "idd_password_policies": ("identity_domain_password_policies", None),
}


def _component_error_summary(err: Exception) -> str:
    status = getattr(err, "status", None)
    code = getattr(err, "code", None)
    msg = getattr(err, "message", None)
    if status is not None or code is not None:
        return f"status={status}, code={code}, message={msg or str(err)}"
    return f"{type(err).__name__}: {err}"


def _parse_args(user_args):
    def _add_principals_passthrough_flags(parser):
        # These are pass-through flags handled by IdentityPrincipalsResource.
        # We register them here so `modules run enum_identity --help` surfaces them.
        parser.add_argument("--idd", "--idd-only", dest="idd_only", action="store_true", help="(principals) Enumerate IDD principals only.")
        parser.add_argument(
            "--classic",
            "--classic-only",
            dest="classic_only",
            action="store_true",
            help="(principals) Enumerate classic principals only.",
        )
        parser.add_argument("--users", action="store_true", help="(principals) Include users.")
        parser.add_argument("--groups", action="store_true", help="(principals) Include groups.")
        parser.add_argument("--dynamic-groups", action="store_true", help="(principals) Include dynamic groups.")
        parser.add_argument("--memberships", action="store_true", help="(principals) Include user-group memberships.")
        parser.add_argument("--domain-filter", help="(principals) Filter IDD domains by substring.")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate Identity Client resources",
        components=COMPONENTS,
        add_extra_args=_add_principals_passthrough_flags,
        include_get=False,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    resource_map = {
        "domains": IdentityDomainsResource(session=session),
        "iam": IdentityIamResource(session=session),
        "principals": IdentityPrincipalsResource(session=session),
        "idd_apps": IdentityIddAppsResource(session=session),
        "idd_app_roles": IdentityIddAppRolesResource(session=session),
        "idd_api_keys": IdentityIddApiKeysResource(session=session),
        "idd_auth_tokens": IdentityIddAuthTokensResource(session=session),
        "idd_grants": IdentityIddGrantsResource(session=session),
        "idd_password_policies": IdentityIddPasswordPoliciesResource(session=session),
    }

    results = []
    for key, _suffix, _help in COMPONENTS:
        if not selected.get(key, False):
            continue
        try:
            results.append(resource_map[key].list(user_args=user_args))
        except Exception as err:
            print(f"[*] enum_identity.{key}: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": key, "error": _component_error_summary(err)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
