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
    IdentityIddMfaSettingsResource,
    IdentityIddPasswordPoliciesResource,
    IdentityPrincipalsResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("list_domains", "list_domains", "Enumerate identity domains from OCI API"),
    ("iam", "iam", "Enumerate classic IAM policies"),
    ("principals", "principals", "Enumerate principals"),
    ("idd_apps", "idd_apps", "Enumerate identity domain applications"),
    ("idd_app_roles", "idd_app_roles", "Enumerate identity domain app roles"),
    ("idd_api_keys", "idd_api_keys", "Enumerate identity domain API keys"),
    ("idd_auth_tokens", "idd_auth_tokens", "Enumerate identity domain auth tokens"),
    ("idd_grants", "idd_grants", "Enumerate identity domain grants"),
    ("idd_password_policies", "idd_password_policies", "Enumerate identity domain password policies"),
    ("idd_mfa_settings", "idd_mfa_settings", "Enumerate identity domain MFA / authentication factor settings"),
]


CACHE_TABLES = {
    "list_domains": ("identity_domains", "compartment_id"),
    "iam": ("identity_policies", "compartment_id"),
    "principals": None,
    "idd_apps": ("identity_domain_apps", None),
    "idd_app_roles": ("identity_domain_app_roles", None),
    "idd_api_keys": ("identity_domain_user_api_keys", None),
    "idd_auth_tokens": ("identity_domain_user_auth_tokens", None),
    "idd_grants": ("identity_domain_grants", None),
    "idd_password_policies": ("identity_domain_password_policies", None),
    "idd_mfa_settings": ("identity_domain_authentication_factor_settings", None),
}


from ocinferno.core.utils.service_runtime import component_soft_skip_or_error


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
        parser.add_argument(
            "--domain-urls", dest="domain_urls", nargs="+", default=[],
            help="(all IDD components) One or more Identity Domain endpoints; used when no domains are cached.",
        )

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
        "list_domains": IdentityDomainsResource(session=session),
        "iam": IdentityIamResource(session=session),
        "principals": IdentityPrincipalsResource(session=session),
        "idd_apps": IdentityIddAppsResource(session=session),
        "idd_app_roles": IdentityIddAppRolesResource(session=session),
        "idd_api_keys": IdentityIddApiKeysResource(session=session),
        "idd_auth_tokens": IdentityIddAuthTokensResource(session=session),
        "idd_grants": IdentityIddGrantsResource(session=session),
        "idd_password_policies": IdentityIddPasswordPoliciesResource(session=session),
        "idd_mfa_settings": IdentityIddMfaSettingsResource(session=session),
    }

    # When --domain-urls and --get are both present, resolve + save each domain URL once
    # here so all components can find the domain in the DB cache rather than each making
    # their own SCIM round-trip.
    if args.domain_urls and "--get" in list(user_args):
        _suite = resource_map["principals"]
        compartment_id = getattr(session, "selected_compartment_id", "") or ""
        for _url in args.domain_urls:
            _suite._try_save_manual_domain(_url, compartment_id)

    results = []
    for key, _suffix, _help in COMPONENTS:
        if not selected.get(key, False):
            continue
        try:
            results.append(resource_map[key].list(user_args=user_args))
        except Exception as err:
            results.append(component_soft_skip_or_error(err, component=key, module_name="enum_identity"))

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
