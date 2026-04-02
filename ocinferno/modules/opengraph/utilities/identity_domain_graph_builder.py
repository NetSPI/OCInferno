#!/usr/bin/env python3
"""
identity_domain_graph_builder.py

Unified Identity Domain relationships -> OpenGraph.

Creates:
  Phase 1 (resource topology/context):
    UserApiKey --USER_API_KEY--> User
    UserSmtpCredential --USER_SMTP_CRED--> User
    UserSmtpCredential --SMTP_AUTH_TO_EMAIL_SERVICE--> EmailService(scope)

  Phase 2 (IDD app role grants/impact):
    Principal --APP_ROLE_GRANTED--> AppRole --ROLE_IN_APPLICATION--> App
    AppRole --IDD_*--> Target nodes (role handlers)
"""

from __future__ import annotations

import json
import re
from collections import Counter

from ocinferno.modules.opengraph.utilities.helpers import (
    build_edge_properties as _build_edge_properties,
    EDGE_CATEGORY_PERMISSION,
    EDGE_CATEGORY_RESOURCE,
    json_list as _json_list_shared,
    json_load as _json_load_shared,
    synthetic_principal_id as _synthetic_principal_id,
)
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    NODE_TYPE_OCI_DYNAMIC_GROUP as NODE_DG,
    NODE_TYPE_OCI_GROUP as NODE_GROUP,
    NODE_TYPE_OCI_USER as NODE_USER,
)
from ocinferno.modules.opengraph.utilities.helpers.context import _dlog
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import (
    ensure_edge as _ensure_edge_shared,
    get_og_state as _og_shared,
    ensure_scope_node as _ensure_scope_node_shared,
    fetch_rows_cached as _fetch_rows_cached,
)


# Tables
TABLE_DOMAINS = "identity_domains"
TABLE_IDD_USERS = "identity_domain_users"
TABLE_IDD_APPS = "identity_domain_apps"
TABLE_IDD_APP_ROLES = "identity_domain_app_roles"
TABLE_IDD_GRANTS = "identity_domain_grants"
TABLE_IDD_USER_API_KEYS = "identity_domain_user_api_keys"
TABLE_IDD_USER_SMTP_CREDS = "identity_domain_user_smtp_credentials"
TABLE_OG_NODES = "opengraph_nodes"


# Node types
NODE_APP = "OCIIDDApplication"
NODE_ROLE = "OCIIDDAppRole"
NODE_USER_API_KEY = "OCIIdentityDomainUserApiKey"
NODE_USER_SMTP_CRED = "OCIIdentityDomainUserSmtpCredential"
NODE_EMAIL_SERVICE = "OCIEmailService"


# Edge types
EDGE_USER_API_KEY = "USER_API_KEY"
EDGE_USER_SMTP_CRED = "USER_SMTP_CRED"
EDGE_SMTP_AUTH_TO_EMAIL_SERVICE = "SMTP_AUTH_TO_EMAIL_SERVICE"
EDGE_IDD_CREATE_USER = "IDD_CREATE_USER"
EDGE_SCOPE_MEMBER_OF = "OCI_SCOPE_MEMBER_OF"


def _s(x):
    if x is None:
        return ""
    return x.strip() if isinstance(x, str) else str(x)


def _json_obj_or_list(value):
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        sv = value.strip()
        if not sv:
            return value
        if sv.startswith("{") or sv.startswith("["):
            try:
                parsed = json.loads(sv)
                return parsed if isinstance(parsed, (dict, list)) else value
            except Exception:
                return value
    return value


def _write_edge_json(
    ctx,
    *,
    src_id: str,
    src_type: str,
    dst_id: str,
    dst_type: str,
    edge_type: str,
    payload: dict,
    edge_category: str = EDGE_CATEGORY_PERMISSION,
):
    _ensure_edge_shared(
        ctx,
        src_id=src_id,
        src_type=src_type,
        dst_id=dst_id,
        dst_type=dst_type,
        edge_type=edge_type,
        edge_properties=_build_edge_properties(
            edge_category=edge_category,
            edge_inner_properties=payload if isinstance(payload, dict) else {},
        ),
        commit=False,
        on_conflict="ignore",
        dedupe=True,
    )


def _domain_display(row: dict) -> str:
    return _s(row.get("display_name") or row.get("name") or row.get("id") or "IdentityDomain")


def _domain_url(row: dict) -> str:
    return _s(row.get("url") or row.get("home_region_url") or "")


def _short_ocid(ocid: str, keep_head: int = 8, keep_tail: int = 6) -> str:
    s = _s(ocid)
    if not s:
        return ""
    if not s.startswith("ocid1."):
        return s if len(s) <= (keep_head + keep_tail + 3) else f"{s[:keep_head]}...{s[-keep_tail:]}"
    token = s.split("..", 1)[1] if ".." in s else s.rsplit(".", 1)[-1]
    token = token or s
    if len(token) <= (keep_head + keep_tail + 3):
        return token
    return f"{token[:keep_head]}...{token[-keep_tail:]}"


def _ensure_email_service_node(ctx, *, loc: str, tenant_id: str) -> str:
    loc = _s(loc)
    if not loc:
        return ""
    node_id = f"email-service@{loc}"
    display_loc = _s((getattr(ctx, "compartment_name_by_id", {}) or {}).get(loc) or "")
    if not display_loc:
        display_loc = "TENANCY" if (_s(tenant_id) and loc == _s(tenant_id)) else _short_ocid(loc)
    display = f"EmailService@{display_loc}"
    ctx.upsert_node(
        node_id=node_id,
        node_type=NODE_EMAIL_SERVICE,
        display_name=display,
        compartment_id=loc,
        tenant_id=tenant_id or ctx.tenant_for_compartment(loc),
        node_properties={"location": loc, "service": "email", "protocol": "smtp"},
        commit=False,
    )
    return node_id


def _iter_ref_values(raw_val) -> list[str]:
    out = []
    refs = _json_obj_or_list(raw_val)
    if isinstance(refs, dict):
        refs = [refs]
    if isinstance(refs, list):
        for g in refs:
            if isinstance(g, dict):
                val = g.get("value") or g.get("id") or g.get("ocid") or g.get("display")
            else:
                val = g
            if isinstance(val, str) and val.strip():
                out.append(val.strip())
    elif isinstance(refs, str) and refs.strip():
        out.append(refs.strip())
    return out


def _table_rows(session, cache: dict, table_name: str) -> list[dict]:
    raw = _fetch_rows_cached(
        session,
        cache,
        table=table_name,
        cache_key=("table_only", table_name),
    )
    return [r for r in (raw or []) if isinstance(r, dict)]


def _resolve_ref_row(ref_value: str, *, by_scim: dict, by_ocid: dict) -> tuple[str, dict | None]:
    ref = _s(ref_value)
    if not ref:
        return "", None
    if ref.startswith("ocid1."):
        return ref, by_ocid.get(ref)
    row = by_scim.get(ref)
    if row and _s(row.get("ocid")):
        return _s(row.get("ocid")), row
    return ref, row


def _ensure_user_node_from_ref(
    *,
    ctx,
    did: str,
    domain_url: str,
    user_ref: str,
    user_by_scim: dict,
    user_by_ocid: dict,
    default_compartment_id: str,
    default_tenant_id: str,
) -> str:
    user_node_id, user_row = _resolve_ref_row(
        user_ref,
        by_scim=user_by_scim,
        by_ocid=user_by_ocid,
    )
    if not user_node_id:
        return ""

    row = user_row or {}
    # Prefer stable login-style identifiers for user node labels when available.
    # Display names can collide (e.g., "PROD User" for multiple accounts).
    user_display = _s(
        row.get("user_name")
        or row.get("name")
        or row.get("display_name")
        or user_node_id
    )
    user_comp = _s(row.get("compartment_ocid") or default_compartment_id)
    user_tenant = _s(row.get("tenancy_ocid") or default_tenant_id)

    ctx.upsert_node(
        node_id=user_node_id,
        node_type=NODE_USER,
        display_name=user_display,
        compartment_id=user_comp,
        tenant_id=user_tenant or ctx.tenant_for_compartment(user_comp),
        node_properties={
            **(dict(row) if isinstance(row, dict) else {"domain_ocid": did}),
            "domain_url": domain_url,
        },
        commit=False,
    )
    return user_node_id


def _link_credential_to_users(
    *,
    ctx,
    did: str,
    domain_url: str,
    credential_node_id: str,
    credential_node_type: str,
    user_refs: list[str],
    user_by_scim: dict,
    user_by_ocid: dict,
    default_compartment_id: str,
    default_tenant_id: str,
    edge_type: str,
    edge_description: str,
):
    for user_ref in user_refs:
        user_node_id = _ensure_user_node_from_ref(
            ctx=ctx,
            did=did,
            domain_url=domain_url,
            user_ref=user_ref,
            user_by_scim=user_by_scim,
            user_by_ocid=user_by_ocid,
            default_compartment_id=default_compartment_id,
            default_tenant_id=default_tenant_id,
        )
        if not user_node_id:
            continue
        _write_edge_json(
            ctx,
            src_id=credential_node_id,
            src_type=credential_node_type,
            dst_id=user_node_id,
            dst_type=NODE_USER,
            edge_type=edge_type,
            payload={"description": edge_description},
            edge_category=EDGE_CATEGORY_RESOURCE,
        )


def _build_identity_domain_resource_graph_offline(*, session, ctx, debug=True, **_):
    ctx.refresh_opengraph_state(force=False)

    table_cache = {}
    domains = _table_rows(session, table_cache, TABLE_DOMAINS)

    if not domains:
        return {"ok": True, "domains": 0, "edges": 0}

    # identity_domains primary key is `id` (OCID), so key directly on that field.
    domain_by_id = {
        d["id"]: d
        for d in domains
        if isinstance(d.get("id"), str) and d.get("id")
    }

    # Build user lookup for API keys / SMTP credentials
    idd_users = _table_rows(session, table_cache, TABLE_IDD_USERS)
    user_by_scim = {u["id"]: u for u in idd_users if isinstance(u.get("id"), str) and u.get("id")}
    user_by_ocid = {u["ocid"]: u for u in idd_users if isinstance(u.get("ocid"), str) and u.get("ocid")}

    stats = {
        "domains": 0,
        "domain_resource_edges": 0,
    }
    stats["domains"] = len(domain_by_id)

    # Apps: node_id follows the IDD app-role section convention in this module.
    apps = _table_rows(session, table_cache, TABLE_IDD_APPS)
    for app in apps:
        did = _s(app.get("domain_ocid") or "")
        app_id = _s(app.get("id") or "")
        if not did or not app_id or did not in domain_by_id:
            continue
        app_nid = _s(app.get("ocid") or "")
        if not app_nid:
            continue
        display = _s(app.get("display_name") or app_id)
        comp_id = _s(app.get("compartment_ocid") or "")
        tenant_id = _s(app.get("tenancy_ocid") or "")
        ctx.upsert_node(
            node_id=app_nid,
            node_type=NODE_APP,
            display_name=display,
            compartment_id=comp_id,
            tenant_id=tenant_id or ctx.tenant_for_compartment(comp_id),
            node_properties={
                **dict(app),
                "domain_url": _domain_url(domain_by_id.get(did) or {}),
            },
            commit=False,
        )
        # Intentionally no IdentityDomain -> app edge.

    # User API Keys
    api_keys = _table_rows(session, table_cache, TABLE_IDD_USER_API_KEYS)
    for k in api_keys:
        did = _s(k.get("domain_ocid") or "")
        if not did or did not in domain_by_id:
            continue
        key_id = _s(k.get("id") or "")
        key_node_id = _s(k.get("ocid") or "")
        if not key_node_id:
            continue
        comp_id = _s(k.get("compartment_ocid") or "")
        tenant_id = _s(k.get("tenancy_ocid") or "")
        domain_url = _domain_url(domain_by_id.get(did) or {})
        display = _s(k.get("description") or k.get("fingerprint") or key_id or key_node_id)
        ctx.upsert_node(
            node_id=key_node_id,
            node_type=NODE_USER_API_KEY,
            display_name=display,
            compartment_id=comp_id,
            tenant_id=tenant_id or ctx.tenant_for_compartment(comp_id),
            node_properties={
                **dict(k),
                "domain_url": domain_url,
                "user_ref": _json_obj_or_list(k.get("user")),
            },
            commit=False,
        )

        _link_credential_to_users(
            ctx=ctx,
            did=did,
            domain_url=domain_url,
            credential_node_id=key_node_id,
            credential_node_type=NODE_USER_API_KEY,
            user_refs=_iter_ref_values(k.get("user")),
            user_by_scim=user_by_scim,
            user_by_ocid=user_by_ocid,
            default_compartment_id=comp_id,
            default_tenant_id=tenant_id,
            edge_type=EDGE_USER_API_KEY,
            edge_description="API key belongs to user.",
        )

    # SMTP Credentials
    smtp_creds = _table_rows(session, table_cache, TABLE_IDD_USER_SMTP_CREDS)
    for c in smtp_creds:
        did = _s(c.get("domain_ocid") or "")
        if not did or did not in domain_by_id:
            continue
        cred_node_id = _s(c.get("ocid") or "")
        if not cred_node_id:
            continue
        comp_id = _s(c.get("compartment_ocid") or "")
        tenant_id = _s(c.get("tenancy_ocid") or "")
        domain_url = _domain_url(domain_by_id.get(did) or {})
        display = _s(c.get("description") or c.get("user_name") or cred_node_id)
        ctx.upsert_node(
            node_id=cred_node_id,
            node_type=NODE_USER_SMTP_CRED,
            display_name=display,
            compartment_id=comp_id,
            tenant_id=tenant_id or ctx.tenant_for_compartment(comp_id),
            node_properties={
                **dict(c),
                "domain_url": domain_url,
                "user_ref": _json_obj_or_list(c.get("user")),
            },
            commit=False,
        )

        email_service_node_id = _ensure_email_service_node(
            ctx,
            loc=comp_id,
            tenant_id=tenant_id,
        )
        if email_service_node_id:
            _write_edge_json(
                ctx,
                src_id=cred_node_id,
                src_type=NODE_USER_SMTP_CRED,
                dst_id=email_service_node_id,
                dst_type=NODE_EMAIL_SERVICE,
                edge_type=EDGE_SMTP_AUTH_TO_EMAIL_SERVICE,
                payload={"description": "SMTP credential can authenticate to OCI Email service."},
                edge_category=EDGE_CATEGORY_RESOURCE,
            )

        _link_credential_to_users(
            ctx=ctx,
            did=did,
            domain_url=domain_url,
            credential_node_id=cred_node_id,
            credential_node_type=NODE_USER_SMTP_CRED,
            user_refs=_iter_ref_values(c.get("user")),
            user_by_scim=user_by_scim,
            user_by_ocid=user_by_ocid,
            default_compartment_id=comp_id,
            default_tenant_id=tenant_id,
            edge_type=EDGE_USER_SMTP_CRED,
            edge_description="SMTP credential belongs to user.",
        )

    if debug:
        _dlog(debug, "identity-domain: graph build complete", **stats)
    return {"ok": True, **stats}


def build_identity_domain_graph_offline(*, session, ctx, debug=True, include_all=None, allowlist=None, auto_commit=True, **kwargs):
    """
    Unified Identity Domain stage:
      1) resource topology/credential graph
      2) IDD app role grant + role-impact graph
    """
    resources_res = _build_identity_domain_resource_graph_offline(
        session=session,
        ctx=ctx,
        debug=debug,
        **kwargs,
    )
    app_roles_res = build_idd_app_role_graph_offline(
        session=session,
        ctx=ctx,
        debug=debug,
        include_all=include_all,
        allowlist=allowlist,
        auto_commit=auto_commit,
        **kwargs,
    )

    ok = bool((resources_res or {}).get("ok", True)) and bool((app_roles_res or {}).get("ok", True))
    out = {
        "ok": ok,
        "resources": resources_res if isinstance(resources_res, dict) else {"ok": True, "result": resources_res},
        "app_roles": app_roles_res if isinstance(app_roles_res, dict) else {"ok": True, "result": app_roles_res},
    }
    if debug:
        _dlog(debug, "identity-domain: unified stage complete", ok=ok)
    return out


# --------------------------------------------------------------------------------------
# Collapsed IDD App Role Graph Builder
# --------------------------------------------------------------------------------------
_PRINCIPAL_KIND_BY_NODE = {
    NODE_USER: "user",
    NODE_GROUP: "group",
    NODE_DG: "dynamic-group",
}
_NODE_TYPE_BY_KIND = {
    "user": NODE_USER,
    "group": NODE_GROUP,
    "dynamic-group": NODE_DG,
}


# -----------------------------
# Edge types
# -----------------------------
EDGE_APP_ROLE_GRANTED = "APP_ROLE_GRANTED"
EDGE_ROLE_OF_APP = "ROLE_IN_APPLICATION"

# Handler-driven edge (role -> targets)
EDGE_IDD_IDENTITY_ADMIN_USER = "IDD_IDENTITY_ADMIN_USER"
EDGE_IDD_USER_ADMIN = "IDD_USER_ADMIN"
EDGE_IDD_USER_MANAGER = "IDD_USER_MANAGER"
EDGE_IDD_ADD_SELF_TO_GROUP = "IDD_ADD_SELF_TO_GROUP"


# -----------------------------
# Edge descriptions (flat: EDGE_NAME -> [descriptions])
# You add/edit descriptions HERE.
# These are injected into edge description payload under "descriptions".
# -----------------------------
EDGE_DESCRIPTIONS = {
    EDGE_APP_ROLE_GRANTED: [
        "A principal (user, group, or dynamic group) has been granted an Identity Domain application role.",
    ],
    EDGE_ROLE_OF_APP: [
        "This role is defined by the referenced Identity Domain application.",
    ],
    EDGE_IDD_IDENTITY_ADMIN_USER: [
        (
            "Identity Domain Administrator can administer users in the same identity domain.\n"
            "This includes high-impact account-control actions such as credential resets, MFA reset/bypass operations, "
            " and moving users between groups."
        ),
    ],
    EDGE_IDD_USER_ADMIN: [
        (
            "User Administrator can administer users in the same identity domain.\n"
            "This includes high-impact account-control actions such as credential resets, MFA reset/bypass operations."
        ),
    ],
    EDGE_IDD_USER_MANAGER: [
        (
            "User Manager can administer users in the same identity domain.\n"
            "This includes high-impact account-control actions such as credential resets, MFA reset/bypass operations."
            "User Manager control might be constrained to specific users/groups within a given identity domain."        
        ),
    ],
    EDGE_IDD_ADD_SELF_TO_GROUP: [
        (
            "The role assignee can add itself to eligible OCI groups in the same identity domain.\n"
        ),
    ],
    EDGE_IDD_CREATE_USER: [
        (
            "Principal can create IAM users in scope "
            "(modeled as principal -> <identity_domain>/new_user@location capability edge)."
        ),
    ],
}

# IDD roles that should emit baseline IAM create-user capability edges.
_IDD_ROLES_WITH_CREATE_USER_CAP = {
    "Identity Domain Administrator",
    "User Administrator",
}


def _idd_domain_scope_prefix(ctx, domain_ocid: str) -> str:
    name = _domain_name_for_ocid(ctx, domain_ocid)
    if not name:
        name = "TargetIdentityDomain"
    safe = re.sub(r"\s+", "_", _s(name))
    safe = safe.replace("/", "_").replace("@", "_").strip("_")
    return safe or "TargetIdentityDomain"


# -----------------------------
# Exact allowlist only (case-insensitive exact)
# -----------------------------
DEFAULT_ALLOWLIST = frozenset(
    {
        ("idcsappid", "identity domain administrator"),
        ("idcsappid", "user administrator"),
        ("idcsappid", "user manager"),
    }
)


def _allowlisted(app_id, role_name, allowlist):
    if not allowlist:
        return True
    app = app_id.strip().lower() if isinstance(app_id, str) else ""
    role = role_name.strip().lower() if isinstance(role_name, str) else ""
    pair = (app, role)
    return pair in allowlist


def _edge_desc(edge_type):
    """Return list[str] descriptions for a given edge type."""
    v = EDGE_DESCRIPTIONS.get(edge_type)
    return v if isinstance(v, list) else []


# -----------------------------
# Domain display helpers
# -----------------------------
def _domain_name_for_ocid(ctx, dom_ocid):
    dom_ocid = dom_ocid.strip() if isinstance(dom_ocid, str) else ""
    if not dom_ocid:
        return ""

    m = getattr(ctx, "domain_name_by_ocid", None)
    if isinstance(m, dict):
        v = m.get(dom_ocid) or ""
        dn = v.strip() if isinstance(v, str) else ""
        if dn:
            return dn

    return ""


def _prefix_domain_display(ctx, dom_ocid, label):
    label = label.strip() if isinstance(label, str) else ""
    if not label:
        return ""
    dn = _domain_name_for_ocid(ctx, dom_ocid)
    if dn and "/" not in label:
        return f"{dn}/{label}"
    return label


# -----------------------------
# Principal indexing / helpers
# -----------------------------
def _principal_kind(node_type):
    return _PRINCIPAL_KIND_BY_NODE.get(node_type, "")

def _grant_kind_and_scim(grantee_obj):
    """
    grantee_obj is parsed dict from grants.grantee
    Returns: (kind, scim_id) where kind in {"user","group","dynamic-group"}.
    """
    t = grantee_obj.get("type")
    scim = grantee_obj.get("value")
    t = t.strip().lower() if isinstance(t, str) else ""
    scim = scim.strip() if isinstance(scim, str) else ""

    if t in ("dynamicgroup", "dynamic-group"):
        return ("dynamic-group", scim) if scim else ("", "")
    if t in ("user", "group"):
        return (t, scim) if scim else ("", "")
    return ("", "")


def _load_opengraph_principal_index(session, debug=False):
    """Build {(kind, domain_ocid, scim_id): node_id} from current OpenGraph nodes."""
    rows = session.get_resource_fields(
        TABLE_OG_NODES,
        columns=["node_type", "node_id", "node_properties"],
    ) or []
    principal_idx = {}

    for r in rows:

        ntype = _s(r.get("node_type"))
        if ntype not in (NODE_USER, NODE_GROUP, NODE_DG):
            continue

        node_id = _s(r.get("node_id"))
        if not node_id:
            continue

        ex = _json_load_shared(r.get("node_properties"), dict)
        did = _s(ex.get("domain_ocid"))
        if not did:
            continue

        scim = _s(ex.get("scim_id"))
        if scim:
            kind = _principal_kind(ntype)
            principal_idx[(kind, did, scim)] = node_id

    if debug:
        _dlog(
            debug,
            "idd_app_roles: principal index built",
            principal_idx_entries=len(principal_idx),
        )
    return principal_idx


def _expand_identity_admin_users_via_group_assignment(
    *,
    users_by_domain,
    protected_users_by_domain,
    protected_groups_by_domain,
    group_member_mapping_cache,
):
    """
    Expand protected users with members of groups assigned a protected role.

    This helper is used for both Identity Domain Administrator and
    User Administrator exclusion sets so role emitters can suppress
    targets that inherit protected roles through group assignment.
    """
    expanded_users = {did: set(uids or set()) for did, uids in (protected_users_by_domain or {}).items()}
    if not isinstance(group_member_mapping_cache, dict) or not group_member_mapping_cache:
        return expanded_users, 0

    user_domain_by_id = {}
    for did, rows in (users_by_domain or {}).items():
        for nid, ntype in (rows or []):
            if ntype == NODE_USER and nid:
                user_domain_by_id[nid] = did

    added = 0
    for did, group_ids in (protected_groups_by_domain or {}).items():
        if not did:
            continue
        bucket = expanded_users.setdefault(did, set())
        for gid in (group_ids or set()):
            if not gid:
                continue
            members = group_member_mapping_cache.get(gid)
            if not members:
                continue
            if isinstance(members, dict):
                member_ids = members.keys()
            elif isinstance(members, (set, list, tuple)):
                member_ids = members
            else:
                continue

            for uid_raw in member_ids:
                uid = _s(uid_raw)
                if not uid:
                    continue

                # Guardrail: keep the protected user in-domain when known.
                member_domain = user_domain_by_id.get(uid)
                if member_domain and member_domain != did:
                    continue

                if uid not in bucket:
                    bucket.add(uid)
                    added += 1

    return expanded_users, added


def _get_cached_nodes_by_domain(session, ctx, *, node_type, cache_attr, debug=False):
    cached = getattr(ctx, cache_attr, None)
    if isinstance(cached, dict):
        return cached

    out = {}
    rows = session.get_resource_fields(
        TABLE_OG_NODES,
        columns=["node_type", "node_id", "node_properties"],
        where_conditions={"node_type": node_type},
    ) or []
    for r in rows:
        node_id = _s(r.get("node_id"))
        if not node_id:
            continue
        props = _json_load_shared(r.get("node_properties"), dict)
        did = _s(props.get("domain_ocid"))
        if not did:
            continue
        out.setdefault(did, []).append((node_id, node_type))
    try:
        setattr(ctx, cache_attr, out)
    except Exception:
        pass
    if debug:
        _dlog(
            debug,
            "idd_app_roles: cached principals by domain",
            node_type=node_type,
            domains=len(out),
            principals=sum(len(v) for v in out.values()),
        )
    return out


def _get_cached_users_by_domain(session, ctx, debug=False):
    return _get_cached_nodes_by_domain(
        session,
        ctx,
        node_type=NODE_USER,
        cache_attr="_idd_users_by_domain_cache",
        debug=debug,
    )


def _get_cached_groups_by_domain(session, ctx, debug=False):
    return _get_cached_nodes_by_domain(
        session,
        ctx,
        node_type=NODE_GROUP,
        cache_attr="_idd_groups_by_domain_cache",
        debug=debug,
    )


def _emit_role_to_users(
    ctx,
    *,
    role_id,
    role_name,
    app_id,
    app_name,
    domain_ocid,
    users_by_domain,
    edge_type,
    handler_name,
    protected_user_ids=None,
    role_scope=None,
    debug=False,
):
    did = _s(domain_ocid)
    if not did:
        return 0, 0

    targets = users_by_domain.get(did) or []
    if not targets:
        _dlog(debug, f"idd_app_roles: {edge_type} has no targets", domain_ocid=did, role_id=role_id)
        return 0, 0

    protected = set(protected_user_ids or set())
    emitted = 0
    skipped_protected = 0

    for (dst_id, dst_type) in targets:
        if not dst_id:
            continue
        if dst_id in protected:
            skipped_protected += 1
            continue

        desc = {
            "domain_ocid": did,
            "role_name": role_name,
            "app_id": app_id,
            "app_name": app_name,
            "handler": handler_name,
            "descriptions": _edge_desc(edge_type),
        }
        if role_scope is not None:
            desc["role_scope"] = role_scope

        _write_edge_json(
            ctx,
            src_id=role_id,
            src_type=NODE_ROLE,
            dst_id=dst_id,
            dst_type=dst_type,
            edge_type=edge_type,
            payload=desc,
        )
        emitted += 1

    return emitted, skipped_protected


def _emit_role_to_groups(
    ctx,
    *,
    role_id,
    role_name,
    app_id,
    app_name,
    domain_ocid,
    groups_by_domain,
    edge_type,
    handler_name,
    protected_group_ids=None,
    role_scope=None,
    debug=False,
):
    did = _s(domain_ocid)
    if not did:
        return 0, 0

    targets = groups_by_domain.get(did) or []
    if not targets:
        _dlog(debug, f"idd_app_roles: {edge_type} has no targets", domain_ocid=did, role_id=role_id)
        return 0, 0

    protected = set(protected_group_ids or set())
    emitted = 0
    skipped_protected = 0
    for (dst_id, dst_type) in targets:
        if not dst_id:
            continue
        if dst_id in protected:
            skipped_protected += 1
            continue

        desc = {
            "domain_ocid": did,
            "role_name": role_name,
            "app_id": app_id,
            "app_name": app_name,
            "handler": handler_name,
            "descriptions": _edge_desc(edge_type),
        }
        if role_scope is not None:
            desc["role_scope"] = role_scope

        _write_edge_json(
            ctx,
            src_id=role_id,
            src_type=NODE_ROLE,
            dst_id=dst_id,
            dst_type=dst_type or NODE_GROUP,
            edge_type=edge_type,
            payload=desc,
        )
        emitted += 1
    return emitted, skipped_protected


# APP_ROLE behavior registry.
# Add new modeled IDD app-role behavior in one place:
#   1) Add edge descriptions in EDGE_DESCRIPTIONS.
#   2) Add role mapping entry here.
#      - user_edge_type: Role -> OCIUser edge type (optional)
#      - group_edge_type: Role -> OCIGroup edge type (optional)
#      - exclude_identity_admin_users/groups: whether to suppress protected targets
#      - exclude_user_admin_users/groups: whether to suppress User Administrator-associated targets
#      - *_handler_label: label written into edge payloads
#      - group_stat_slug: stats key suffix for group-edge emissions
APP_ROLE_MODELS = {
    "Identity Domain Administrator": {
        "user_edge_type": EDGE_IDD_IDENTITY_ADMIN_USER,
        "user_handler_label": "Identity Domain Administrator",
        "exclude_identity_admin_users": False,
        "group_edge_type": EDGE_IDD_ADD_SELF_TO_GROUP,
        "group_handler_label": "Identity Domain Administrator",
        "exclude_identity_admin_groups": False,
        "group_stat_slug": "idd_add_self_to_group",
    },
    "User Administrator": {
        "user_edge_type": EDGE_IDD_USER_ADMIN,
        "user_handler_label": "User Administrator",
        "exclude_identity_admin_users": True,
        "group_edge_type": EDGE_IDD_ADD_SELF_TO_GROUP,
        "group_handler_label": "User Administrator",
        "exclude_identity_admin_groups": True,
        "group_stat_slug": "idd_user_admin_add_self_to_group",
    },
    "User Manager": {
        "user_edge_type": EDGE_IDD_USER_MANAGER,
        "user_handler_label": "User Manager",
        "exclude_identity_admin_users": True,
        "exclude_user_admin_users": True,
        "exclude_user_admin_groups": True,
    },
}


def _upsert_idd_app_and_role_nodes(
    *,
    ctx,
    did: str,
    app_id: str,
    app_name: str,
    app_compartment_id: str,
    app_tenant_id: str,
    app_row: dict | None = None,
    role_id: str,
    role_name: str,
    role_compartment_id: str,
    role_tenant_id: str,
    role_row: dict | None = None,
):
    app_nid = _s((app_row or {}).get("ocid")) if isinstance(app_row, dict) else ""
    if not app_nid:
        app_nid = f"iddapp::{did}::{app_id}"
    role_nid = _s((role_row or {}).get("ocid")) if isinstance(role_row, dict) else ""
    if not role_nid:
        role_nid = f"iddrole::{did}::{role_id}"
    ctx.upsert_node(
        node_id=app_nid,
        node_type=NODE_APP,
        display_name=app_name or app_id,
        compartment_id=app_compartment_id,
        tenant_id=app_tenant_id,
        node_properties={
            **(
                dict(app_row)
                if isinstance(app_row, dict)
                else {
                    "domain_ocid": did,
                    "id": app_id,
                    "compartment_ocid": app_compartment_id or None,
                }
            ),
        },
        commit=False,
    )
    ctx.upsert_node(
        node_id=role_nid,
        node_type=NODE_ROLE,
        display_name=role_name or role_id,
        compartment_id=role_compartment_id,
        tenant_id=role_tenant_id,
        node_properties={
            **(
                dict(role_row)
                if isinstance(role_row, dict)
                else {
                    "domain_ocid": did,
                    "id": role_id,
                    "compartment_ocid": role_compartment_id or None,
                }
            ),
        },
        commit=False,
    )
    return app_nid, role_nid


def _emit_role_of_app_edge(
    *,
    ctx,
    did: str,
    role_nid: str,
    role_id: str,
    app_nid: str,
    app_id: str,
    role_name: str = "",
    grant_compartment_ocid: str = "",
    empty_role: bool = False,
):
    payload = {
        "domain_ocid": did,
        "role_id": role_id,
        "app_id": app_id,
        "descriptions": _edge_desc(EDGE_ROLE_OF_APP),
    }
    if role_name:
        payload["role_name"] = role_name
    if grant_compartment_ocid:
        payload["grant_compartment_ocid"] = grant_compartment_ocid
    if empty_role:
        payload["empty_role"] = True
    _write_edge_json(
        ctx,
        src_id=role_nid,
        src_type=NODE_ROLE,
        dst_id=app_nid,
        dst_type=NODE_APP,
        edge_type=EDGE_ROLE_OF_APP,
        payload=payload,
        edge_category=EDGE_CATEGORY_RESOURCE,
    )


def _run_idd_role_emitters(
    *,
    session,
    ctx,
    raw_role_name: str,
    role_nid: str,
    role_name: str,
    app_id: str,
    app_name: str,
    did: str,
    role_scope: dict,
    groups_by_domain: dict,
    idd_admin_groups_by_domain: dict,
    user_admin_groups_by_domain: dict,
    stats: Counter,
    stats_prefix: str,
    debug: bool,
):
    model = APP_ROLE_MODELS.get(raw_role_name)

    user_edge_type = _s(model.get("user_edge_type"))

    # If the app role has edge defs for target users...
    if user_edge_type:
        try:

            # Get all users in current identity domain
            users_by_domain = _get_cached_users_by_domain(session, ctx, debug=debug)
            
            # Retrieve users excluded by modeled protected-role constraints.
            protected_user_ids = set()
            if bool(model.get("exclude_identity_admin_users")):
                protected_users = getattr(ctx, "_idd_identity_admin_users_by_domain_cache", {}) or {}
                protected_user_ids.update(protected_users.get(did) or set())
            if bool(model.get("exclude_user_admin_users")):
                protected_users = getattr(ctx, "_idd_user_admin_users_by_domain_cache", {}) or {}
                protected_user_ids.update(protected_users.get(did) or set())
            
            emitted, skipped_protected_users = _emit_role_to_users(
                ctx,
                role_id=role_nid,
                role_name=role_name,
                app_id=app_id,
                app_name=app_name,
                domain_ocid=did,
                users_by_domain=users_by_domain,
                edge_type=user_edge_type,
                handler_name=_s(model.get("user_handler_label") or raw_role_name),
                protected_user_ids=protected_user_ids,
                role_scope=role_scope,
                debug=debug,
            )
            stats[f"{stats_prefix}role_handlers_ran"] += 1
            stats[f"{stats_prefix}role_handler_edges_emitted"] += int(emitted or 0)
            if debug:
                _dlog(
                    debug,
                    "idd_app_roles: modeled user-edge emit complete",
                    role=raw_role_name,
                    role_id=role_nid,
                    edge_type=user_edge_type,
                    emitted=emitted,
                    skipped_protected_users=skipped_protected_users,
                )
        except Exception as e:
            stats[f"{stats_prefix}role_handler_errors"] += 1
            _dlog(debug, "idd_app_roles: role handler failed", role=raw_role_name, err=f"{type(e).__name__}: {e}")

    group_edge_type = _s(model.get("group_edge_type"))
    if not group_edge_type:
        return

    stat_slug = _s(model.get("group_stat_slug"))
    if not stat_slug:
        stat_slug = "group_edges"
    try:
        protected_group_ids = set()
        if bool(model.get("exclude_identity_admin_groups")):
            protected_group_ids.update((idd_admin_groups_by_domain or {}).get(did) or set())
        if bool(model.get("exclude_user_admin_groups")):
            protected_group_ids.update((user_admin_groups_by_domain or {}).get(did) or set())
        emitted, skipped_protected_groups = _emit_role_to_groups(
            ctx,
            role_id=role_nid,
            role_name=role_name,
            app_id=app_id,
            app_name=app_name,
            domain_ocid=did,
            groups_by_domain=groups_by_domain,
            edge_type=group_edge_type,
            handler_name=_s(model.get("group_handler_label") or raw_role_name),
            protected_group_ids=protected_group_ids,
            role_scope=role_scope,
            debug=debug,
        )
        stats[f"{stats_prefix}{stat_slug}_edges_emitted"] += int(emitted or 0)
        if debug:
            _dlog(
                debug,
                "idd_app_roles: modeled group-edge emit complete",
                role=raw_role_name,
                role_id=role_nid,
                edge_type=group_edge_type,
                emitted=emitted,
                skipped_protected_groups=skipped_protected_groups,
            )
    except Exception as e:
        stats[f"{stats_prefix}{stat_slug}_errors"] += 1
        _dlog(
            debug,
            "idd_app_roles: role group-edge emit failed",
            role=raw_role_name,
            role_id=role_nid,
            emitter=stat_slug,
            err=f"{type(e).__name__}: {e}",
        )


def _build_idd_role_info(
    *,
    ctx,
    roles,
    app_row_by_key,
    compartment_for_row,
    domain_compartment_by_ocid=None,
    stats,
):
    # Input `roles` row shape (identity_domain_app_roles table), examples:
    #   {
    #     "domain_ocid": "ocid1.domain...",
    #     "id": "<role_scim_id>",
    #     "display_name": "User Administrator",
    #     "compartment_ocid": "ocid1.compartment...",
    #     "app": "{\"value\":\"<app_scim_id>\",\"display\":\"IDCSAppId\"}",
    #     "limited_to_one_or_more_groups": true|false|"true"|"false",
    #     "members": "[{...}, ...]"
    #   }
    #
    # Input `app_row_by_key` shape:
    #   {
    #     ("<domain_ocid>", "<app_scim_id>"): <identity_domain_apps row dict>,
    #     ...
    #   }
    #
    # Output 1: role_info
    #   {
    #     ("<domain_ocid>", "<role_scim_id>"): (
    #       "<prefixed_role_display>",
    #       "<app_scim_id>",
    #       "<prefixed_app_display>",
    #       "<role_compartment_ocid>",
    #       "<app_compartment_ocid>",
    #     ),
    #     ...
    #   }
    #
    # Output 2: role_scope_by_role
    #   {
    #     ("<domain_ocid>", "<role_scim_id>"): {
    #       "limited_to_one_or_more_groups": bool,
    #       "members_count": int,
    #       "scope_mode": "selected_groups_or_limited" | "all_users_or_default",
    #     },
    #     ...
    #   }
    role_info = {}
    role_scope_by_role = {}

    # Accept multiple app identifier shapes from identity_domain_app_roles.app:
    # - JSON object (value/display/ref)
    # - plain display/name string (for some enum paths)
    app_lookup_by_alias = {}
    if isinstance(app_row_by_key, dict):
        for key, row in app_row_by_key.items():
            if not (isinstance(key, tuple) and len(key) == 2 and isinstance(row, dict)):
                continue
            app_did = _s(key[0] or "")
            app_id = _s(key[1] or "")
            if not (app_did and app_id):
                continue
            aliases = {
                app_id,
                _s(row.get("display_name") or ""),
                _s(row.get("name") or ""),
                _s(row.get("ocid") or ""),
            }
            for alias in aliases:
                alias_l = _s(alias).lower()
                if alias_l:
                    app_lookup_by_alias.setdefault((app_did, alias_l), (app_id, row))
    
    for r in roles:
        did, rid = _s(r.get("domain_ocid") or ""), _s(r.get("id") or "")
        if not (did and rid):
            stats["roles_skipped_missing_bits"] += 1
            continue

        raw_role_name = r.get("display_name")
        raw_role_name = raw_role_name.strip() if isinstance(raw_role_name, str) else ""
        role_name = _prefix_domain_display(ctx, did, raw_role_name or rid)
        role_comp = compartment_for_row(r)

        appref = _json_load_shared(r.get("app"), dict)
        app_raw = _s(r.get("app") or "")
        aid = _s(appref.get("value") or appref.get("id") or "")
        app_row = app_row_by_key.get((did, aid)) if (aid and isinstance(app_row_by_key, dict)) else None

        # Fallback when `app` is stored as plain label (e.g. "IDCS Application")
        # instead of JSON object with `value`.
        if not aid and app_raw:
            found = app_lookup_by_alias.get((did, app_raw.lower()))
            if found:
                aid, app_row = found

        # Fallback using unique_name prefix pattern: "<app_id>_<role_name>".
        if not aid:
            unique_name = _s(r.get("unique_name") or "")
            if "_" in unique_name:
                app_token_raw = unique_name.split("_", 1)[0].strip()
                app_token = app_token_raw.lower()
                found = app_lookup_by_alias.get((did, app_token))
                if found:
                    aid, app_row = found
                elif app_token_raw:
                    # Some domains can omit IDCSAppId in identity_domain_apps while still
                    # emitting app-role rows (for example "IDCSAppId_User Manager").
                    # Keep the app token so role modeling does not drop these assignments.
                    aid = app_token_raw
                    stats["roles_fallback_app_id_from_unique_name"] += 1

        if not aid:
            stats["roles_skipped_missing_bits"] += 1
            continue

        app_name = _s(appref.get("display") or "") or app_raw
        if not app_name and isinstance(app_row, dict):
            app_name = _s(app_row.get("display_name") or "")
        if not app_name:
            app_name = aid
        app_name = _prefix_domain_display(ctx, did, app_name)

        app_comp = ""
        if isinstance(app_row, dict):
            app_comp = _s(app_row.get("compartment_ocid") or "")
        if not app_comp:
            app_comp = appref.get("compartment_ocid") or ""
            if isinstance(app_comp, str):
                app_comp = app_comp.strip()
            else:
                app_comp = ""
        # Some tenants return blank compartment_ocid for app-role rows.
        # Fall back to the owning app's compartment to preserve role modeling.
        if not role_comp:
            role_comp = app_comp
            stats["roles_fallback_to_app_compartment"] += 1

        # If app/role compartment is still unknown, fall back to domain location.
        domain_comp = _s((domain_compartment_by_ocid or {}).get(did) or "")
        if not app_comp and role_comp:
            app_comp = role_comp
            stats["roles_fallback_app_compartment_from_role"] += 1
        if not app_comp and domain_comp:
            app_comp = domain_comp
            stats["roles_fallback_app_compartment_from_domain"] += 1
        if not role_comp and app_comp:
            role_comp = app_comp
            stats["roles_fallback_to_app_compartment"] += 1
        if not role_comp and domain_comp:
            role_comp = domain_comp
            stats["roles_fallback_role_compartment_from_domain"] += 1
        if not app_comp or not role_comp:
            stats["roles_skipped_missing_compartment"] += 1
            continue

        role_info[(did, rid)] = (role_name, aid, app_name, role_comp, app_comp)
        limited_raw = r.get("limited_to_one_or_more_groups")
        limited_groups = bool(limited_raw) if isinstance(limited_raw, bool) else str(limited_raw).strip().lower() in ("true", "1", "yes")
        members = _json_list_shared(r.get("members"))
        role_scope_by_role[(did, rid)] = {
            "limited_to_one_or_more_groups": limited_groups,
            "members_count": len(members),
            "scope_mode": "selected_groups_or_limited" if limited_groups else "all_users_or_default",
        }
        stats["roles_indexed"] += 1
    return role_info, role_scope_by_role


def build_idd_app_role_graph_offline(
    *,
    session,
    ctx,
    allowlist=None,
    include_all=None,
    auto_commit=True,
    debug=False,
    **_ignored_kwargs,
):
    """
    Offline IDD AppRole grants -> OpenGraph (NO capability nodes).

    Scope behavior:
      - compartment_id is NOT global.
      - We require explicit compartment_ocid per entity row (app / role / grant).
      - If required compartment data is missing, that role/grant path is skipped.
      - tenant_id is derived PER ENTITY via ctx.tenant_for_compartment(_comp_id)
        when a compartment_id is present.

    Display behavior:
      - For App/Role display_name: prefix "DomainName/" when domain name is resolvable from domain_ocid,
        and label does not already contain "/".

    Role handler behavior:
      - After emitting Role->App, run a handler (if configured) to emit Role->Target edges.
    """
    stats = Counter()
    include_all = (
        bool((getattr(ctx, "iam_config", {}) or {}).get("include_all"))
        if include_all is None
        else bool(include_all)
    )
    # allowlist accepted shapes:
    #   - default tuple-pair set: {("idcsappid", "user administrator"), ...}
    allowlist = DEFAULT_ALLOWLIST if allowlist is None else allowlist

    # ---------------------------------------------------------------------
    # Helpers: scope + tenant resolution
    # ---------------------------------------------------------------------
    def _compartment_for_row(row):
        cid = row.get("compartment_ocid") or ""
        cid = cid.strip() if isinstance(cid, str) else ""
        return cid

    def _tenant_for_compartment(cid):
        cid = cid.strip() if isinstance(cid, str) else ""
        if not cid:
            return ""
        try:
            out = ctx.tenant_for_compartment(cid) or ""
            return out.strip() if isinstance(out, str) else ""
        except Exception:
            return ""

    # Existing principal lookup from graph rows:
    #   (kind, domain_ocid, scim_id) -> node_id
    principal_idx = _load_opengraph_principal_index(session, debug=debug)

    table_cache = {}
    apps = _table_rows(session, table_cache, TABLE_IDD_APPS)
    roles = _table_rows(session, table_cache, TABLE_IDD_APP_ROLES)
    grants = _table_rows(session, table_cache, TABLE_IDD_GRANTS)
    domains = _table_rows(session, table_cache, TABLE_DOMAINS)
    # Row lookup maps keyed by (domain_ocid, scim_id).
    # Example: ("ocid1.domain...", "0a1b2c...") -> full DB row dict
    app_row_by_key = {
        (_s(a.get("domain_ocid") or ""), _s(a.get("id") or "")): a
        for a in apps
        if isinstance(a, dict) and _s(a.get("domain_ocid") or "") and _s(a.get("id") or "")
    }
    role_row_by_key = {
        (_s(r.get("domain_ocid") or ""), _s(r.get("id") or "")): r
        for r in roles
        if isinstance(r, dict) and _s(r.get("domain_ocid") or "") and _s(r.get("id") or "")
    }
    domain_compartment_by_ocid = {
        _s(d.get("id") or ""): _s(d.get("compartment_ocid") or d.get("compartment_id") or "")
        for d in domains
        if isinstance(d, dict) and _s(d.get("id") or "")
    }

    role_info, role_scope_by_role = _build_idd_role_info(
        ctx=ctx,
        roles=roles,
        app_row_by_key=app_row_by_key,
        compartment_for_row=_compartment_for_row,
        domain_compartment_by_ocid=domain_compartment_by_ocid,
        stats=stats,
    )
    # role_info:
    #   (domain_ocid, role_scim_id) -> (role_name, app_scim_id, app_name, role_compartment_ocid, app_compartment_ocid)
    # role_scope_by_role:
    #   (domain_ocid, role_scim_id) -> {"limited_to_one_or_more_groups": bool, "members_count": int, "scope_mode": str}

    # ---------------------------------------------------------------------
    # Phase 1: Build principal -> role -> app assignments from grant rows
    # ---------------------------------------------------------------------
    # `gr` row shape example (identity_domain_grants table):
    #   {
    #     "domain_ocid": "ocid1.domain...",
    #     "entitlement": "{\"attribute_name\":\"appRoles\",\"attribute_value\":\"<role_scim_id>\"}",
    #     "grantee": "{\"type\":\"User|Group|DynamicGroup\",\"value\":\"<principal_scim_id>\"}",
    #     "compartment_ocid": "ocid1.compartment...",
    #   }
    #
    # Local tracking maps:
    # - idd_admin_*_by_domain: Identity Domain Administrator exclusion sets
    # - user_admin_*_by_domain: User Administrator exclusion sets (used by User Manager model)
    # - new_*_ids_by_domain: newly created principal stubs to merge into cached domain targets later
    idd_admin_users_by_domain = {}
    idd_admin_groups_by_domain = {}
    user_admin_users_by_domain = {}
    user_admin_groups_by_domain = {}
    new_user_ids_by_domain = {}
    new_group_ids_by_domain = {}
    # role_emit_queue shape:
    #   (domain_ocid, role_scim_id) -> {
    #       "raw_role_name": str, "role_nid": str, "role_name": str,
    #       "app_id": str, "app_name": str, "did": str, "role_scope": dict
    #   }
    role_emit_queue = {}
    # include_all_emit_queue has the same value shape as role_emit_queue, but only for
    # roles with no grant rows (used with stats_prefix="include_all_" in Phase 2).
    include_all_emit_queue = {}
    # Aggregate IDD create-user capabilities so one role->scope edge carries
    # all observed assignment context for that role in that location.
    idd_create_user_agg = {}

    # Step through each grant gathered
    for gr in grants:
        did = _s(gr.get("domain_ocid") or "")
        if not did:
            stats["grants_skipped_missing_bits"] += 1
            continue

        # grant entitlement contains the ID of the role
        entitlement = _json_load_shared(gr.get("entitlement"), dict)
        entitlement_name = _s(
            entitlement.get("attribute_name")
            or gr.get("entitlement_attribute_name")
            or ""
        )
        if entitlement_name != "appRoles":
            continue
        rid = _s(
            entitlement.get("attribute_value")
            or gr.get("entitlement_attribute_value")
            or gr.get("entitlement")
            or ""
        )
        if not rid:
            stats["grants_skipped_missing_bits"] += 1
            continue

        # kind and scim are kind and scim of principal that is GRANTED the role (ex a user)
        grantee_obj = _json_load_shared(gr.get("grantee"), dict)
        if not grantee_obj:
            grantee_obj = {
                "type": gr.get("grantee_type"),
                "value": gr.get("grantee_id"),
            }
        else:
            if not grantee_obj.get("type"):
                grantee_obj["type"] = gr.get("grantee_type")
            if not grantee_obj.get("value"):
                grantee_obj["value"] = gr.get("grantee_id")
        kind, scim = _grant_kind_and_scim(grantee_obj)
        if not (kind and scim):
            stats["grants_skipped_missing_bits"] += 1
            continue

        # Given the domain ID and the ID of the role, gather the full role info data 
        # enumerated and set up earlier from role table if possible. With the role simple
        # name, see if the role is in our allowlist if we dont include include-all
        meta = role_info.get((did, rid))
        if not meta:
            stats["assignments_skipped_missing_role_meta"] += 1
            continue
        role_name, app_id, app_name, role_comp_id, app_comp_id = meta
        raw_role_name = role_name.split("/", 1)[-1] if "/" in role_name else role_name
        if (not include_all) and (not _allowlisted(app_id, raw_role_name, allowlist)):
            stats["assignments_filtered_allowlist"] += 1
            continue

        if not role_comp_id or not app_comp_id:
            stats["assignments_skipped_missing_compartment"] += 1
            continue

        # Get comp ID for grant and tenatn ID for grant, app, and role
        role_scope = role_scope_by_role.get((did, rid), {})
        grant_comp_id = _compartment_for_row(gr)
        if not grant_comp_id:
            stats["assignments_skipped_missing_compartment"] += 1
            continue
        grant_tenant_id = _tenant_for_compartment(grant_comp_id) or ""
        role_key = (did, rid)
        app_tenant_id = _tenant_for_compartment(app_comp_id) or ""
        role_tenant_id = _tenant_for_compartment(role_comp_id) or ""

        # Create app and role nodes if not already present
        app_nid, role_nid = _upsert_idd_app_and_role_nodes(
            ctx=ctx,
            did=did,
            app_id=app_id,
            app_name=app_name,
            app_compartment_id=app_comp_id,
            app_tenant_id=app_tenant_id,
            app_row=app_row_by_key.get((did, app_id)),
            role_id=rid,
            role_name=role_name,
            role_compartment_id=role_comp_id,
            role_tenant_id=role_tenant_id,
            role_row=role_row_by_key.get((did, rid)),
        )

        # Create edge linking APP to ROLE ownership wise (AppRole --ROLE_IN_APPLICATION--> App)
        _emit_role_of_app_edge(
            ctx=ctx,
            did=did,
            role_nid=role_nid,
            role_id=rid,
            app_nid=app_nid,
            app_id=app_id,
            role_name=role_name,
            grant_compartment_ocid=grant_comp_id,
        )

        # Get kind of target, domain id of target, and scim of target
        # Check our dict populated earlier to see if we have any users/groups matching this
        key = (kind, did, scim)
        principal_id = principal_idx.get(key, "")
        principal_type = _NODE_TYPE_BY_KIND.get(kind, NODE_DG)
        
        if principal_id:
            stats["principal_reused"] += 1

        # If we have no principal record yet, create a synthetic principal ID.
        # Grant rows don't include user/group OCIDs, so SCIM+kind+domain is the stable key.
        else:
            principal_id = _synthetic_principal_id(kind, domain_ocid=did, scim_id=scim)
            stub_label = _prefix_domain_display(ctx, did, f"{kind}:{scim}") or principal_id
            ctx.upsert_node(
                node_id=principal_id,
                node_type=principal_type,
                display_name=stub_label,
                compartment_id=grant_comp_id,
                tenant_id=grant_tenant_id,
                node_properties={
                    "stub": True,
                    "domain_ocid": did,
                    "scim_id": scim,
                    "principal_type": kind,
                    "compartment_ocid": grant_comp_id or None,
                },
                commit=False,
            )
            principal_idx[key] = principal_id
            stats["principal_stub_created"] += 1
            if principal_type == NODE_USER:
                new_user_ids_by_domain.setdefault(did, set()).add(principal_id)

        if principal_type == NODE_GROUP and principal_id:
            new_group_ids_by_domain.setdefault(did, set()).add(principal_id)
        
        # Keep tallies of principals assigned protected roles used for exclusion
        # in modeled privilege-escalation edges.
        if raw_role_name == "Identity Domain Administrator":
            if principal_type == NODE_USER:
                idd_admin_users_by_domain.setdefault(did, set()).add(principal_id)
            elif principal_type == NODE_GROUP:
                idd_admin_groups_by_domain.setdefault(did, set()).add(principal_id)
        elif raw_role_name == "User Administrator":
            if principal_type == NODE_USER:
                user_admin_users_by_domain.setdefault(did, set()).add(principal_id)
            elif principal_type == NODE_GROUP:
                user_admin_groups_by_domain.setdefault(did, set()).add(principal_id)

        # Create edge linking APP to ROLE ownership wise (Principal --APP_ROLE_GRANTED--> AppRole)
        _write_edge_json(
            ctx,
            src_id=principal_id,
            src_type=principal_type,
            dst_id=role_nid,
            dst_type=NODE_ROLE,
            edge_type=EDGE_APP_ROLE_GRANTED,
            payload={
                "domain_ocid": did,
                "scim_id": scim,
                "role_id": rid,
                "role_name": role_name,
                "app_id": app_id,
                "grant_compartment_ocid": grant_comp_id or None,
                "descriptions": _edge_desc(EDGE_APP_ROLE_GRANTED),
            },
        )

        # Collect IDD-scoped create-user capability from IDD app-role assignments.
        #   app-role --IDD_CREATE_USER--> <IdentityDomain>/new_user@<location>
        # Emit is deferred so metadata can include all observed assignee principals.
        if raw_role_name in _IDD_ROLES_WITH_CREATE_USER_CAP and grant_comp_id:
            idd_scope_token = f"{_idd_domain_scope_prefix(ctx, did)}/new_user"
            scope_id, scope_type, _ = _ensure_scope_node_shared(
                ctx,
                token=idd_scope_token,
                loc=grant_comp_id,
                tenant_id=grant_tenant_id,
                compartment_id=grant_comp_id,
                commit=False,
                dedupe=True,
            )
            if scope_id:
                agg_key = (
                    role_nid,
                    scope_id,
                    scope_type or "OCIResourceGroup",
                    did,
                    grant_comp_id,
                    grant_tenant_id,
                )
                bucket = idd_create_user_agg.setdefault(
                    agg_key,
                    {
                        "role_names": set(),
                        "app_ids": set(),
                        "role_ids": set(),
                        "principal_ids": set(),
                        "principal_types": set(),
                    },
                )
                bucket["role_names"].add(raw_role_name)
                bucket["role_ids"].add(rid)
                if app_id:
                    bucket["app_ids"].add(app_id)
                if principal_id:
                    bucket["principal_ids"].add(principal_id)
                if principal_type:
                    bucket["principal_types"].add(principal_type)

        # Create de-duped list for later phase 2 when poniting to targets
        role_emit_queue.setdefault(
            role_key,
            {
                "raw_role_name": raw_role_name,
                "role_nid": role_nid,
                "role_name": role_name,
                "app_id": app_id,
                "app_name": app_name,
                "did": did,
                "role_scope": role_scope,
            },
        )
        stats["assignments_emitted"] += 1

    users_by_domain = _get_cached_users_by_domain(session, ctx, debug=debug)
    groups_by_domain = _get_cached_groups_by_domain(session, ctx, debug=debug)
    for did, node_ids in (new_user_ids_by_domain or {}).items():
        existing = {nid for nid, _ in (users_by_domain.get(did) or [])}
        for nid in node_ids:
            if nid and nid not in existing:
                users_by_domain.setdefault(did, []).append((nid, NODE_USER))
                existing.add(nid)
    for did, node_ids in (new_group_ids_by_domain or {}).items():
        existing = {nid for nid, _ in (groups_by_domain.get(did) or [])}
        for nid in node_ids:
            if nid and nid not in existing:
                groups_by_domain.setdefault(did, []).append((nid, NODE_GROUP))
                existing.add(nid)

    # Expand IDD-admin user exclusions to include users in IDD-admin groups.
    idd_admin_users_by_domain, _ = _expand_identity_admin_users_via_group_assignment(
        users_by_domain=users_by_domain,
        protected_users_by_domain=idd_admin_users_by_domain,
        protected_groups_by_domain=idd_admin_groups_by_domain,
        group_member_mapping_cache=getattr(ctx, "group_member_mapping_cache", {}) or {},
    )
    # Expand User Administrator protections in the same way (group-assigned roles).
    user_admin_users_by_domain, _ = _expand_identity_admin_users_via_group_assignment(
        users_by_domain=users_by_domain,
        protected_users_by_domain=user_admin_users_by_domain,
        protected_groups_by_domain=user_admin_groups_by_domain,
        group_member_mapping_cache=getattr(ctx, "group_member_mapping_cache", {}) or {},
    )
    try:
        setattr(ctx, "_idd_users_by_domain_cache", users_by_domain)
        setattr(ctx, "_idd_groups_by_domain_cache", groups_by_domain)
        setattr(ctx, "_idd_identity_admin_users_by_domain_cache", idd_admin_users_by_domain)
        setattr(ctx, "_idd_identity_admin_groups_by_domain_cache", idd_admin_groups_by_domain)
        setattr(ctx, "_idd_user_admin_users_by_domain_cache", user_admin_users_by_domain)
        setattr(ctx, "_idd_user_admin_groups_by_domain_cache", user_admin_groups_by_domain)
    except Exception:
        pass

    # Emit aggregated IDD create-user edges and scope->ANY_USER links.
    og_state = _og_shared(ctx)
    existing_edges = og_state.get("existing_edges_set") if isinstance(og_state, dict) else set()
    if not isinstance(existing_edges, set):
        existing_edges = set()

    for (
        role_nid,
        scope_id,
        scope_type,
        did,
        grant_comp_id,
        grant_tenant_id,
    ), details in (idd_create_user_agg or {}).items():
        role_names = sorted({rn for rn in (details.get("role_names") or set()) if _s(rn)})
        app_ids = sorted({aid for aid in (details.get("app_ids") or set()) if _s(aid)})
        role_ids = sorted({rid for rid in (details.get("role_ids") or set()) if _s(rid)})
        principal_ids = sorted({pid for pid in (details.get("principal_ids") or set()) if _s(pid)})
        principal_types = sorted({pt for pt in (details.get("principal_types") or set()) if _s(pt)})
        role_name_joined = ", ".join(role_names)

        _write_edge_json(
            ctx,
            src_id=role_nid,
            src_type=NODE_ROLE,
            dst_id=scope_id,
            dst_type=scope_type or "OCIResourceGroup",
            edge_type=EDGE_IDD_CREATE_USER,
            payload={
                "domain_ocid": did,
                "role_name": role_name_joined,
                "role_names": role_names,
                "role_id": role_ids[0] if role_ids else "",
                "role_ids": role_ids,
                "app_id": app_ids[0] if app_ids else "",
                "app_ids": app_ids,
                "principal_id": principal_ids[0] if principal_ids else "",
                "principal_ids": principal_ids,
                "principal_types": principal_types,
                "grant_compartment_ocid": grant_comp_id,
                "descriptions": _edge_desc(EDGE_IDD_CREATE_USER),
            },
        )
        stats["idd_create_user_scope_edges_emitted"] += 1

        # Optional subset link:
        # only add <domain>/new_user@loc --OCI_SCOPE_MEMBER_OF--> ANY_USER@loc
        # when ANY_USER@loc already has outgoing edges.
        any_user_scope_id = f"ANY_USER@{grant_comp_id}" if grant_comp_id else ""
        any_user_has_outgoing = any(
            (_s(src_id) == any_user_scope_id)
            for (src_id, _edge_type, _dst_id) in (existing_edges or set())
        ) if any_user_scope_id else False

        if any_user_has_outgoing:
            any_user_scope_id, any_user_scope_type, _ = _ensure_scope_node_shared(
                ctx,
                token="ANY_USER",
                loc=grant_comp_id,
                tenant_id=grant_tenant_id,
                compartment_id=grant_comp_id,
                commit=False,
                dedupe=True,
            )
            _write_edge_json(
                ctx,
                src_id=scope_id,
                src_type=scope_type or "OCIResourceGroup",
                dst_id=any_user_scope_id,
                dst_type=any_user_scope_type or "OCIAnyUser",
                edge_type=EDGE_SCOPE_MEMBER_OF,
                payload={
                    "description": "Synthetic scope inclusion link.",
                    "resource_family": False,
                    "resource_used": False,
                },
                edge_category=EDGE_CATEGORY_RESOURCE,
            )
            stats["idd_create_user_scope_member_edges_emitted"] += 1
        else:
            stats["idd_create_user_scope_member_edges_skipped_no_any_user_outgoing"] += 1

    # ---------------------------------------------------------------------
    # include_all: add remaining role->app edges without grant rows
    # ex. if a role exists but is not assigned to anyone still include it
    # ---------------------------------------------------------------------
    if include_all:
        for (did, rid), meta in (role_info or {}).items():
            role_name, app_id, app_name, role_comp_id, app_comp_id = meta
            raw_role_name = role_name.split("/", 1)[-1] if "/" in role_name else role_name

            if not role_comp_id or not app_comp_id:
                stats["include_all_skipped_missing_compartment"] += 1
                continue

            role_scope = role_scope_by_role.get((did, rid), {})
            role_key = (did, rid)
            if role_key in role_emit_queue:
                continue

            app_tenant_id = _tenant_for_compartment(app_comp_id) or ""
            role_tenant_id = _tenant_for_compartment(role_comp_id) or ""
            app_nid, role_nid = _upsert_idd_app_and_role_nodes(
                ctx=ctx,
                did=did,
                app_id=app_id,
                app_name=app_name,
                app_compartment_id=app_comp_id,
                app_tenant_id=app_tenant_id,
                app_row=app_row_by_key.get((did, app_id)),
                role_id=rid,
                role_name=role_name,
                role_compartment_id=role_comp_id,
                role_tenant_id=role_tenant_id,
                role_row=role_row_by_key.get((did, rid)),
            )

            _emit_role_of_app_edge(
                ctx=ctx,
                did=did,
                role_nid=role_nid,
                role_id=rid,
                app_nid=app_nid,
                app_id=app_id,
                empty_role=True,
            )
            include_all_emit_queue[role_key] = {
                "raw_role_name": raw_role_name,
                "role_nid": role_nid,
                "role_name": role_name,
                "app_id": app_id,
                "app_name": app_name,
                "did": did,
                "role_scope": role_scope,
            }
            stats["include_all_role_app_edges"] += 1

    # ---------------------------------------------------------------------
    # Phase 2: emit role->target modeled edges once per role
    # ---------------------------------------------------------------------
    # role_emit_queue example value:
    #   {
    #     ("ocid1.domain.oc1..aaaa", "0ab12role"): {
    #       "raw_role_name": "User Administrator",
    #       "role_nid": "ocid1.approle.oc1..aaaa",
    #       "role_name": "TestDomain/User Administrator",
    #       "app_id": "IDCSAppId",
    #       "app_name": "TestDomain/IDCSAppId",
    #       "did": "ocid1.domain.oc1..aaaa",
    #       "role_scope": {"limited_to_one_or_more_groups": False, "members_count": 0, "scope_mode": "all_users_or_default"},
    #     }
    #   }
    # include_all_emit_queue example key:
    #   ("ocid1.domain.oc1..aaaa", "f9d8c7role")

    # Go through our role emit queue we created in part 1
    for item in role_emit_queue.values():
        _run_idd_role_emitters(
            session=session,
            ctx=ctx,
            raw_role_name=item["raw_role_name"],
            role_nid=item["role_nid"],
            role_name=item["role_name"],
            app_id=item["app_id"],
            app_name=item["app_name"],
            did=item["did"],
            role_scope=item["role_scope"],
            groups_by_domain=groups_by_domain,
            idd_admin_groups_by_domain=idd_admin_groups_by_domain,
            user_admin_groups_by_domain=user_admin_groups_by_domain,
            stats=stats,
            stats_prefix="",
            debug=debug,
        )

    # roles from include_all that don't have grants and exist
    for item in include_all_emit_queue.values():
        _run_idd_role_emitters(
            session=session,
            ctx=ctx,
            raw_role_name=item["raw_role_name"],
            role_nid=item["role_nid"],
            role_name=item["role_name"],
            app_id=item["app_id"],
            app_name=item["app_name"],
            did=item["did"],
            role_scope=item["role_scope"],
            groups_by_domain=groups_by_domain,
            idd_admin_groups_by_domain=idd_admin_groups_by_domain,
            user_admin_groups_by_domain=user_admin_groups_by_domain,
            stats=stats,
            stats_prefix="include_all_",
            debug=debug,
        )

    if auto_commit:
        try:
            ctx.commit()
        except Exception:
            pass

    res = {
        "ok": True,
        "allowlist": allowlist,
        "apps_loaded": len(apps),
        "roles_loaded": len(roles),
        "grants_loaded": len(grants),
        "stats": dict(stats),
    }
    _dlog(debug, "idd_app_roles: summary", **res)
    return res
