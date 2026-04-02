"""
policy_parser_enrichment.py

Helpers for enriching parsed OCI IAM policy statements before graph emission.
"""

from ocinferno.modules.opengraph.utilities.helpers.core_helpers import l as _l, s as _s

_SUBJ_TYPES_NEED_DOMAIN = {
    "group",
    "group-id",
    "user",
    "user-id",
    "dynamic-group",
    "dynamic-group-id",
}


def _domain_ocid_for_name(ctx, dom_name):
    dom_name = _s(dom_name)
    if not dom_name:
        return ""
    try:
        return ctx.get_or_create_domain_ocid(dom_name) or ""
    except Exception:
        pass
    m = getattr(ctx, "domain_ocid_by_name", None) or {}
    if isinstance(m, dict):
        return _s(m.get(dom_name) or m.get(dom_name.lower()) or "")
    return ""


def enrich_domain_ocids_in_parsed_statements(ctx, parsed, domain_cast=None):
    """
    Enrich parsed statements in-place:
      - inject identity domain when missing (IDD mode)
      - resolve identity_domain_ocid
      - resolve principal OCID for IDD/classic group and dynamic-group labels
    """
    default_dom_ocid = _s(getattr(ctx, "default_domain_ocid", "") or "")
    has_domain_map = isinstance(getattr(ctx, "domain_ocid_by_name", None), dict)
    idd_mode = bool(default_dom_ocid or has_domain_map)
    cast = _s(domain_cast) or "Default"

    principal_idx = getattr(ctx, "_idd_principal_idx_by_domain", None)
    if not isinstance(principal_idx, dict):
        principal_idx = {"group": {}, "dynamic-group": {}, "user": {}}
        sess = ctx.session
        try:
            rows = sess.get_resource_fields(
                "identity_domain_groups",
                columns=["display_name", "ocid", "domain_ocid"],
            ) or []
            for r in rows:
                did = _s(r.get("domain_ocid"))
                name = _s(r.get("display_name")).strip().lower()
                ocid = _s(r.get("ocid"))
                if did and name and ocid:
                    principal_idx["group"][(did, name)] = ocid
        except Exception:
            pass

        try:
            rows = sess.get_resource_fields(
                "identity_domain_dynamic_groups",
                columns=["display_name", "ocid", "domain_ocid"],
            ) or []
            for r in rows:
                did = _s(r.get("domain_ocid"))
                name = _s(r.get("display_name")).strip().lower()
                ocid = _s(r.get("ocid"))
                if did and name and ocid:
                    principal_idx["dynamic-group"][(did, name)] = ocid
        except Exception:
            pass

        try:
            rows = sess.get_resource_fields(
                "identity_domain_users",
                columns=["user_name", "display_name", "ocid", "domain_ocid"],
            ) or []
            for r in rows:
                did = _s(r.get("domain_ocid"))
                ocid = _s(r.get("ocid"))
                if not (did and ocid):
                    continue
                uname = _s(r.get("user_name")).strip().lower()
                dname = _s(r.get("display_name")).strip().lower()
                if uname:
                    principal_idx["user"][(did, uname)] = ocid
                if dname:
                    principal_idx["user"][(did, dname)] = ocid
        except Exception:
            pass

        try:
            ctx._idd_principal_idx_by_domain = principal_idx
        except Exception:
            pass

    def _resolve_principal_ocid(subject_type_l: str, domain_ocid: str, label: str) -> str:
        domain_ocid = _s(domain_ocid)
        label = _s(label).strip().lower()
        if not domain_ocid or not label:
            return ""
        mp = principal_idx.get(subject_type_l, {})
        return _s(mp.get((domain_ocid, label)) or "")

    def _resolve_classic_principal_ocid(subject_type_l: str, label: str) -> str:
        label = _s(label).strip().lower()
        if not label:
            return ""
        if subject_type_l == "group":
            mp = getattr(ctx, "classic_group_by_name", None) or {}
            return _s(mp.get(label) or "")
        if subject_type_l == "dynamic-group":
            mp = getattr(ctx, "classic_dg_by_name", None) or {}
            return _s(mp.get(label) or "")
        return ""

    for st in parsed or []:
        subj = st.get("subject") or {}
        subj_type_l = _l(subj.get("type"))
        if subj_type_l not in _SUBJ_TYPES_NEED_DOMAIN:
            continue

        for sv in (subj.get("values") or []):
            if not isinstance(sv, dict):
                continue
            label = _s(sv.get("label") or "")
            dom_name = _s(sv.get("identity_domain") or "")
            dom_ocid = _s(sv.get("identity_domain_ocid") or "")

            if not dom_name:
                if not idd_mode:
                    continue
                sv["identity_domain"] = cast
                dom_name = cast

            if not dom_ocid:
                dom_ocid = _s(_domain_ocid_for_name(ctx, dom_name) or "")
                if not dom_ocid:
                    continue
                sv["identity_domain_ocid"] = dom_ocid

            if _s(sv.get("ocid") or ""):
                continue

            principal_ocid = _resolve_principal_ocid(subj_type_l, dom_ocid, label)
            if not principal_ocid and subj_type_l in {"group", "dynamic-group"}:
                principal_ocid = _resolve_classic_principal_ocid(subj_type_l, label)
            if principal_ocid:
                sv["ocid"] = principal_ocid
                sv["id"] = principal_ocid

    return parsed

