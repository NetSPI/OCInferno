#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iam_conditionals.py

Offline condition evaluation engine for OCI IAM parsed statements.

Public API (kept):
  - ConditionEvalResult
  - StatementConditionalsEngine.evaluate_candidates(...)

Key semantics (kept):
  - request.operation clause-local handling (OR-safe)
  - Any unresolved/unsupported => CUT OFF and return unresolved for whole tree
  - strict_time_filter / strict_operation_filter drop behavior preserved
  - request.user.name supports "/glob*/" and "regex:<expr>"

Key behavior (kept from your recent iteration):
  - We carry candidate SUBJECTS as dicts through the AST (ctx.subjects),
    trimming/replacing the list as we evaluate.
  - Branch-first options are returned upstream (OR/ANY produces multiple options).
  - Target.* handlers can trim resources via DB-backed matching (session.get_resource_fields).

This version:
  - Adds handlers for:
      * target.job.operation
      * target.stack.id
  - Consolidates the per-resource id/name handlers into one generic column handler
    while preserving the wrappers and existing behavior (time handlers, tag handlers,
    request.user.*, request.operation, DB-backed matching, etc.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import fnmatch
import json
import re
from typing import Any


from ocinferno.modules.opengraph.utilities.helpers.constants import (
    SUPPORTED_VARIABLES,
    CORE_API_OPERATION_PERMISSIONS,
    API_OPERATION_PERMISSION_SOURCES,
    NODE_TYPE_OCI_DYNAMIC_GROUP,
    NODE_TYPE_OCI_GROUP,
    NODE_TYPE_OCI_USER,
    RESOURCE_SCOPE_MAP,
    RESOURCE_PRINCIPAL_SCOPE_TOKENS,
    PERMISSION_MAPPING,
    DEFAULT_RESOURCE_FAMILIES,
)


def _build_operation_indexes_shared(*, api_sources, core_sources, norm_s, norm_l):
    op_to: dict[str, set[str]] = {}
    op_to_by_service: dict[str, dict[str, set[str]]] = {}
    no_perms_by_service: dict[str, set[str]] = {}
    known: set[str] = set()
    no_perms: set[str] = set()

    sources = api_sources or (core_sources or {})
    for src in (sources or ()):
        if not isinstance(src, dict):
            continue
        for _svc, ops in src.items():
            svc = norm_l(norm_s(_svc))
            if not svc or not isinstance(ops, dict):
                continue
            for opname, rec in ops.items():
                if not isinstance(opname, str) or not opname.strip():
                    continue
                opname = opname.strip()
                known.add(opname)

                required = set()
                notes = ""
                if isinstance(rec, dict):
                    notes = norm_s(rec.get("notes") or "")
                    for p in (rec.get("permissions_all") or ()):
                        if isinstance(p, str) and p.strip():
                            required.add(p.strip())
                    for p in (rec.get("permissions_any") or ()):
                        if isinstance(p, str) and p.strip():
                            required.add(p.strip())
                    for cp in (rec.get("conditional_permissions") or ()):
                        if not isinstance(cp, dict):
                            continue
                        for p in (cp.get("requires_all") or ()):
                            if isinstance(p, str) and p.strip():
                                required.add(p.strip())
                        for p in (cp.get("requires_any") or ()):
                            if isinstance(p, str) and p.strip():
                                required.add(p.strip())

                    if rec.get("no_permissions_required"):
                        no_perms_by_service.setdefault(opname, set()).add(svc)

                if (not required) and notes and ("no permissions required" in notes.lower()):
                    no_perms_by_service.setdefault(opname, set()).add(svc)

                if required:
                    op_to.setdefault(opname, set()).update(required)
                    op_to_by_service.setdefault(opname, {}).setdefault(svc, set()).update(required)

    for opname, svcs in (no_perms_by_service or {}).items():
        if svcs and not (op_to.get(opname) or set()):
            no_perms.add(opname)

    return op_to, sorted(known), no_perms, op_to_by_service, no_perms_by_service


def _build_service_resource_indexes_shared(*, permission_mapping, norm_s, norm_l):
    service_to_tokens: dict[str, set[str]] = {}
    token_to_services: dict[str, set[str]] = {}
    pm = permission_mapping or {}
    for _verb, svc_map in (pm or {}).items():
        if not isinstance(svc_map, dict):
            continue
        for svc, res_map in (svc_map or {}).items():
            svc_l = norm_l(norm_s(svc))
            if not svc_l or not isinstance(res_map, dict):
                continue
            service_to_tokens.setdefault(svc_l, set())
            for tok in (res_map or {}).keys():
                tok_l = norm_l(norm_s(tok))
                if not tok_l:
                    continue
                service_to_tokens[svc_l].add(tok_l)
                token_to_services.setdefault(tok_l, set()).add(svc_l)
    return service_to_tokens, token_to_services


def _candidate_services_for_resource_tokens_shared(
    *,
    resource_tokens_l: set[str],
    token_to_services: dict[str, set[str]],
    aliases: dict[str, tuple[str, ...]],
    canon_tokens_fn,
    wildcard_fn,
    norm_s,
    norm_l,
    family_map,
):
    toks = canon_tokens_fn(resource_tokens_l or set())
    if not toks or wildcard_fn(toks):
        return set()

    def _expand_tokens_with_families(tokens: set[str]) -> set[str]:
        out = set(tokens or ())
        fam = family_map or {}
        stack = list(out)
        seen = set(out)
        while stack:
            cur = stack.pop()
            members = fam.get(cur) or fam.get(norm_l(cur)) or ()
            if not isinstance(members, (set, list, tuple)):
                continue
            for m in members:
                ml = norm_l(norm_s(m))
                if not ml or ml in seen:
                    continue
                seen.add(ml)
                out.add(ml)
                stack.append(ml)
        return out

    def _service_alias_set(service_name: str) -> set[str]:
        s = norm_l(norm_s(service_name))
        if not s:
            return set()
        out = {s}
        out |= set((aliases or {}).get(s, ()))
        for k, vals in (aliases or {}).items():
            if s in set(vals or ()):
                out.add(k)
        return out

    expanded = _expand_tokens_with_families(toks)
    out: set[str] = set()
    for tok in expanded:
        for svc in (token_to_services.get(tok) or set()):
            out |= _service_alias_set(svc)
    return out


_SUPPORTED_VAR_KEYS = {
    _k
    for _grp in (SUPPORTED_VARIABLES or {}).values()
    if isinstance(_grp, dict)
    for _k in _grp.keys()
    if isinstance(_k, str)
}

_TIME_HANDLER_VARS = (
    "request.utc-timestamp",
    "request.utc-timestamp.month-of-year",
    "request.utc-timestamp.day-of-month",
    "request.utc-timestamp.day-of-week",
    "request.utc-timestamp.time-of-day",
)

_TARGET_COLUMN_HANDLER_SPECS = {
    "target.key.id": {
        "token": "keys",
        "col": "id",
        "applicable": {"vaults", "secrets", "keys"},
        "allow_patterns": False,
        "allow_in": False,
        "missing_is_match_for_neq": True,
    },
    "target.vault.id": {
        "token": "vaults",
        "col": "id",
        "applicable": {"vaults", "secrets", "keys"},
        "allow_patterns": False,
        "allow_in": False,
        "missing_is_match_for_neq": True,
    },
    "target.secret.name": {
        "token": "secrets",
        "col": "name",
        "applicable": {"vaults", "secrets", "keys"},
        "allow_patterns": True,
        "allow_in": True,
        "missing_is_match_for_neq": True,
    },
    "target.secret.id": {
        "token": "secrets",
        "col": "id",
        "applicable": {"vaults", "secrets", "keys"},
        "allow_patterns": False,
        "allow_in": False,
        "missing_is_match_for_neq": True,
    },
    "target.job.operation": {
        "token": "orm-jobs",
        "col": "operation",
        "applicable": {"orm_jobs", "orm-jobs", "jobs", "resource-manager-jobs"},
        "allow_patterns": False,
        "allow_in": True,
        "missing_is_match_for_neq": True,
    },
    "target.stack.id": {
        "token": "orm-stacks",
        "col": "id",
        "applicable": {"orm_stacks", "stacks", "orm-stacks", "resource-manager-stacks"},
        "allow_patterns": False,
        "allow_in": False,
        "missing_is_match_for_neq": True,
    },
    "target.desktoppool.id": {
        "token": "desktop-pool",
        "col": "id",
        "applicable": {"desktop-pool", "desktop-pools", "desktop-pool-family", "published-desktops", "desktop", "desktops"},
        "allow_patterns": False,
        "allow_in": False,
        "missing_is_match_for_neq": True,
    },
    "target.desktoppool.name": {
        "token": "desktop-pool",
        "col": "display_name",
        "applicable": {"desktop-pool", "desktop-pools", "desktop-pool-family", "published-desktops", "desktop", "desktops"},
        "allow_patterns": True,
        "allow_in": True,
        "missing_is_match_for_neq": True,
    },
    "target.desktop.id": {
        "token": "desktop",
        "col": "id",
        "applicable": {"desktop", "desktops", "published-desktops", "desktop-pool-desktops", "desktop-pool-family"},
        "allow_patterns": False,
        "allow_in": False,
        "missing_is_match_for_neq": True,
    },
    "target.bastion.ocid": {
        "token": "bastion",
        "col": "id",
        "applicable": {"bastion", "bastions", "bastion-family", "bastion-session", "bastion-sessions"},
        "allow_patterns": False,
        "allow_in": False,
        "missing_is_match_for_neq": True,
    },
    "target.bastion.name": {
        "token": "bastion",
        "col": "name",
        "applicable": {"bastion", "bastions", "bastion-family", "bastion-session", "bastion-sessions"},
        "allow_patterns": True,
        "allow_in": True,
        "missing_is_match_for_neq": True,
    },
    "target.bastion-session.username": {
        "token": "bastion-session",
        "col": "target_resource_details",
        "key_path": "target_resource_operating_system_user_name",
        "applicable": {"bastion-session", "bastion-sessions", "bastion-family"},
        "allow_patterns": True,
        "allow_in": True,
        "missing_is_match_for_neq": True,
    },
    "target.resource.ocid": {
        "token": "bastion-session",
        "col": "target_resource_details",
        "key_path": "target_resource_id",
        "applicable": {"bastion-session", "bastion-sessions", "bastion-family"},
        "allow_patterns": False,
        "allow_in": False,
        "missing_is_match_for_neq": True,
    },
    "target.loggroup.id": {
        "token": "log-groups",
        "col": "id",
        "applicable": {"log-groups", "logging-family", "log-content", "unified-configuration"},
        "allow_patterns": False,
        "allow_in": False,
        "missing_is_match_for_neq": True,
    },
    "target.domain.id": {
        "token": "domains",
        "col": "id",
        "applicable": {"domains"},
        "allow_patterns": False,
        "allow_in": True,
        "missing_is_match_for_neq": True,
    },
    "target.tag-namespace.id": {
        "token": "tag-namespaces",
        "col": "id",
        "applicable": {"tag-namespaces"},
        "allow_patterns": False,
        "allow_in": True,
        "missing_is_match_for_neq": True,
    },
    "target.tag-namespace.name": {
        "token": "tag-namespaces",
        "col": "name",
        "applicable": {"tag-namespaces"},
        "allow_patterns": True,
        "allow_in": True,
        "missing_is_match_for_neq": True,
    },
    "target.dns-record.type": {
        "token": "dns-zone-records",
        "col": "rtype",
        "applicable": {"dns-zone-records", "dns-records"},
        "allow_patterns": False,
        "allow_in": True,
        "missing_is_match_for_neq": True,
    },
    "target.dns-domain.name": {
        "token": "dns-zone-records",
        "col": "domain",
        "applicable": {"dns-zone-records", "dns-records"},
        "allow_patterns": False,
        "allow_in": True,
        "missing_is_match_for_neq": True,
    },
    "target.repo.name": {
        "token": "repos",
        "col": "display_name",
        "applicable": {"repos"},
        "allow_patterns": True,
        "allow_in": True,
        "missing_is_match_for_neq": True,
    },
}


@dataclass(slots=True)
class ConditionEvalResult:
    drop_statement: bool = False
    resolved_true: bool = False
    resolved_false: bool = False
    unresolved: bool = False
    impossible_conditional: bool = False

    applied_restrictions: bool = False
    allowed_subjects: list[dict] = field(default_factory=list)
    allowed_location_ids: list[str] = field(default_factory=list)
    matched_resource_node_ids: list[str] = field(default_factory=list)
    matched_rows_by_table: dict[str, list[dict]] = field(default_factory=dict)

    trimmed_verbs_l: set[str] | None = None
    trimmed_permissions: set[str] | None = None

    reasons: list[str] = field(default_factory=list)
    supported_clauses: int = 0
    unsupported_clauses: int = 0

    options: list[dict] = field(default_factory=list)


class BoolTri(Enum):
    TRUE = 1
    FALSE = 2
    UNKNOWN = 3


@dataclass(slots=True)
class EvalContext:
    subjects: list[dict]
    verbs_l: set[str]
    perms: set[str]
    resource_tokens_l: set[str]
    location_ids: set[str]
    children_by_compartment_id: dict[str, set[str]] = field(default_factory=dict)


@dataclass(slots=True)
class ContextDelta:
    tri: BoolTri = BoolTri.UNKNOWN

    replace_subjects: list[dict] | None = None
    filter_subject_ids: set[str] | None = None

    allowed_location_ids: set[str] | None = None

    matched_resource_node_ids: set[str] | None = None
    matched_rows_by_table: dict[str, list[dict]] | None = None

    trimmed_verbs_l: set[str] | None = None
    trimmed_permissions: set[str] | None = None

    unresolved: bool = False
    reason: str = ""


class _CondUtil:
    EXCLUDED_VARS: set[str] = set()

    @staticmethod
    def s(x) -> str:
        return x.strip() if isinstance(x, str) else ""

    @staticmethod
    def l(x) -> str:
        return x.strip().lower() if isinstance(x, str) else ""

    @staticmethod
    def norm_op(op: str) -> str:
        o = _CondUtil.l(op)
        if o in {"=", "=="}:
            return "eq"
        if o in {"!=", "<>"}:
            return "neq"
        if o == "ne":
            return "neq"
        return o

    @staticmethod
    def as_int(x) -> int | None:
        try:
            return int(x)
        except Exception:
            return None

    @staticmethod
    def as_str_list(x) -> list[str]:
        if isinstance(x, list):
            out = []
            for v in x:
                if isinstance(v, str):
                    sv = v.strip()
                    if sv:
                        out.append(sv)
                elif isinstance(v, dict):
                    sv = _CondUtil.s(v.get("value"))
                    if sv:
                        out.append(sv)
            return out
        sx = _CondUtil.s(x)
        return [sx] if sx else []

    @staticmethod
    def lhs_attr(clause: dict) -> str:
        lhs = clause.get("lhs") or {}
        if isinstance(lhs, str):
            return _CondUtil.s(lhs)
        if isinstance(lhs, dict) and lhs.get("type") == "attribute":
            return _CondUtil.s(lhs.get("value"))
        return ""

    @staticmethod
    def op(clause: dict) -> str:
        return _CondUtil.l(clause.get("op"))

    @staticmethod
    def rhs_value(clause: dict) -> tuple[str, object]:
        rhs = clause.get("rhs")
        if rhs is None:
            rhs = clause.get("right")

        if isinstance(rhs, dict):
            if ("from" in rhs and "to" in rhs) or ("from" in clause and "to" in clause):
                r = dict(rhs)
                if "from" in clause and "from" not in r:
                    r["from"] = clause.get("from")
                if "to" in clause and "to" not in r:
                    r["to"] = clause.get("to")
                r.setdefault("type", r.get("type") or "range")
                return "range", r

            rtype = _CondUtil.s(rhs.get("type"))
            if rtype == "pattern":
                return "pattern", (rhs.get("pattern") or rhs.get("value"))
            vals = rhs.get("values")
            if isinstance(vals, list):
                return (rtype or "values"), vals
            return rtype, rhs.get("value")

        return "", rhs

    @staticmethod
    def subject_id(subj: dict) -> str:
        if not isinstance(subj, dict):
            return ""
        return _CondUtil.s(subj.get("id") or subj.get("node_id") or subj.get("ocid") or subj.get("value") or "")

    @staticmethod
    def normalize_subjects(candidate_subjects) -> list[dict]:
        out: list[dict] = []
        if candidate_subjects is None:
            return out

        if isinstance(candidate_subjects, dict):
            sid = _CondUtil.subject_id(candidate_subjects)
            if sid:
                d = dict(candidate_subjects)
                d["id"] = sid
                out.append(d)
            return out

        if isinstance(candidate_subjects, str):
            s = _CondUtil.s(candidate_subjects)
            return ([{"id": s}] if s else [])

        if isinstance(candidate_subjects, (list, tuple, set)):
            for v in candidate_subjects:
                if isinstance(v, dict):
                    sid = _CondUtil.subject_id(v)
                    if not sid:
                        continue
                    d = dict(v)
                    d["id"] = sid
                    out.append(d)
                elif isinstance(v, str):
                    s = _CondUtil.s(v)
                    if s:
                        out.append({"id": s})
            return out

        return out

    @staticmethod
    def subject_ids(subjects: list[dict]) -> set[str]:
        return {sid for sid in (_CondUtil.subject_id(s) for s in (subjects or [])) if sid}

    @staticmethod
    def iso_dt(s: str) -> datetime | None:
        ss = _CondUtil.s(s)
        if not ss:
            return None
        try:
            if ss.endswith("Z"):
                ss = ss[:-1] + "+00:00"
            dt = datetime.fromisoformat(ss)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None

    @staticmethod
    def time_hms_utc(dt: datetime) -> str:
        return dt.strftime("%H:%M:%SZ")

    @staticmethod
    def parse_hms_to_seconds(hms: str) -> int | None:
        s = _CondUtil.s(hms)
        if not s:
            return None
        if s.endswith("Z"):
            s = s[:-1]
        parts = s.split(":")
        if len(parts) != 3:
            return None
        try:
            hh = int(parts[0])
            mm = int(parts[1])
            ss = int(parts[2])
            if not (0 <= hh <= 23 and 0 <= mm <= 59 and 0 <= ss <= 59):
                return None
            return hh * 3600 + mm * 60 + ss
        except Exception:
            return None

    @staticmethod
    def time_between(now_s: int, start_s: int, end_s: int) -> bool:
        if start_s <= end_s:
            return start_s <= now_s <= end_s
        return now_s >= start_s or now_s <= end_s

    @staticmethod
    def strip_pattern_delims(p: str) -> str:
        s = _CondUtil.s(p)
        if len(s) >= 2 and s[0] == "/" and s[-1] == "/":
            return s[1:-1]
        return s

    @staticmethod
    def pattern_match(name: str, pattern: str) -> bool:
        n = _CondUtil.s(name)
        p = _CondUtil.s(pattern)
        if not n or not p:
            return False

        if p.lower().startswith("regex:"):
            expr = p[6:]
            try:
                return re.search(expr, n) is not None
            except Exception:
                return False

        p = _CondUtil.strip_pattern_delims(p)
        return fnmatch.fnmatchcase(n, p)

    @staticmethod
    def merge_rows_by_table(a: dict[str, list[dict]] | None, b: dict[str, list[dict]] | None) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for src in (a or {}, b or {}):
            if not isinstance(src, dict):
                continue
            for tname, rows in src.items():
                if not tname or not isinstance(rows, list):
                    continue
                cur = out.setdefault(tname, [])
                seen = set()
                for r in cur:
                    if isinstance(r, dict):
                        rid = r.get("id") or r.get("compartment_id")
                        if rid:
                            seen.add(rid)
                for r in rows:
                    if not isinstance(r, dict):
                        continue
                    rid = r.get("id") or r.get("compartment_id")
                    if rid and rid in seen:
                        continue
                    if rid:
                        seen.add(rid)
                    cur.append(r)
        return out

    @staticmethod
    def canon_tokens(toks) -> set[str]:
        return {_CondUtil.l(_CondUtil.s(t)) for t in (toks or ()) if _CondUtil.s(t)}

    @staticmethod
    def is_wildcard_tokens(toks: set[str]) -> bool:
        return bool(toks & {"all-resources", "all_resources"})


def _build_operation_indexes():
    return _build_operation_indexes_shared(
        api_sources=API_OPERATION_PERMISSION_SOURCES,
        core_sources=CORE_API_OPERATION_PERMISSIONS,
        norm_s=_CondUtil.s,
        norm_l=_CondUtil.l,
    )


def _build_service_resource_indexes():
    return _build_service_resource_indexes_shared(
        permission_mapping=PERMISSION_MAPPING,
        norm_s=_CondUtil.s,
        norm_l=_CondUtil.l,
    )


_SERVICE_ALIASES: dict[str, tuple[str, ...]] = {
    # API_OPERATION_PERMISSION_SOURCES uses "desktops"; PERMISSION_MAPPING uses "secure_desktops".
    "desktops": ("secure_desktops",),
    "secure_desktops": ("desktops",),
}


def _service_alias_set(service_name: str) -> set[str]:
    s = _CondUtil.l(_CondUtil.s(service_name))
    if not s:
        return set()
    out = {s}
    out |= set(_SERVICE_ALIASES.get(s, ()))
    for k, vals in (_SERVICE_ALIASES or {}).items():
        if s in set(vals or ()):
            out.add(k)
    return out


def _candidate_services_for_resource_tokens(resource_tokens_l: set[str]) -> set[str]:
    return _candidate_services_for_resource_tokens_shared(
        resource_tokens_l=resource_tokens_l,
        token_to_services=_TOKEN_TO_SERVICES,
        aliases=_SERVICE_ALIASES,
        canon_tokens_fn=_CondUtil.canon_tokens,
        wildcard_fn=_CondUtil.is_wildcard_tokens,
        norm_s=_CondUtil.s,
        norm_l=_CondUtil.l,
        family_map=DEFAULT_RESOURCE_FAMILIES,
    )


_SERVICE_TO_RESOURCE_TOKENS, _TOKEN_TO_SERVICES = _build_service_resource_indexes()
(
    _OP_TO_REQUIRED_PERMS,
    _ALL_KNOWN_OPS,
    _OPS_NO_REQUIRED_PERMS,
    _OP_TO_REQUIRED_PERMS_BY_SERVICE,
    _OPS_NO_REQUIRED_PERMS_BY_SERVICE,
) = _build_operation_indexes()


def _delta_true(reason: str = "") -> ContextDelta:
    return ContextDelta(tri=BoolTri.TRUE, reason=reason)


def _delta_false(reason: str = "") -> ContextDelta:
    return ContextDelta(tri=BoolTri.FALSE, reason=reason)


def _delta_unknown(reason: str = "", unresolved: bool = True) -> ContextDelta:
    return ContextDelta(tri=BoolTri.UNKNOWN, unresolved=unresolved, reason=reason)


def _looks_like_verb_derived_input(ctx: EvalContext) -> bool:
    return bool(ctx.verbs_l)


def _eval_time_clause(
    *,
    var: str,
    op: str,
    rhs_val,
    eval_time_utc: datetime,
    strict_time_filter: bool,
) -> ContextDelta:
    v = _CondUtil.s(var)
    o = _CondUtil.norm_op(op)

    def _mismatch(reason: str) -> ContextDelta:
        return _delta_false(reason) if strict_time_filter else _delta_unknown("time mismatch", unresolved=False)

    def _parse_iso_dt(x) -> datetime | None:
        return _CondUtil.iso_dt(_CondUtil.s(x))

    def _parse_hms_seconds(x) -> int | None:
        return _CondUtil.parse_hms_to_seconds(_CondUtil.s(x))

    def _pull_scalar(x) -> str:
        if isinstance(x, dict):
            return _CondUtil.s(x.get("value") or x.get("pattern") or x.get("name"))
        return _CondUtil.s(x)

    def _extract_between_pair(x) -> tuple[str | None, str | None]:
        if isinstance(x, dict) and ("from" in x) and ("to" in x):
            a = _pull_scalar(x.get("from"))
            b = _pull_scalar(x.get("to"))
            return (a or None), (b or None)
        if isinstance(x, (list, tuple)) and len(x) == 2:
            a = _pull_scalar(x[0])
            b = _pull_scalar(x[1])
            return (a or None), (b or None)
        if isinstance(x, dict):
            vals = x.get("values")
            if isinstance(vals, list) and len(vals) == 2:
                a = _pull_scalar(vals[0])
                b = _pull_scalar(vals[1])
                return (a or None), (b or None)
        return None, None

    if v == "request.utc-timestamp":
        rhs_dt = _parse_iso_dt(rhs_val)
        if not rhs_dt:
            return _delta_unknown("utc-timestamp rhs not ISO 8601", unresolved=True)
        got = eval_time_utc
        if o == "before":
            return _delta_true("utc-timestamp before OK") if got < rhs_dt else _mismatch("utc-timestamp before FAIL")
        if o == "after":
            return _delta_true("utc-timestamp after OK") if got > rhs_dt else _mismatch("utc-timestamp after FAIL")
        return _delta_unknown(f"utc-timestamp unsupported op={o}", unresolved=True)

    if v == "request.utc-timestamp.month-of-year":
        got = int(eval_time_utc.month)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"month-of-year unsupported op={o}", unresolved=True)
        if o == "in":
            wants = [_CondUtil.as_int(s) for s in _CondUtil.as_str_list(rhs_val)]
            wants = [w for w in wants if w is not None]
            if not wants:
                return _delta_unknown("month-of-year rhs invalid", unresolved=True)
            return _delta_true("month-of-year in OK") if got in wants else _mismatch("month-of-year in FAIL")
        want = _CondUtil.as_int(_CondUtil.s(rhs_val))
        if want is None:
            return _delta_unknown("month-of-year rhs not int", unresolved=True)
        ok = (got == want) if o == "eq" else (got != want)
        return _delta_true("month-of-year match OK") if ok else _mismatch("month-of-year match FAIL")

    if v == "request.utc-timestamp.day-of-month":
        got = int(eval_time_utc.day)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"day-of-month unsupported op={o}", unresolved=True)
        if o == "in":
            wants = [_CondUtil.as_int(s) for s in _CondUtil.as_str_list(rhs_val)]
            wants = [w for w in wants if w is not None]
            if not wants:
                return _delta_unknown("day-of-month rhs invalid", unresolved=True)
            return _delta_true("day-of-month in OK") if got in wants else _mismatch("day-of-month in FAIL")
        want = _CondUtil.as_int(_CondUtil.s(rhs_val))
        if want is None:
            return _delta_unknown("day-of-month rhs not int", unresolved=True)
        ok = (got == want) if o == "eq" else (got != want)
        return _delta_true("day-of-month match OK") if ok else _mismatch("day-of-month match FAIL")

    if v == "request.utc-timestamp.day-of-week":
        got = eval_time_utc.strftime("%A").lower()
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"day-of-week unsupported op={o}", unresolved=True)
        if o == "in":
            wants = [s.lower() for s in _CondUtil.as_str_list(rhs_val) if _CondUtil.s(s)]
            if not wants:
                return _delta_unknown("day-of-week rhs invalid", unresolved=True)
            return _delta_true("day-of-week in OK") if got in wants else _mismatch("day-of-week in FAIL")
        want = _CondUtil.s(rhs_val).lower()
        if not want:
            return _delta_unknown("day-of-week rhs empty", unresolved=True)
        ok = (got == want) if o == "eq" else (got != want)
        return _delta_true("day-of-week match OK") if ok else _mismatch("day-of-week match FAIL")

    if v == "request.utc-timestamp.time-of-day":
        if o != "between":
            return _delta_unknown(f"time-of-day unsupported op={o} (expects between)", unresolved=True)
        start_raw, end_raw = _extract_between_pair(rhs_val)
        if not start_raw or not end_raw:
            return _delta_unknown("time-of-day between requires from/to values", unresolved=True)
        start_s = _parse_hms_seconds(start_raw)
        end_s = _parse_hms_seconds(end_raw)
        if start_s is None or end_s is None:
            return _delta_unknown("time-of-day between rhs not HH:MM:SSZ", unresolved=True)
        now_s = _parse_hms_seconds(_CondUtil.time_hms_utc(eval_time_utc))
        if now_s is None:
            return _delta_unknown("time-of-day eval time parse failed", unresolved=True)
        ok = _CondUtil.time_between(now_s, start_s, end_s)
        return _delta_true("time-of-day between OK") if ok else _mismatch("time-of-day between FAIL")

    return _delta_unknown(f"time var unsupported: {v}", unresolved=True)


def _eval_target_compartment_id_clause(
    *,
    op: str,
    rhs_val,
    candidate_location_ids: set[str],
    children_by_compartment_id: dict[str, set[str]] | None = None,
) -> ContextDelta:
    o = _CondUtil.norm_op(op)
    if o not in {"eq", "neq"}:
        return _delta_unknown(f"target.compartment.id unsupported op={o}")

    want = _CondUtil.s(rhs_val)
    if not want:
        return _delta_unknown("target.compartment.id rhs empty")
    if not candidate_location_ids:
        return _delta_unknown("target.compartment.id no candidate locations")

    if o == "eq":
        expanded = {want}
        children_by = children_by_compartment_id or {}
        stack = [want]
        while stack:
            cur = stack.pop()
            for child in (children_by.get(cur) or set()):
                cid = _CondUtil.s(child)
                if not cid or cid in expanded:
                    continue
                expanded.add(cid)
                stack.append(cid)

        allowed = expanded & set(candidate_location_ids or set())
        if allowed:
            return ContextDelta(
                tri=BoolTri.TRUE,
                allowed_location_ids=allowed,
                reason=f"target.compartment.id == {want} (+descendants)",
            )
        return _delta_false(f"target.compartment.id == {want} not in candidates")

    allowed = {c for c in candidate_location_ids if c != want}
    if not allowed:
        return _delta_false("target.compartment.id != removed all candidates")
    return ContextDelta(tri=BoolTri.TRUE, allowed_location_ids=allowed, reason="target.compartment.id != filtered")


def _extract_request_operation_ops(var: str, op: str, rhs_type: str, rhs_val) -> set[str]:
    if _CondUtil.l(var) != "request.operation":
        return set()

    o = _CondUtil.norm_op(op)

    if rhs_type in {"pattern", "regex"}:
        pat = _CondUtil.s(rhs_val)
        return {k for k in _ALL_KNOWN_OPS if pat and _CondUtil.pattern_match(k, pat)}

    if o == "eq":
        s = _CondUtil.s(rhs_val)
        return {s} if s else set()

    if o == "in":
        return {x for x in (_CondUtil.s(v) for v in _CondUtil.as_str_list(rhs_val)) if x}

    return set()


def _operation_requirements_for_context(
    opname: str,
    resource_tokens_l: set[str],
) -> tuple[set[str], bool, bool, bool]:
    """
    Resolve request.operation permission requirements in statement scope.

    Returns:
      (required_perms, no_permissions_required, known_operation, scoped_mismatch)
    """
    name = _CondUtil.s(opname)
    if not name:
        return set(), False, False, False

    scoped_svcs = _candidate_services_for_resource_tokens(resource_tokens_l or set())

    svc_req = _OP_TO_REQUIRED_PERMS_BY_SERVICE.get(name) or {}
    svc_no_perm = _OPS_NO_REQUIRED_PERMS_BY_SERVICE.get(name) or set()
    known = bool(
        (name in _ALL_KNOWN_OPS)
        or (name in _OP_TO_REQUIRED_PERMS)
        or (name in _OPS_NO_REQUIRED_PERMS)
        or svc_req
        or svc_no_perm
    )

    # If statement resources don't constrain service scope, use broad fallback.
    if not scoped_svcs:
        if name in _OPS_NO_REQUIRED_PERMS:
            return set(), True, known, False
        req = set(_OP_TO_REQUIRED_PERMS.get(name) or ())
        if req:
            return req, False, known, False
        return set(), False, known, False

    matched_service = False
    required: set[str] = set()
    no_perm = False

    for svc, perms in (svc_req or {}).items():
        if _service_alias_set(svc) & scoped_svcs:
            matched_service = True
            required |= set(perms or ())

    for svc in (svc_no_perm or set()):
        if _service_alias_set(svc) & scoped_svcs:
            matched_service = True
            no_perm = True

    if required:
        return required, False, True, False
    if no_perm:
        return set(), True, True, False
    if matched_service:
        # Service matched but no explicit perms means no permissions required.
        return set(), True, True, False
    if known:
        return set(), False, True, True
    return set(), False, False, False


@dataclass(slots=True)
class EvalOption:
    tri: BoolTri
    ctx: EvalContext
    matched_resource_node_ids: set[str] = field(default_factory=set)
    matched_rows_by_table: dict[str, list[dict]] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    cutoff_unresolved: bool = False


@dataclass(slots=True)
class NodeResult:
    tri: BoolTri
    cutoff_unresolved: bool
    options: list[EvalOption]
    reasons: list[str]
    supported: int
    unsupported: int


class StatementConditionalsEngine:
    def __init__(
        self,
        *,
        ctx,
        session,
        debug: bool = True,
        eval_time_utc: datetime | None = None,
    ):
        self.ctx = ctx
        self.session = session
        self.debug = bool(debug)

        self.eval_time_utc = eval_time_utc or datetime.now(timezone.utc)
        if self.eval_time_utc.tzinfo is None:
            self.eval_time_utc = self.eval_time_utc.replace(tzinfo=timezone.utc)

        iam_cfg = getattr(ctx, "iam_config", {}) or {}
        self.strict_time_filter = bool(iam_cfg.get("drop_time_based_no_effective_permissions"))
        self.strict_operation_filter = bool(iam_cfg.get("drop_all_no_effective_permissions"))
        self.drop_impossible_conditionals = self.strict_operation_filter
        self._resource_table_info_cache: dict[frozenset[str], dict[str, dict]] = {}
        self._subject_name_cache: dict[str, str] = {}
        self._dns_zone_cache: dict[str, dict] | None = None
        self._table_query_cache: dict[tuple[str, tuple[tuple[str, str], ...]], list[dict]] = {}

        self._handlers = {
            # request principals - general
            "request.groups.id": self._h_request_groups_id,

            # tags - general
            "target.resource.compartment.tag": self._h_target_resource_compartment_tag,
            "target.resource.tag": self._h_target_resource_tag,

            # DNS - zones/records
            "target.dns-zone.id": self._h_target_dns_zone_id,
            "target.dns-zone.name": self._h_target_dns_zone_name,
            "target.dns-zone.apex-label": self._h_target_dns_zone_apex_label,
            "target.dns-zone.parent-domain": self._h_target_dns_zone_parent_domain,
            "target.dns.scope": self._h_target_dns_scope,
            "target.dns-zone.source-compartment.id": self._h_target_dns_zone_source_compartment_id,
            "target.dns-zone.destination-compartment.id": self._h_target_dns_zone_destination_compartment_id,

            "target.compartment.id": self._h_target_compartment_id,
            "request.instance.compartment.id": self._h_request_instance_compartment_id,
            "request.operation": self._h_request_operation,

            "request.user.id": self._h_request_user_id,
            "request.user.name": self._h_request_user_name,

            "request.principal.compartment.tag": self._h_request_principal_compartment_tag,
            "request.principal.group.tag": self._h_request_principal_group_tag,
            "request.user.mfaTotpVerified": self._h_unresolvable,

            "request.permission": self._h_request_permission,
            "request.networkSource.name": self._h_unresolvable,
            "request.region": self._h_unresolvable,
            "request.ad": self._h_unresolvable,
            "target.compartment.name": self._h_target_compartment_name,

            # IAM-specific targets
            "target.user.id": self._h_target_user_id,
            "target.user.name": self._h_target_user_name,
            "target.group.id": self._h_target_group_id,
            "target.group.name": self._h_target_group_name,
            "target.group.member": self._h_target_group_member,
            "target.dynamic-group.id": self._h_target_dynamic_group_id,
            "target.dynamic-group.name": self._h_target_dynamic_group_name,
            "target.policy.id": self._h_target_policy_id,
            "target.policy.name": self._h_target_policy_name,
            "target.policy.autoupdate": self._h_unresolvable,
            "target.credential.type": self._h_target_credential_type,
            "target.resource.domain.id": self._h_target_resource_domain_id,
            "target.resource.domain.name": self._h_target_resource_domain_name,
            "target.domain.name": self._h_target_domain_name,
        }
        self._handlers.update({var: self._make_time_handler(var) for var in _TIME_HANDLER_VARS})
        self._handlers.update(self._build_target_column_handlers())

    def _query_rows_cached(self, table_name: str, where: dict | None):
        tname = _CondUtil.s(table_name)
        if not tname:
            return []
        where = where if isinstance(where, dict) and where else {}
        key = (tname, tuple(sorted((str(k), str(v)) for k, v in where.items())))
        if key in self._table_query_cache:
            return self._table_query_cache.get(key) or []
        rows = self.session.get_resource_fields(
            tname,
            where_conditions=where if where else None,
            columns=None,
        ) or []
        self._table_query_cache[key] = rows
        return rows

    def _make_time_handler(self, varname: str):
        def _handler(*, op: str, rhs_val, **_):
            return _eval_time_clause(
                var=varname,
                op=op,
                rhs_val=rhs_val,
                eval_time_utc=self.eval_time_utc,
                strict_time_filter=self.strict_time_filter,
            )

        return _handler

    def _make_target_column_handler(self, varname: str, spec: dict):
        token = spec.get("token")
        col = spec.get("col")
        applicable = spec.get("applicable")
        allow_patterns = bool(spec.get("allow_patterns", False))
        allow_in = bool(spec.get("allow_in", False))
        missing_is_match_for_neq = bool(spec.get("missing_is_match_for_neq", True))
        key_path = spec.get("key_path")

        def _handler(*, op: str, rhs_val, ctx: EvalContext, **_):
            return self._h_target_column(
                varname=varname,
                token=token,
                col=col,
                op=op,
                rhs_val=rhs_val,
                ctx=ctx,
                applicable=applicable,
                allow_patterns=allow_patterns,
                allow_in=allow_in,
                missing_is_match_for_neq=missing_is_match_for_neq,
                key_path=key_path,
            )

        return _handler

    def _build_target_column_handlers(self) -> dict[str, object]:
        out = {}
        for varname, spec in (_TARGET_COLUMN_HANDLER_SPECS or {}).items():
            if not isinstance(spec, dict):
                continue
            out[varname] = self._make_target_column_handler(varname, spec)
        return out

    # -----------------------------
    # DROP-IN HELPERS (small + reusable)
    # -----------------------------

    # -----------------------------
    # PRINCIPAL CORE (NO expansion by default)
    # -----------------------------

    def _subjects_by_kind(self, ctx: EvalContext, kind: str) -> list[dict]:
        k = _CondUtil.l(kind)
        out = []
        for s in (ctx.subjects or []):
            sk = self._subj_kind(s)
            # Normalize a few spellings
            if k in {"dynamic-group", "dynamic_group", "dynamicgroup"}:
                if sk in {"dynamic-group", "dynamic_group", "dynamicgroup"}:
                    out.append(s)
            else:
                if sk == k:
                    out.append(s)
        return out

    def _delta_keep_subject_ids(self, keep_ids: set[str], *, reason: str) -> ContextDelta:
        if not keep_ids:
            return _delta_false(reason)
        return ContextDelta(tri=BoolTri.TRUE, filter_subject_ids=set(keep_ids), unresolved=False, reason=reason)

    def _principal_id_eq(
        self,
        *,
        ctx: EvalContext,
        want_id: str,
        want_kind: str,
        varname: str,
        expand: str | None = None,   # None | "group_to_users" | "dg_to_members"
    ) -> ContextDelta:
        """
        Base primitive for request.* principal-id filters.

        expand=None (default):
        - only filters existing ctx.subjects of want_kind by id.

        expand="group_to_users":
        - require the matched subject to be a group, then expand matched groups -> user ids.

        expand="dg_to_members":
        - require the matched subject to be a dynamic-group, then expand matched DGs -> member ids.

        IMPORTANT: expansion only happens if expand != None.
        """
        want = _CondUtil.s(want_id)
        if not want:
            return _delta_unknown(f"{varname} rhs empty", unresolved=True)

        kind_candidates = self._subjects_by_kind(ctx, want_kind)
        if not kind_candidates:
            return _delta_unknown(f"{varname}: no candidate subjects of kind={want_kind}", unresolved=True)

        matched = [s for s in kind_candidates if self._subj_id(s) == want]
        if not matched:
            return _delta_false(f"{varname}: {want_kind} {want} not in candidate subjects")

        # default: keep the matching subject ids (no expansion)
        if not expand:
            keep_ids = {self._subj_id(s) for s in matched if self._subj_id(s)}
            return self._delta_keep_subject_ids(keep_ids, reason=f"{varname}: matched {len(keep_ids)} {want_kind}(s)")

        # explicit expansion requested by handler
        if expand == "group_to_users":
            return self._expand_group_subjects_to_users(ctx, restrict_group_ids={want})

        if expand == "dg_to_members":
            return self._expand_dynamic_group_subjects(ctx, restrict_dynamic_group_ids={want})

        return _delta_unknown(f"{varname}: invalid expand mode={expand}", unresolved=True)

    def _kind_to_node_type(self, kind: str) -> str:
        k = _CondUtil.l(kind)
        return {
            "user": NODE_TYPE_OCI_USER,
            "group": NODE_TYPE_OCI_GROUP,
            "dynamic-group": NODE_TYPE_OCI_DYNAMIC_GROUP,
            "dynamic_group": NODE_TYPE_OCI_DYNAMIC_GROUP,
            "dynamicgroup": NODE_TYPE_OCI_DYNAMIC_GROUP,
            "resource": "OCIResource",
        }.get(k, "OCIResource")

    def _subj_kind(self, s: dict) -> str:
        k = _CondUtil.l(s.get("kind") or s.get("type") or "")
        if k:
            return k
        nt = _CondUtil.l(s.get("node_type") or "")
        if nt == "ociuser":
            return "user"
        if nt == "ocigroup":
            return "group"
        if nt == "ocidynamicgroup":
            return "dynamic-group"
        if nt == "ociresource":
            return "resource"
        if nt == "ocianyuser":
            return "any-user"
        if nt == "ocianygroup":
            return "any-group"
        if nt == "ociservice":
            return "service"
        return ""

    def _subj_id(self, s: dict) -> str:
        return _CondUtil.subject_id(s)

    def _replace_subjects(self, ids: set[str], *, kind: str, reason: str) -> ContextDelta:
        if not ids:
            return _delta_false(reason)
        nt = self._kind_to_node_type(kind)
        return ContextDelta(
            tri=BoolTri.TRUE,
            replace_subjects=[{"id": x, "node_type": nt} for x in sorted(ids)],
            unresolved=False,
            reason=reason,
        )

    def _filter_subjects(self, ctx: EvalContext, keep_ids: set[str], *, reason: str) -> ContextDelta:
        if not keep_ids:
            return _delta_false(reason)
        return ContextDelta(tri=BoolTri.TRUE, filter_subject_ids=set(keep_ids), unresolved=False, reason=reason)


    def _node_from_condition_expr(self, expr: dict) -> dict:
        if not isinstance(expr, dict):
            return {}

        etype = _CondUtil.l(expr.get("type"))

        if etype == "clause":
            node = expr.get("node")
            if isinstance(node, dict):
                return {"clause": node}
            if "lhs" in expr:
                return {"clause": expr}
            return {}

        if etype == "group" or "items" in expr:
            mode = _CondUtil.l(expr.get("mode") or "all")
            if mode not in {"all", "any"}:
                mode = "all"
            children = []
            for it in (expr.get("items") or []):
                if not isinstance(it, dict):
                    continue
                child = self._node_from_condition_expr(it)
                if child:
                    children.append(child)
            return {"op": mode, "children": children}

        if "lhs" in expr:
            return {"clause": expr}

        return {}

    def _normalize_condition_tree(self, cond: dict | None) -> dict:
        if not isinstance(cond, dict):
            return {"op": "all", "children": []}

        if "clauses" in cond:
            mode = _CondUtil.l(cond.get("mode") or "all")
            if mode not in {"all", "any"}:
                mode = "all"
            clauses = [c for c in (cond.get("clauses") or []) if isinstance(c, dict)]
            return {"op": mode, "children": [{"clause": c} for c in clauses]}

        node = self._node_from_condition_expr(cond)
        if not node:
            return {"op": "all", "children": []}
        if "clause" in node:
            return {"op": "all", "children": [node]}
        return node

    def _count_clause_nodes(self, node: dict) -> int:
        if not isinstance(node, dict):
            return 0
        if "clause" in node:
            return 1
        total = 0
        for ch in (node.get("children") or []):
            total += self._count_clause_nodes(ch)
        return total

    def evaluate_candidates(
        self,
        *,
        state: dict | None = None,
        st: dict | None = None,
        candidate_subjects=None,
        candidate_location_ids=None,
        allowed_resource_tokens=None,
        verbs_l: set[str] | None = None,
        perms: set[str] | None = None,
    ) -> ConditionEvalResult:
        res = ConditionEvalResult()
        base_loc_pairs: list[tuple[str, bool]] = []
        if state:
            st = st if st is not None else dict(state.get("st") or {})
            candidate_subjects = candidate_subjects if candidate_subjects is not None else list(
                state.get("base_candidate_subjects") or state.get("candidate_subjects") or []
            )
            candidate_location_ids = (
                candidate_location_ids
                if candidate_location_ids is not None
                else [cid for cid, _inh in (state.get("base_loc_pairs_all") or state.get("loc_pairs_all") or [])]
            )
            base_loc_pairs = list(state.get("base_loc_pairs_all") or state.get("loc_pairs_all") or [])
            allowed_resource_tokens = (
                allowed_resource_tokens
                if allowed_resource_tokens is not None
                else list(state.get("base_res_tokens") or state.get("res_tokens") or [])
            )
            verbs_l = verbs_l if verbs_l is not None else set(
                state.get("base_direct_verbs_l") or state.get("direct_verbs_l") or ()
            )
            if perms is None:
                direct_perms = set(state.get("base_direct_perms") or state.get("direct_perms") or ())
                perms = set(
                    direct_perms
                    or state.get("base_effective_perms")
                    or state.get("effective_perms")
                    or ()
                )

        st = dict(st or {})
        if not base_loc_pairs:
            base_loc_pairs = [(str(cid), False) for cid in (candidate_location_ids or []) if str(cid)]

        cond = st.get("conditions") or {}
        node = self._normalize_condition_tree(cond)

        in_ctx = EvalContext(
            subjects=_CondUtil.normalize_subjects(candidate_subjects),
            resource_tokens_l=set(allowed_resource_tokens or ()),
            location_ids=set(candidate_location_ids or ()),
            verbs_l=set(verbs_l or ()),
            perms=set(perms or ()),
            children_by_compartment_id=getattr(self.ctx, "children_by_compartment_id", None) or {},
        )

        ev = self._eval_node(node=node, ctx=in_ctx)

        res.supported_clauses = ev.supported
        res.unsupported_clauses = ev.unsupported
        res.reasons.extend(ev.reasons)

        if ev.tri == BoolTri.FALSE and (self.strict_time_filter or self.strict_operation_filter):
            res.drop_statement = True
            return res

        impossible = bool(ev.tri == BoolTri.FALSE and not ev.cutoff_unresolved)

        if ev.tri == BoolTri.UNKNOWN or ev.cutoff_unresolved:
            res.unresolved = True
        else:
            if ev.tri == BoolTri.TRUE:
                res.resolved_true = True
            else:
                res.resolved_false = True

        res.options = []
        merged_rows_by_table: dict[str, list[dict]] = {}
        matched_union: set[str] = set()

        cand_loc_set = set(candidate_location_ids or ())
        cand_subj_ids = _CondUtil.subject_ids(in_ctx.subjects)
        cand_verbs = set(verbs_l or ())
        cand_perms = set(perms or ())

        any_restriction = False

        for opt in ev.options:
            opt_subjects = _CondUtil.normalize_subjects(opt.ctx.subjects)
            opt_subj_ids = _CondUtil.subject_ids(opt_subjects)

            opt_loc_set = set(opt.ctx.location_ids or ())
            opt_verbs = set(opt.ctx.verbs_l or ())
            opt_perms = set(opt.ctx.perms or ())

            if (
                opt_loc_set != cand_loc_set
                or opt_subj_ids != cand_subj_ids
                or opt_verbs != cand_verbs
                or opt_perms != cand_perms
                or opt.matched_rows_by_table
                or opt.matched_resource_node_ids
            ):
                any_restriction = True

            res.options.append(
                {
                    "delta_option_tri": "TRUE" if opt.tri == BoolTri.TRUE else ("FALSE" if opt.tri == BoolTri.FALSE else "UNKNOWN"),
                    "delta_candidate_subjects": [dict(s) for s in (opt_subjects or [])],
                    "delta_loc_pairs_all": (
                        [(cid, inh) for cid, inh in base_loc_pairs if cid in opt_loc_set]
                        if opt_loc_set
                        else list(base_loc_pairs)
                    ),
                    "delta_trimmed_verbs": set(opt_verbs),
                    "delta_trimmed_perms": set(opt_perms),
                    "delta_matched_resource_node_ids": sorted(set(opt.matched_resource_node_ids or ())),
                    "delta_matched_rows_by_table": dict(opt.matched_rows_by_table or {}),
                    "delta_option_reasons": list(opt.reasons or []),
                }
            )

            merged_rows_by_table = _CondUtil.merge_rows_by_table(
                merged_rows_by_table,
                dict(opt.matched_rows_by_table or {}),
            )
            matched_union |= set(opt.matched_resource_node_ids or ())

        if merged_rows_by_table:
            res.matched_rows_by_table = merged_rows_by_table

        if matched_union:
            res.matched_resource_node_ids = sorted(matched_union)

        res.applied_restrictions = bool(any_restriction)

        if res.options:
            any_subjects = any(opt.get("delta_candidate_subjects") for opt in res.options)
            any_locations = any(opt.get("delta_loc_pairs_all") for opt in res.options)
            if not any_subjects or not any_locations:
                impossible = True
        elif ev.tri in {BoolTri.TRUE, BoolTri.FALSE} and not ev.cutoff_unresolved:
            impossible = True

        res.impossible_conditional = bool(impossible)
        if res.impossible_conditional and self.drop_impossible_conditionals:
            res.drop_statement = True

        return res

    def _eval_node(self, *, node: dict, ctx: EvalContext) -> NodeResult:
        if "clause" in node:
            delta, supported, unsupported, reasons = self._eval_clause_delta(clause=node["clause"], ctx=ctx)

            if delta.tri == BoolTri.FALSE:
                return NodeResult(
                    tri=BoolTri.FALSE,
                    cutoff_unresolved=False,
                    options=[],
                    reasons=reasons,
                    supported=supported,
                    unsupported=unsupported,
                )

            new_ctx = self._apply_delta(ctx, delta)

            opt = EvalOption(
                tri=delta.tri,
                ctx=new_ctx,
                matched_resource_node_ids=set(delta.matched_resource_node_ids or ()),
                matched_rows_by_table=dict(delta.matched_rows_by_table or {}),
                reasons=reasons,
                cutoff_unresolved=bool(delta.unresolved),
            )

            tri = BoolTri.UNKNOWN if delta.tri == BoolTri.UNKNOWN else BoolTri.TRUE
            cutoff = bool(delta.unresolved) or (delta.tri == BoolTri.UNKNOWN)
            return NodeResult(tri=tri, cutoff_unresolved=cutoff, options=[opt], reasons=reasons, supported=supported, unsupported=unsupported)

        op = _CondUtil.l(node.get("op") or "all")
        if op not in {"all", "any"}:
            op = "all"
        children = node.get("children") or []

        supported = 0
        unsupported = 0
        reasons: list[str] = []

        if op == "all":
            cur_opts = [EvalOption(tri=BoolTri.TRUE, ctx=ctx)]
            for ch in children:
                next_opts: list[EvalOption] = []
                for base in cur_opts:
                    r = self._eval_node(node=ch, ctx=base.ctx)
                    supported += r.supported
                    unsupported += r.unsupported
                    reasons.extend(r.reasons)

                    for child_opt in r.options:
                        new_tri = (
                            BoolTri.TRUE
                            if (base.tri == BoolTri.TRUE and child_opt.tri == BoolTri.TRUE and not child_opt.cutoff_unresolved)
                            else BoolTri.UNKNOWN
                        )
                        next_opts.append(
                            EvalOption(
                                tri=new_tri,
                                ctx=child_opt.ctx,
                                matched_resource_node_ids=set(base.matched_resource_node_ids) | set(child_opt.matched_resource_node_ids),
                                matched_rows_by_table=_CondUtil.merge_rows_by_table(base.matched_rows_by_table, child_opt.matched_rows_by_table),
                                reasons=list(base.reasons) + list(child_opt.reasons),
                                cutoff_unresolved=bool(base.cutoff_unresolved or child_opt.cutoff_unresolved),
                            )
                        )

                if not next_opts:
                    return NodeResult(tri=BoolTri.FALSE, cutoff_unresolved=False, options=[], reasons=reasons, supported=supported, unsupported=unsupported)
                cur_opts = next_opts

            if any(o.tri == BoolTri.TRUE and not o.cutoff_unresolved for o in cur_opts):
                return NodeResult(tri=BoolTri.TRUE, cutoff_unresolved=False, options=cur_opts, reasons=reasons, supported=supported, unsupported=unsupported)
            return NodeResult(tri=BoolTri.UNKNOWN, cutoff_unresolved=True, options=cur_opts, reasons=reasons, supported=supported, unsupported=unsupported)

        all_opts: list[EvalOption] = []
        any_true = False

        for ch in children:
            r = self._eval_node(node=ch, ctx=ctx)
            supported += r.supported
            unsupported += r.unsupported
            reasons.extend(r.reasons)

            for o in r.options:
                all_opts.append(o)
                if o.tri == BoolTri.TRUE and not o.cutoff_unresolved:
                    any_true = True

        if any_true:
            return NodeResult(tri=BoolTri.TRUE, cutoff_unresolved=False, options=all_opts, reasons=reasons, supported=supported, unsupported=unsupported)
        if all_opts:
            return NodeResult(tri=BoolTri.UNKNOWN, cutoff_unresolved=True, options=all_opts, reasons=reasons, supported=supported, unsupported=unsupported)
        return NodeResult(tri=BoolTri.FALSE, cutoff_unresolved=False, options=[], reasons=reasons, supported=supported, unsupported=unsupported)

    def _apply_delta(self, ctx: EvalContext, delta: ContextDelta) -> EvalContext:
        new = EvalContext(
            subjects=list(ctx.subjects or []),
            location_ids=set(ctx.location_ids),
            resource_tokens_l=set(ctx.resource_tokens_l),
            verbs_l=set(ctx.verbs_l),
            perms=set(ctx.perms),
            children_by_compartment_id=ctx.children_by_compartment_id,
        )

        if delta.replace_subjects is not None:
            new.subjects = _CondUtil.normalize_subjects(delta.replace_subjects)
        elif delta.filter_subject_ids is not None:
            allowed = set(delta.filter_subject_ids)
            new.subjects = [s for s in (new.subjects or []) if _CondUtil.subject_id(s) in allowed]

        if delta.allowed_location_ids is not None:
            new.location_ids &= set(delta.allowed_location_ids)

            allowed_locs = set(new.location_ids)
            if delta.matched_rows_by_table:
                trimmed_rows = {}
                trimmed_ids = set()

                for tname, rows in delta.matched_rows_by_table.items():
                    kept = []
                    for r in rows:
                        cid = r.get("compartment_id")
                        if not cid or cid in allowed_locs:
                            kept.append(r)
                            rid = r.get("id")
                            if rid:
                                trimmed_ids.add(rid)
                    if kept:
                        trimmed_rows[tname] = kept

                delta.matched_rows_by_table = trimmed_rows
                delta.matched_resource_node_ids = trimmed_ids

        if delta.trimmed_verbs_l is not None:
            new.verbs_l = set(delta.trimmed_verbs_l)

        if delta.trimmed_permissions is not None:
            new.perms = set(delta.trimmed_permissions)

        return new

    def _eval_clause_delta(self, *, clause: dict, ctx: EvalContext) -> tuple[ContextDelta, int, int, list[str]]:
        reasons: list[str] = []
        supported = 0
        unsupported = 0

        var_full = _CondUtil.lhs_attr(clause)
        var = _CondUtil.l(var_full)
        op = _CondUtil.op(clause)
        rhs_type, rhs_val = _CondUtil.rhs_value(clause)

        if not var:
            reasons.append("missing lhs attribute")
            return _delta_unknown("missing lhs attribute", unresolved=True), supported, unsupported + 1, reasons

        if var in _CondUtil.EXCLUDED_VARS:
            reasons.append(f"excluded var: {var}")
            return _delta_unknown(f"excluded var: {var}", unresolved=True), supported, unsupported + 1, reasons

        var_key = var
        if var.startswith("target.resource.tag."):
            var_key = "target.resource.tag"
        elif var.startswith("target.resource.compartment.tag."):
            var_key = "target.resource.compartment.tag"
        elif var.startswith("request.principal.compartment.tag."):
            var_key = "request.principal.compartment.tag"
        elif var.startswith("request.principal.group.tag."):
            var_key = "request.principal.group.tag"

        if (var_key not in _SUPPORTED_VAR_KEYS) and (var_key not in self._handlers):
            reasons.append(f"unsupported var: {var_key}")
            return _delta_unknown(f"unsupported var: {var_key}", unresolved=True), supported, unsupported + 1, reasons

        handler = self._handlers.get(var_key)
        if handler is None:
            reasons.append(f"known-but-unimplemented var: {var_key}")
            return _delta_unknown(f"known-but-unimplemented var: {var_key}", unresolved=True), supported, unsupported + 1, reasons

        supported += 1
        delta = handler(var=var_full, op=op, rhs_val=rhs_val, rhs_type=rhs_type, ctx=ctx, st=None)

        if delta.reason:
            reasons.append(delta.reason)

        if delta.allowed_location_ids is not None:
            if not (set(ctx.location_ids) & set(delta.allowed_location_ids)):
                return ContextDelta(tri=BoolTri.FALSE, allowed_location_ids=set(), unresolved=bool(delta.unresolved), reason=delta.reason), supported, unsupported, reasons

        cand_ids = _CondUtil.subject_ids(ctx.subjects)

        if delta.replace_subjects is not None:
            after_ids = _CondUtil.subject_ids(_CondUtil.normalize_subjects(delta.replace_subjects))
            if not after_ids:
                return ContextDelta(tri=BoolTri.FALSE, replace_subjects=[], unresolved=bool(delta.unresolved), reason=delta.reason), supported, unsupported, reasons

        if delta.filter_subject_ids is not None:
            if not (cand_ids & set(delta.filter_subject_ids)):
                return ContextDelta(tri=BoolTri.FALSE, filter_subject_ids=set(), unresolved=bool(delta.unresolved), reason=delta.reason), supported, unsupported, reasons

        return delta, supported, unsupported, reasons


    # tag helpers + handlers
    def _parse_tag_attr(self, var_full: str, base_prefix: str) -> tuple[str, str] | None:
        v = _CondUtil.s(var_full)
        if not v or not _CondUtil.l(v).startswith(base_prefix + "."):
            return None
        suffix = v[len(base_prefix) + 1 :]
        parts = [p for p in suffix.split(".") if p]
        if len(parts) != 2:
            return None
        return parts[0], parts[1]

    def _load_tags_obj(self, x) -> dict:
        if isinstance(x, dict):
            return x
        if isinstance(x, str) and x.strip():
            try:
                v = json.loads(x)
                return v if isinstance(v, dict) else {}
            except Exception:
                return {}
        return {}

    def _row_tag_value(self, row: dict, namespace: str, key: str) -> str | None:
        if not isinstance(row, dict):
            return None
        # NOTE: Tag matching is defined-tags only (no freeform/system tags).
        defined = self._load_tags_obj(row.get("defined_tags"))
        ns = _CondUtil.s(namespace)
        k = _CondUtil.s(key)
        if ns and isinstance(defined.get(ns), dict) and k in defined.get(ns, {}):
            return _CondUtil.s(defined.get(ns, {}).get(k))

        # Identity Domain "tags" field (various possible shapes)
        tags = row.get("tags")
        if tags is None:
            return None
        if isinstance(tags, str) and tags.strip():
            try:
                tags = json.loads(tags)
            except Exception:
                return None

        # tags as dict of namespaces -> keys
        if isinstance(tags, dict):
            # Allow "definedTags" nested shape only
            defined2 = self._load_tags_obj(tags.get("defined_tags"))
            if ns and isinstance(defined2.get(ns), dict) and k in defined2.get(ns, {}):
                return _CondUtil.s(defined2.get(ns, {}).get(k))

            # Direct namespace->key mapping
            if ns and isinstance(tags.get(ns), dict) and k in tags.get(ns, {}):
                return _CondUtil.s(tags.get(ns, {}).get(k))

            # Flat dict with "Namespace.Key" keys
            flat_key = f"{ns}.{k}" if ns and k else ""
            if flat_key and flat_key in tags:
                return _CondUtil.s(tags.get(flat_key))

        # tags as list of {key/name/namespace,...}
        if isinstance(tags, list):
            for item in tags:
                if not isinstance(item, dict):
                    continue
                in_ns = _CondUtil.s(item.get("namespace") or "")
                in_key = _CondUtil.s(item.get("key") or item.get("name") or "")
                val = item.get("value") if "value" in item else item.get("tagValue")
                # If key is "Namespace.Key", split it
                if in_key and "." in in_key and (not in_ns):
                    parts = in_key.split(".", 1)
                    in_ns, in_key = parts[0], parts[1]
                if ns and k and in_ns == ns and in_key == k:
                    return _CondUtil.s(val)
        return None

    def _expand_descendants(self, *, roots: set[str], children_by_compartment_id: dict[str, set[str]]) -> set[str]:
        expanded: set[str] = set()
        stack = list(roots)
        while stack:
            cur = stack.pop()
            if cur in expanded:
                continue
            expanded.add(cur)
            for ch in children_by_compartment_id.get(cur, ()):
                if ch not in expanded:
                    stack.append(ch)
        return expanded

    # db extraction + mapping
    def _row_get_value(self, row: dict, col: str | list[str] | tuple[str, ...], key_path: str | list[str] | tuple[str, ...] | None = None) -> Any:
        if isinstance(col, (list, tuple)):
            parts = []
            for c in col:
                v = row.get(c)
                if v is None:
                    return None
                parts.append(str(v))
            return "::".join(parts)

        col = _CondUtil.s(col)
        if not col:
            return None

        v = row.get(col)

        if not key_path:
            return v

        kp = key_path.split(".") if isinstance(key_path, str) else list(key_path)

        if isinstance(v, str):
            s = v.strip()
            if s and s[0] in "{[":
                try:
                    v = json.loads(s)
                except Exception:
                    return None

        for k in kp:
            if not isinstance(v, dict):
                return None
            v = v.get(k)
        return v

    def _extract_user_ref(self, raw) -> str:
        """
        Best-effort extraction of a user OCID from SCIM-like fields.
        Accepts dicts or JSON strings with keys like value/id/ocid.
        """
        if isinstance(raw, dict):
            return _CondUtil.s(raw.get("value") or raw.get("id") or raw.get("ocid") or raw.get("user_id") or "")
        if isinstance(raw, str):
            s = raw.strip()
            if not s:
                return ""
            if s[0] in "{[":
                try:
                    parsed = json.loads(s)
                except Exception:
                    return _CondUtil.s(s)
                if isinstance(parsed, dict):
                    return _CondUtil.s(parsed.get("value") or parsed.get("id") or parsed.get("ocid") or parsed.get("user_id") or "")
                if isinstance(parsed, list) and parsed:
                    for item in parsed:
                        if isinstance(item, dict):
                            got = _CondUtil.s(item.get("value") or item.get("id") or item.get("ocid") or item.get("user_id") or "")
                            if got:
                                return got
                return ""
            return _CondUtil.s(s)
        return ""

    def _match_any_name(self, row: dict, *, fields: list[str], matcher) -> bool:
        for f in fields:
            val = row.get(f)
            if not val:
                continue
            if matcher(_CondUtil.s(val)):
                return True
        return False

    def _resolve_domain_ids_by_name(self, *, op: str, rhs_val, rhs_type: str) -> set[str]:
        o = _CondUtil.norm_op(op)
        rows = self.session.get_resource_fields("identity_domains", columns=["id", "name", "display_name"]) or []
        if not rows:
            return set()

        if o == "in":
            names = {n for n in (_CondUtil.s(x) for x in _CondUtil.as_str_list(rhs_val)) if n}
            if not names:
                return set()
            return {
                _CondUtil.s(r.get("id"))
                for r in rows
                if _CondUtil.s(r.get("name")) in names or _CondUtil.s(r.get("display_name")) in names
            }

        raw = _CondUtil.s(rhs_val)
        if not raw:
            return set()
        if rhs_type in {"pattern", "regex"} or self._rhs_is_regexish(raw):
            matcher, _mkind = self._compile_matcher_from_rhs(raw)
        else:
            matcher = (lambda x: x == raw)
        return {
            _CondUtil.s(r.get("id"))
            for r in rows
            if matcher(_CondUtil.s(r.get("name"))) or matcher(_CondUtil.s(r.get("display_name")))
        }

    def _resolve_user_ids_by_name(self, *, op: str, rhs_val, rhs_type: str) -> set[str]:
        o = _CondUtil.norm_op(op)
        raw = _CondUtil.s(rhs_val)
        names = []
        matcher = None

        if o == "in":
            names = [n for n in (_CondUtil.s(x) for x in _CondUtil.as_str_list(rhs_val)) if n]
            if not names:
                return set()
        else:
            if not raw:
                return set()
            if rhs_type in {"pattern", "regex"} or self._rhs_is_regexish(raw):
                matcher, _mkind = self._compile_matcher_from_rhs(raw)
            else:
                matcher = (lambda x: x == raw)

        rows = []
        try:
            rows.extend(self.session.get_resource_fields("identity_users", columns=["id", "name", "email"]) or [])
        except Exception:
            pass
        try:
            rows.extend(self.session.get_resource_fields("identity_domain_users", columns=["id", "ocid", "display_name", "user_name"]) or [])
        except Exception:
            pass

        out: set[str] = set()
        for r in rows:
            uid = _CondUtil.s(r.get("ocid") or r.get("id") or "")
            if not uid:
                continue
            candidates = [
                _CondUtil.s(r.get("name")),
                _CondUtil.s(r.get("display_name")),
                _CondUtil.s(r.get("user_name")),
                _CondUtil.s(r.get("email")),
            ]
            candidates = [c for c in candidates if c]
            if not candidates:
                continue
            if o == "in":
                if any(c in names for c in candidates):
                    out.add(uid)
                continue
            if matcher and any(matcher(c) for c in candidates):
                out.add(uid)
        return out

    def _resolve_resource_table_info(self, resource_tokens_l: set[str]) -> dict[str, dict]:
        tok_key = frozenset(_CondUtil.canon_tokens(resource_tokens_l or set()))
        if tok_key in self._resource_table_info_cache:
            return dict(self._resource_table_info_cache[tok_key])

        scope_map = (
            getattr(self.ctx, "RESOURCE_SCOPE_MAP", None)
            or getattr(self.ctx, "resource_scope_map", None)
            or getattr(self.ctx, "scope_map", None)
        )
        if not isinstance(scope_map, dict):
            try:
                from ocinferno.modules.opengraph.utilities.resource_scope_graph_builder import RESOURCE_SCOPE_MAP as scope_map
            except Exception:
                scope_map = {}

        try:
            from ocinferno.modules.opengraph.utilities.helpers.constants import DEFAULT_RESOURCE_FAMILIES as families
            families = families or {}
        except Exception:
            families = {}

        def canon(x: str) -> str:
            return _CondUtil.l(_CondUtil.s(x))

        def norm_path(p):
            if not p:
                return None
            if isinstance(p, str):
                p = p.strip()
                return p or None
            if isinstance(p, (list, tuple)):
                p = [canon(x) for x in p if _CondUtil.s(x)]
                return p or None
            return None

        out: dict[str, dict] = {}

        def add_token(tok: str):
            tok = canon(tok)
            info = scope_map.get(tok)
            if not isinstance(info, dict):
                return
            tables = info.get("tables")
            specs = []
            if isinstance(tables, (list, tuple)):
                base = {k: v for k, v in info.items() if k != "tables"}
                for entry in tables:
                    if not isinstance(entry, dict):
                        continue
                    merged = dict(base)
                    merged.update(entry)
                    specs.append(merged)
            else:
                specs.append(info)

            for spec in specs:
                if not isinstance(spec, dict):
                    continue
                table = _CondUtil.s(spec.get("table"))
                if not table:
                    continue
                key = f"{tok}:{table}"
                out[key] = {
                    "table": table,
                    "id_col": spec.get("id_col") or "id",
                    "id_path": norm_path(spec.get("id_path") or spec.get("id_json_path") or spec.get("id_key_path")),
                    "compartment_col": _CondUtil.s(spec.get("compartment_col") or ""),
                }

        toks = {canon(t) for t in (resource_tokens_l or ()) if _CondUtil.s(t)}

        if "all-resources" in toks or "all_resources" in toks:
            for tok, info in scope_map.items():
                if isinstance(info, dict) and info.get("table"):
                    add_token(tok)
            self._resource_table_info_cache[tok_key] = dict(out)
            return out

        for tok in sorted(toks):
            if tok in families:
                for child in families.get(tok) or ():
                    add_token(child)
            else:
                add_token(tok)

        self._resource_table_info_cache[tok_key] = dict(out)
        return out

    def _match_resources_across_tables(
        self,
        *,
        resource_tokens_l: set[str],
        location_ids: set[str],
        reason_ok: str,
        reason_fail: str,
        row_matches=None,
        per_table_where: dict | None = None,
        include_missing_compartment_filter: bool = False,
        match_col: str | None = None,
        match_key_path: str | list[str] | tuple[str, ...] | None = None,
        match_op: str = "eq",
        match_value=None,
        missing_is_match_for_ne: bool = True,
    ) -> "ContextDelta":
        info_by_token = self._resolve_resource_table_info(set(resource_tokens_l or ()))
        if not info_by_token:
            return _delta_unknown("no resource tables resolved for tokens", unresolved=True)

        locs = set(location_ids or ())
        if not locs and not include_missing_compartment_filter:
            return _delta_unknown("no candidate locations to scope resource match", unresolved=True)

        if row_matches is None:
            col = _CondUtil.s(match_col)
            if not col:
                return _delta_unknown("no row_matches provided and no match_col specified", unresolved=True)

            o = _CondUtil.norm_op(match_op)

            def row_matches(r: dict) -> bool:
                actual = self._row_get_value(r, col, match_key_path)
                if o == "eq":
                    return actual is not None and actual == match_value
                if o == "neq":
                    return (actual is None and missing_is_match_for_ne) or (actual is not None and actual != match_value)
                return False

        table_info: dict[str, dict] = {}
        for info in info_by_token.values():
            t = _CondUtil.s(info.get("table"))
            if not t or t in table_info:
                continue
            table_info[t] = {
                "id_col": info.get("id_col") or "id",
                "id_path": info.get("id_path"),
                "compartment_col": _CondUtil.s(info.get("compartment_col") or ""),
            }

        matched_rows_by_table: dict[str, list[dict]] = {}
        matched_ids: set[str] = set()

        for tname, info in sorted(table_info.items()):
            id_col = info.get("id_col") or "id"
            id_path = info.get("id_path")
            comp_col = info.get("compartment_col") or "compartment_id"
            comp_ids = [None] if not comp_col else (sorted(locs) if locs else [None])

            for cid in comp_ids:
                where = dict(per_table_where or {})
                if cid is not None:
                    if comp_col:
                        where[comp_col] = _CondUtil.s(cid)
                    elif not include_missing_compartment_filter:
                        continue

                try:
                    rows = self._query_rows_cached(tname, where if where else None) or []
                except Exception:
                    continue

                for r in rows:
                    try:
                        if row_matches(r):
                            matched_rows_by_table.setdefault(tname, []).append(r)
                            rid = self._row_get_value(r, id_col, id_path)
                            rid = _CondUtil.s(rid or "")
                            if rid:
                                matched_ids.add(rid)
                    except Exception:
                        continue

        if not matched_rows_by_table:
            return ContextDelta(tri=BoolTri.FALSE, matched_resource_node_ids=set(), matched_rows_by_table={}, unresolved=False, reason=reason_fail)

        return ContextDelta(tri=BoolTri.TRUE, matched_resource_node_ids=matched_ids, matched_rows_by_table=matched_rows_by_table, unresolved=False, reason=reason_ok)

    def _expand_applicable_with_families(self, applicable: set[str]) -> set[str]:
        """
        If applicable includes a child token (e.g., "secrets"), also allow any
        resource-family tokens whose DEFAULT_RESOURCE_FAMILIES expansion includes it.
        """
        applicable = {_CondUtil.l(_CondUtil.s(x)) for x in (applicable or set()) if _CondUtil.s(x)}
        if not applicable:
            return set()

        try:
            from ocinferno.modules.opengraph.utilities.helpers.constants import DEFAULT_RESOURCE_FAMILIES as families
            families = families or {}
        except Exception:
            families = {}

        # Build reverse map: child -> {families...}
        fams_for_child: dict[str, set[str]] = {}
        for fam, kids in (families or {}).items():
            fam_l = _CondUtil.l(_CondUtil.s(fam))
            if not fam_l or not isinstance(kids, (list, tuple, set)):
                continue
            for k in kids:
                k_l = _CondUtil.l(_CondUtil.s(k))
                if k_l:
                    fams_for_child.setdefault(k_l, set()).add(fam_l)

        out = set(applicable)
        for child in list(applicable):
            out |= fams_for_child.get(child, set())

        return out


    def _compile_matcher_from_rhs(self, raw: str):
        """
        Build a matcher from RHS string.

        Returns: (matcher_fn(str)->bool, kind:str)

        Supports:
        - regex:<expr>  -> regex search
        - /glob*/       -> fnmatch glob
        - regex-ish     -> attempt regex compile (auto)
        - else          -> exact string compare
        """
        s = _CondUtil.s(raw)
        if not s:
            return (lambda _n: False), "empty"

        # explicit regex:
        if s.lower().startswith("regex:"):
            expr = s[6:]
            try:
                rx = re.compile(expr)
                return (lambda n: bool(rx.search(_CondUtil.s(n)))), "regex"
            except Exception:
                return (lambda _n: False), "bad-regex"

        # /.../ treated as glob (your convention)
        if len(s) >= 2 and s[0] == "/" and s[-1] == "/":
            pat = s[1:-1]
            return (lambda n: fnmatch.fnmatchcase(_CondUtil.s(n), _CondUtil.s(pat))), "glob"

        # auto regex-ish
        if self._rhs_is_regexish(s):
            try:
                rx = re.compile(s)
                return (lambda n: bool(rx.search(_CondUtil.s(n)))), "regex-auto"
            except Exception:
                return (lambda _n: False), "bad-regex-auto"

        # exact
        want = s
        return (lambda n: _CondUtil.s(n) == want), "exact"

    # generic consolidated column handler core
    def _rhs_is_regexish(self, s: str) -> bool:
        s = _CondUtil.s(s)
        if not s:
            return False
        sl = s.lower()
        if sl.startswith("regex:"):
            return True
        if len(s) >= 2 and s[0] == "/" and s[-1] == "/":
            return True
        strong_tokens = ["\\", "[", "]", "(", ")", "{", "}", "|", "^", "$"]
        if any(tok in s for tok in strong_tokens):
            return True
        if ".*" in s or ".+" in s:
            return True
        return False

    def _delta_false_mismatch(self, varname: str, toks: set[str]) -> ContextDelta:
        toks_s = ",".join(sorted(toks)) if toks else ""
        return ContextDelta(tri=BoolTri.FALSE, unresolved=False, reason=f"{varname}: resource-token mismatch (tokens={toks_s})")

    def _effective_scope_or_mismatch(self, *, varname: str, ctx: EvalContext, applicable: set[str], force_token: str) -> tuple[ContextDelta | None, set[str]]:
        toks = _CondUtil.canon_tokens(ctx.resource_tokens_l)
        if toks and (not _CondUtil.is_wildcard_tokens(toks)) and not (toks & set(applicable or ())):
            return self._delta_false_mismatch(varname, toks), set()
        return None, {force_token}

    def _tokens_for_applicable(self, *, varname: str, ctx: EvalContext, applicable: set[str]) -> tuple[ContextDelta | None, set[str]]:
        """
        Resolve which resource tokens to query for a handler.

        - If statement tokens don't intersect applicable (and not wildcard), return FALSE.
        - Otherwise return the intersection (if explicit) or full applicable set.
        """
        toks = _CondUtil.canon_tokens(ctx.resource_tokens_l)
        applicable = self._expand_applicable_with_families(set(applicable or ()))
        if toks and (not _CondUtil.is_wildcard_tokens(toks)) and not (toks & applicable):
            return self._delta_false_mismatch(varname, toks), set()
        if toks and not _CondUtil.is_wildcard_tokens(toks):
            return None, set(toks & applicable)
        return None, set(applicable)

    def _build_tag_row_matcher(
        self,
        *,
        var_full: str,
        base_prefix: str,
        op: str,
        rhs_val,
        varname_for_errors: str,
        ctx: EvalContext | None = None,
    ) -> tuple[ContextDelta | None, callable | None, str | None]:
        """
        Build a row matcher for tag-based clauses.

        Returns: (early_delta, matcher_fn, debug_kind)
        - If early_delta is not None -> caller should return it immediately
        - matcher_fn(row)->bool implements eq/neq semantics
        - debug_kind is "exact"/"glob"/"regex"/"regex-auto" for reason strings
        """
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq"}:
            return _delta_unknown(f"{varname_for_errors} only supports '=' or '!=' offline", unresolved=True), None, None

        nk = self._parse_tag_attr(var_full=var_full, base_prefix=base_prefix)
        if not nk:
            return _delta_unknown(f"{varname_for_errors} unparseable tag attribute", unresolved=True), None, None

        namespace, key = nk
        raw = _CondUtil.s(rhs_val)
        if not raw:
            return _delta_unknown(f"{varname_for_errors} rhs empty", unresolved=True), None, None

        if _CondUtil.l(raw) == "request.groups.id":
            if ctx is None:
                return _delta_unknown(f"{varname_for_errors}: request.groups.id requires context", unresolved=True), None, None
            group_ids = self._resolve_request_group_ids(ctx)
            if group_ids is None:
                return _delta_unknown(f"{varname_for_errors}: request.groups.id group cache missing", unresolved=True), None, None
            group_ids = { _CondUtil.s(g) for g in (group_ids or set()) if _CondUtil.s(g) }

            def row_matches(row: dict) -> bool:
                tag_val = self._row_tag_value(row, namespace, key)
                if tag_val is None:
                    return (o == "neq")
                tag_val_s = _CondUtil.s(tag_val)
                ok = tag_val_s in group_ids
                return ok if o == "eq" else (not ok)

            return None, row_matches, "request.groups.id"

        matcher, mkind = self._compile_matcher_from_rhs(raw)
        if mkind in {"bad-regex", "bad-regex-auto"}:
            return _delta_unknown(f"{varname_for_errors} invalid regex: {raw}", unresolved=True), None, None

        def row_matches(row: dict) -> bool:
            tag_val = self._row_tag_value(row, namespace, key)

            # OCI-ish semantics:
            #   eq  => tag must exist AND match
            #   neq => tag missing OR does not match
            if tag_val is None:
                return (o == "neq")

            ok = matcher(_CondUtil.s(tag_val))
            return ok if o == "eq" else (not ok)

        return None, row_matches, mkind


    def _h_target_column(
        self,
        *,
        varname: str,
        token: str,
        op: str,
        rhs_val,
        ctx: EvalContext,
        col: str,
        key_path: str | list[str] | tuple[str, ...] | None = None,
        allow_regex: bool = False,
        allow_patterns: bool | None = None,
        allow_in: bool | None = None,
        applicable: set[str] | None = None,
        missing_is_match_for_neq: bool = True,
    ) -> ContextDelta:
        """
        Generic "match a column (optionally inside JSON)" handler.

        Supports:
        - eq / neq / in
        - Optional JSON key path: col="node_properties", key_path="a.b.c"
        - Optional regex/glob matching (Python-side), controlled by allow_regex

        Notes:
        - If allow_regex=True, RHS may be regex:<expr> or /glob*/ or "regex-ish".
        - If allow_regex=False, RHS is treated literally (exact string compare).
        - For JSON + regex/glob we must use row_matches.
        - For JSON + literal eq/neq we can use match_col/match_key_path (fast path).
        """
        o = _CondUtil.norm_op(op)
        if allow_patterns is not None:
            allow_regex = bool(allow_patterns)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"{varname} unsupported op={o}", unresolved=True)
        if o == "in" and allow_in is False:
            return _delta_unknown(f"{varname} does not support 'in' offline", unresolved=True)

        col = _CondUtil.s(col)
        if not col:
            return _delta_unknown(f"{varname} missing col", unresolved=True)

        applicable = self._expand_applicable_with_families(set(applicable or {token}))
        early_delta, forced_tokens = self._effective_scope_or_mismatch(
            varname=varname,
            ctx=ctx,
            applicable=applicable,
            force_token=token,
        )
        if early_delta is not None:
            return early_delta

        # -----------------------------
        # IN: exact list membership
        # -----------------------------
        if o == "in":
            vals = [v for v in (_CondUtil.s(x) for x in _CondUtil.as_str_list(rhs_val)) if v]
            if not vals:
                return _delta_unknown(f"{varname} in rhs empty", unresolved=True)

            vals_set = set(vals)

            def matches(row: dict) -> bool:
                v = self._row_get_value(row, col, key_path)
                sv = _CondUtil.s(v)
                return bool(sv and sv in vals_set)

            return self._match_resources_across_tables(
                resource_tokens_l=forced_tokens,
                location_ids=set(ctx.location_ids or ()),
                row_matches=matches,
                reason_ok=f"{varname} in-list matched {token} via DB",
                reason_fail=f"{varname}: no matching {token} (in)",
            )

        # -----------------------------
        # EQ / NEQ
        # -----------------------------
        raw = _CondUtil.s(rhs_val)
        if not raw:
            return _delta_unknown(f"{varname} rhs empty", unresolved=True)

        # If regex not allowed, always treat RHS as literal
        if not allow_regex:
            # Fast path: literal compare via match_col/match_key_path
            return self._match_resources_across_tables(
                resource_tokens_l=forced_tokens,
                location_ids=set(ctx.location_ids or ()),
                match_col=col,
                match_key_path=key_path,
                match_op=o,
                match_value=raw,
                missing_is_match_for_ne=missing_is_match_for_neq,
                reason_ok=f"{varname} matched {token} via DB ({o}, literal)",
                reason_fail=f"{varname}: no matching {token}",
            )

        # Regex/glob/exact via Python matcher
        matcher, mkind = self._compile_matcher_from_rhs(raw)
        if mkind in {"bad-regex", "bad-regex-auto"}:
            return _delta_unknown(f"{varname} invalid regex: {raw}", unresolved=True)

        def matches(row: dict) -> bool:
            v = self._row_get_value(row, col, key_path)
            sv = _CondUtil.s(v)
            if not sv:
                return (o == "neq") and missing_is_match_for_neq
            ok = matcher(sv)
            return ok if o == "eq" else (not ok)

        return self._match_resources_across_tables(
            resource_tokens_l=forced_tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok=f"{varname} matched {token} via DB ({o}, {mkind})",
            reason_fail=f"{varname}: no matching {token}",
        )

    # -----------------------------
    # GENERIC PRINCIPAL EXPANSION (for future request.* principal conditionals)
    # - group subjects -> user ids via ctx.group_member_mapping_cache[group_id] = set(user_ocids)
    # - dynamic-group subjects -> member ids via ctx.dynamic_group_member_mapping_cache[dg_id] = {member_id: row, ...}
    # -----------------------------

    # -----------------------------
    # EXPLICIT EXPANSION HELPERS (only called by handlers that request expand=...)
    # -----------------------------

    def _expand_group_subjects_to_users(
        self,
        ctx: EvalContext,
        *,
        restrict_group_ids: set[str] | None = None,
    ) -> ContextDelta:
        """
        Expand group subjects -> user ids.

        Only expands:
        - group subjects already present in ctx.subjects
        - optionally restricted to restrict_group_ids
        """
        restrict = { _CondUtil.s(x) for x in (restrict_group_ids or set()) if _CondUtil.s(x) }
        cache = getattr(self.ctx, "group_member_mapping_cache", {}) or {}

        out_users: set[str] = set()
        saw_any_group = False

        for s in (ctx.subjects or []):
            if self._subj_kind(s) != "group":
                continue
            gid = self._subj_id(s)
            if not gid:
                continue
            if restrict and gid not in restrict:
                continue

            saw_any_group = True
            members = cache.get(gid)
            if members is None:
                return _delta_unknown(f"group members not cached for {gid}", unresolved=True)

            out_users |= { _CondUtil.s(u) for u in (members or set()) if _CondUtil.s(u) }

        if restrict and not saw_any_group:
            return _delta_false("group_to_users expansion: requested group id not in candidate subjects")

        if not out_users:
            return _delta_false("group_to_users expansion: no members")

        return ContextDelta(
            tri=BoolTri.TRUE,
            replace_subjects=[{"id": x, "node_type": NODE_TYPE_OCI_USER} for x in sorted(out_users)],
            unresolved=False,
            reason=f"group->users expansion ({len(out_users)})",
        )


    def _expand_dynamic_group_subjects(
        self,
        ctx: EvalContext,
        *,
        restrict_dynamic_group_ids: set[str] | None = None,
    ) -> ContextDelta:
        """
        Expand dynamic-group subjects -> member ids (resource principals).

        Only expands:
        - DG subjects already present in ctx.subjects
        - optionally restricted to restrict_dynamic_group_ids
        """
        restrict = { _CondUtil.s(x) for x in (restrict_dynamic_group_ids or set()) if _CondUtil.s(x) }
        cache = getattr(self.ctx, "dynamic_group_member_mapping_cache", {}) or {}

        out_members: set[str] = set()
        saw_any_dg = False

        for s in (ctx.subjects or []):
            sk = self._subj_kind(s)
            if sk not in {"dynamic-group", "dynamic_group", "dynamicgroup"}:
                continue
            dg_id = self._subj_id(s)
            if not dg_id:
                continue
            if restrict and dg_id not in restrict:
                continue

            saw_any_dg = True
            rows_by_id = cache.get(dg_id)
            if rows_by_id is None:
                return _delta_unknown(f"dynamic-group members not cached for {dg_id}", unresolved=True)

            out_members |= { _CondUtil.s(mid) for mid in (rows_by_id.keys() or ()) if _CondUtil.s(mid) }

        if restrict and not saw_any_dg:
            return _delta_false("dg_to_members expansion: requested dg id not in candidate subjects")

        if not out_members:
            return _delta_false("dg_to_members expansion: no members")

        return ContextDelta(
            tri=BoolTri.TRUE,
            replace_subjects=[{"id": x, "node_type": "OCIResource"} for x in sorted(out_members)],
            unresolved=False,
            reason=f"dg->members expansion ({len(out_members)})",
        )

    def _has_dynamic_group_subjects(self, ctx: EvalContext) -> bool:
        kinds = {self._subj_kind(s) for s in (ctx.subjects or [])}
        return bool(kinds & {"dynamic-group", "dynamic_group", "dynamicgroup"})

    def _expand_dynamic_group_subjects_by_compartment(self, ctx: EvalContext, compartment_id: str) -> list[dict] | None:
        cid = _CondUtil.s(compartment_id)
        if not cid:
            return []
        cache = getattr(self.ctx, "dynamic_group_member_mapping_cache", {}) or {}
        out: list[dict] = []
        saw_any_dg = False

        for s in (ctx.subjects or []):
            sk = self._subj_kind(s)
            if sk not in {"dynamic-group", "dynamic_group", "dynamicgroup"}:
                continue
            dg_id = self._subj_id(s)
            if not dg_id:
                continue
            saw_any_dg = True
            rows_by_id = cache.get(dg_id)
            if rows_by_id is None:
                return None
            for mid, row in (rows_by_id or {}).items():
                if not mid or not isinstance(row, dict):
                    continue
                mcomp = _CondUtil.s(row.get("compartment_id") or row.get("compartment_ocid") or "")
                if mcomp != cid:
                    continue
                node_type = _CondUtil.s(row.get("node_type") or "OCIResource")
                out.append({"id": _CondUtil.s(mid), "node_type": node_type})

        if not saw_any_dg:
            return []

        # de-dupe by id
        dedup = {}
        for r in out:
            rid = r.get("id")
            if rid and rid not in dedup:
                dedup[rid] = r
        return list(dedup.values())

    def _iter_scope_specs(self, spec):
        if not isinstance(spec, dict):
            return ()
        tables = spec.get("tables")
        if isinstance(tables, (list, tuple)):
            base = {k: v for k, v in spec.items() if k != "tables"}
            out = []
            for entry in tables:
                if not isinstance(entry, dict):
                    continue
                merged = dict(base)
                merged.update(entry)
                out.append(merged)
            return out
        return (spec,)

    def _row_get(self, row: dict, key):
        if not isinstance(row, dict):
            return None
        if isinstance(key, (list, tuple)):
            parts = []
            for k in key:
                v = row.get(k)
                if v is None:
                    return None
                parts.append(str(v))
            return "::".join(parts)
        return row.get(key)

    def _resource_principal_subjects_by_compartment(self, compartment_id: str) -> list[dict] | None:
        """
        Expand ANY-USER/ANY-GROUP to resource principals in a compartment.
        Uses RESOURCE_PRINCIPAL_SCOPE_TOKENS + RESOURCE_SCOPE_MAP.
        """
        cid = _CondUtil.s(compartment_id)
        if not cid:
            return []

        sess = getattr(self, "session", None)
        if sess is None:
            return None

        out: dict[str, dict] = {}
        for tok in sorted(RESOURCE_PRINCIPAL_SCOPE_TOKENS or ()):
            spec = RESOURCE_SCOPE_MAP.get(_CondUtil.l(tok))
            for s in self._iter_scope_specs(spec):
                if not isinstance(s, dict):
                    continue
                table = s.get("table")
                id_col = s.get("id_col")
                comp_col = s.get("compartment_col")
                node_type = s.get("node_type") or "OCIResource"
                if not (table and id_col and comp_col):
                    continue
                try:
                    rows = sess.get_resource_fields(table, where_conditions={comp_col: cid}) or []
                except Exception:
                    continue
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    rid = self._row_get(row, id_col)
                    if not (isinstance(rid, str) and rid):
                        continue
                    out[rid] = {"id": rid, "node_type": node_type, "kind": "resource"}
        return list(out.values())

    def _eval_tag_clause(
        self,
        *,
        var_full: str,
        base_prefix: str,
        op: str,
        rhs_val,
        ctx: EvalContext,
        resource_tokens_l: set[str],
        ok_prefix: str,
        fail_reason: str,
    ) -> ContextDelta:
        """
        Thin wrapper around _build_tag_row_matcher + _match_resources_across_tables.
        """
        early, row_matches, mkind = self._build_tag_row_matcher(
            var_full=var_full,
            base_prefix=base_prefix,
            op=op,
            rhs_val=rhs_val,
            varname_for_errors=base_prefix,   # good enough for error strings
            ctx=ctx,
        )
        if early is not None:
            return early

        o = _CondUtil.norm_op(op)

        return self._match_resources_across_tables(
            resource_tokens_l=set(resource_tokens_l or ()),
            location_ids=set(ctx.location_ids or ()),
            row_matches=row_matches,
            reason_ok=f"{ok_prefix} ({o}, {mkind})",
            reason_fail=fail_reason,
        )

    def _compartment_tag_poststep(
        self,
        *,
        d: ContextDelta,
        ctx: EvalContext,
        reason_prefix: str,
    ) -> ContextDelta:
        matched_roots = set(getattr(d, "matched_resource_node_ids", set()) or ())
        if not matched_roots:
            return ContextDelta(
                tri=BoolTri.FALSE,
                allowed_location_ids=set(),
                matched_rows_by_table={"resource_compartments": []},
                unresolved=False,
                reason=f"{reason_prefix}: no matching compartments",
            )

        expanded = self._expand_descendants(
            roots=matched_roots,
            children_by_compartment_id=ctx.children_by_compartment_id,
        )
        allowed = expanded & set(ctx.location_ids or ())
        if not allowed:
            return ContextDelta(
                tri=BoolTri.FALSE,
                allowed_location_ids=set(),
                unresolved=False,
                reason=f"{reason_prefix}: expansion produced no in-scope compartments",
            )
        
        # Unlike target.resources.tag, target.resources.compartment.tag only reduces the location values in ContextDelta, no resource changes
        return ContextDelta(
            tri=BoolTri.TRUE,
            allowed_location_ids=allowed,
            unresolved=False,
            reason=f"{reason_prefix}: matched + expanded descendants",
        )


    # specific handlers
    def _h_target_compartment_id(self, *, op: str, rhs_val, ctx: EvalContext, **_):
        return _eval_target_compartment_id_clause(
            op=op,
            rhs_val=rhs_val,
            candidate_location_ids=set(ctx.location_ids),
            children_by_compartment_id=getattr(ctx, "children_by_compartment_id", None),
        )

    def _h_request_instance_compartment_id(self, *, op: str, rhs_val, ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq"}:
            return _delta_unknown(f"request.instance.compartment.id unsupported op={o}", unresolved=True)

        want = _CondUtil.s(rhs_val)
        if not want:
            return _delta_unknown("request.instance.compartment.id rhs empty", unresolved=True)

        # If caller is a dynamic-group (resource principal), trim subjects to DG members in compartment.
        if self._has_dynamic_group_subjects(ctx):
            subjects = self._expand_dynamic_group_subjects_by_compartment(ctx, want)
            if subjects is None:
                return _delta_unknown("request.instance.compartment.id: dynamic-group members not cached", unresolved=True)
            if not subjects:
                return _delta_false("request.instance.compartment.id: no DG members in compartment")
            return ContextDelta(
                tri=BoolTri.TRUE,
                replace_subjects=subjects,
                unresolved=False,
                reason="request.instance.compartment.id: filtered dynamic-group members by compartment",
            )

        # ANY-USER/ANY-GROUP: treat as resource principals in the compartment.
        has_any_user, has_any_group = self._is_any_principal(ctx)
        if has_any_user or has_any_group:
            subjects = self._resource_principal_subjects_by_compartment(want)
            if subjects is None:
                return _delta_unknown("request.instance.compartment.id: resource principal expansion failed", unresolved=True)
            if not subjects:
                return _delta_false("request.instance.compartment.id: no resource principals in compartment")
            return ContextDelta(
                tri=BoolTri.TRUE,
                replace_subjects=subjects,
                unresolved=False,
                reason="request.instance.compartment.id: any-principal -> resource principals in compartment",
            )

        # Not applicable for other subject types in our caller-oriented model.
        return _delta_unknown("request.instance.compartment.id: unsupported subject type", unresolved=True)

    def _h_request_operation(self, *, var: str, op: str, rhs_val, ctx: EvalContext, rhs_type: str, **_):
        o = _CondUtil.norm_op(op)
        if o == "neq":
            return _delta_unknown("request.operation neq not modelable offline", unresolved=True)

        ops = _extract_request_operation_ops(var, op, rhs_type or "", rhs_val)
        if not ops:
            return _delta_unknown(f"request.operation unsupported/empty op={o}", unresolved=True)

        required: set[str] = set()
        unknown_ops: list[str] = []
        scoped_mismatch_ops: list[str] = []
        saw_no_perm_op = False
        resolved_ops = 0
        for oname in sorted(ops):
            req, no_perm, known, scoped_mismatch = _operation_requirements_for_context(oname, set(ctx.resource_tokens_l or ()))
            if scoped_mismatch:
                scoped_mismatch_ops.append(oname)
                continue
            if not known:
                unknown_ops.append(oname)
                continue
            resolved_ops += 1
            if no_perm:
                saw_no_perm_op = True
                continue
            if req:
                required |= req

        if unknown_ops and not resolved_ops:
            return _delta_unknown("unknown operation(s): " + ", ".join(sorted(unknown_ops)), unresolved=True)

        if not resolved_ops and scoped_mismatch_ops:
            return _delta_false(
                "request.operation not compatible with statement resource scope: "
                + ", ".join(sorted(scoped_mismatch_ops))
            )

        # If a no-permission op is present in the set, avoid over-trimming or false negatives.
        if saw_no_perm_op and required:
            keep = set(ctx.perms or required)
            return ContextDelta(
                tri=BoolTri.TRUE,
                trimmed_permissions=keep,
                unresolved=False,
                reason="request.operation includes no-permission operation(s); permissions not trimmed",
            )

        if not required and saw_no_perm_op:
            return _delta_true("request.operation: no-permission operation")
        if not required:
            return _delta_unknown("operation perms mapping empty", unresolved=True)

        verb_derived = _looks_like_verb_derived_input(ctx)

        if not ctx.perms:
            trimmed = set(required)
            mode = "no_ctx_perms"
        elif verb_derived:
            if (ctx.perms & required):
                trimmed = set(required)
                mode = "verb_derived_hit"
            else:
                trimmed = set()
                mode = "verb_derived_miss"
        else:
            trimmed = ctx.perms & required
            mode = "explicit_intersect"

        if ctx.perms and not trimmed:
            return ContextDelta(tri=BoolTri.FALSE, trimmed_permissions=set(), unresolved=False, reason=f"request.operation requires perms not satisfied (mode={mode})")

        return ContextDelta(tri=BoolTri.TRUE, trimmed_permissions=trimmed, unresolved=False, reason=f"request.operation satisfied (mode={mode})")

    def _h_request_permission(self, *, var: str, op: str, rhs_val, rhs_type: str, ctx: EvalContext, **_) -> ContextDelta:
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"} and rhs_type not in {"pattern", "regex"}:
            return _delta_unknown(f"request.permission unsupported op={o}", unresolved=True)

        perms = { _CondUtil.s(p) for p in (ctx.perms or set()) if _CondUtil.s(p) }
        if not perms:
            return _delta_unknown("request.permission: no permissions in context", unresolved=True)

        # Build matcher or candidate set
        want_set: set[str] = set()
        matcher = None

        if rhs_type in {"pattern", "regex"}:
            raw = _CondUtil.s(rhs_val)
            matcher, mkind = self._compile_matcher_from_rhs(raw)
            if mkind in {"bad-regex", "bad-regex-auto"}:
                return _delta_unknown(f"request.permission invalid pattern: {raw}", unresolved=True)
        elif o == "in":
            want_set = { _CondUtil.s(v) for v in _CondUtil.as_str_list(rhs_val) if _CondUtil.s(v) }
        else:
            raw = _CondUtil.s(rhs_val)
            if not raw:
                return _delta_unknown("request.permission rhs empty", unresolved=True)
            want_set = { raw }

        # Case-insensitive matching against ctx.perms
        perms_by_l = {p.lower(): p for p in perms}

        matched: set[str] = set()
        if matcher:
            for p in perms:
                if matcher(p):
                    matched.add(p)
        else:
            for w in want_set:
                if w.lower() in perms_by_l:
                    matched.add(perms_by_l[w.lower()])

        if o == "neq":
            if not matched:
                return ContextDelta(tri=BoolTri.TRUE, trimmed_permissions=perms, unresolved=False, reason="request.permission != no matches")
            trimmed = {p for p in perms if p not in matched}
            if not trimmed:
                return ContextDelta(tri=BoolTri.FALSE, trimmed_permissions=set(), unresolved=False, reason="request.permission != filtered all perms")
            return ContextDelta(tri=BoolTri.TRUE, trimmed_permissions=trimmed, unresolved=False, reason="request.permission != filtered perms")

        # eq / in / pattern
        if not matched:
            return _delta_false("request.permission: no matching permissions")
        return ContextDelta(tri=BoolTri.TRUE, trimmed_permissions=matched, unresolved=False, reason=f"request.permission matched {len(matched)} perms")

    def _h_request_user_id(self, *, op: str, rhs_val, ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o != "eq":
            return _delta_unknown(f"request.user.id unsupported op={o}", unresolved=True)

        want = _CondUtil.s(rhs_val)
        if not want:
            return _delta_unknown("request.user.id rhs empty", unresolved=True)

        # ANY_USER: restrict to users in scoped compartments
        has_any_user, has_any_group = self._is_any_principal(ctx)
        if has_any_user:
            locs = set(ctx.location_ids or ())
            if locs and not self._user_exists_in_locations(want, locs):
                return _delta_false("request.user.id: user not found in scoped compartments")
            return ContextDelta(
                tri=BoolTri.TRUE,
                replace_subjects=[{"id": want, "node_type": NODE_TYPE_OCI_USER}],
                unresolved=False,
                reason="request.user.id (ANY_USER): matched user id in scope",
            )

        # Group subjects: ensure user belongs to at least one allowed group
        if self._has_group_subjects(ctx):
            ok = self._user_in_any_group(want, ctx)
            if ok is None:
                return _delta_unknown("request.user.id: group membership cache missing", unresolved=True)
            if not ok:
                return _delta_false("request.user.id: user not in allowed group subjects")
            return ContextDelta(
                tri=BoolTri.TRUE,
                replace_subjects=[{"id": want, "node_type": NODE_TYPE_OCI_USER}],
                unresolved=False,
                reason="request.user.id: user is member of allowed group(s)",
            )

        # Concrete user subjects: filter directly
        return ContextDelta(
            tri=BoolTri.TRUE,
            filter_subject_ids={want},
            unresolved=False,
            reason="request.user.id: filtered to explicit user id",
        )

    def _h_request_user_name(self, *, op: str, rhs_val, ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o == "eq":
            pats = [_CondUtil.s(rhs_val)]
            if not pats[0]:
                return _delta_unknown("request.user.name rhs empty", unresolved=True)
        elif o == "in":
            pats = [p for p in _CondUtil.as_str_list(rhs_val) if p]
            if not pats:
                return _delta_unknown("request.user.name in rhs empty", unresolved=True)
        elif o == "neq":
            pats = [_CondUtil.s(rhs_val)]
            if not pats[0]:
                return _delta_unknown("request.user.name rhs empty", unresolved=True)
        else:
            return _delta_unknown(f"request.user.name unsupported op={o}", unresolved=True)

        resolved_any = False
        matched_ids: set[str] = set()

        has_any_user, _ = self._is_any_principal(ctx)
        if has_any_user:
            # Expand ANY_USER -> concrete users in candidate locations, then filter by name.
            locs = set(ctx.location_ids or ())
            users = self._users_in_locations(locs)
            if not users:
                return _delta_unknown("request.user.name: no users available to expand ANY_USER", unresolved=True)

            for uid, names in users:
                if not names:
                    continue
                resolved_any = True
                is_match = any(_CondUtil.pattern_match(nm, p) for nm in names for p in pats)
                if o == "neq":
                    is_match = not is_match
                if is_match:
                    matched_ids.add(uid)

            if not resolved_any:
                return _delta_unknown("request.user.name: could not resolve any user names", unresolved=True)
            if not matched_ids:
                return _delta_false("request.user.name matched none")

            return ContextDelta(
                tri=BoolTri.TRUE,
                replace_subjects=[{"id": x, "node_type": NODE_TYPE_OCI_USER} for x in sorted(matched_ids)],
                unresolved=False,
                reason="request.user.name expanded ANY_USER to matching users",
            )

        # Group subjects: expand group members, then filter by name
        if self._has_group_subjects(ctx):
            user_ids = self._expand_group_subjects_to_user_ids(ctx)
            if user_ids is None:
                return _delta_unknown("request.user.name: group membership cache missing", unresolved=True)
            if not user_ids:
                return _delta_false("request.user.name: no members in allowed group subjects")

            names_by_id = self._user_names_by_id()
            for uid in user_ids:
                names = names_by_id.get(uid) or []
                if not names:
                    continue
                resolved_any = True
                is_match = any(_CondUtil.pattern_match(nm, p) for nm in names for p in pats)
                if o == "neq":
                    is_match = not is_match
                if is_match:
                    matched_ids.add(uid)

            if not resolved_any:
                return _delta_unknown("request.user.name: could not resolve user names for group members", unresolved=True)
            if not matched_ids:
                return _delta_false("request.user.name matched none in group members")

            return ContextDelta(
                tri=BoolTri.TRUE,
                replace_subjects=[{"id": x, "node_type": NODE_TYPE_OCI_USER} for x in sorted(matched_ids)],
                unresolved=False,
                reason="request.user.name filtered group members by name",
            )

        # Concrete subjects (user IDs): filter by resolved subject name
        for subj in (ctx.subjects or []):
            sid = _CondUtil.subject_id(subj)
            if not sid:
                continue
            nm = self._resolve_subject_name(sid)
            if not nm:
                continue
            resolved_any = True

            is_match = any(_CondUtil.pattern_match(nm, p) for p in pats)
            if o == "neq":
                is_match = not is_match
            if is_match:
                matched_ids.add(sid)

        if not resolved_any:
            return _delta_unknown("request.user.name could not resolve any candidate names", unresolved=True)
        if not matched_ids:
            return _delta_false("request.user.name matched none")

        return ContextDelta(tri=BoolTri.TRUE, filter_subject_ids=matched_ids, unresolved=False, reason="request.user.name filtered subjects")

    def _resolve_subject_name(self, subject_node_id: str) -> str:
        sid = _CondUtil.s(subject_node_id)
        if not sid:
            return ""

        cached = self._subject_name_cache.get(sid)
        if cached:
            return cached

        for attr in ("nodes_by_id", "node_map", "graph_nodes_by_id"):
            m = getattr(self.ctx, attr, None)
            if isinstance(m, dict):
                rec = m.get(sid)
                if isinstance(rec, dict):
                    for k in ("display_name", "name", "idcs_name"):
                        v = rec.get(k)
                        if isinstance(v, str) and v.strip():
                            v = v.strip()
                            self._subject_name_cache[sid] = v
                            return v
                    props = rec.get("properties")
                    if isinstance(props, dict):
                        for k in ("name", "display_name"):
                            v = props.get(k)
                            if isinstance(v, str) and v.strip():
                                v = v.strip()
                                self._subject_name_cache[sid] = v
                                return v
        return ""

    # -----------------------------------------------------------------
    # IAM target.* handlers (resource-scoped)
    # -----------------------------------------------------------------

    def _h_target_compartment_name(self, *, op: str, rhs_val, ctx: EvalContext, rhs_type: str = "", **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.compartment.name unsupported op={o}", unresolved=True)

        locs = set(ctx.location_ids or ())
        if not locs:
            return _delta_unknown("target.compartment.name no candidate locations", unresolved=True)

        if o == "in":
            names = [n for n in (_CondUtil.s(x) for x in _CondUtil.as_str_list(rhs_val)) if n]
            if not names:
                return _delta_unknown("target.compartment.name in rhs empty", unresolved=True)
            name_set = set(names)
            rows = self.session.get_resource_fields("resource_compartments", columns=["compartment_id", "name"]) or []
            matched_ids = { _CondUtil.s(r.get("compartment_id")) for r in rows if _CondUtil.s(r.get("name")) in name_set }
        else:
            raw = _CondUtil.s(rhs_val)
            if not raw:
                return _delta_unknown("target.compartment.name rhs empty", unresolved=True)
            if rhs_type in {"pattern", "regex"} or self._rhs_is_regexish(raw):
                matcher, _mkind = self._compile_matcher_from_rhs(raw)
            else:
                matcher = (lambda x: x == raw)
            rows = self.session.get_resource_fields("resource_compartments", columns=["compartment_id", "name"]) or []
            matched_ids = {
                _CondUtil.s(r.get("compartment_id"))
                for r in rows
                if matcher(_CondUtil.s(r.get("name")))
            }

        matched_ids = {i for i in matched_ids if i}
        if o in {"eq", "in"}:
            allowed = locs & matched_ids
            if not allowed:
                return _delta_false("target.compartment.name matched no candidate locations")
            return ContextDelta(tri=BoolTri.TRUE, allowed_location_ids=allowed, unresolved=False, reason="target.compartment.name matched locations")

        # neq
        allowed = {c for c in locs if c not in matched_ids}
        if not allowed:
            return _delta_false("target.compartment.name != removed all candidates")
        return ContextDelta(tri=BoolTri.TRUE, allowed_location_ids=allowed, unresolved=False, reason="target.compartment.name != filtered")

    def _h_target_user_id(self, *, op: str, rhs_val, ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.user.id unsupported op={o}", unresolved=True)

        ids = [i for i in (_CondUtil.s(x) for x in (_CondUtil.as_str_list(rhs_val) if o == "in" else [rhs_val])) if i]
        if not ids:
            return _delta_unknown("target.user.id rhs empty", unresolved=True)
        want_ids = set(ids)

        early, tokens = self._tokens_for_applicable(varname="target.user.id", ctx=ctx, applicable={"users", "credentials"})
        if early is not None:
            return early
        if not tokens:
            return _delta_unknown("target.user.id no applicable tokens", unresolved=True)

        def matches(row: dict) -> bool:
            uid = self._extract_user_ref(row.get("user")) if "user" in row else _CondUtil.s(row.get("ocid") or row.get("id") or "")
            if not uid:
                return (o == "neq")
            in_set = uid in want_ids
            if o == "neq":
                return not in_set
            return in_set

        return self._match_resources_across_tables(
            resource_tokens_l=tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok="target.user.id matched resources",
            reason_fail="target.user.id: no matching resources",
        )

    def _h_target_user_name(self, *, op: str, rhs_val, rhs_type: str = "", ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.user.name unsupported op={o}", unresolved=True)

        if o == "in":
            name_list = [n for n in (_CondUtil.s(x) for x in _CondUtil.as_str_list(rhs_val)) if n]
            if not name_list:
                return _delta_unknown("target.user.name in rhs empty", unresolved=True)
            name_set = set(name_list)
            matcher = None
        else:
            raw = _CondUtil.s(rhs_val)
            if not raw:
                return _delta_unknown("target.user.name rhs empty", unresolved=True)
            if rhs_type in {"pattern", "regex"} or self._rhs_is_regexish(raw):
                matcher, _mkind = self._compile_matcher_from_rhs(raw)
            else:
                matcher = (lambda x: x == raw)
            name_set = set()

        # Resolve user ids by name (for credential rows)
        matched_user_ids = self._resolve_user_ids_by_name(op=o, rhs_val=rhs_val, rhs_type=rhs_type)

        early, tokens = self._tokens_for_applicable(varname="target.user.name", ctx=ctx, applicable={"users", "credentials"})
        if early is not None:
            return early
        if not tokens:
            return _delta_unknown("target.user.name no applicable tokens", unresolved=True)

        def matches(row: dict) -> bool:
            # Credential row: match via resolved user ids
            if "user" in row:
                uid = self._extract_user_ref(row.get("user"))
                if not uid:
                    return (o == "neq")
                in_set = uid in matched_user_ids
                if o == "neq":
                    return not in_set
                return in_set

            # User row: match by name fields
            fields = ["name", "display_name", "user_name", "email"]
            if o == "in":
                found = any(_CondUtil.s(row.get(f)) in name_set for f in fields if row.get(f))
            else:
                found = self._match_any_name(row, fields=fields, matcher=matcher)

            if o == "neq":
                return not found
            return found

        if o in {"eq", "in"} and not matched_user_ids and not name_set and matcher is None:
            return _delta_false("target.user.name matched no users")

        return self._match_resources_across_tables(
            resource_tokens_l=tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok="target.user.name matched resources",
            reason_fail="target.user.name: no matching resources",
        )

    def _h_target_group_id(self, *, op: str, rhs_val, ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.group.id unsupported op={o}", unresolved=True)
        ids = [i for i in (_CondUtil.s(x) for x in (_CondUtil.as_str_list(rhs_val) if o == "in" else [rhs_val])) if i]
        if not ids:
            return _delta_unknown("target.group.id rhs empty", unresolved=True)
        want_ids = set(ids)

        early, tokens = self._tokens_for_applicable(varname="target.group.id", ctx=ctx, applicable={"groups"})
        if early is not None:
            return early

        def matches(row: dict) -> bool:
            gid = _CondUtil.s(row.get("ocid") or row.get("id") or "")
            if not gid:
                return (o == "neq")
            in_set = gid in want_ids
            return (not in_set) if o == "neq" else in_set

        return self._match_resources_across_tables(
            resource_tokens_l=tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok="target.group.id matched groups",
            reason_fail="target.group.id: no matching groups",
        )

    def _h_target_group_name(self, *, op: str, rhs_val, rhs_type: str = "", ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.group.name unsupported op={o}", unresolved=True)

        if o == "in":
            name_list = [n for n in (_CondUtil.s(x) for x in _CondUtil.as_str_list(rhs_val)) if n]
            if not name_list:
                return _delta_unknown("target.group.name in rhs empty", unresolved=True)
            name_set = set(name_list)
            matcher = None
        else:
            raw = _CondUtil.s(rhs_val)
            if not raw:
                return _delta_unknown("target.group.name rhs empty", unresolved=True)
            if rhs_type in {"pattern", "regex"} or self._rhs_is_regexish(raw):
                matcher, _mkind = self._compile_matcher_from_rhs(raw)
            else:
                matcher = (lambda x: x == raw)
            name_set = set()

        early, tokens = self._tokens_for_applicable(varname="target.group.name", ctx=ctx, applicable={"groups"})
        if early is not None:
            return early

        def matches(row: dict) -> bool:
            fields = ["name", "display_name"]
            if o == "in":
                found = any(_CondUtil.s(row.get(f)) in name_set for f in fields if row.get(f))
            else:
                found = self._match_any_name(row, fields=fields, matcher=matcher)
            return (not found) if o == "neq" else found

        return self._match_resources_across_tables(
            resource_tokens_l=tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok="target.group.name matched groups",
            reason_fail="target.group.name: no matching groups",
        )

    def _h_target_group_member(self, *, op: str, rhs_val, ctx: EvalContext, **_):
        """
        target.group.member is a boolean (true/false). Offline we only support:
        - target.group.member = true
        ...and only when explicit user subjects are present.
        """
        o = _CondUtil.norm_op(op)
        if o != "eq":
            return _delta_unknown(f"target.group.member unsupported op={o}", unresolved=True)

        raw = _CondUtil.s(rhs_val).lower()
        if raw not in {"true", "false"}:
            return _delta_unknown("target.group.member rhs must be true/false", unresolved=True)
        if raw == "false":
            return _delta_unknown("target.group.member=false not modeled offline", unresolved=True)

        # Only proceed if we have explicit user subjects
        user_ids = {self._subj_id(s) for s in (ctx.subjects or []) if self._subj_kind(s) in {"user", "user-id"} and self._subj_id(s)}
        if not user_ids:
            return _delta_unknown("target.group.member: no explicit user subjects to evaluate", unresolved=True)

        cache = getattr(self.ctx, "group_member_mapping_cache", {}) or {}
        if not cache:
            return _delta_unknown("target.group.member: group membership cache missing", unresolved=True)

        early, tokens = self._tokens_for_applicable(varname="target.group.member", ctx=ctx, applicable={"groups"})
        if early is not None:
            return early

        # Build matched group ids in scope
        info_by_token = self._resolve_resource_table_info(set(tokens))
        if not info_by_token:
            return _delta_unknown("target.group.member: no resource tables resolved", unresolved=True)

        locs = set(ctx.location_ids or ())
        matched_ids: set[str] = set()
        matched_rows_by_table: dict[str, list[dict]] = {}

        table_info: dict[str, dict] = {}
        for info in info_by_token.values():
            t = _CondUtil.s(info.get("table"))
            if not t or t in table_info:
                continue
            table_info[t] = {
                "id_col": info.get("id_col") or "id",
                "id_path": info.get("id_path"),
                "compartment_col": _CondUtil.s(info.get("compartment_col") or ""),
            }

        for tname, info in sorted(table_info.items()):
            id_col = info.get("id_col") or "id"
            id_path = info.get("id_path")
            comp_col = info.get("compartment_col") or "compartment_id"
            comp_ids = [None] if not comp_col else (sorted(locs) if locs else [None])

            for cid in comp_ids:
                where = {}
                if cid is not None:
                    if comp_col:
                        where[comp_col] = _CondUtil.s(cid)
                    else:
                        continue
                try:
                    rows = self.session.get_resource_fields(tname, where_conditions=where if where else None, columns=None) or []
                except Exception:
                    continue
                for r in rows:
                    gid = _CondUtil.s(self._row_get_value(r, id_col, id_path) or r.get("ocid") or r.get("id"))
                    if not gid:
                        continue
                    members = cache.get(gid)
                    if members is None:
                        continue
                    if any(_CondUtil.s(u) in members for u in user_ids):
                        matched_rows_by_table.setdefault(tname, []).append(r)
                        matched_ids.add(gid)

        if not matched_ids:
            return ContextDelta(tri=BoolTri.FALSE, matched_resource_node_ids=set(), matched_rows_by_table={}, unresolved=False, reason="target.group.member matched none")

        return ContextDelta(
            tri=BoolTri.TRUE,
            matched_resource_node_ids=matched_ids,
            matched_rows_by_table=matched_rows_by_table,
            unresolved=False,
            reason="target.group.member matched groups containing request.user",
        )

    def _h_target_dynamic_group_id(self, *, op: str, rhs_val, ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.dynamic-group.id unsupported op={o}", unresolved=True)
        ids = [i for i in (_CondUtil.s(x) for x in (_CondUtil.as_str_list(rhs_val) if o == "in" else [rhs_val])) if i]
        if not ids:
            return _delta_unknown("target.dynamic-group.id rhs empty", unresolved=True)
        want_ids = set(ids)

        early, tokens = self._tokens_for_applicable(varname="target.dynamic-group.id", ctx=ctx, applicable={"dynamic-groups"})
        if early is not None:
            return early

        def matches(row: dict) -> bool:
            did = _CondUtil.s(row.get("ocid") or row.get("id") or "")
            if not did:
                return (o == "neq")
            in_set = did in want_ids
            return (not in_set) if o == "neq" else in_set

        return self._match_resources_across_tables(
            resource_tokens_l=tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok="target.dynamic-group.id matched dynamic-groups",
            reason_fail="target.dynamic-group.id: no matching dynamic-groups",
        )

    def _h_target_dynamic_group_name(self, *, op: str, rhs_val, rhs_type: str = "", ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.dynamic-group.name unsupported op={o}", unresolved=True)

        if o == "in":
            name_list = [n for n in (_CondUtil.s(x) for x in _CondUtil.as_str_list(rhs_val)) if n]
            if not name_list:
                return _delta_unknown("target.dynamic-group.name in rhs empty", unresolved=True)
            name_set = set(name_list)
            matcher = None
        else:
            raw = _CondUtil.s(rhs_val)
            if not raw:
                return _delta_unknown("target.dynamic-group.name rhs empty", unresolved=True)
            if rhs_type in {"pattern", "regex"} or self._rhs_is_regexish(raw):
                matcher, _mkind = self._compile_matcher_from_rhs(raw)
            else:
                matcher = (lambda x: x == raw)
            name_set = set()

        early, tokens = self._tokens_for_applicable(varname="target.dynamic-group.name", ctx=ctx, applicable={"dynamic-groups"})
        if early is not None:
            return early

        def matches(row: dict) -> bool:
            fields = ["name", "display_name"]
            if o == "in":
                found = any(_CondUtil.s(row.get(f)) in name_set for f in fields if row.get(f))
            else:
                found = self._match_any_name(row, fields=fields, matcher=matcher)
            return (not found) if o == "neq" else found

        return self._match_resources_across_tables(
            resource_tokens_l=tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok="target.dynamic-group.name matched dynamic-groups",
            reason_fail="target.dynamic-group.name: no matching dynamic-groups",
        )

    def _h_target_policy_id(self, *, op: str, rhs_val, ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.policy.id unsupported op={o}", unresolved=True)
        ids = [i for i in (_CondUtil.s(x) for x in (_CondUtil.as_str_list(rhs_val) if o == "in" else [rhs_val])) if i]
        if not ids:
            return _delta_unknown("target.policy.id rhs empty", unresolved=True)
        want_ids = set(ids)

        early, tokens = self._tokens_for_applicable(varname="target.policy.id", ctx=ctx, applicable={"policies"})
        if early is not None:
            return early

        def matches(row: dict) -> bool:
            pid = _CondUtil.s(row.get("id") or "")
            if not pid:
                return (o == "neq")
            in_set = pid in want_ids
            return (not in_set) if o == "neq" else in_set

        return self._match_resources_across_tables(
            resource_tokens_l=tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok="target.policy.id matched policies",
            reason_fail="target.policy.id: no matching policies",
        )

    def _h_target_policy_name(self, *, op: str, rhs_val, rhs_type: str = "", ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.policy.name unsupported op={o}", unresolved=True)

        if o == "in":
            name_list = [n for n in (_CondUtil.s(x) for x in _CondUtil.as_str_list(rhs_val)) if n]
            if not name_list:
                return _delta_unknown("target.policy.name in rhs empty", unresolved=True)
            name_set = set(name_list)
            matcher = None
        else:
            raw = _CondUtil.s(rhs_val)
            if not raw:
                return _delta_unknown("target.policy.name rhs empty", unresolved=True)
            if rhs_type in {"pattern", "regex"} or self._rhs_is_regexish(raw):
                matcher, _mkind = self._compile_matcher_from_rhs(raw)
            else:
                matcher = (lambda x: x == raw)
            name_set = set()

        early, tokens = self._tokens_for_applicable(varname="target.policy.name", ctx=ctx, applicable={"policies"})
        if early is not None:
            return early

        def matches(row: dict) -> bool:
            fields = ["name"]
            if o == "in":
                found = any(_CondUtil.s(row.get(f)) in name_set for f in fields if row.get(f))
            else:
                found = self._match_any_name(row, fields=fields, matcher=matcher)
            return (not found) if o == "neq" else found

        return self._match_resources_across_tables(
            resource_tokens_l=tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok="target.policy.name matched policies",
            reason_fail="target.policy.name: no matching policies",
        )

    def _h_target_credential_type(self, *, op: str, rhs_val, ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "in"}:
            return _delta_unknown(f"target.credential.type unsupported op={o}", unresolved=True)

        raw_types = _CondUtil.as_str_list(rhs_val) if o == "in" else [_CondUtil.s(rhs_val)]
        raw_types = [t.lower() for t in raw_types if _CondUtil.s(t)]
        if not raw_types:
            return _delta_unknown("target.credential.type rhs empty", unresolved=True)

        type_to_tokens = {
            "smtp": {"identity-domain-user-smtp-credentials"},
            "smtp-credential": {"identity-domain-user-smtp-credentials"},
            "smtp-credentials": {"identity-domain-user-smtp-credentials"},
            "api-key": {"identity-domain-user-api-keys"},
            "apikey": {"identity-domain-user-api-keys"},
            "db-credential": {"identity-domain-user-db-credentials"},
            "db-credentials": {"identity-domain-user-db-credentials"},
        }

        matched_tokens: set[str] = set()
        for t in raw_types:
            matched_tokens |= type_to_tokens.get(t, set())

        if not matched_tokens:
            return _delta_unknown("target.credential.type unknown or unsupported type", unresolved=True)

        early, _ = self._tokens_for_applicable(varname="target.credential.type", ctx=ctx, applicable={"credentials"})
        if early is not None:
            return early

        return self._match_resources_across_tables(
            resource_tokens_l=matched_tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=lambda _r: True,
            reason_ok="target.credential.type matched credentials",
            reason_fail="target.credential.type: no matching credentials",
        )

    def _h_target_resource_domain_id(self, *, op: str, rhs_val, ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.resource.domain.id unsupported op={o}", unresolved=True)

        ids = [i for i in (_CondUtil.s(x) for x in (_CondUtil.as_str_list(rhs_val) if o == "in" else [rhs_val])) if i]
        if not ids:
            return _delta_unknown("target.resource.domain.id rhs empty", unresolved=True)
        want_ids = set(ids)

        early, tokens = self._tokens_for_applicable(varname="target.resource.domain.id", ctx=ctx, applicable={"users", "groups", "dynamic-groups", "credentials"})
        if early is not None:
            return early
        if not tokens:
            return _delta_unknown("target.resource.domain.id no applicable tokens", unresolved=True)

        def matches(row: dict) -> bool:
            dom = _CondUtil.s(row.get("domain_ocid") or "")
            if not dom:
                return (o == "neq")
            in_set = dom in want_ids
            return (not in_set) if o == "neq" else in_set

        return self._match_resources_across_tables(
            resource_tokens_l=tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok="target.resource.domain.id matched resources",
            reason_fail="target.resource.domain.id: no matching resources",
        )

    def _h_target_resource_domain_name(self, *, op: str, rhs_val, rhs_type: str = "", ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.resource.domain.name unsupported op={o}", unresolved=True)

        dom_ids = self._resolve_domain_ids_by_name(op=o, rhs_val=rhs_val, rhs_type=rhs_type)
        if not dom_ids and o in {"eq", "in"}:
            return _delta_false("target.resource.domain.name matched no domains")

        early, tokens = self._tokens_for_applicable(varname="target.resource.domain.name", ctx=ctx, applicable={"users", "groups", "dynamic-groups", "credentials"})
        if early is not None:
            return early

        def matches(row: dict) -> bool:
            dom = _CondUtil.s(row.get("domain_ocid") or "")
            if not dom:
                return (o == "neq")
            in_set = dom in dom_ids
            return (not in_set) if o == "neq" else in_set

        return self._match_resources_across_tables(
            resource_tokens_l=tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok="target.resource.domain.name matched resources",
            reason_fail="target.resource.domain.name: no matching resources",
        )

    def _h_target_domain_name(self, *, op: str, rhs_val, rhs_type: str = "", ctx: EvalContext, **_):
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.domain.name unsupported op={o}", unresolved=True)

        if o == "in":
            name_list = [n for n in (_CondUtil.s(x) for x in _CondUtil.as_str_list(rhs_val)) if n]
            if not name_list:
                return _delta_unknown("target.domain.name in rhs empty", unresolved=True)
            name_set = set(name_list)
            matcher = None
        else:
            raw = _CondUtil.s(rhs_val)
            if not raw:
                return _delta_unknown("target.domain.name rhs empty", unresolved=True)
            if rhs_type in {"pattern", "regex"} or self._rhs_is_regexish(raw):
                matcher, _mkind = self._compile_matcher_from_rhs(raw)
            else:
                matcher = (lambda x: x == raw)
            name_set = set()

        early, tokens = self._tokens_for_applicable(varname="target.domain.name", ctx=ctx, applicable={"domains"})
        if early is not None:
            return early

        def matches(row: dict) -> bool:
            fields = ["name", "display_name"]
            if o == "in":
                found = any(_CondUtil.s(row.get(f)) in name_set for f in fields if row.get(f))
            else:
                found = self._match_any_name(row, fields=fields, matcher=matcher)
            return (not found) if o == "neq" else found

        return self._match_resources_across_tables(
            resource_tokens_l=tokens,
            location_ids=set(ctx.location_ids or ()),
            row_matches=matches,
            reason_ok="target.domain.name matched domains",
            reason_fail="target.domain.name: no matching domains",
        )

    def _h_target_job_operation(self, *, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        return self._h_target_column(
            varname="target.job.operation",
            token="orm-jobs",
            op=op,
            rhs_val=rhs_val,
            ctx=ctx,
            col="operation",
            allow_regex=False,
            allow_in=True,
            applicable={"orm_jobs", "orm-jobs", "jobs", "resource-manager-jobs"},
        )

    def _h_target_stack_id(self, *, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        return self._h_target_column(
            varname="target.stack.id",
            token="orm-stacks",
            op=op,
            rhs_val=rhs_val,
            ctx=ctx,
            col="id",
            allow_regex=False,
            allow_in=True,
            applicable={"orm_stacks", "stacks", "orm-stacks", "resource-manager-stacks"},
        )

    def _h_target_loggroup_id(self, *, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        return self._h_target_column(
            varname="target.loggroup.id",
            token="log-groups",
            op=op,
            rhs_val=rhs_val,
            ctx=ctx,
            col="id",
            allow_regex=False,
            allow_in=True,
            applicable={"log-groups", "logging-family", "log-content", "unified-configuration"},
        )

    def _h_unresolvable(self, *, var: str, **_):
        return _delta_unknown(f"offline-unresolvable var: {var}", unresolved=True)
    # DNS handlers
    def _dns_zone_rows(self) -> list[dict]:
        if isinstance(self._dns_zone_cache, dict):
            return list(self._dns_zone_cache.values())
        rows = self.session.get_resource_fields("dns_zones") or []
        cache = {}
        for r in rows:
            if not isinstance(r, dict):
                continue
            zid = _CondUtil.s(r.get("id") or "")
            if not zid:
                continue
            cache[zid] = r
        self._dns_zone_cache = cache
        return list(cache.values())

    def _dns_zone_by_id(self) -> dict[str, dict]:
        if isinstance(self._dns_zone_cache, dict):
            return self._dns_zone_cache
        self._dns_zone_rows()
        return self._dns_zone_cache or {}

    def _dns_tokens_ok(self, varname: str, ctx: EvalContext) -> tuple[ContextDelta | None, bool, bool]:
        toks = _CondUtil.canon_tokens(ctx.resource_tokens_l)
        if toks and (not _CondUtil.is_wildcard_tokens(toks)) and not (toks & {"dns-zones", "dns-zone-records", "dns-records"}):
            return self._delta_false_mismatch(varname, toks), False, False
        allow_zones = (not toks) or _CondUtil.is_wildcard_tokens(toks) or ("dns-zones" in toks)
        allow_records = (not toks) or _CondUtil.is_wildcard_tokens(toks) or ("dns-zone-records" in toks) or ("dns-records" in toks)
        return None, allow_zones, allow_records

    def _merge_match_deltas(self, deltas: list[ContextDelta], varname: str) -> ContextDelta:
        deltas = [d for d in deltas if isinstance(d, ContextDelta)]
        if not deltas:
            return _delta_unknown(f"{varname}: no applicable resource tables", unresolved=True)
        any_true = any(d.tri == BoolTri.TRUE for d in deltas)
        any_unknown = any(d.tri == BoolTri.UNKNOWN for d in deltas)
        tri = BoolTri.TRUE if any_true else (BoolTri.UNKNOWN if any_unknown else BoolTri.FALSE)
        matched_rows: dict[str, list[dict]] = {}
        matched_ids: set[str] = set()
        reasons = []
        for d in deltas:
            reasons.append(d.reason)
            if d.matched_rows_by_table:
                matched_rows = _CondUtil.merge_rows_by_table(matched_rows, d.matched_rows_by_table)
            if d.matched_resource_node_ids:
                matched_ids |= set(d.matched_resource_node_ids or ())
        return ContextDelta(
            tri=tri,
            matched_rows_by_table=matched_rows if matched_rows else None,
            matched_resource_node_ids=matched_ids if matched_ids else None,
            unresolved=bool(tri == BoolTri.UNKNOWN),
            reason="; ".join([r for r in reasons if r]),
        )

    def _h_target_dns_zone_id(self, *, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq"}:
            return _delta_unknown(f"target.dns-zone.id unsupported op={o}", unresolved=True)
        want = _CondUtil.s(rhs_val)
        if not want:
            return _delta_unknown("target.dns-zone.id rhs empty", unresolved=True)

        early, allow_zones, allow_records = self._dns_tokens_ok("target.dns-zone.id", ctx)
        if early is not None:
            return early

        deltas = []
        if allow_zones:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zones"},
                    location_ids=set(ctx.location_ids or ()),
                    match_col="id",
                    match_op=o,
                    match_value=want,
                    reason_ok="target.dns-zone.id matched dns-zones",
                    reason_fail="target.dns-zone.id no matching dns-zones",
                )
            )
        if allow_records:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zone-records"},
                    location_ids=set(ctx.location_ids or ()),
                    match_col="zone_id",
                    match_op=o,
                    match_value=want,
                    reason_ok="target.dns-zone.id matched dns-zone-records",
                    reason_fail="target.dns-zone.id no matching dns-zone-records",
                )
            )
        return self._merge_match_deltas(deltas, "target.dns-zone.id")

    def _h_target_dns_zone_name(self, *, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.dns-zone.name unsupported op={o}", unresolved=True)
        vals = [v for v in (_CondUtil.s(x) for x in (_CondUtil.as_str_list(rhs_val) if o == "in" else [rhs_val])) if v]
        if not vals:
            return _delta_unknown("target.dns-zone.name rhs empty", unresolved=True)
        vals_set = set(vals)

        early, allow_zones, allow_records = self._dns_tokens_ok("target.dns-zone.name", ctx)
        if early is not None:
            return early

        def zone_matches(row: dict) -> bool:
            v = _CondUtil.s(row.get("name"))
            if not v:
                return o == "neq"
            ok = v in vals_set
            return ok if o != "neq" else (not ok)

        def record_matches(row: dict) -> bool:
            zid = _CondUtil.s(row.get("zone_id"))
            if not zid:
                return o == "neq"
            z = self._dns_zone_by_id().get(zid) or {}
            v = _CondUtil.s(z.get("name"))
            if not v:
                return o == "neq"
            ok = v in vals_set
            return ok if o != "neq" else (not ok)

        deltas = []
        if allow_zones:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zones"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=zone_matches,
                    reason_ok="target.dns-zone.name matched dns-zones",
                    reason_fail="target.dns-zone.name no matching dns-zones",
                )
            )
        if allow_records:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zone-records"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=record_matches,
                    reason_ok="target.dns-zone.name matched dns-zone-records",
                    reason_fail="target.dns-zone.name no matching dns-zone-records",
                )
            )
        return self._merge_match_deltas(deltas, "target.dns-zone.name")

    def _h_target_dns_zone_apex_label(self, *, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq"}:
            return _delta_unknown(f"target.dns-zone.apex-label unsupported op={o}", unresolved=True)
        want = _CondUtil.s(rhs_val)
        if not want:
            return _delta_unknown("target.dns-zone.apex-label rhs empty", unresolved=True)

        early, allow_zones, allow_records = self._dns_tokens_ok("target.dns-zone.apex-label", ctx)
        if early is not None:
            return early

        def apex_from_name(n: str) -> str:
            n = _CondUtil.s(n)
            if not n:
                return ""
            return n.split(".", 1)[0]

        def zone_matches(row: dict) -> bool:
            v = apex_from_name(row.get("name"))
            if not v:
                return o == "neq"
            ok = v == want
            return ok if o != "neq" else (not ok)

        def record_matches(row: dict) -> bool:
            zid = _CondUtil.s(row.get("zone_id"))
            z = self._dns_zone_by_id().get(zid) or {}
            v = apex_from_name(z.get("name"))
            if not v:
                return o == "neq"
            ok = v == want
            return ok if o != "neq" else (not ok)

        deltas = []
        if allow_zones:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zones"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=zone_matches,
                    reason_ok="target.dns-zone.apex-label matched dns-zones",
                    reason_fail="target.dns-zone.apex-label no matching dns-zones",
                )
            )
        if allow_records:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zone-records"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=record_matches,
                    reason_ok="target.dns-zone.apex-label matched dns-zone-records",
                    reason_fail="target.dns-zone.apex-label no matching dns-zone-records",
                )
            )
        return self._merge_match_deltas(deltas, "target.dns-zone.apex-label")

    def _h_target_dns_zone_parent_domain(self, *, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq"}:
            return _delta_unknown(f"target.dns-zone.parent-domain unsupported op={o}", unresolved=True)
        want = _CondUtil.s(rhs_val)
        if not want:
            return _delta_unknown("target.dns-zone.parent-domain rhs empty", unresolved=True)

        early, allow_zones, allow_records = self._dns_tokens_ok("target.dns-zone.parent-domain", ctx)
        if early is not None:
            return early

        def parent_from_name(n: str) -> str:
            n = _CondUtil.s(n)
            if not n or "." not in n:
                return ""
            return n.split(".", 1)[1]

        def zone_matches(row: dict) -> bool:
            v = parent_from_name(row.get("name"))
            if not v:
                return o == "neq"
            ok = v == want
            return ok if o != "neq" else (not ok)

        def record_matches(row: dict) -> bool:
            zid = _CondUtil.s(row.get("zone_id"))
            z = self._dns_zone_by_id().get(zid) or {}
            v = parent_from_name(z.get("name"))
            if not v:
                return o == "neq"
            ok = v == want
            return ok if o != "neq" else (not ok)

        deltas = []
        if allow_zones:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zones"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=zone_matches,
                    reason_ok="target.dns-zone.parent-domain matched dns-zones",
                    reason_fail="target.dns-zone.parent-domain no matching dns-zones",
                )
            )
        if allow_records:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zone-records"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=record_matches,
                    reason_ok="target.dns-zone.parent-domain matched dns-zone-records",
                    reason_fail="target.dns-zone.parent-domain no matching dns-zone-records",
                )
            )
        return self._merge_match_deltas(deltas, "target.dns-zone.parent-domain")

    def _h_target_dns_scope(self, *, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq", "in"}:
            return _delta_unknown(f"target.dns.scope unsupported op={o}", unresolved=True)
        vals = [v for v in (_CondUtil.s(x) for x in (_CondUtil.as_str_list(rhs_val) if o == "in" else [rhs_val])) if v]
        if not vals:
            return _delta_unknown("target.dns.scope rhs empty", unresolved=True)
        vals_set = set(vals)

        early, allow_zones, allow_records = self._dns_tokens_ok("target.dns.scope", ctx)
        if early is not None:
            return early

        def zone_matches(row: dict) -> bool:
            v = _CondUtil.s(row.get("scope"))
            if not v:
                return o == "neq"
            ok = v in vals_set
            return ok if o != "neq" else (not ok)

        def record_matches(row: dict) -> bool:
            zid = _CondUtil.s(row.get("zone_id"))
            z = self._dns_zone_by_id().get(zid) or {}
            v = _CondUtil.s(z.get("scope"))
            if not v:
                return o == "neq"
            ok = v in vals_set
            return ok if o != "neq" else (not ok)

        deltas = []
        if allow_zones:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zones"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=zone_matches,
                    reason_ok="target.dns.scope matched dns-zones",
                    reason_fail="target.dns.scope no matching dns-zones",
                )
            )
        if allow_records:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zone-records"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=record_matches,
                    reason_ok="target.dns.scope matched dns-zone-records",
                    reason_fail="target.dns.scope no matching dns-zone-records",
                )
            )
        return self._merge_match_deltas(deltas, "target.dns.scope")

    def _h_target_dns_zone_source_compartment_id(self, *, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq"}:
            return _delta_unknown(f"target.dns-zone.source-compartment.id unsupported op={o}", unresolved=True)
        want = _CondUtil.s(rhs_val)
        if not want:
            return _delta_unknown("target.dns-zone.source-compartment.id rhs empty", unresolved=True)

        early, allow_zones, allow_records = self._dns_tokens_ok("target.dns-zone.source-compartment.id", ctx)
        if early is not None:
            return early

        def zone_matches(row: dict) -> bool:
            v = _CondUtil.s(row.get("compartment_id"))
            if not v:
                return o == "neq"
            ok = v == want
            return ok if o != "neq" else (not ok)

        def record_matches(row: dict) -> bool:
            zid = _CondUtil.s(row.get("zone_id"))
            z = self._dns_zone_by_id().get(zid) or {}
            v = _CondUtil.s(z.get("compartment_id"))
            if not v:
                return o == "neq"
            ok = v == want
            return ok if o != "neq" else (not ok)

        deltas = []
        if allow_zones:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zones"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=zone_matches,
                    reason_ok="target.dns-zone.source-compartment.id matched dns-zones",
                    reason_fail="target.dns-zone.source-compartment.id no matching dns-zones",
                )
            )
        if allow_records:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zone-records"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=record_matches,
                    reason_ok="target.dns-zone.source-compartment.id matched dns-zone-records",
                    reason_fail="target.dns-zone.source-compartment.id no matching dns-zone-records",
                )
            )
        return self._merge_match_deltas(deltas, "target.dns-zone.source-compartment.id")

    def _h_target_dns_zone_destination_compartment_id(self, *, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        o = _CondUtil.norm_op(op)
        if o not in {"eq", "neq"}:
            return _delta_unknown(f"target.dns-zone.destination-compartment.id unsupported op={o}", unresolved=True)
        want = _CondUtil.s(rhs_val)
        if not want:
            return _delta_unknown("target.dns-zone.destination-compartment.id rhs empty", unresolved=True)

        early, allow_zones, allow_records = self._dns_tokens_ok("target.dns-zone.destination-compartment.id", ctx)
        if early is not None:
            return early

        def zone_matches(row: dict) -> bool:
            v = _CondUtil.s(row.get("compartment_id"))
            if not v:
                return o == "neq"
            ok = v == want
            return ok if o != "neq" else (not ok)

        def record_matches(row: dict) -> bool:
            zid = _CondUtil.s(row.get("zone_id"))
            z = self._dns_zone_by_id().get(zid) or {}
            v = _CondUtil.s(z.get("compartment_id"))
            if not v:
                return o == "neq"
            ok = v == want
            return ok if o != "neq" else (not ok)

        deltas = []
        if allow_zones:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zones"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=zone_matches,
                    reason_ok="target.dns-zone.destination-compartment.id matched dns-zones",
                    reason_fail="target.dns-zone.destination-compartment.id no matching dns-zones",
                )
            )
        if allow_records:
            deltas.append(
                self._match_resources_across_tables(
                    resource_tokens_l={"dns-zone-records"},
                    location_ids=set(ctx.location_ids or ()),
                    row_matches=record_matches,
                    reason_ok="target.dns-zone.destination-compartment.id matched dns-zone-records",
                    reason_fail="target.dns-zone.destination-compartment.id no matching dns-zone-records",
                )
            )
        return self._merge_match_deltas(deltas, "target.dns-zone.destination-compartment.id")

    def _h_target_resource_tag(self, *, var: str, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        return self._eval_tag_clause(
            var_full=var,
            base_prefix="target.resource.tag",
            op=op,
            rhs_val=rhs_val,
            ctx=ctx,
            resource_tokens_l=set(ctx.resource_tokens_l or ()),
            ok_prefix="target.resource.tag matched resources via DB",
            fail_reason="target.resource.tag: no matching resources",
        )


    def _h_target_resource_compartment_tag(self, *, var: str, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        d = self._eval_tag_clause(
            var_full=var,
            base_prefix="target.resource.compartment.tag",
            op=op,
            rhs_val=rhs_val,
            ctx=ctx,
            resource_tokens_l={"compartments"},
            ok_prefix="target.resource.compartment.tag matched compartments via DB",
            fail_reason="target.resource.compartment.tag: no matching compartments",
        )
        return self._compartment_tag_poststep(d=d, ctx=ctx, reason_prefix="target.resource.compartment.tag")

    def _h_request_principal_group_tag(self, *, var: str, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        early, row_matches, mkind = self._build_tag_row_matcher(
            var_full=var,
            base_prefix="request.principal.group.tag",
            op=op,
            rhs_val=rhs_val,
            varname_for_errors="request.principal.group.tag",
            ctx=ctx,
        )
        if early is not None:
            return early

        matched_groups, comp_by_id = self._collect_group_tag_matches(row_matches)
        matched_dgs = self._collect_dynamic_group_tag_matches(row_matches)

        if not matched_groups and not matched_dgs:
            return _delta_false("request.principal.group.tag: no tagged groups or dynamic-groups matched")

        kinds = {self._subj_kind(s) for s in (ctx.subjects or [])}
        locs = set(ctx.location_ids or ())

        # ANY_USER -> expand to users in policy compartments, then filter by tagged group membership
        if kinds & {"any-user", "any_user", "anyuser"}:
            if not matched_groups:
                return _delta_false("request.principal.group.tag: any-user but no tagged groups matched")
            user_ids = self._user_ids_for_group_ids(matched_groups)
            if user_ids is None:
                return _delta_unknown("request.principal.group.tag: group membership cache missing", unresolved=True)
            if locs:
                loc_users = self._user_ids_in_locations(locs)
                user_ids = user_ids & loc_users
            if not user_ids:
                return _delta_false("request.principal.group.tag: no users in tagged groups (scoped)")
            return self._replace_subjects_as(
                user_ids,
                kind="user",
                reason=f"request.principal.group.tag: any-user -> users in tagged groups ({len(user_ids)})",
            )

        # ANY_GROUP -> expand to all groups in policy compartments, then filter by tags
        if kinds & {"any-group", "any_group", "anygroup"}:
            group_scope = self._group_ids_in_locations(locs)
            keep = set(matched_groups) & set(group_scope)
            if not keep:
                return _delta_false("request.principal.group.tag: no tagged groups in scope")
            return self._replace_subjects_as(
                keep,
                kind="group",
                reason=f"request.principal.group.tag: any-group -> tagged groups ({len(keep)})",
            )

        # Group subjects -> keep only tagged groups
        if "group" in kinds:
            cand_ids = {self._subj_id(s) for s in (ctx.subjects or []) if self._subj_kind(s) == "group"}
            keep = cand_ids & matched_groups
            if not keep:
                return _delta_false("request.principal.group.tag: group subject(s) not tagged")
            return self._filter_subjects(ctx, keep, reason="request.principal.group.tag: matched tagged group subjects")

        # User subjects -> keep users who are in tagged groups (no expansion)
        if "user" in kinds:
            if not matched_groups:
                return _delta_false("request.principal.group.tag: no tagged groups for user subjects")
            cand_ids = {self._subj_id(s) for s in (ctx.subjects or []) if self._subj_kind(s) == "user"}
            keep = set()
            for uid in cand_ids:
                ok = self._user_in_group_ids(uid, matched_groups)
                if ok is None:
                    return _delta_unknown("request.principal.group.tag: group membership cache missing", unresolved=True)
                if ok:
                    keep.add(uid)
            if not keep:
                return _delta_false("request.principal.group.tag: user subjects not in tagged groups")
            return self._filter_subjects(ctx, keep, reason="request.principal.group.tag: matched user subjects in tagged groups")

        # Dynamic-group subjects -> keep only tagged dynamic-groups
        if kinds & {"dynamic-group", "dynamic_group", "dynamicgroup"}:
            cand_ids = {self._subj_id(s) for s in (ctx.subjects or []) if self._subj_kind(s) in {"dynamic-group", "dynamic_group", "dynamicgroup"}}
            keep = cand_ids & matched_dgs
            if not keep:
                return _delta_false("request.principal.group.tag: dynamic-group subject(s) not tagged")
            return self._filter_subjects(ctx, keep, reason="request.principal.group.tag: matched tagged dynamic-group subjects")

        # Resource subjects (from DG expansion) -> keep members in tagged DGs (no further expansion)
        if "resource" in kinds:
            if not matched_dgs:
                return _delta_false("request.principal.group.tag: no tagged dynamic-groups for resource subjects")
            resource_ids = self._resource_ids_for_dynamic_group_ids(matched_dgs)
            if resource_ids is None:
                return _delta_unknown("request.principal.group.tag: dynamic-group members not cached", unresolved=True)
            cand_ids = {self._subj_id(s) for s in (ctx.subjects or []) if self._subj_kind(s) == "resource"}
            keep = cand_ids & resource_ids
            if not keep:
                return _delta_false("request.principal.group.tag: resource subjects not in tagged dynamic-groups")
            return self._filter_subjects(ctx, keep, reason="request.principal.group.tag: matched resource subjects in tagged dynamic-groups")

        return _delta_unknown("request.principal.group.tag: unsupported subject kind", unresolved=True)

    def _h_request_principal_compartment_tag(self, *, var: str, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        early, row_matches, mkind = self._build_tag_row_matcher(
            var_full=var,
            base_prefix="request.principal.compartment.tag",
            op=op,
            rhs_val=rhs_val,
            varname_for_errors="request.principal.compartment.tag",
            ctx=ctx,
        )
        if early is not None:
            return early

        matched_compartments: set[str] = set()
        for c in (getattr(self.ctx, "compartments", []) or []):
            if not isinstance(c, dict):
                continue
            if not row_matches(c):
                continue
            cid = _CondUtil.s(c.get("compartment_id") or "")
            if cid:
                matched_compartments.add(cid)

        if not matched_compartments:
            return _delta_false("request.principal.compartment.tag: no tagged compartments matched")

        # Keep only compartments that are in the policy scope (if any)
        locs = set(ctx.location_ids or ())
        scoped = matched_compartments & locs if locs else matched_compartments
        if locs and not scoped:
            return _delta_false("request.principal.compartment.tag: no tagged compartments in scope")

        kinds = {self._subj_kind(s) for s in (ctx.subjects or [])}

        # ANY_USER -> expand to all users in policy compartments, then keep those in tagged compartments
        if kinds & {"any-user", "any_user", "anyuser"}:
            user_ids = self._user_ids_in_locations(scoped)
            if not user_ids:
                return _delta_false("request.principal.compartment.tag: no users in tagged compartments (scoped)")
            return self._replace_subjects_as(
                user_ids,
                kind="user",
                reason=f"request.principal.compartment.tag: any-user -> users in tagged compartments ({len(user_ids)})",
            )

        # ANY_GROUP -> expand to all groups in policy compartments, then keep those in tagged compartments
        if kinds & {"any-group", "any_group", "anygroup"}:
            group_ids = self._group_ids_in_locations(scoped)
            if not group_ids:
                return _delta_false("request.principal.compartment.tag: no groups in tagged compartments (scoped)")
            return self._replace_subjects_as(
                group_ids,
                kind="group",
                reason=f"request.principal.compartment.tag: any-group -> groups in tagged compartments ({len(group_ids)})",
            )

        # User subjects -> keep users whose compartment is tagged
        if "user" in kinds:
            scoped_users = self._user_ids_in_locations(scoped)
            cand_ids = {self._subj_id(s) for s in (ctx.subjects or []) if self._subj_kind(s) == "user"}
            keep = cand_ids & scoped_users
            if not keep:
                return _delta_false("request.principal.compartment.tag: user subjects not in tagged compartments")
            return self._filter_subjects(ctx, keep, reason="request.principal.compartment.tag: matched user subjects in tagged compartments")

        # Group subjects -> keep groups whose own compartment is tagged
        if "group" in kinds:
            comp_by_id = self._group_compartment_by_id()
            cand_ids = {self._subj_id(s) for s in (ctx.subjects or []) if self._subj_kind(s) == "group"}
            keep = {gid for gid in cand_ids if comp_by_id.get(gid) in scoped}
            if not keep:
                return _delta_false("request.principal.compartment.tag: group subjects not in tagged compartments")
            return self._filter_subjects(ctx, keep, reason="request.principal.compartment.tag: matched group subjects in tagged compartments")

        # Dynamic-group subjects -> keep DGs whose own compartment is tagged
        if kinds & {"dynamic-group", "dynamic_group", "dynamicgroup"}:
            comp_by_id = self._dynamic_group_compartment_by_id()
            cand_ids = {self._subj_id(s) for s in (ctx.subjects or []) if self._subj_kind(s) in {"dynamic-group", "dynamic_group", "dynamicgroup"}}
            keep = {gid for gid in cand_ids if comp_by_id.get(gid) in scoped}
            if not keep:
                return _delta_false("request.principal.compartment.tag: dynamic-group subjects not in tagged compartments")
            return self._filter_subjects(ctx, keep, reason="request.principal.compartment.tag: matched dynamic-group subjects in tagged compartments")

        return _delta_unknown("request.principal.compartment.tag: unsupported subject kind", unresolved=True)

    def _collect_group_tag_matches(self, row_matches) -> tuple[set[str], dict[str, str]]:
        matched: set[str] = set()
        comp_by_id: dict[str, str] = {}

        for g in (getattr(self.ctx, "idd_groups", []) or []):
            if not isinstance(g, dict):
                continue
            gid = _CondUtil.s(g.get("ocid") or "")
            if not gid:
                continue
            if not row_matches(g):
                continue
            matched.add(gid)
            comp = _CondUtil.s(g.get("compartment_ocid") or g.get("compartment_id") or "")
            if comp:
                comp_by_id[gid] = comp

        for g in (getattr(self.ctx, "classic_groups", []) or []):
            if not isinstance(g, dict):
                continue
            gid = _CondUtil.s(g.get("id") or "")
            if not gid:
                continue
            if not row_matches(g):
                continue
            matched.add(gid)
            comp = _CondUtil.s(g.get("compartment_id") or "")
            if comp:
                comp_by_id[gid] = comp

        return matched, comp_by_id

    def _collect_dynamic_group_tag_matches(self, row_matches) -> set[str]:
        matched: set[str] = set()
        for g in (getattr(self.ctx, "idd_dynamic_groups", []) or []):
            if not isinstance(g, dict):
                continue
            gid = _CondUtil.s(g.get("ocid") or "")
            if not gid:
                continue
            if row_matches(g):
                matched.add(gid)
        for g in (getattr(self.ctx, "classic_dynamic_groups", []) or []):
            if not isinstance(g, dict):
                continue
            gid = _CondUtil.s(g.get("id") or "")
            if not gid:
                continue
            if row_matches(g):
                matched.add(gid)
        return matched

    def _user_ids_for_group_ids(self, group_ids: set[str]) -> set[str] | None:
        if not group_ids:
            return set()
        cache = getattr(self.ctx, "group_member_mapping_cache", {}) or {}
        out: set[str] = set()
        for gid in group_ids:
            members = cache.get(gid)
            if members is None:
                return None
            out |= { _CondUtil.s(u) for u in (members or set()) if _CondUtil.s(u) }
        return out

    def _group_ids_for_user_ids(self, user_ids: set[str]) -> set[str] | None:
        user_ids = { _CondUtil.s(u) for u in (user_ids or set()) if _CondUtil.s(u) }
        if not user_ids:
            return set()
        cache = getattr(self.ctx, "group_member_mapping_cache", {}) or {}
        if not cache:
            return None
        out: set[str] = set()
        for gid, members in cache.items():
            if not members:
                continue
            mset = { _CondUtil.s(u) for u in (members or set()) if _CondUtil.s(u) }
            if mset & user_ids:
                out.add(_CondUtil.s(gid))
        return out

    def _resolve_request_group_ids(self, ctx: EvalContext) -> set[str] | None:
        kinds = {self._subj_kind(s) for s in (ctx.subjects or [])}
        locs = set(ctx.location_ids or ())

        out: set[str] = set()

        # Group subjects (explicit)
        out |= {self._subj_id(s) for s in (ctx.subjects or []) if self._subj_kind(s) == "group" and self._subj_id(s)}

        # ANY_GROUP -> all groups in scope
        if kinds & {"any-group", "any_group", "anygroup"}:
            out |= self._group_ids_in_locations(locs)

        # User subjects -> groups those users belong to
        if "user" in kinds:
            user_ids = {self._subj_id(s) for s in (ctx.subjects or []) if self._subj_kind(s) == "user" and self._subj_id(s)}
            gids = self._group_ids_for_user_ids(user_ids)
            if gids is None:
                return None
            out |= gids

        # ANY_USER -> groups for users in scope
        if kinds & {"any-user", "any_user", "anyuser"}:
            user_ids = self._user_ids_in_locations(locs)
            gids = self._group_ids_for_user_ids(user_ids)
            if gids is None:
                return None
            out |= gids

        return out

    def _resource_ids_for_dynamic_group_ids(self, dg_ids: set[str]) -> set[str] | None:
        if not dg_ids:
            return set()
        cache = getattr(self.ctx, "dynamic_group_member_mapping_cache", {}) or {}
        out: set[str] = set()
        for dg_id in dg_ids:
            rows_by_id = cache.get(dg_id)
            if rows_by_id is None:
                return None
            out |= { _CondUtil.s(mid) for mid in (rows_by_id.keys() or ()) if _CondUtil.s(mid) }
        return out

    def _user_ids_in_locations(self, locs: set[str]) -> set[str]:
        return {uid for uid, _names in self._users_in_locations(locs)}

    def _group_compartment_by_id(self) -> dict[str, str]:
        comp_by_id: dict[str, str] = {}
        for g in (getattr(self.ctx, "idd_groups", []) or []):
            if not isinstance(g, dict):
                continue
            gid = _CondUtil.s(g.get("ocid") or "")
            if not gid:
                continue
            comp = _CondUtil.s(g.get("compartment_ocid") or g.get("compartment_id") or "")
            if comp:
                comp_by_id[gid] = comp
        for g in (getattr(self.ctx, "classic_groups", []) or []):
            if not isinstance(g, dict):
                continue
            gid = _CondUtil.s(g.get("id") or "")
            if not gid:
                continue
            comp = _CondUtil.s(g.get("compartment_id") or "")
            if comp:
                comp_by_id[gid] = comp
        return comp_by_id

    def _dynamic_group_compartment_by_id(self) -> dict[str, str]:
        comp_by_id: dict[str, str] = {}
        for g in (getattr(self.ctx, "idd_dynamic_groups", []) or []):
            if not isinstance(g, dict):
                continue
            gid = _CondUtil.s(g.get("ocid") or "")
            if not gid:
                continue
            comp = _CondUtil.s(g.get("compartment_ocid") or g.get("compartment_id") or "")
            if comp:
                comp_by_id[gid] = comp
        for g in (getattr(self.ctx, "classic_dynamic_groups", []) or []):
            if not isinstance(g, dict):
                continue
            gid = _CondUtil.s(g.get("id") or "")
            if not gid:
                continue
            comp = _CondUtil.s(g.get("compartment_id") or "")
            if comp:
                comp_by_id[gid] = comp
        return comp_by_id

    def _group_ids_in_locations(self, locs: set[str]) -> set[str]:
        locs = { _CondUtil.s(x) for x in (locs or set()) if _CondUtil.s(x) }
        comp_by_id = self._group_compartment_by_id()
        if not locs:
            return set(comp_by_id.keys())
        return {gid for gid, comp in comp_by_id.items() if comp in locs}

    def _dynamic_group_ids_in_locations(self, locs: set[str]) -> set[str]:
        locs = { _CondUtil.s(x) for x in (locs or set()) if _CondUtil.s(x) }
        comp_by_id = self._dynamic_group_compartment_by_id()
        if not locs:
            return set(comp_by_id.keys())
        return {gid for gid, comp in comp_by_id.items() if comp in locs}

    def _user_in_group_ids(self, user_id: str, group_ids: set[str]) -> bool | None:
        uid = _CondUtil.s(user_id)
        if not uid:
            return False
        cache = getattr(self.ctx, "group_member_mapping_cache", {}) or {}
        for gid in (group_ids or set()):
            members = cache.get(gid)
            if members is None:
                return None
            if uid in members:
                return True
        return False

    def _dynamic_group_members_in_compartments(self, ctx: EvalContext, compartment_ids: set[str]) -> list[dict] | None:
        cset = { _CondUtil.s(x) for x in (compartment_ids or set()) if _CondUtil.s(x) }
        if not cset:
            return []
        cache = getattr(self.ctx, "dynamic_group_member_mapping_cache", {}) or {}
        out: list[dict] = []
        saw_any_dg = False

        for s in (ctx.subjects or []):
            sk = self._subj_kind(s)
            if sk not in {"dynamic-group", "dynamic_group", "dynamicgroup"}:
                continue
            dg_id = self._subj_id(s)
            if not dg_id:
                continue
            saw_any_dg = True
            rows_by_id = cache.get(dg_id)
            if rows_by_id is None:
                return None
            for mid, row in (rows_by_id or {}).items():
                if not mid or not isinstance(row, dict):
                    continue
                mcomp = _CondUtil.s(row.get("compartment_id") or row.get("compartment_ocid") or "")
                if mcomp not in cset:
                    continue
                node_type = _CondUtil.s(row.get("node_type") or "OCIResource")
                out.append({"id": _CondUtil.s(mid), "node_type": node_type})

        if not saw_any_dg:
            return []

        dedup = {}
        for r in out:
            rid = r.get("id")
            if rid and rid not in dedup:
                dedup[rid] = r
        return list(dedup.values())

    # -----------------------------
    # LIGHTWEIGHT HANDLER: request.groups.id
    # -----------------------------

    # -----------------------------
    # SUBJECT HELPERS (drop-in, reusable)
    # -----------------------------

    def _is_any_principal(self, ctx: EvalContext) -> tuple[bool, bool]:
        """
        Returns (has_any_user, has_any_group) based on candidate subject kinds.
        """
        kinds = {self._subj_kind(s) for s in (ctx.subjects or [])}
        has_any_user = bool(kinds & {"any-user", "any_user", "anyuser"})
        has_any_group = bool(kinds & {"any-group", "any_group", "anygroup"})
        return has_any_user, has_any_group


    def _replace_subjects_as(self, ids: set[str], *, kind: str, reason: str) -> ContextDelta:
        """
        Generic replace-subjects helper for future principal-trimming handlers.
        """
        if not ids:
            return _delta_false(reason)

        nt = self._kind_to_node_type(kind)
        return ContextDelta(
            tri=BoolTri.TRUE,
            replace_subjects=[{"id": x, "node_type": nt} for x in sorted(ids)],
            unresolved=False,
            reason=reason,
        )


    # -----------------------------
    # GROUP -> USERS expansion (updated)
    # -----------------------------

    def _expand_group_id_to_users(self, *, group_id: str) -> ContextDelta:
        """
        Expand a specific group OCID to user OCIDs using ctx.group_member_mapping_cache.

        This works even if ctx.subjects are ANY_USER (i.e., the group isn't present
        as a candidate subject). This is necessary for ANY_USER + request.groups.id behavior.
        """
        gid = _CondUtil.s(group_id)
        if not gid:
            return _delta_unknown("group_id_to_users: missing group id", unresolved=True)

        cache = getattr(self.ctx, "group_member_mapping_cache", {}) or {}
        members = cache.get(gid)
        if members is None:
            return _delta_unknown(f"group members not cached for {gid}", unresolved=True)

        user_ids = { _CondUtil.s(u) for u in (members or ()) if _CondUtil.s(u) }
        if not user_ids:
            return _delta_false(f"group {gid} has 0 cached members")

        return self._replace_subjects_as(
            user_ids,
            kind="user",
            reason=f"request.groups.id: expanded group {gid} -> users ({len(user_ids)})",
        )

    def _has_group_subjects(self, ctx: EvalContext) -> bool:
        kinds = {self._subj_kind(s) for s in (ctx.subjects or [])}
        return "group" in kinds

    def _expand_group_subjects_to_user_ids(self, ctx: EvalContext) -> set[str] | None:
        cache = getattr(self.ctx, "group_member_mapping_cache", {}) or {}
        out_users: set[str] = set()
        saw_any_group = False

        for s in (ctx.subjects or []):
            if self._subj_kind(s) != "group":
                continue
            gid = self._subj_id(s)
            if not gid:
                continue
            saw_any_group = True
            members = cache.get(gid)
            if members is None:
                return None
            out_users |= { _CondUtil.s(u) for u in (members or set()) if _CondUtil.s(u) }

        if not saw_any_group:
            return set()

        return out_users

    def _user_names_by_id(self) -> dict[str, list[str]]:
        m: dict[str, list[str]] = {}
        for u in (getattr(self.ctx, "idd_users", []) or []):
            if not isinstance(u, dict):
                continue
            uid = _CondUtil.s(u.get("ocid") or "")
            if not uid:
                continue
            names = [u.get("display_name"), u.get("user_name"), u.get("name"), u.get("email")]
            names = [n.strip() for n in names if isinstance(n, str) and n.strip()]
            if names:
                m[uid] = names
        for u in (getattr(self.ctx, "classic_users", []) or []):
            if not isinstance(u, dict):
                continue
            uid = _CondUtil.s(u.get("id") or "")
            if not uid:
                continue
            names = [u.get("name"), u.get("email"), u.get("description")]
            names = [n.strip() for n in names if isinstance(n, str) and n.strip()]
            if names:
                m[uid] = names
        return m

    def _users_in_locations(self, locs: set[str]) -> list[tuple[str, list[str]]]:
        users = []
        for u in (getattr(self.ctx, "idd_users", []) or []):
            if not isinstance(u, dict):
                continue
            comp = _CondUtil.s(u.get("compartment_ocid") or u.get("compartment_id") or "")
            if locs and comp not in locs:
                continue
            uid = _CondUtil.s(u.get("ocid") or "")
            if not uid:
                continue
            names = [u.get("display_name"), u.get("user_name"), u.get("name"), u.get("email")]
            users.append((uid, [n for n in names if isinstance(n, str) and n.strip()]))
        for u in (getattr(self.ctx, "classic_users", []) or []):
            if not isinstance(u, dict):
                continue
            comp = _CondUtil.s(u.get("compartment_id") or "")
            if locs and comp not in locs:
                continue
            uid = _CondUtil.s(u.get("id") or "")
            if not uid:
                continue
            names = [u.get("name"), u.get("email"), u.get("description")]
            users.append((uid, [n for n in names if isinstance(n, str) and n.strip()]))
        return users

    def _user_exists_in_locations(self, user_id: str, locs: set[str]) -> bool:
        uid = _CondUtil.s(user_id)
        if not uid:
            return False
        if not locs:
            return True
        for u in (getattr(self.ctx, "idd_users", []) or []):
            if not isinstance(u, dict):
                continue
            if _CondUtil.s(u.get("ocid") or "") != uid:
                continue
            comp = _CondUtil.s(u.get("compartment_ocid") or u.get("compartment_id") or "")
            return comp in locs
        for u in (getattr(self.ctx, "classic_users", []) or []):
            if not isinstance(u, dict):
                continue
            if _CondUtil.s(u.get("id") or "") != uid:
                continue
            comp = _CondUtil.s(u.get("compartment_id") or "")
            return comp in locs
        return False

    def _user_in_any_group(self, user_id: str, ctx: EvalContext) -> bool | None:
        uid = _CondUtil.s(user_id)
        if not uid:
            return False
        cache = getattr(self.ctx, "group_member_mapping_cache", {}) or {}
        for s in (ctx.subjects or []):
            if self._subj_kind(s) != "group":
                continue
            gid = self._subj_id(s)
            if not gid:
                continue
            members = cache.get(gid)
            if members is None:
                return None
            if uid in members:
                return True
        return False



    # -----------------------------
    # request.groups.id handler (updated semantics)
    # -----------------------------

    # note this handles ANY-USER by exploding group edges for only those grousp that match
    def _h_request_groups_id(self, *, op: str, rhs_val, ctx: EvalContext, **_) -> ContextDelta:
        """
        request.groups.id = <group_ocid>

        Semantics for offline graphing:

        - If candidates include ANY_USER:
            Expand the specified group id -> users, then REPLACE subjects with those users,
            effectively restricting the ANY_USER principal to "users who are members of group X".

            NOTE/TODO (research):
                This behavior assumes "any-user where request.groups.id=X" should be modeled
                as explicit user principals (exploded from group membership). If later research
                shows OCI semantics or best graph model should remain group-container based,
                revert this to: replace ANY_USER with group container(s) instead of users.

        - If candidates include ANY_GROUP:
            Replace subjects with the group container id (no expansion), since it’s a group-gated principal.

        - If candidates are concrete group subjects:
            Filter to the matching group id (no expansion by default).

        - If candidates are dynamic-groups:
            Filter to the matching dynamic-group id (no expansion by default).
        """
        o = _CondUtil.norm_op(op)
        if o != "eq":
            return _delta_unknown("request.groups.id expects '='", unresolved=True)

        gid = _CondUtil.s(rhs_val)
        if not gid:
            return _delta_unknown("request.groups.id rhs empty", unresolved=True)

        has_any_user, has_any_group = self._is_any_principal(ctx)

        # -------------------------
        # ANY_USER case => explode group -> users (restricted)
        # -------------------------
        if has_any_user:
            return self._expand_group_id_to_users(group_id=gid)

        # -------------------------
        # ANY_GROUP case => keep group container(s)
        # -------------------------
        if has_any_group:
            return self._replace_subjects_as(
                {gid},
                kind="group",
                reason=f"request.groups.id: ANY_GROUP gated by group {gid} (no expansion)",
            )

        # Otherwise, use candidate subjects as-is (filter if relevant)
        subjects = list(ctx.subjects or [])
        kinds = {self._subj_kind(s) for s in subjects}

        # Concrete group candidates
        if "group" in kinds:
            cand_group_ids = {self._subj_id(s) for s in subjects if self._subj_kind(s) == "group" and self._subj_id(s)}
            if gid not in cand_group_ids:
                return _delta_false(f"request.groups.id: group {gid} not in candidate subjects")

            return ContextDelta(
                tri=BoolTri.TRUE,
                filter_subject_ids={gid},
                unresolved=False,
                reason=f"request.groups.id: matched group {gid} (filtered)",
            )

        # Dynamic-group candidates
        if kinds & {"dynamic-group", "dynamic_group", "dynamicgroup"}:
            cand_dg_ids = {
                self._subj_id(s)
                for s in subjects
                if self._subj_kind(s) in {"dynamic-group", "dynamic_group", "dynamicgroup"} and self._subj_id(s)
            }
            if gid not in cand_dg_ids:
                return _delta_false(f"request.groups.id: dynamic-group {gid} not in candidate subjects")

            return ContextDelta(
                tri=BoolTri.TRUE,
                filter_subject_ids={gid},
                unresolved=False,
                reason=f"request.groups.id: matched dynamic-group {gid} (filtered)",
            )

        return _delta_unknown("request.groups.id: candidate subjects not any-*/group/dynamic-group", unresolved=True)
