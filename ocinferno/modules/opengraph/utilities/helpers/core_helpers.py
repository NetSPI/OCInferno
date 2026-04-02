from __future__ import annotations

import hashlib
import json
import re

try:
    from ocinferno.core.console import UtilityTools
except (ImportError, ModuleNotFoundError):
    UtilityTools = None


def dlog(debug: bool, msg: str, **kv) -> None:
    if UtilityTools and hasattr(UtilityTools, "dlog"):
        try:
            UtilityTools.dlog(bool(debug), msg, **kv)
        except Exception:
            pass


def s(x) -> str:
    return x.strip() if isinstance(x, str) else ""


def l(x) -> str:
    return x.strip().lower() if isinstance(x, str) else ""


def scope_token_loc(value) -> tuple[str, str]:
    """
    Parse scope ids of the form "<token>@<location>".
    Returns ("", "") when input is not a scope id.
    """
    raw = s(value)
    if not raw or "@" not in raw:
        return "", ""
    token, loc = raw.split("@", 1)
    return l(token), s(loc)


def short_text(x, n: int = 200) -> str:
    text = "" if x is None else str(x)
    return text if len(text) <= n else (text[:n] + "...")


def short_hash(value, n: int = 12) -> str:
    """
    Stable short SHA1 digest for deterministic synthetic identifiers.
    """
    text = "" if value is None else str(value)
    size = int(n) if isinstance(n, int) and n > 0 else 12
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:size]


def synthetic_principal_id(
    kind,
    *,
    domain_ocid: str = "",
    scim_id: str = "",
    label: str = "",
    tenant_id: str = "",
) -> str:
    """
    Canonical synthetic principal node-id format used across OpenGraph builders.

    Examples:
      - SCIM-backed (IDD):
          synthetic::principal::user::ocid1.domain...::scim:1659b300...
      - Label-backed (policy parser fallback):
          synthetic::principal::group::-::name:admins:ten:ocid1.tenancy...
    """
    k = l(kind).replace("dynamicgroup", "dynamic-group")
    if not k:
        k = "principal"
    dom = s(domain_ocid) or "-"
    scim = s(scim_id)
    if scim:
        ref = f"scim:{scim}"
    else:
        lbl = l(label)
        lbl = re.sub(r"\s+", " ", lbl).strip()
        lbl = re.sub(r"[^a-z0-9._-]+", "_", lbl) if lbl else "-"
        ten = s(tenant_id) or "-"
        ref = f"name:{lbl}:ten:{ten}"
    return f"synthetic::principal::{k}::{dom}::{ref}"


_OCID_TYPE_RE = re.compile(r"^ocid1\.([a-z0-9_]+)\.", re.IGNORECASE)


def ocid_type(value) -> str:
    """
    Return normalized OCID type segment (e.g. 'instance' from 'ocid1.instance...').
    Returns empty string when value is not a valid OCID-like string.
    """
    svalue = s(value)
    if not svalue:
        return ""
    m = _OCID_TYPE_RE.match(svalue)
    return m.group(1).lower() if m else ""


def parse_defined_tag_var(var_full, *, base_prefix: str = "tag", suffix: str = "value") -> tuple[str, str] | None:
    """
    Parse defined-tag variable paths of the form:
      <base_prefix>.<namespace>.<key>.<suffix>

    Default shape is OCI DG matching-rule style:
      tag.<namespace>.<key>.value
    """
    raw = s(var_full)
    prefix = s(base_prefix)
    end = s(suffix)
    if not raw or not prefix or not end:
        return None
    head = f"{prefix}."
    if not raw.startswith(head):
        return None
    tail = raw[len(head):]
    parts = tail.split(".")
    if len(parts) != 3:
        return None
    ns, key, last = parts
    ns = s(ns)
    key = s(key)
    if last != end or not ns or not key:
        return None
    return (ns, key)


def json_load(x, want):
    """
    Load JSON from a dict/list or JSON-string, returning want() on failure.
    want must be `dict` or `list`.
    """
    if isinstance(x, want):
        return x
    if isinstance(x, str):
        if not x:
            return want()
        try:
            v = json.loads(x)
            return v if isinstance(v, want) else want()
        except Exception:
            return want()
    return want()


def json_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, str):
        if not x:
            return []
        try:
            v = json.loads(x)
            return v if isinstance(v, list) else []
        except Exception:
            return []
    return []


def as_json_text(v, default: str = "[]") -> str:
    """DB storage helper: store JSON-ish columns as text."""
    if v is None:
        return default
    if isinstance(v, str):
        return v or default
    try:
        return json.dumps(v, separators=(",", ":"), sort_keys=False)
    except Exception:
        return default


def is_empty_value(v) -> bool:
    return v is None or v == "" or v == [] or v == {} or v == ()


def _stable_key(v):
    if isinstance(v, (str, int, float, bool, tuple)):
        return v
    try:
        return repr(v)
    except Exception:
        return str(v)


def merge_list(dst_list, src_list):
    if not isinstance(dst_list, list):
        dst_list = [] if is_empty_value(dst_list) else [dst_list]
    if not isinstance(src_list, list):
        src_list = [] if is_empty_value(src_list) else [src_list]
    if not dst_list:
        return list(src_list)
    if not src_list:
        return dst_list
    out = list(dst_list)
    seen = {_stable_key(item) for item in out}
    for item in src_list:
        key = _stable_key(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def merge_value(dst_v, src_v):
    """
    Merge src into dst without overwriting non-empty scalars.
    Dicts are merged recursively; lists/tuples are unioned.
    """
    if is_empty_value(src_v):
        return dst_v
    if is_empty_value(dst_v):
        return src_v
    if isinstance(dst_v, dict) and isinstance(src_v, dict):
        for k, sv in src_v.items():
            dv = dst_v.get(k)
            dst_v[k] = merge_value(dv, sv)
        return dst_v
    if isinstance(dst_v, (list, tuple)) or isinstance(src_v, (list, tuple)):
        return merge_list(list(dst_v) if isinstance(dst_v, (list, tuple)) else dst_v,
                          list(src_v) if isinstance(src_v, (list, tuple)) else src_v)
    return dst_v


EDGE_CATEGORY_GROUP_MEMBERSHIP = "GROUP_MEMBERSHIP"
EDGE_CATEGORY_PERMISSION = "PERMISSION"
EDGE_CATEGORY_RESOURCE = "RESOURCE"
_EDGE_CATEGORY_NORMALIZE = {
    EDGE_CATEGORY_GROUP_MEMBERSHIP: EDGE_CATEGORY_GROUP_MEMBERSHIP,
    EDGE_CATEGORY_PERMISSION: EDGE_CATEGORY_PERMISSION,
    EDGE_CATEGORY_RESOURCE: EDGE_CATEGORY_RESOURCE,
}


def _normalize_edge_category(category, *, fallback=EDGE_CATEGORY_RESOURCE):
    c = str(category or "").strip().upper()
    if not c:
        return fallback
    return _EDGE_CATEGORY_NORMALIZE.get(c, fallback)


def infer_edge_category(*, edge_type="", fallback=EDGE_CATEGORY_RESOURCE):
    et = str(edge_type or "").strip().upper()
    if "MEMBER" in et:
        return EDGE_CATEGORY_GROUP_MEMBERSHIP
    if any(
        token in et
        for token in ("CREATE_", "UPDATE_", "DELETE_", "READ_", "USE_", "MANAGE_", "_ADMIN", "TAKEOVER", "SEND_", "CAN_")
    ):
        return EDGE_CATEGORY_PERMISSION
    return _normalize_edge_category(fallback, fallback=EDGE_CATEGORY_RESOURCE)


def build_edge_properties(*, edge_category, edge_inner_properties=None, **extra_inner):
    inner = {}
    if isinstance(edge_inner_properties, dict):
        inner = dict(edge_inner_properties)
    if extra_inner:
        inner = merge_value(inner, extra_inner)
    cat = _normalize_edge_category(edge_category, fallback=EDGE_CATEGORY_RESOURCE)
    return {"edge_category": cat, "edge_inner_properties": inner}


def normalize_edge_properties(edge_properties, *, edge_type="", default_category=""):
    props = json_load(edge_properties, dict)
    if not isinstance(props, dict):
        props = {}
    inner = props.get("edge_inner_properties")
    inner = dict(inner) if isinstance(inner, dict) else {}
    fallback = infer_edge_category(
        edge_type=edge_type,
        fallback=default_category or EDGE_CATEGORY_RESOURCE,
    )
    category = _normalize_edge_category(props.get("edge_category"), fallback=fallback)
    return {"edge_category": category, "edge_inner_properties": inner}


def merge_edge_properties(existing, incoming, *, edge_type="", default_category=""):
    a = normalize_edge_properties(existing, edge_type=edge_type, default_category=default_category)
    b = normalize_edge_properties(incoming, edge_type=edge_type, default_category=default_category)

    a_cat = _normalize_edge_category(a.get("edge_category"), fallback=EDGE_CATEGORY_RESOURCE)
    b_cat = _normalize_edge_category(b.get("edge_category"), fallback=EDGE_CATEGORY_RESOURCE)
    if a_cat == b_cat:
        category = a_cat
    elif a_cat == EDGE_CATEGORY_RESOURCE:
        category = b_cat
    elif b_cat == EDGE_CATEGORY_RESOURCE:
        category = a_cat
    else:
        category = b_cat

    a_inner = a.get("edge_inner_properties")
    b_inner = b.get("edge_inner_properties")
    inner = merge_value(
        dict(a_inner) if isinstance(a_inner, dict) else {},
        dict(b_inner) if isinstance(b_inner, dict) else {},
    )
    return {"edge_category": category, "edge_inner_properties": inner}


def flatten_edge_properties(edge_properties, *, edge_type="", default_category=""):
    norm = normalize_edge_properties(edge_properties, edge_type=edge_type, default_category=default_category)
    out = {"edge_category": _normalize_edge_category(norm.get("edge_category"), fallback=EDGE_CATEGORY_RESOURCE)}
    inner = norm.get("edge_inner_properties")
    if isinstance(inner, dict):
        out.update(inner)
    return out


def statement_stable_key(item) -> str:
    if isinstance(item, dict):
        sid = s(item.get("stmt_id") or "")
        if sid:
            return sid
        pid = s(item.get("policy_id") or "")
        sidx = item.get("statement_index")
        if pid and sidx is not None:
            return f"{pid}:{sidx}"
        stmt = s(item.get("stmt") or "")
        if stmt:
            return stmt
        return repr(sorted(item.items()))
    return repr(item)


def merge_statement_entries(dst_list: list, src_list: list) -> list:
    if not isinstance(dst_list, list):
        dst_list = []
    if not isinstance(src_list, list):
        return dst_list
    seen = {statement_stable_key(x) for x in dst_list}
    for item in src_list:
        key = statement_stable_key(item)
        if key in seen:
            continue
        seen.add(key)
        dst_list.append(item)
    return dst_list


def statement_texts(items) -> list[str]:
    out = []
    for item in (items or []):
        if isinstance(item, str):
            txt = s(item)
            if txt:
                out.append(txt)
            continue
        if isinstance(item, dict):
            txt = s(item.get("stmt") or item.get("statement") or "")
            if txt:
                out.append(txt)
    return out


def statement_policy_ids(items) -> list[str]:
    out = []
    seen = set()
    for item in (items or []):
        if not isinstance(item, dict):
            continue
        pid = s(item.get("policy_id") or "")
        if not pid or pid in seen:
            continue
        seen.add(pid)
        out.append(pid)
    return out


def edge_row_with_flattened_properties(row):
    if not isinstance(row, dict):
        return {}
    out = dict(row)
    props = flatten_edge_properties(
        row.get("edge_properties"),
        edge_type=s(row.get("edge_type") or ""),
    )
    if not isinstance(props, dict) or not props:
        return out
    for key, val in props.items():
        if key not in out or is_empty_value(out.get(key)):
            out[key] = val
    return out


def node_properties_from_row(row):
    if not isinstance(row, dict):
        return {}
    props = json_load(row.get("node_properties"), dict)
    if isinstance(props, dict):
        return dict(props)
    return {}
