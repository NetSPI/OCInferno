from __future__ import annotations

"""
Dynamic-group matching rules engine.

Public interfaces:
- DynamicGroupRuleEvaluator.match_iter(...): Stream matched resources for one matching-rule.
- DynamicGroupPermissionLocationMatcher.match_dynamic_groups_for_permission_location(...):
  Find dynamic groups whose rules match a permission+location context.
"""

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Tuple

from oci_lexer_parser import parse_dynamic_group_matching_rules  # type: ignore
from ocinferno.modules.opengraph.utilities.helpers.core_helpers import (
    dlog as _core_dlog,
    json_load as _json_load,
    parse_defined_tag_var as _parse_defined_tag_var,
)
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    PERMISSION_MAPPING,
    RESOURCE_PRINCIPAL_SCOPE_TOKENS,
    RESOURCE_SCOPE_MAP_TUPLE,
    RESOURCE_TYPE_ALIASES,
)

VAR_INSTANCE_ID = "instance.id"
VAR_INSTANCE_COMPARTMENT_ID = "instance.compartment.id"

VAR_RESOURCE_ID = "resource.id"
VAR_RESOURCE_COMPARTMENT_ID = "resource.compartment.id"
VAR_RESOURCE_TYPE = "resource.type"

OP_EQ = "eq"
OP_NEQ = "neq"
OP_EXISTS = "exists"
OP_MATCHES = "matches"
OP_NOT_MATCHES = "not_matches"

SUPPORTED_VARS = {
    VAR_INSTANCE_ID,
    VAR_INSTANCE_COMPARTMENT_ID,
    VAR_RESOURCE_ID,
    VAR_RESOURCE_COMPARTMENT_ID,
    VAR_RESOURCE_TYPE,
}

_INSTANCE_RESOURCE_TYPE = "instance"

@dataclass(frozen=True, slots=True)
class Pred:
    var: str
    op: str
    rhs: Any | None
    tag: Optional[Tuple[str, str]] = None

@dataclass(frozen=True, slots=True)
class Node:
    kind: str
    children: Tuple["Node", ...] = ()
    pred: Optional[Pred] = None


# -----------------------------------------------------------------------------
# Permission+Location helper index builder
# (resolved lazily by DynamicGroupPermissionLocationMatcher)
# -----------------------------------------------------------------------------
def _build_permission_resource_type_index() -> Dict[str, set[str]]:
    idx: Dict[str, set[str]] = {}
    if not isinstance(PERMISSION_MAPPING, dict):
        return idx

    for verb_map in PERMISSION_MAPPING.values():
        if not isinstance(verb_map, dict):
            continue
        for service_map in verb_map.values():
            if not isinstance(service_map, dict):
                continue
            for resource_token, perms in service_map.items():
                if not isinstance(perms, list):
                    continue
                token = str(resource_token or "").strip().lower()
                if not token:
                    continue
                resolved_types = {token, *RESOURCE_TYPE_ALIASES.get(token, ())}
                for p in perms:
                    perm = str(p or "").strip().upper()
                    if not perm:
                        continue
                    idx.setdefault(perm, set()).update(resolved_types)
    return idx


@lru_cache(maxsize=256)
def _compile_regex(pattern: str) -> re.Pattern:
    return re.compile(pattern)


def _match_regex(value: Any, rhs: Any | None) -> bool:
    if rhs is None:
        return False
    text = str(value or "")
    if hasattr(rhs, "search"):
        try:
            return rhs.search(text) is not None
        except Exception:
            return False
    try:
        pat = _compile_regex(str(rhs))
    except re.error:
        return False
    return pat.search(text) is not None


def _resource_type_alias_closure(resource_type: str) -> set[str]:
    rt = str(resource_type or "").strip().lower()
    if not rt:
        return set()
    out = {rt, *RESOURCE_TYPE_ALIASES.get(rt, ())}
    for alias, vals in RESOURCE_TYPE_ALIASES.items():
        if rt in vals:
            out.add(alias)
    out.discard("")
    return out


def _build_allowed_dg_types() -> set[str]:
    """
    Dynamic-group membership should only evaluate OCI resource-principal types.
    Build the allowlist from RESOURCE_PRINCIPAL_SCOPE_TOKENS and scope-map aliases.
    """
    allowed: set[str] = set()
    allowed_tokens = {str(t).strip().lower() for t in (RESOURCE_PRINCIPAL_SCOPE_TOKENS or set()) if str(t).strip()}
    if not allowed_tokens:
        return allowed
    for (iam_token, dg_type), _spec in RESOURCE_SCOPE_MAP_TUPLE.items():
        iam_token_l = str(iam_token or "").strip().lower()
        dg_type_l = str(dg_type or "").strip().lower()
        if iam_token_l in allowed_tokens or dg_type_l in allowed_tokens:
            allowed.update(_resource_type_alias_closure(dg_type_l))
    return allowed


ALLOWED_DG_RESOURCE_TYPES = _build_allowed_dg_types()


def _build_table_to_dg_types_index() -> Dict[str, set[str]]:
    allowed_types = ALLOWED_DG_RESOURCE_TYPES
    table_types: Dict[str, set[str]] = {}
    for (_iam_token, dg_type), spec in RESOURCE_SCOPE_MAP_TUPLE.items():
        table_name = spec.get("table") if isinstance(spec, dict) else None
        if not (isinstance(table_name, str) and table_name and isinstance(dg_type, str) and dg_type):
            continue
        dg_aliases = _resource_type_alias_closure(dg_type)
        if allowed_types and not dg_aliases.intersection(allowed_types):
            continue
        type_set = table_types.setdefault(table_name, set())
        type_set.update(dg_aliases)
    return table_types


TABLE_TO_DG_TYPES = _build_table_to_dg_types_index()


def _ocid_resource_type_hint(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text.startswith("ocid1.") or "." not in text[6:]:
        return None
    # ocid1.<resource_type>.<realm>...
    return text.split(".", 2)[1] or None


def _infer_pred_dg_types(pred: Pred) -> set[str] | None:
    if pred.var.startswith("instance."):
        return _resource_type_alias_closure(_INSTANCE_RESOURCE_TYPE)
    if pred.var == VAR_RESOURCE_TYPE and pred.op == OP_EQ and isinstance(pred.rhs, str):
        return _resource_type_alias_closure(pred.rhs)
    if pred.var == VAR_RESOURCE_ID and pred.op == OP_EQ and isinstance(pred.rhs, str):
        hint = _ocid_resource_type_hint(pred.rhs)
        if hint:
            return _resource_type_alias_closure(hint)
    return None


def _resolve_var(*, var: str, row: Dict[str, Any]) -> Any:
    if var in {VAR_INSTANCE_ID, VAR_RESOURCE_ID}:
        return row.get("id")
    if var in {VAR_INSTANCE_COMPARTMENT_ID, VAR_RESOURCE_COMPARTMENT_ID}:
        return row.get("compartment_id")
    if var == VAR_RESOURCE_TYPE:
        return row.get("resource_type")
    supported = ", ".join(sorted(SUPPORTED_VARS))
    raise ValueError(
        f"Unsupported matching-rule variable '{var}'. "
        f"Supported variables: {supported}, or tag.<namespace>.<key>.value"
    )


def _extract_resource_id_from_row(*, row: Dict[str, Any], id_key: Any, table_name: str) -> Any:
    """
    Resolve a stable resource identifier from a row using mapping id_col metadata.

    - id_col as string: direct row lookup.
    - id_col as list/tuple: composite ID from all components.
    """
    if isinstance(id_key, str):
        return row.get(id_key)
    if isinstance(id_key, (list, tuple)):
        parts: list[str] = []
        for key_name in id_key:
            if not isinstance(key_name, str) or not key_name:
                continue
            value = row.get(key_name)
            if value is None or value == "":
                return None
            parts.append(f"{key_name}={value}")
        if not parts:
            return None
        return f"{table_name}:{'|'.join(parts)}"
    return None


# Example inputs:
#   pred = Pred(var="resource.type", op="eq", rhs="instance", tag=None)
#   row  = {"id":"ocid1.instance...", "compartment_id":"ocid1.compartment...", "resource_type":"instance", "defined_tags":{"team":{"env":"prod"}}}
#   -> True when row["resource_type"] == "instance"
#
#   pred = Pred(var="tag.team.env.value", op="eq", rhs="prod", tag=("team", "env"))
#   row  = {"defined_tags":{"team":{"env":"prod"}}}
#   -> True when defined_tags["team"]["env"] == "prod"
def _eval_pred(*, pred: Pred, row: Dict[str, Any]) -> bool:
    if pred.tag is not None:
        ns, key = pred.tag
        defined_tags = _json_load(row.get("defined_tags"), dict)
        val = defined_tags.get(ns, {}).get(key)
        if pred.op == OP_EXISTS:
            return val is not None
        if pred.op == OP_EQ:
            return (val in pred.rhs) if isinstance(pred.rhs, list) else (val == pred.rhs)
        if pred.op == OP_NEQ:
            return (val not in pred.rhs) if isinstance(pred.rhs, list) else (val != pred.rhs)
        if pred.op == OP_MATCHES:
            return _match_regex(val, pred.rhs)
        if pred.op == OP_NOT_MATCHES:
            return not _match_regex(val, pred.rhs)
        return False

    value = _resolve_var(var=pred.var, row=row)
    if pred.op == OP_EXISTS:
        return value is not None
    if pred.op == OP_EQ:
        return (value in pred.rhs) if isinstance(pred.rhs, list) else (value == pred.rhs)
    if pred.op == OP_NEQ:
        return (value not in pred.rhs) if isinstance(pred.rhs, list) else (value != pred.rhs)
    if pred.op == OP_MATCHES:
        return _match_regex(value, pred.rhs)
    if pred.op == OP_NOT_MATCHES:
        return not _match_regex(value, pred.rhs)
    return False


def _compile_nodes(parsed: Any) -> Tuple[Node, ...]:
    def extract_pred_from_lexer(node: Dict[str, Any]) -> Optional[Pred]:
        var = node.get("lhs")
        if not var or not isinstance(var, str):
            return None

        # Parses in tag.<arbitrary1>.<arbitrary2>.value.
        # If lhs does not start with tag., returns None
        tag = _parse_defined_tag_var(var)

        # If we have no tag or lhs is not suppoted exit
        if tag is None and var not in SUPPORTED_VARS:
            supported = ", ".join(sorted(SUPPORTED_VARS))
            raise ValueError(
                f"Unsupported matching-rule variable '{var}'. "
                f"Supported variables: {supported}, or tag.<namespace>.<key>.value"
            )

        rhs_obj = node.get("rhs")
        raw_op = str(node.get("op") or "").strip().lower()
        rhs_is_regex = isinstance(rhs_obj, dict) and str(rhs_obj.get("type") or "").lower() == "regex"

        if rhs_is_regex and raw_op in {"eq", "="}:
            op = OP_MATCHES
        elif rhs_is_regex and raw_op in {"neq", "!="}:
            op = OP_NOT_MATCHES
        elif raw_op in {"eq", "="}:
            op = OP_EQ
        elif raw_op in {"neq", "!="}:
            op = OP_NEQ

        # If JSON is exists or we parsed a tag
        elif raw_op == "exists" or tag is not None:
            op = OP_EXISTS
        else:
            return None

        rhs = None
        if op in (OP_EQ, OP_NEQ, OP_MATCHES, OP_NOT_MATCHES):
            rhs_type = str(rhs_obj.get("type") or "").lower() if isinstance(rhs_obj, dict) else ""
            if rhs_type == "regex":
                rhs = rhs_obj.get("pattern")
            elif rhs_type:
                rhs = rhs_obj.get("value")
            else:
                rhs = rhs_obj

        return Pred(var=var, op=op, rhs=rhs, tag=tag)

    def compile_expr(expr: Dict[str, Any]) -> Optional[Node]:

        etype = str(expr.get("type") or "").lower()

        # "group" means it has more clauses in it
        if etype == "group":
            
            kind = "any" if expr.get("mode") == "any" else "all"
            
            kids: list[Node] = []
            for item in expr.get("items") or []:
                
                # go through each item in "group" exp and build clause/group nodes per
                # recursion
                itype = str(item.get("type") or "").lower()

                if itype == "clause":
                    pr = extract_pred_from_lexer(item.get("node") or {})
                    if pr:
                        kids.append(Node(kind="pred", pred=pr))

                elif itype == "group":
                    cn = compile_expr(item)
                    if cn:
                        kids.append(cn)

                else:
                    cn = compile_expr(item.get("expr")) if isinstance(item.get("expr"), dict) else None
                    if cn:
                        kids.append(cn)

            return Node(kind=kind, children=tuple(kids)) if kids else None

        # "clause" is most atomic unit
        if etype == "clause":
            pr = extract_pred_from_lexer(expr.get("node") or expr)
            if pr:
                return Node(kind="pred", pred=pr)
            return None

        return None

    raw_nodes: list[Node] = []
    for rule in (parsed.get("rules") or []) if isinstance(parsed, dict) else []:

        expr = rule.get("expr")
        
        if (n := compile_expr(expr)) is not None:
            raw_nodes.append(n)

    # Compiled rule shape: tuple[Node], where each Node is `pred`, `all`, or `any`.
    return tuple(raw_nodes)


@lru_cache(maxsize=512)
def compile_matching_rule_nodes(rule_text: str) -> Tuple[Node, ...]:
    # `report` mode usually yields (payload, diagnostics), but older parser builds may return payload only.
    result = parse_dynamic_group_matching_rules(
        rule_text,
        nested_simplify=True,
        error_mode="report",
    )
    payload, diagnostics = result if isinstance(result, tuple) else (result, {})
    errors = (diagnostics or {}).get("errors") if isinstance(diagnostics, dict) else []
    if errors:
        raise ValueError(f"Dynamic-group matching-rule parse failed: {errors[0]}")
    return _compile_nodes(payload)


class DynamicGroupRuleEvaluator:
    def __init__(
        self,
        session: Any,
        *,
        debug: bool = False,
    ) -> None:
        self.session = session
        self.debug = debug

        self.debug_max_rows = 10
        self.debug_max_pred_logs = 30
        self._pred_log_count = 0
        self._row_log_count = 0

    def _merge(self, acc: Dict[str, Dict[str, Any]], m: Dict[str, Any]) -> None:
        rid = m["id"]
        src_table = m["source_table"]
        raw_row = m["raw_row"]
        src_node_type = m.get("node_type")

        # `acc` shape: {resource_id: {"node_type","by_table": {table: {"rows": [raw_row, ...]}}}}
        entry = acc.setdefault(rid, {"node_type": src_node_type or "OCIResource", "by_table": {}})

        current_type = str(entry.get("node_type") or "").strip().lower()
        if src_node_type and current_type in {"", "ociresource", "ocigenericresource"}:
            entry["node_type"] = src_node_type

        entry.setdefault("by_table", {}).setdefault(src_table, {}).setdefault("rows", []).append(raw_row)

    def _copy_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        by_table = {}
        for tname, meta in (entry.get("by_table") or {}).items():
            rows = meta.get("rows") if isinstance(meta, dict) else []
            by_table[tname] = {"rows": list(rows or [])}
        return {
            "node_type": entry.get("node_type") or "OCIResource",
            "by_table": by_table,
        }

    def _merge_entry(self, dst: Dict[str, Any], src: Dict[str, Any]) -> None:
        src_type = src.get("node_type")
        if (
            str(dst.get("node_type") or "").strip().lower() in {"", "ociresource", "ocigenericresource"}
            and src_type
        ):
            dst["node_type"] = src_type
        dst_tables = dst.setdefault("by_table", {})
        for tname, meta in (src.get("by_table") or {}).items():
            rows = meta.get("rows") if isinstance(meta, dict) else []
            slot = dst_tables.setdefault(tname, {"rows": []})
            slot.setdefault("rows", []).extend(list(rows or []))

    def _union_acc(self, left: Dict[str, Dict[str, Any]], right: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        out = {rid: self._copy_entry(entry) for rid, entry in left.items()}
        for rid, entry in right.items():
            if rid in out:
                self._merge_entry(out[rid], entry)
            else:
                out[rid] = self._copy_entry(entry)
        return out

    def _intersect_acc(self, left: Dict[str, Dict[str, Any]], right: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        shared = set(left.keys()).intersection(right.keys())
        out: Dict[str, Dict[str, Any]] = {}
        for rid in shared:
            merged = self._copy_entry(left[rid])
            self._merge_entry(merged, right[rid])
            out[rid] = merged
        return out

    def _scan_pred_matches(
        self,
        pred: Pred,
        *,
        compartment_id: str | None,
    ) -> Dict[str, Dict[str, Any]]:
        acc: Dict[str, Dict[str, Any]] = {}
        pred_types = _infer_pred_dg_types(pred)

        for (_iam_token, dg_type), spec in RESOURCE_SCOPE_MAP_TUPLE.items():
            dg_aliases = _resource_type_alias_closure(dg_type)
            if ALLOWED_DG_RESOURCE_TYPES and not dg_aliases.intersection(ALLOWED_DG_RESOURCE_TYPES):
                continue
            if pred_types is not None and not _resource_type_alias_closure(dg_type).intersection(pred_types):
                continue

            tname, id_key, compartment_key = spec.get("table"), spec.get("id_col"), spec.get("compartment_col")
            if not id_key:
                continue
            where_conditions = {compartment_key: compartment_id} if compartment_id and compartment_key else None
            if compartment_id and not where_conditions:
                continue
            rows = self.session.get_resource_fields(tname, where_conditions=where_conditions) or []

            if self.debug:
                _core_dlog(self.debug, "dg-eval: scan: table", table=tname, rows=len(rows))

            for row in rows:
                rid = _extract_resource_id_from_row(row=row, id_key=id_key, table_name=tname or "")
                if not rid:
                    continue

                comp = row.get(compartment_key) or None

                if compartment_id and str(comp or "") != compartment_id:
                    continue

                rtype = row.get("resource_type") or dg_type or tname

                if self.debug and self._row_log_count < self.debug_max_rows:
                    _core_dlog(self.debug, "dg-eval: norm", table=tname, id=rid, rtype=rtype, comp=(comp or ""))
                    self._row_log_count += 1
                    
                norm = {
                    "id": rid,
                    "compartment_id": comp,
                    "defined_tags": row.get(spec.get("defined_tags_col") or "defined_tags"),
                    "node_type": spec.get("node_type") or "OCIResource",
                    "resource_type": rtype,
                    "source_table": tname,
                    "raw_row": row,
                }
                # Go through each row and take the row and the expression
                # depending on express analyze row and return True/False
                # If true keep the row, if false drop it.
                ok = _eval_pred(pred=pred, row=norm)
                if self.debug and self._pred_log_count < self.debug_max_pred_logs:
                    _core_dlog(
                        self.debug,
                        "dg-eval: pred",
                        id=norm.get("id"),
                        var=pred.var,
                        op=pred.op,
                        rhs=(pred.rhs or ""),
                        ok=ok,
                    )
                    self._pred_log_count += 1

                # If our database row is good relative to pred, then keep it and add
                # to accumulator
                if ok:
                    self._merge(acc, norm)
        return acc

    def _eval_node_acc(
        self,
        node: Node,
        *,
        compartment_id: str | None,
    ) -> Dict[str, Dict[str, Any]]:
        if node.kind == "pred":
            if node.pred is None:
                return {}
            return self._scan_pred_matches(
                node.pred,
                compartment_id=compartment_id,
            )

        child_maps = [
            self._eval_node_acc(
                child,
                compartment_id=compartment_id,
            )
            for child in node.children
        ]

        if node.kind == "all":
            if not child_maps:
                return {}
            out = child_maps[0]
            for m in child_maps[1:]:
                out = self._intersect_acc(out, m)
                if not out:
                    break
            return out
        if node.kind == "any":
            out: Dict[str, Dict[str, Any]] = {}
            for m in child_maps:
                out = self._union_acc(out, m)
            return out
        raise ValueError(f"Unsupported compiled node kind: {node.kind!r}")

    def _match_acc(
        self,
        rule_text: str,
        *,
        compartment_id: Optional[str] = None,
    ) -> Dict[str, Dict[str, Any]]:
        self._pred_log_count = 0
        self._row_log_count = 0

        # `nodes` shape example:
        # (
        #   Node(
        #     kind="all",
        #     children=(
        #       Node(kind="pred", pred=Pred(var="resource.type", op="eq", rhs="instance", tag=None)),
        #       Node(
        #         kind="any",
        #         children=(
        #           Node(kind="pred", pred=Pred(var="resource.compartment.id", op="eq", rhs="ocid1.compartment...a", tag=None)),
        #           Node(kind="pred", pred=Pred(var="resource.compartment.id", op="eq", rhs="ocid1.compartment...b", tag=None)),
        #         ),
        #       ),
        #     ),
        #   ),
        # )
        nodes = compile_matching_rule_nodes(rule_text)
        if self.debug:
            _core_dlog(self.debug, "dg-eval: compile", count=len(nodes))

        compartment_id = str(compartment_id or "").strip() or None

        # acc shape:
        # {
        #   "<resource_id>": {
        #     "node_type": "OCIResource|<specific type>",
        #     "by_table": {"<table_name>": {"rows": [<raw_row_dict>, ...]}}
        #   }
        # }
        # Accumulates matched resources by resource-id.
        # Example:
        #   {
        #     "ocid1.instance....": {
        #       "node_type": "OCIComputeInstance",
        #       "by_table": {"compute_instances": {"rows": [<raw_row>, ...]}}
        #     }
        #   }
        acc: Dict[str, Dict[str, Any]] = {}

        # Parser returns `rules[]` as independent top-level expressions with no
        # explicit connector between entries, so we treat entries as OR:
        #   rules = [ALL{A,B}, ALL{C,D}]  =>  (A and B) OR (C and D)
        # `ALL`/`ANY` semantics are still enforced recursively inside each node.
        # If caller needs global AND, it must be encoded in one AST expression.
        for node in nodes:
            node_matches = self._eval_node_acc(
                node,
                compartment_id=compartment_id,
            )
            acc = self._union_acc(acc, node_matches)

        if self.debug:
            _core_dlog(self.debug, "dg-eval: scan: plan", total=len(nodes))
        return acc

    def match_iter(
        self,
        rule_text: str,
        *,
        compartment_id: Optional[str] = None,
    ) -> Iterable[Dict[str, Any]]:
        acc = self._match_acc(
            rule_text,
            compartment_id=compartment_id,
        )
        # Yields merged match rows with `id` reattached from the acc key.
        # Output shape: {"id","node_type","by_table": {...}}
        for rid, m in acc.items():
            out = dict(m)
            out["id"] = rid
            yield out

class DynamicGroupPermissionLocationMatcher:
    """
    Permission+location helper flow.

    This class is intentionally separate from DynamicGroupRuleEvaluator to keep
    core rule-evaluation concerns isolated from permission-mapping concerns.
    """
    _permission_resource_type_index: Dict[str, set[str]] | None = None

    def __init__(self, evaluator: DynamicGroupRuleEvaluator) -> None:
        self.evaluator = evaluator

    @staticmethod
    def _node_matches_row(node: Node, row: Dict[str, Any]) -> bool:
        if node.kind == "pred":
            return bool(node.pred) and _eval_pred(pred=node.pred, row=row)
        if node.kind == "all":
            return all(DynamicGroupPermissionLocationMatcher._node_matches_row(c, row) for c in (node.children or ()))
        if node.kind == "any":
            return any(DynamicGroupPermissionLocationMatcher._node_matches_row(c, row) for c in (node.children or ()))
        return False

    @classmethod
    def _rule_matches_hypothetical_resource(
        cls,
        *,
        rule_text: str,
        location: str,
        candidate_resource_types: set[str],
    ) -> bool:
        nodes = compile_matching_rule_nodes(rule_text)
        if not nodes:
            return False
        for resource_type in (candidate_resource_types or set()):
            row = {
                "id": "candidate-resource",
                "compartment_id": location,
                "resource_type": resource_type,
                "defined_tags": {},
            }
            if any(cls._node_matches_row(node, row) for node in nodes):
                return True
        return False

    @classmethod
    def _get_permission_resource_type_index(cls) -> Dict[str, set[str]]:
        if cls._permission_resource_type_index is None:
            cls._permission_resource_type_index = _build_permission_resource_type_index()
        return cls._permission_resource_type_index

    def _resource_types_for_permission(self, permission: str) -> set[str]:
        perm = str(permission or "").strip().upper()
        if not perm:
            return set()
        out = set(self._get_permission_resource_type_index().get(perm, set()))

        # Conservative fallback for common compute-style permissions.
        if not out and perm.startswith("INSTANCE_"):
            out.add(_INSTANCE_RESOURCE_TYPE)
        return out

    @staticmethod
    def _match_row_intersects_allowed_types(match_row: Dict[str, Any], allowed_types: set[str]) -> bool:
        by_table = match_row.get("by_table")
        if not isinstance(by_table, dict):
            return False
        for table_name in by_table.keys():
            if not isinstance(table_name, str):
                continue
            if TABLE_TO_DG_TYPES.get(table_name, set()).intersection(allowed_types):
                return True
        return False

    def match_dynamic_groups_for_permission_location(
        self,
        dynamic_groups: Iterable[Dict[str, Any]],
        *,
        permission: str,
        location: str,
    ) -> List[Dict[str, Any]]:
        permission = str(permission or "").strip().upper()
        location = str(location or "").strip()
        if not permission or not location:
            return []

        allowed_types = self._resource_types_for_permission(permission)
        scoped_evaluator = DynamicGroupRuleEvaluator(session=self.evaluator.session, debug=self.evaluator.debug)
        out: List[Dict[str, Any]] = []

        for dg in (dynamic_groups or []):
            if not isinstance(dg, dict):
                continue
            rule = str(dg.get("matching_rule") or "").strip()
            if not rule:
                continue

            dg_compartment = str(dg.get("compartment_ocid") or dg.get("compartment_id") or "").strip()
            if dg_compartment and dg_compartment != location:
                continue

            matches = list(
                scoped_evaluator.match_iter(
                    rule,
                    compartment_id=location,
                )
            )
            if allowed_types:
                matches = [m for m in matches if self._match_row_intersects_allowed_types(m, allowed_types)]

            hypothetical_candidate_match = False
            if not matches:
                candidate_types = set()
                for rt in (allowed_types or set()):
                    candidate_types.update(_resource_type_alias_closure(rt))
                if permission.startswith("INSTANCE_"):
                    candidate_types.add(_INSTANCE_RESOURCE_TYPE)
                candidate_types = {str(t).strip().lower() for t in candidate_types if str(t).strip()}
                try:
                    hypothetical_candidate_match = self._rule_matches_hypothetical_resource(
                        rule_text=rule,
                        location=location,
                        candidate_resource_types=candidate_types,
                    )
                except Exception:
                    hypothetical_candidate_match = False

            if not matches and not hypothetical_candidate_match:
                continue

            dg_id = str(dg.get("ocid") or dg.get("id") or "").strip()
            dg_name = str(dg.get("display_name") or dg.get("name") or dg_id).strip()
            # One result per matching dynamic-group scoped to permission+location context.
            out.append(
                {
                    "dynamic_group_id": dg_id,
                    "dynamic_group_name": dg_name,
                    "permission": permission,
                    "location": location,
                    "allowed_resource_types": sorted(allowed_types),
                    "match_count": len(matches),
                    "matched_resource_ids": [m.get("id") for m in matches if isinstance(m, dict) and m.get("id")],
                    "matching_rule": rule,
                    "hypothetical_candidate_match": bool(hypothetical_candidate_match),
                }
            )
        return out
