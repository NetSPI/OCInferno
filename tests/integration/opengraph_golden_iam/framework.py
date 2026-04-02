from __future__ import annotations

import copy
import difflib
import json
import os
import sys
import types
from pathlib import Path
from typing import Any

if "oci_lexer_parser" not in sys.modules:
    parser_stub = types.ModuleType("oci_lexer_parser")
    parser_stub.parse_dynamic_group_matching_rules = lambda *_a, **_k: {"rules": []}
    parser_stub.parse_policy_statements = lambda *_a, **_k: ({"statements": []}, {"errors": [], "error_count": 0})
    sys.modules["oci_lexer_parser"] = parser_stub

import ocinferno.modules.opengraph.utilities.iam_policy_base_relation_graph_builder as iam_base_builder
from ocinferno.modules.opengraph.enumeration.enum_oracle_cloud_hound_data import run_module
from ocinferno.modules.opengraph.utilities.helpers import matching_rules_engine
from tests.integration.opengraph_test_harness import IntegrationTestDataController, OpenGraphTestSession

SCENARIO_ROOT = Path(__file__).resolve().parent / "scenarios"
GOLDEN_ROOT = Path(__file__).resolve().parent / "golden"
STATEMENT_FILENAME = "statement.txt"
FIXTURE_FILENAME = "fixture.json"
REGEN_ENV_VAR = "OCINFERNO_REGEN_GOLDEN"


def discover_scenario_dirs(root: Path = SCENARIO_ROOT) -> list[Path]:
    out = []
    for statement_path in root.rglob(STATEMENT_FILENAME):
        if statement_path.is_file():
            out.append(statement_path.parent)
    return sorted(set(out))


def scenario_id_for_path(path: Path) -> str:
    rel = path.relative_to(SCENARIO_ROOT)
    return rel.as_posix()


def golden_path_for_scenario(path: Path) -> Path:
    rel = path.relative_to(SCENARIO_ROOT)
    return (GOLDEN_ROOT / rel).with_suffix(".json")


def _read_statement_lines(statement_path: Path) -> list[str]:
    lines: list[str] = []
    for raw in statement_path.read_text(encoding="utf-8").splitlines():
        line = str(raw or "").strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        lines.append(line)
    return lines


def load_scenario(path: Path) -> dict[str, Any]:
    if not path.is_dir():
        raise ValueError(f"scenario must be a directory: {path}")

    statement_path = path / STATEMENT_FILENAME
    if not statement_path.is_file():
        raise ValueError(f"scenario missing required {STATEMENT_FILENAME}: {path}")

    statements = _read_statement_lines(statement_path)
    if not statements:
        raise ValueError(f"scenario has no policy/matching statements in {statement_path}")

    fixture_path = path / FIXTURE_FILENAME
    raw_fixture: dict[str, Any] = {}
    if fixture_path.is_file():
        loaded = json.loads(fixture_path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError(f"{FIXTURE_FILENAME} must be a JSON object: {fixture_path}")
        raw_fixture = loaded

    scenario = copy.deepcopy(raw_fixture)
    scenario["name"] = scenario_id_for_path(path)
    scenario["statement_inputs"] = statements

    inputs = scenario.get("inputs")
    if not isinstance(inputs, dict):
        raise ValueError(f"scenario missing required 'inputs' object: {path}")

    seed_tables = inputs.get("seed_tables")
    if not isinstance(seed_tables, dict):
        raise ValueError(f"scenario missing required 'inputs.seed_tables' object: {path}")

    # Keep statements human-authored in statement.txt by default; if a policy row does not
    # define its own statements, we inject the scenario's statement lines.
    policy_rows = seed_tables.get("identity_policies")
    if isinstance(policy_rows, list):
        for row in policy_rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("statements") or "").strip():
                continue
            row["statements"] = json.dumps(statements)

    return scenario


def _canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _canonicalize(value[k]) for k in sorted(value.keys(), key=lambda x: str(x))}

    if isinstance(value, list):
        out = [_canonicalize(v) for v in value]
        if all(not isinstance(v, (dict, list)) for v in out):
            return sorted(out, key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":")))
        return out

    if isinstance(value, str):
        text = value.strip()
        if text and text[0] in "[{":
            try:
                return _canonicalize(json.loads(text))
            except Exception:
                return value
    return value


def normalize_opengraph_payload(payload: dict[str, Any]) -> dict[str, Any]:
    norm = _canonicalize(copy.deepcopy(payload or {}))
    graph = norm.get("graph") if isinstance(norm, dict) else {}
    if not isinstance(graph, dict):
        graph = {}

    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []

    def _node_key(node: Any) -> tuple[str, str]:
        if not isinstance(node, dict):
            return ("", json.dumps(node, sort_keys=True, separators=(",", ":")))
        node_id = str(node.get("id") or "")
        kinds = node.get("kinds") if isinstance(node.get("kinds"), list) else []
        primary_kind = str(kinds[0] if kinds else "")
        return (primary_kind, node_id)

    def _edge_key(edge: Any) -> tuple[str, str, str]:
        if not isinstance(edge, dict):
            dumped = json.dumps(edge, sort_keys=True, separators=(",", ":"))
            return ("", "", dumped)
        start = edge.get("start") if isinstance(edge.get("start"), dict) else {}
        end = edge.get("end") if isinstance(edge.get("end"), dict) else {}
        src = str(start.get("value") or "")
        dst = str(end.get("value") or "")
        kind = str(edge.get("kind") or "")
        return (src, kind, dst)

    graph["nodes"] = sorted(nodes, key=_node_key)
    graph["edges"] = sorted(edges, key=_edge_key)
    norm["graph"] = graph
    return norm


def _build_policy_statement_stub_map(raw: Any, *, statements: list[str] | None = None) -> dict[str, dict[str, Any]]:
    statement_lines = [str(s).strip() for s in (statements or []) if str(s).strip()]

    if isinstance(raw, dict):
        out: dict[str, dict[str, Any]] = {}
        for k, v in raw.items():
            if not isinstance(v, dict):
                continue
            key = str(k).strip()
            # Support index-addressed maps: {"0": {...parsed...}}
            if key.isdigit() and statement_lines:
                idx = int(key)
                if 0 <= idx < len(statement_lines):
                    out[statement_lines[idx]] = copy.deepcopy(v)
                    continue
            out[key] = copy.deepcopy(v)
        return out

    if isinstance(raw, list):
        out: dict[str, dict[str, Any]] = {}
        # Compact mode: list of parsed statement payloads in the same order
        # as statement.txt lines.
        if statement_lines and all(isinstance(item, dict) and "kind" in item for item in raw):
            for idx, parsed in enumerate(raw):
                if idx >= len(statement_lines):
                    break
                out[statement_lines[idx]] = copy.deepcopy(parsed)
            return out

        for item in raw:
            if not isinstance(item, dict):
                continue
            stmt = str(item.get("raw") or "").strip()
            parsed = item.get("parsed")
            if stmt and isinstance(parsed, dict):
                out[stmt] = copy.deepcopy(parsed)
        return out

    return {}


def _build_dynamic_rule_stub_map(raw: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, dict):
        return {}
    return {
        str(rule): copy.deepcopy(payload)
        for rule, payload in raw.items()
        if isinstance(payload, dict)
    }


def _apply_parser_stubs(monkeypatch, scenario: dict[str, Any]) -> None:
    parser_stubs = (
        scenario.get("inputs", {})
        .get("parser_stubs", {})
    )
    if not isinstance(parser_stubs, dict):
        parser_stubs = {}

    policy_stmt_map = _build_policy_statement_stub_map(
        parser_stubs.get("policy_statements"),
        statements=list(scenario.get("statement_inputs") or ()),
    )
    dynamic_rule_map = _build_dynamic_rule_stub_map(parser_stubs.get("dynamic_group_matching_rules"))

    def _parse_policy_statements_stub(statements, **_kwargs):
        stmts = statements if isinstance(statements, list) else []
        parsed_statements: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        for raw_stmt in stmts:
            key = str(raw_stmt or "").strip()
            parsed = policy_stmt_map.get(key)
            if isinstance(parsed, dict):
                parsed_statements.append(copy.deepcopy(parsed))
            else:
                errors.append({"statement": key, "error": "no scenario parser stub"})

        return {"statements": parsed_statements}, {"errors": errors, "error_count": len(errors)}

    def _parse_dynamic_group_matching_rules_stub(rule_text, *_args, **_kwargs):
        key = str(rule_text or "").strip()
        payload = dynamic_rule_map.get(key)
        if isinstance(payload, dict):
            return copy.deepcopy(payload)
        return {"rules": []}

    monkeypatch.setattr(iam_base_builder, "parse_policy_statements", _parse_policy_statements_stub)
    monkeypatch.setattr(matching_rules_engine, "parse_dynamic_group_matching_rules", _parse_dynamic_group_matching_rules_stub)


def _seed_tables(dc: IntegrationTestDataController, *, workspace_id: int, seed_tables: dict[str, Any]) -> None:
    for table_name, rows in seed_tables.items():
        if not isinstance(table_name, str) or not table_name:
            continue
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            payload = dict(row)
            payload["workspace_id"] = workspace_id
            ok = dc.save_dict_row(
                db="service",
                table_name=table_name,
                row=payload,
                on_conflict="replace",
                commit=True,
            )
            if not ok:
                raise AssertionError(f"failed to seed {table_name}: {row}")


def run_scenario(scenario: dict[str, Any], *, tmp_path: Path, monkeypatch) -> dict[str, Any]:
    workspace = scenario.get("workspace") if isinstance(scenario.get("workspace"), dict) else {}

    workspace_id = int(workspace.get("workspace_id") or 9191)
    workspace_name = str(workspace.get("workspace_name") or "opengraph-golden")
    tenancy_ocid = str(workspace.get("tenancy_ocid") or "ocid1.tenancy.oc1..golden")
    compartment_ocid = str(workspace.get("compartment_ocid") or "ocid1.compartment.oc1..golden")

    dc = IntegrationTestDataController(tmp_path)
    if not dc.create_service_tables_from_yaml():
        raise AssertionError("failed to create service tables for scenario")

    session = OpenGraphTestSession(
        dc,
        workspace_id=workspace_id,
        workspace_name=workspace_name,
        compartment_id=compartment_ocid,
        tenant_id=tenancy_ocid,
        output_root=tmp_path / "exports",
    )

    inputs = scenario.get("inputs") if isinstance(scenario.get("inputs"), dict) else {}
    seed_tables = inputs.get("seed_tables") if isinstance(inputs.get("seed_tables"), dict) else {}

    _seed_tables(dc, workspace_id=workspace_id, seed_tables=seed_tables)
    _apply_parser_stubs(monkeypatch, scenario)

    args = scenario.get("module_args")
    module_args = [str(x) for x in args] if isinstance(args, list) else []

    try:
        produced = run_module(module_args, session)
        return normalize_opengraph_payload(produced if isinstance(produced, dict) else {})
    finally:
        dc.close()


def _render_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=False) + "\n"


def assert_matches_golden(*, actual: dict[str, Any], golden_path: Path) -> None:
    regen = os.getenv(REGEN_ENV_VAR, "").strip() == "1"
    if regen:
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(_render_json(actual), encoding="utf-8")

    if not golden_path.exists():
        raise AssertionError(
            f"golden file missing: {golden_path}\n"
            f"Set {REGEN_ENV_VAR}=1 and rerun to generate it."
        )

    expected = normalize_opengraph_payload(json.loads(golden_path.read_text(encoding="utf-8")))
    if actual != expected:
        expected_text = _render_json(expected)
        actual_text = _render_json(actual)
        diff = "".join(
            difflib.unified_diff(
                expected_text.splitlines(keepends=True),
                actual_text.splitlines(keepends=True),
                fromfile=str(golden_path),
                tofile="actual",
            )
        )
        raise AssertionError(f"golden mismatch for {golden_path}\n{diff}")
