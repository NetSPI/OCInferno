from __future__ import annotations

from pathlib import Path

import pytest

from tests.integration.opengraph_golden_iam.framework import (
    assert_matches_golden,
    discover_scenario_dirs,
    golden_path_for_scenario,
    load_scenario,
    run_scenario,
    scenario_id_for_path,
)


SCENARIO_DIRS = discover_scenario_dirs()


@pytest.mark.parametrize("scenario_path", SCENARIO_DIRS, ids=lambda p: scenario_id_for_path(Path(p)))
def test_opengraph_statement_scenario_matches_golden(scenario_path: Path, tmp_path: Path, monkeypatch):
    scenario = load_scenario(Path(scenario_path))
    scenario_tmp = tmp_path / scenario_id_for_path(Path(scenario_path)).replace("/", "__")
    scenario_tmp.mkdir(parents=True, exist_ok=True)

    actual = run_scenario(scenario, tmp_path=scenario_tmp, monkeypatch=monkeypatch)
    golden_path = golden_path_for_scenario(Path(scenario_path))
    assert_matches_golden(actual=actual, golden_path=golden_path)
