from __future__ import annotations

from tests.enum_modules.harness import assert_module_flags_parse, assert_module_runs_offline

MODULE = "ocinferno.modules.apigateway.enumeration.enum_apigateway"

def test_enum_apigateway_flags_and_offline_smoke():
    assert_module_flags_parse(MODULE)
    assert_module_runs_offline(MODULE)
