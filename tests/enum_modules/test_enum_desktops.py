from __future__ import annotations

from tests.enum_modules.harness import assert_module_flags_parse, assert_module_runs_offline

MODULE = "ocinferno.modules.desktops.enumeration.enum_desktops"

def test_enum_desktops_flags_and_offline_smoke():
    assert_module_flags_parse(MODULE)
    assert_module_runs_offline(MODULE)
