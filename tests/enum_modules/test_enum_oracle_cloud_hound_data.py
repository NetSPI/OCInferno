from __future__ import annotations

from tests.enum_modules.harness import assert_module_flags_parse, assert_module_runs_offline

MODULE = "ocinferno.modules.opengraph.enumeration.enum_oracle_cloud_hound_data"

def test_enum_oracle_cloud_hound_data_flags_and_offline_smoke():
    assert_module_flags_parse(MODULE)
    assert_module_runs_offline(MODULE)
