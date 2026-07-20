from __future__ import annotations

from argparse import Namespace

from ocinferno.modules.everything.enumeration import enum_all


def _args(*, modules=None, not_modules=None) -> Namespace:
    return Namespace(modules=modules, not_modules=not_modules)


def test_no_selectors_no_once_flags_runs_everything():
    flags = enum_all._resolve_service_run_flags(  # pylint: disable=protected-access
        _args(),
        any_once_flags=False,
        should_enum_comp=False,
        debug=False,
    )
    assert flags and all(flags.values())


def test_config_check_only_no_comp_skips_enumeration():
    # `enum_all --config-check` with no --comp and no explicit --modules is the
    # "just re-audit already-collected data" shortcut -- it must NOT re-run
    # enumeration.
    flags = enum_all._resolve_service_run_flags(  # pylint: disable=protected-access
        _args(),
        any_once_flags=True,
        should_enum_comp=False,
        debug=False,
    )
    assert flags and not any(flags.values())


def test_comp_plus_config_check_still_runs_enumeration():
    # Regression: `enum_all --comp --config-check` (discover compartments, enumerate
    # everything, then audit) previously silently ran ZERO service enumeration
    # because any_once_flags alone zeroed out service selection, leaving
    # process_config_check to run against whatever (often nothing) was already in
    # the DB and report a false "0 findings". --comp must imply wanting a fresh
    # enumeration pass.
    flags = enum_all._resolve_service_run_flags(  # pylint: disable=protected-access
        _args(),
        any_once_flags=True,
        should_enum_comp=True,
        debug=False,
    )
    assert flags and all(flags.values())


def test_explicit_modules_selector_overrides_once_flags_regardless_of_comp():
    flags = enum_all._resolve_service_run_flags(  # pylint: disable=protected-access
        _args(modules=["identity"]),
        any_once_flags=True,
        should_enum_comp=False,
        debug=False,
    )
    assert flags.get("identity") is True
    assert sum(1 for v in flags.values() if v) == 1


def test_not_modules_selector_with_once_flags_runs_all_minus_exclusion():
    flags = enum_all._resolve_service_run_flags(  # pylint: disable=protected-access
        _args(not_modules=["identity"]),
        any_once_flags=True,
        should_enum_comp=False,
        debug=False,
    )
    assert flags.get("identity") is False
    assert all(v for k, v in flags.items() if k != "identity")
