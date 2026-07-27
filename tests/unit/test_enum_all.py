from __future__ import annotations

from argparse import Namespace

import pytest

from ocinferno.modules.everything.enumeration import enum_all


def _download_args(*, download=None, not_downloads=None) -> Namespace:
    return Namespace(download=download, not_downloads=not_downloads)


def _target_args() -> Namespace:
    return Namespace(save=False, get=False, download=None, not_downloads=None)


def _service_args(*, modules=None, not_modules=None) -> Namespace:
    return Namespace(modules=modules, not_modules=not_modules)


_PLAN_CASES = [
    pytest.param(None, None, False, [], [], [], id="no-flags-routes-nothing"),
    pytest.param([], None, True, [], [], [], id="download-without-tokens-routes-all"),
    pytest.param(
        ["buckets", "orm_variables"], None, False,
        [enum_all.MOD_OBJECT_STORAGE, enum_all.MOD_RESOURCE_MANAGER], [],
        [enum_all.MOD_OBJECT_STORAGE, enum_all.MOD_RESOURCE_MANAGER],
        id="download-with-tokens-routes-selective",
    ),
    pytest.param(
        None, ["object_storage"], False,
        [enum_all.MOD_API_GATEWAY], [enum_all.MOD_OBJECT_STORAGE], [],
        id="not-downloads-without-download-is-all-minus-exclusions",
    ),
    pytest.param(
        ["buckets", "api_content"], ["buckets"], False,
        [enum_all.MOD_API_GATEWAY], [enum_all.MOD_OBJECT_STORAGE], [],
        id="download-and-not-downloads-intersect",
    ),
]


@pytest.mark.parametrize(
    "download, not_downloads, expected_download_all, expect_in, expect_not_in, expect_download_flag",
    _PLAN_CASES,
)
def test_resolve_download_plan(download, not_downloads, expected_download_all, expect_in, expect_not_in, expect_download_flag):
    download_all, extras = enum_all._resolve_download_plan(  # pylint: disable=protected-access
        _download_args(download=download, not_downloads=not_downloads),
        debug=False,
    )
    assert download_all is expected_download_all
    for mod in expect_in:
        assert mod in extras
    for mod in expect_not_in:
        assert mod not in extras
    for mod in expect_download_flag:
        assert "--download" in extras[mod]


def test_enum_all_unknown_download_token_raises():
    with pytest.raises(ValueError, match="Unknown download token"):
        enum_all._resolve_download_plan(  # pylint: disable=protected-access
            _download_args(download=["not_a_real_token"], not_downloads=None),
            debug=False,
        )


# ---- Umbrella categories: metadata / content ---------------------------------

def test_categories_partition_all_tokens():
    # metadata and content together cover EVERY canonical token, with no overlap.
    meta = enum_all.DOWNLOAD_TOKEN_CATEGORIES["metadata"]
    content = enum_all.DOWNLOAD_TOKEN_CATEGORIES["content"]
    known = set(enum_all.DOWNLOAD_TOKEN_MODULE_ARGS.keys())
    assert meta.isdisjoint(content)
    assert (meta | content) == known


@pytest.mark.parametrize(
    "download, not_downloads, expect_in, expect_not_in",
    [
        pytest.param(
            ["metadata"], None,
            [enum_all.MOD_CORE_COMPUTE, enum_all.MOD_API_GATEWAY],
            [enum_all.MOD_OBJECT_STORAGE, enum_all.MOD_VAULT],
            id="metadata-category-routes-light-only",
        ),
        pytest.param(
            ["content"], None,
            [enum_all.MOD_OBJECT_STORAGE, enum_all.MOD_VAULT],
            [enum_all.MOD_CORE_COMPUTE],
            id="content-category-routes-heavy",
        ),
        pytest.param(
            ["content"], ["vault_secrets"],
            [enum_all.MOD_OBJECT_STORAGE], [enum_all.MOD_VAULT],
            id="category-minus-token",
        ),
        pytest.param(
            [], ["content"],
            [enum_all.MOD_CORE_COMPUTE], [enum_all.MOD_OBJECT_STORAGE, enum_all.MOD_VAULT],
            id="download-all-minus-content-leaves-metadata",
        ),
        pytest.param(
            ["metadata", "vault_secrets"], None,
            [enum_all.MOD_VAULT, enum_all.MOD_CORE_COMPUTE], [],
            id="categories-and-tokens-compose",
        ),
    ],
)
def test_download_categories(download, not_downloads, expect_in, expect_not_in):
    download_all, extras = enum_all._resolve_download_plan(  # pylint: disable=protected-access
        _download_args(download=download, not_downloads=not_downloads),
        debug=False,
    )
    assert download_all is False
    for mod in expect_in:
        assert mod in extras
    for mod in expect_not_in:
        assert mod not in extras


# ---------------------------------------------------------------------------
# _module_args_for_target: identity component override behavior
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cid", ["ocid1.compartment.oc1..example", "ocid1.tenancy.oc1..example"])
def test_enum_all_identity_no_component_override(cid):
    result = enum_all._module_args_for_target(  # pylint: disable=protected-access
        _target_args(),
        "ocinferno.modules.identityclient.enumeration.enum_identity",
        cid,
        debug=False,
        download_all=False,
        module_download_extras=None,
    )
    assert "--domains" not in result
    assert "--iam" not in result
    assert "--principals" not in result
    assert "--classic-only" not in result


# ---------------------------------------------------------------------------
# _resolve_service_run_flags: module selection logic
# ---------------------------------------------------------------------------

def test_no_selectors_no_once_flags_runs_everything_except_default_excluded():
    # Audit is deliberately excluded from the default "run everything" sweep.
    flags = enum_all._resolve_service_run_flags(  # pylint: disable=protected-access
        _service_args(),
        any_once_flags=False,
        should_enum_comp=False,
        debug=False,
    )
    assert flags
    assert flags["audit"] is False
    assert all(v for k, v in flags.items() if k != "audit")


def test_explicit_modules_audit_still_selects_it():
    # An explicit --modules <token> is an include-list, so audit being excluded
    # from the default sweep must not stop it from being explicitly runnable.
    flags = enum_all._resolve_service_run_flags(  # pylint: disable=protected-access
        _service_args(modules=["audit"]),
        any_once_flags=False,
        should_enum_comp=False,
        debug=False,
    )
    assert flags["audit"] is True
    assert all(v is False for k, v in flags.items() if k != "audit")


def test_config_check_only_no_comp_skips_enumeration():
    # `enum_all --config-check` with no --comp and no explicit --modules must NOT
    # re-run enumeration.
    flags = enum_all._resolve_service_run_flags(  # pylint: disable=protected-access
        _service_args(),
        any_once_flags=True,
        should_enum_comp=False,
        debug=False,
    )
    assert flags and not any(flags.values())


def test_comp_plus_config_check_still_runs_enumeration():
    # Regression: `enum_all --comp --config-check` previously silently ran ZERO
    # service enumeration because any_once_flags alone zeroed out service selection.
    flags = enum_all._resolve_service_run_flags(  # pylint: disable=protected-access
        _service_args(),
        any_once_flags=True,
        should_enum_comp=True,
        debug=False,
    )
    assert flags
    assert flags["audit"] is False
    assert all(v for k, v in flags.items() if k != "audit")


def test_explicit_modules_selector_overrides_once_flags_regardless_of_comp():
    flags = enum_all._resolve_service_run_flags(  # pylint: disable=protected-access
        _service_args(modules=["identity"]),
        any_once_flags=True,
        should_enum_comp=False,
        debug=False,
    )
    assert flags.get("identity") is True
    assert sum(1 for v in flags.values() if v) == 1


def test_not_modules_selector_with_once_flags_runs_all_minus_exclusion():
    flags = enum_all._resolve_service_run_flags(  # pylint: disable=protected-access
        _service_args(not_modules=["identity"]),
        any_once_flags=True,
        should_enum_comp=False,
        debug=False,
    )
    assert flags.get("identity") is False
    assert all(v for k, v in flags.items() if k != "identity")
