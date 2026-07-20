from __future__ import annotations

from argparse import Namespace

import pytest

from ocinferno.modules.everything.enumeration import enum_all


def _args(*, download=None, not_downloads=None) -> Namespace:
    return Namespace(download=download, not_downloads=not_downloads)


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
        _args(download=download, not_downloads=not_downloads),
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
            _args(download=["not_a_real_token"], not_downloads=None),
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
        _args(download=download, not_downloads=not_downloads),
        debug=False,
    )
    assert download_all is False
    for mod in expect_in:
        assert mod in extras
    for mod in expect_not_in:
        assert mod not in extras

