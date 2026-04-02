from __future__ import annotations

from argparse import Namespace

import pytest

from ocinferno.modules.everything.enumeration import enum_all


def _args(*, download=None, not_downloads=None) -> Namespace:
    return Namespace(download=download, not_downloads=not_downloads)


def test_enum_all_no_download_flags_routes_nothing():
    download_all, extras = enum_all._resolve_download_plan(  # pylint: disable=protected-access
        _args(download=None, not_downloads=None),
        debug=False,
    )

    assert download_all is False
    assert extras == {}


def test_enum_all_download_without_tokens_routes_all():
    download_all, extras = enum_all._resolve_download_plan(  # pylint: disable=protected-access
        _args(download=[], not_downloads=None),
        debug=False,
    )

    assert download_all is True
    assert extras == {}


def test_enum_all_download_with_tokens_routes_selective():
    download_all, extras = enum_all._resolve_download_plan(  # pylint: disable=protected-access
        _args(download=["buckets", "orm_variables"], not_downloads=None),
        debug=False,
    )

    assert download_all is False
    assert enum_all.MOD_OBJECT_STORAGE in extras
    assert enum_all.MOD_RESOURCE_MANAGER in extras
    assert "--download" in extras[enum_all.MOD_OBJECT_STORAGE]
    assert "--download" in extras[enum_all.MOD_RESOURCE_MANAGER]


def test_enum_all_not_downloads_without_download_means_all_minus_exclusions():
    download_all, extras = enum_all._resolve_download_plan(  # pylint: disable=protected-access
        _args(download=None, not_downloads=["object_storage"]),
        debug=False,
    )

    assert download_all is False
    assert enum_all.MOD_OBJECT_STORAGE not in extras
    assert enum_all.MOD_API_GATEWAY in extras


def test_enum_all_download_and_not_downloads_apply_intersection():
    download_all, extras = enum_all._resolve_download_plan(  # pylint: disable=protected-access
        _args(download=["buckets", "api_content"], not_downloads=["buckets"]),
        debug=False,
    )

    assert download_all is False
    assert enum_all.MOD_OBJECT_STORAGE not in extras
    assert enum_all.MOD_API_GATEWAY in extras


def test_enum_all_unknown_download_token_raises():
    with pytest.raises(ValueError, match="Unknown download token"):
        enum_all._resolve_download_plan(  # pylint: disable=protected-access
            _args(download=["not_a_real_token"], not_downloads=None),
            debug=False,
        )

