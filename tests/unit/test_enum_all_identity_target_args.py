from __future__ import annotations

from argparse import Namespace

from ocinferno.modules.everything.enumeration import enum_all


def _args() -> Namespace:
    return Namespace(
        save=False,
        get=False,
        download=None,
        not_downloads=None,
    )


def test_enum_all_non_tenancy_identity_override_includes_domains_and_idd_principals():
    result = enum_all._module_args_for_target(  # pylint: disable=protected-access
        _args(),
        "ocinferno.modules.identityclient.enumeration.enum_identity",
        "ocid1.compartment.oc1..example",
        debug=False,
        download_all=False,
        module_download_extras=None,
    )

    assert "--domains" not in result
    assert "--iam" not in result
    assert "--principals" not in result
    assert "--classic-only" not in result


def test_enum_all_tenancy_identity_no_component_override():
    result = enum_all._module_args_for_target(  # pylint: disable=protected-access
        _args(),
        "ocinferno.modules.identityclient.enumeration.enum_identity",
        "ocid1.tenancy.oc1..example",
        debug=False,
        download_all=False,
        module_download_extras=None,
    )

    assert "--domains" not in result
    assert "--iam" not in result
    assert "--principals" not in result
