from __future__ import annotations

from argparse import Namespace

import pytest

from ocinferno.modules.everything.enumeration import enum_all


def _args() -> Namespace:
    return Namespace(
        save=False,
        get=False,
        download=None,
        not_downloads=None,
    )


@pytest.mark.parametrize("cid", ["ocid1.compartment.oc1..example", "ocid1.tenancy.oc1..example"])
def test_enum_all_identity_no_component_override(cid):
    result = enum_all._module_args_for_target(  # pylint: disable=protected-access
        _args(),
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
