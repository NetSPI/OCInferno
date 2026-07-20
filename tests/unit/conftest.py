from __future__ import annotations

import importlib
import sys

import pytest


@pytest.fixture
def real_identity_principals_oci(monkeypatch):
    """Another unit-test module (test_enum_identity_principals_flags) stubs `oci` into
    sys.modules at import time and never restores it. The identity exploit tests need
    the real SDK models/to_dict, so swap the real oci in for the duration of the test
    and restore the prior sys.modules state on teardown.

    Shared across every test file that exercises identity exploit logic (all of which
    lives in modules/identityclient/utilities/helpers.py).

    Yields the helpers module for convenience.
    """
    from ocinferno.modules.identityclient.utilities import helpers as ip

    keys = [k for k in list(sys.modules) if k == "oci" or k.startswith("oci.")]
    saved = {k: sys.modules[k] for k in keys}
    for k in keys:
        if getattr(sys.modules[k], "__file__", None) is None:  # stub has no real __file__
            del sys.modules[k]
    real_oci = importlib.import_module("oci")
    importlib.import_module("oci.util")
    importlib.import_module("oci.identity.models")
    importlib.import_module("oci.identity_domains.models")
    monkeypatch.setattr(ip, "oci", real_oci)
    yield ip
    for k in [k for k in list(sys.modules) if k == "oci" or k.startswith("oci.")]:
        del sys.modules[k]
    sys.modules.update(saved)
