"""Shared helpers for session unit tests.

Provides the OCI stub, session-module importer, FakeDataMaster, and JWT
factory used across test_session_explicit_api_and_session_token.py,
test_session_resource_principal.py, and test_session_delegation_token.py.
"""
from __future__ import annotations

import base64
import importlib
import json
import sys
import types


def _install_oci_stub() -> None:
    # Only stub when the real SDK is genuinely not installed -- unconditionally
    # installing a fake module here would permanently shadow the real `oci` for
    # the rest of the pytest session for any other test file that needs it
    # (collection-order dependent).
    try:
        import oci  # noqa: F401
        return
    except ImportError:
        pass

    class _DynamicStub:
        def __init__(self, name: str = "stub"):
            self._name = name

        def __getattr__(self, item: str):
            return _DynamicStub(f"{self._name}.{item}")

        def __call__(self, *args, **kwargs):
            return _DynamicStub(f"{self._name}()")

        def __iter__(self):
            return iter(())

        def __bool__(self):
            return False

    oci_mod = types.ModuleType("oci")
    auth_mod = types.ModuleType("oci.auth")
    cert_mod = types.ModuleType("oci.auth.certificate_retriever")
    fed_mod = types.ModuleType("oci.auth.federation_client")
    sks_mod = types.ModuleType("oci.auth.session_key_supplier")
    sign_mod = types.ModuleType("oci.auth.signers")
    cfg_mod = types.ModuleType("oci.config")
    exc_mod = types.ModuleType("oci.exceptions")
    util_mod = types.ModuleType("oci.util")

    class PEMStringCertificateRetriever:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class X509FederationClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def get_security_token(self):
            return "stub-token"

    class SessionKeySupplier:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class SecurityTokenSigner:
        def __init__(self, token, private_key):
            self.token = token
            self.private_key = private_key

    class X509FederationClientBasedSecurityTokenSigner:
        def __init__(self, federation_client):
            self.federation_client = federation_client

    class ConfigFileNotFound(Exception):
        pass

    class InvalidKeyFilePath(Exception):
        pass

    class ProfileNotFound(Exception):
        pass

    def from_file(**_kwargs):
        return {}

    def validate_config(_cfg):
        return True

    def to_dict(obj):
        return obj

    cert_mod.PEMStringCertificateRetriever = PEMStringCertificateRetriever
    fed_mod.X509FederationClient = X509FederationClient
    sks_mod.SessionKeySupplier = SessionKeySupplier
    sign_mod.SecurityTokenSigner = SecurityTokenSigner
    sign_mod.X509FederationClientBasedSecurityTokenSigner = X509FederationClientBasedSecurityTokenSigner

    cfg_mod.from_file = from_file
    cfg_mod.validate_config = validate_config

    exc_mod.ConfigFileNotFound = ConfigFileNotFound
    exc_mod.InvalidKeyFilePath = InvalidKeyFilePath
    exc_mod.ProfileNotFound = ProfileNotFound

    util_mod.to_dict = to_dict

    auth_mod.certificate_retriever = cert_mod
    auth_mod.federation_client = fed_mod
    auth_mod.session_key_supplier = sks_mod
    auth_mod.signers = sign_mod

    oci_mod.auth = auth_mod
    oci_mod.config = cfg_mod
    oci_mod.exceptions = exc_mod
    oci_mod.util = util_mod
    oci_mod.retry = types.SimpleNamespace(DEFAULT_RETRY_STRATEGY=None)
    oci_mod.core = types.SimpleNamespace(models=_DynamicStub("oci.core.models"))

    oci_mod.__getattr__ = lambda attr: _DynamicStub(f"oci.{attr}")
    auth_mod.__getattr__ = lambda attr: _DynamicStub(f"oci.auth.{attr}")

    sys.modules["oci"] = oci_mod
    sys.modules["oci.auth"] = auth_mod
    sys.modules["oci.auth.certificate_retriever"] = cert_mod
    sys.modules["oci.auth.federation_client"] = fed_mod
    sys.modules["oci.auth.session_key_supplier"] = sks_mod
    sys.modules["oci.auth.signers"] = sign_mod
    sys.modules["oci.config"] = cfg_mod
    sys.modules["oci.exceptions"] = exc_mod
    sys.modules["oci.util"] = util_mod


def _import_session_module():
    try:
        return importlib.import_module("ocinferno.core.session")
    except ModuleNotFoundError as e:
        if e.name != "oci":
            raise
        _install_oci_stub()
        sys.modules.pop("ocinferno.core.session", None)
        return importlib.import_module("ocinferno.core.session")


class FakeDataMaster:
    def __init__(self):
        self.records = {}

    def fetch_cred(self, workspace_id, credname):
        return self.records.get((workspace_id, credname))

    def insert_creds(self, workspace_id, credname, credtype, session_creds):
        self.records[(workspace_id, credname)] = {
            "credname": credname,
            "credtype": credtype,
            "session_creds": session_creds,
        }
        return True

    def save_value_to_table_column(self, **_kwargs):
        return True


class FakeSigner:
    """Minimal signer stub used in session credential tests."""
    def __init__(self, token, private_key):
        self.token = token
        self.private_key = private_key


def jwt_with_tenancy(tenancy_ocid: str) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"res_tenant": tenancy_ocid, "exp": 4102444800}).encode("utf-8")
    ).decode("utf-8").rstrip("=")
    return f"h.{payload}.s"
