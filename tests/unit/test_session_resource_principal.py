from __future__ import annotations

import base64
import importlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def _install_oci_stub() -> None:
    if "oci" in sys.modules:
        return

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

    def _oci_getattr(attr):
        return _DynamicStub(f"oci.{attr}")

    def _auth_getattr(attr):
        return _DynamicStub(f"oci.auth.{attr}")

    oci_mod.__getattr__ = _oci_getattr
    auth_mod.__getattr__ = _auth_getattr

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


SESSION_MOD = _import_session_module()
SessionUtility = SESSION_MOD.SessionUtility
CredRecord = SESSION_MOD.CredRecord


class _FakeDataMaster:
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


class _FakeSigner:
    def __init__(self, token, private_key):
        self.token = token
        self.private_key = private_key


def _jwt_with_tenancy(tenancy_ocid: str) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"res_tenant": tenancy_ocid, "exp": 4102444800}).encode("utf-8")
    ).decode("utf-8").rstrip("=")
    return f"h.{payload}.s"


class TestSessionResourcePrincipal(unittest.TestCase):
    def _make_session(self):
        s = SessionUtility.__new__(SessionUtility)
        s.workspace_id = 11
        s.workspace_name = "unit"
        s.workspace_directory_name = "11_unit"
        s.data_master = _FakeDataMaster()
        s.api_logger = SimpleNamespace(set_credname=lambda _v: None, enabled=False)
        s.config_global_proxy_dict = ""
        s.individual_run_proxy = None
        s.credname = None
        s.credentials = None
        s.credentials_type = None
        s.tenant_id = None
        s.compartment_id = None
        s.region = None
        s.add_compartment_id = lambda *_a, **_k: None
        return s

    def test_add_resource_profile_token_accepts_inline_token_and_private_key(self):
        session = self._make_session()
        tenancy = "ocid1.tenancy.oc1..unit"
        token = _jwt_with_tenancy(tenancy)
        extra_args = {
            "token": token,
            "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
            "region": "us-phoenix-1",
        }

        with patch.object(SESSION_MOD.serialization, "load_pem_private_key", return_value=object()):
            with patch.object(SESSION_MOD, "SecurityTokenSigner", _FakeSigner):
                rc = session.add_resource_profile_token("rp_inline", extra_args)

        self.assertEqual(rc, 1)
        self.assertEqual(session.credentials_type, "resource-principal")
        self.assertEqual(session.tenant_id, tenancy)
        self.assertEqual(session.region, "us-phoenix-1")
        self.assertIsInstance(session.credentials, dict)
        self.assertEqual(session.credentials["signer"].token, token)

        stored = session.data_master.fetch_cred(11, "rp_inline")
        self.assertIsNotNone(stored)
        self.assertEqual(stored["credtype"], "resource-principal")
        payload = json.loads(stored["session_creds"])
        self.assertTrue(payload.get("resource_principal"))
        self.assertEqual(payload.get("rpst_content"), token)
        self.assertIn("private_pem_content", payload)

    def test_add_resource_profile_token_accepts_filepath_with_token_and_key_files(self):
        session = self._make_session()
        tenancy = "ocid1.tenancy.oc1..fromfile"
        token = _jwt_with_tenancy(tenancy)

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            token_file = base / "rpst.txt"
            key_file = base / "rp_key.pem"
            ref_file = base / "rp.conf"

            token_file.write_text(token, encoding="utf-8")
            key_file.write_text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n", encoding="utf-8")
            ref_file.write_text(
                f"token_file={token_file}\nprivate_key_file={key_file}\nregion=us-ashburn-1\n",
                encoding="utf-8",
            )

            with patch.object(SESSION_MOD.serialization, "load_pem_private_key", return_value=object()):
                with patch.object(SESSION_MOD, "SecurityTokenSigner", _FakeSigner):
                    rc = session.add_resource_profile_token("rp_file", {"filepath": str(ref_file)})

        self.assertEqual(rc, 1)
        self.assertEqual(session.region, "us-ashburn-1")
        self.assertEqual(session.tenant_id, tenancy)
        stored = session.data_master.fetch_cred(11, "rp_file")
        payload = json.loads(stored["session_creds"])
        self.assertTrue(payload.get("rpst_file"))
        self.assertTrue(payload.get("private_pem_file"))

    def test_add_resource_profile_token_accepts_reference_file_alias(self):
        session = self._make_session()
        tenancy = "ocid1.tenancy.oc1..fromref"
        token = _jwt_with_tenancy(tenancy)

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            token_file = base / "rpst.txt"
            key_file = base / "rp_key.pem"
            ref_file = base / "rp.conf"

            token_file.write_text(token, encoding="utf-8")
            key_file.write_text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n", encoding="utf-8")
            ref_file.write_text(
                f"token_file={token_file}\nprivate_key_file={key_file}\nregion=us-chicago-1\n",
                encoding="utf-8",
            )

            with patch.object(SESSION_MOD.serialization, "load_pem_private_key", return_value=object()):
                with patch.object(SESSION_MOD, "SecurityTokenSigner", _FakeSigner):
                    rc = session.add_resource_profile_token("rp_ref_alias", {"reference_file": str(ref_file)})

        self.assertEqual(rc, 1)
        self.assertEqual(session.region, "us-chicago-1")
        self.assertEqual(session.tenant_id, tenancy)

    def test_add_resource_profile_token_rejects_conflicting_reference_paths(self):
        session = self._make_session()

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            a = base / "a.conf"
            b = base / "b.conf"
            a.write_text("token_file=./t\nprivate_key_file=./k\n", encoding="utf-8")
            b.write_text("token_file=./t\nprivate_key_file=./k\n", encoding="utf-8")

            rc = session.add_resource_profile_token(
                "rp_conflict",
                {"reference_file": str(a), "filepath": str(b)},
            )

        self.assertIsNone(rc)

    def test_load_resource_profile_force_refresh_reloads_token_from_file(self):
        session = self._make_session()
        tenancy = "ocid1.tenancy.oc1..rotate"
        old_token = _jwt_with_tenancy(tenancy)
        new_token = _jwt_with_tenancy(tenancy).replace(".s", ".s2")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            token_file = base / "token.txt"
            token_file.write_text(new_token, encoding="utf-8")

            rec = CredRecord(
                credname="rp_rotate",
                credtype="resource-principal",
                session_creds=json.dumps(
                    {
                        "resource_principal": True,
                        "rpst_content": old_token,
                        "rpst_file": str(token_file),
                        "private_pem_content": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
                        "region": "us-phoenix-1",
                    }
                ),
            )

            with patch.object(SESSION_MOD.serialization, "load_pem_private_key", return_value=object()):
                with patch.object(SESSION_MOD, "SecurityTokenSigner", _FakeSigner):
                    rc = session._load_resource_profile_from_record(rec, force_refresh=True)

        self.assertEqual(rc, 1)
        self.assertEqual(session.credentials["signer"].token, new_token)
        self.assertEqual(session.credentials_type, "resource-principal")


if __name__ == "__main__":
    unittest.main()
