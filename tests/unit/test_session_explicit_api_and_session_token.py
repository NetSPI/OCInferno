from __future__ import annotations

import base64
import importlib
import json
import os
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

    def save_value_to_table_column(self, **_kwargs):
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


class TestSessionExplicitApiKeyAndSessionToken(unittest.TestCase):
    def _make_session(self):
        s = SessionUtility.__new__(SessionUtility)
        s.workspace_id = 22
        s.workspace_name = "unit"
        s.workspace_directory_name = "22_unit"
        s.data_master = _FakeDataMaster()
        s.api_logger = SimpleNamespace(set_credname=lambda _v: None, enabled=False)
        s.config_global_proxy_dict = ""
        s.individual_run_proxy = None
        s.individual_run_debug = False
        s.credname = None
        s.credentials = None
        s.credentials_type = None
        s.tenant_id = None
        s.compartment_id = None
        s.region = None
        s.add_compartment_id = lambda *_a, **_k: None
        return s

    def test_add_api_key_accepts_explicit_values(self):
        session = self._make_session()
        with patch.object(SESSION_MOD, "validate_config", return_value=True):
            rc = session.add_api_key(
                "api_inline",
                {
                    "user": "ocid1.user.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                    "tenancy_id": "ocid1.tenancy.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "region": "us-phoenix-1",
                    "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
                },
            )
        self.assertEqual(rc, 1)
        self.assertEqual(session.credentials_type, "Profile")
        self.assertEqual(session.region, "us-phoenix-1")
        self.assertEqual(
            session.tenant_id, "ocid1.tenancy.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )

        stored = session.data_master.fetch_cred(22, "api_inline")
        self.assertIsNotNone(stored)
        self.assertEqual(stored["credtype"], "api-key")
        payload = json.loads(stored["session_creds"])
        self.assertEqual(payload.get("auth_type"), "api_key")
        self.assertEqual(payload.get("user"), "ocid1.user.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(payload.get("fingerprint"), "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99")

    def test_add_session_token_accepts_explicit_values_and_extracts_tenancy(self):
        session = self._make_session()
        tenancy = "ocid1.tenancy.oc1..tokeninline"
        token = _jwt_with_tenancy(tenancy)

        with patch.object(SESSION_MOD.serialization, "load_pem_private_key", return_value=object()):
            with patch.object(SESSION_MOD, "SecurityTokenSigner", _FakeSigner):
                rc = session.add_session_token(
                    "st_inline",
                    {
                        "token_value": token,
                        "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
                        "region": "us-ashburn-1",
                    },
                )

        self.assertEqual(rc, 1)
        self.assertEqual(session.credentials_type, "Profile Session")
        self.assertEqual(session.region, "us-ashburn-1")
        self.assertEqual(session.tenant_id, tenancy)
        self.assertEqual(session.credentials["signer"].token, token)

        stored = session.data_master.fetch_cred(22, "st_inline")
        self.assertIsNotNone(stored)
        self.assertEqual(stored["credtype"], "session-token")
        payload = json.loads(stored["session_creds"])
        self.assertEqual(payload.get("auth_type"), "session_token")
        self.assertEqual(payload.get("security_token_content"), token)

    def test_load_stored_session_token_force_refresh_reloads_token_file(self):
        session = self._make_session()
        tenancy = "ocid1.tenancy.oc1..rotate_session"
        old_token = _jwt_with_tenancy(tenancy)
        new_token = _jwt_with_tenancy(tenancy).replace(".s", ".s2")

        with tempfile.TemporaryDirectory() as td:
            token_file = Path(td) / "session_token.txt"
            token_file.write_text(new_token, encoding="utf-8")

            session.data_master.insert_creds(
                22,
                "st_reload",
                "session-token",
                json.dumps(
                    {
                        "auth_type": "session_token",
                        "security_token_content": old_token,
                        "security_token_file": str(token_file),
                        "key_content": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
                        "region": "us-phoenix-1",
                        "tenancy": tenancy,
                    }
                ),
            )

            with patch.object(SESSION_MOD.serialization, "load_pem_private_key", return_value=object()):
                with patch.object(SESSION_MOD, "SecurityTokenSigner", _FakeSigner):
                    rc = session.load_stored_creds("st_reload", force_refresh=True)

        self.assertEqual(rc, 1)
        self.assertEqual(session.credentials_type, "Profile Session")
        self.assertEqual(session.credentials["signer"].token, new_token)

    def test_build_instance_profile_signer_restores_proxy_environment(self):
        session = self._make_session()
        session._resolve_proxy = lambda *_args, **_kwargs: "http://127.0.0.1:8080"
        session._ipdbg = lambda *_args, **_kwargs: None
        session._validate_pems = lambda *_args, **_kwargs: None

        def _fake_read_text_file(path_str, label):
            if "key" in str(label).lower():
                return "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", None
            return "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----", None

        session._read_text_file = _fake_read_text_file

        class _FakeRequestsSession:
            def __init__(self):
                self.proxies = {}
                self.trust_env = True
                self.verify = True

            def request(self, *_args, **_kwargs):
                return SimpleNamespace(status_code=200)

            def get(self, *_args, **_kwargs):
                return SimpleNamespace(status_code=200)

        class _FakeFederationClient:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

            def get_security_token(self):
                return "stub-token"

        class _FakeFederationSigner:
            def __init__(self, federation_client):
                self.federation_client = federation_client

        class _FakePemRetriever:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        class _FakeSessionKeySupplier:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        with patch.dict(os.environ, {}, clear=True):
            with patch.object(SESSION_MOD.requests, "Session", _FakeRequestsSession):
                with patch.object(SESSION_MOD, "PEMStringCertificateRetriever", _FakePemRetriever):
                    with patch.object(SESSION_MOD, "SessionKeySupplier", _FakeSessionKeySupplier):
                        with patch.object(SESSION_MOD, "X509FederationClient", _FakeFederationClient):
                            with patch.object(SESSION_MOD, "X509FederationClientBasedSecurityTokenSigner", _FakeFederationSigner):
                                signer, cfg, err = session._build_instance_profile_signer(
                                    ref_cfg={
                                        "leaf_cert_file": "leaf.pem",
                                        "leaf_key_file": "leaf.key",
                                        "intermediate_cert_file": "intermediate.pem",
                                    },
                                    region="us-ashburn-1",
                                    tenancy_id="ocid1.tenancy.oc1..example",
                                    proxy="http://127.0.0.1:8080",
                                    log_requests=False,
                                    force_refresh=False,
                                )

            self.assertIsNone(err)
            self.assertIsNotNone(signer)
            self.assertEqual(cfg.get("region"), "us-ashburn-1")
            self.assertEqual(cfg.get("tenancy"), "ocid1.tenancy.oc1..example")
            self.assertNotIn("HTTP_PROXY", os.environ)
            self.assertNotIn("HTTPS_PROXY", os.environ)
            self.assertNotIn("http_proxy", os.environ)
            self.assertNotIn("https_proxy", os.environ)


if __name__ == "__main__":
    unittest.main()
