"""Delegation-token (OBO) auth as an OPTIONAL add-on to instance-principal.

Delegation is not a separate credential type: `instance-principal` gains an optional
`--delegation-token[-file]`. When present, the instance-principal signer (on-host via
IMDS, or off-box reconstructed from harvested cert material) also stamps the signed
`opc-obo-token` header. Mirrors test_session_resource_principal.py's harness.
"""
from __future__ import annotations

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

        def __call__(self, *a, **k):
            return _DynamicStub(f"{self._name}()")

        def __iter__(self):
            return iter(())

        def __bool__(self):
            return False

    oci_mod = types.ModuleType("oci")
    auth_mod = types.ModuleType("oci.auth")
    sign_mod = types.ModuleType("oci.auth.signers")
    util_mod = types.ModuleType("oci.util")
    exc_mod = types.ModuleType("oci.exceptions")
    util_mod.to_dict = lambda o: o
    auth_mod.signers = sign_mod
    oci_mod.auth = auth_mod
    oci_mod.util = util_mod
    oci_mod.exceptions = exc_mod
    oci_mod.__getattr__ = lambda a: _DynamicStub(f"oci.{a}")
    auth_mod.__getattr__ = lambda a: _DynamicStub(f"oci.auth.{a}")
    for name, mod in [("oci", oci_mod), ("oci.auth", auth_mod), ("oci.auth.signers", sign_mod),
                      ("oci.util", util_mod), ("oci.exceptions", exc_mod)]:
        sys.modules[name] = mod


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
AUTH_MOD = importlib.import_module("ocinferno.core.auth")
SessionUtility = SESSION_MOD.SessionUtility
CredRecord = SESSION_MOD.CredRecord


class _FakeDataMaster:
    def __init__(self):
        self.records = {}

    def fetch_cred(self, workspace_id, credname):
        return self.records.get((workspace_id, credname))

    def insert_creds(self, workspace_id, credname, credtype, session_creds):
        self.records[(workspace_id, credname)] = {"credname": credname, "credtype": credtype, "session_creds": session_creds}
        return True


class _FakeX509Base:
    """Stand-in federation signer whose obo subclass we assert against."""
    def __init__(self, federation_client, generic_headers=None, body_headers=None):
        self.federation_client = federation_client
        self.generic_headers = list(generic_headers or [])

    def do_request_sign(self, request, enforce_content_headers=True):
        return request


class _FakePEMRetriever:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeFederationClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.session_key_supplier = SimpleNamespace(get_key_pair=lambda: {"private": "priv"})

    def get_security_token(self):
        return "fed-token"


class _FakeSessionKeySupplier:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def _write_ref(base: Path, region="us-phoenix-1", tenancy="ocid1.tenancy.oc1..unit") -> Path:
    (base / "leaf.pem").write_text("LEAF", encoding="utf-8")
    (base / "key.pem").write_text("KEY", encoding="utf-8")
    (base / "int.pem").write_text("INT", encoding="utf-8")
    ref = base / "ref.json"
    ref.write_text(json.dumps({
        "leaf_cert_file": str(base / "leaf.pem"),
        "leaf_key_file": str(base / "key.pem"),
        "intermediate_cert_file": str(base / "int.pem"),
        "region": region,
        "tenancy_id": tenancy,
    }), encoding="utf-8")
    return ref


class TestInstancePrincipalDelegation(unittest.TestCase):
    def _make_session(self):
        s = SessionUtility.__new__(SessionUtility)
        s.workspace_id = 7
        s.workspace_name = "unit"
        s.workspace_directory_name = "7_unit"
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
        s._validate_pems = lambda *_a, **_k: None
        return s

    def _federation_patches(self):
        import contextlib
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(AUTH_MOD, "X509FederationClientBasedSecurityTokenSigner", _FakeX509Base))
        stack.enter_context(patch.object(AUTH_MOD, "PEMStringCertificateRetriever", _FakePEMRetriever))
        stack.enter_context(patch.object(AUTH_MOD, "X509FederationClient", _FakeFederationClient))
        stack.enter_context(patch.object(AUTH_MOD, "SessionKeySupplier", _FakeSessionKeySupplier))
        return stack

    def test_reference_file_with_delegation_token_file_stores_source(self):
        session = self._make_session()
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ref = _write_ref(base)
            tok = base / "delegation_token"
            tok.write_text("OBO.TOKEN.abc", encoding="utf-8")
            with self._federation_patches():
                rc = session.add_instance_profile_token("ip_deleg", {
                    "reference_file": str(ref),
                    "delegation_token_file": str(tok),
                })

        self.assertEqual(rc, 1)
        self.assertEqual(session.region, "us-phoenix-1")
        self.assertEqual(session.tenant_id, "ocid1.tenancy.oc1..unit")
        signer = session.credentials["signer"]
        self.assertIn("opc-obo-token", signer.generic_headers)
        req = SimpleNamespace(headers={})
        signer.do_request_sign(req)
        self.assertEqual(req.headers["opc-obo-token"], "OBO.TOKEN.abc")
        # stored under the instance-principal credtype, token kept as a SOURCE (file)
        stored = session.data_master.fetch_cred(7, "ip_deleg")
        self.assertEqual(stored["credtype"], "instance-principal")
        payload = json.loads(stored["session_creds"])
        self.assertEqual(payload["delegation_token_file"], str(tok))
        self.assertEqual(payload["delegation_token"], "")

    def test_reference_file_without_delegation_is_plain_instance_principal(self):
        session = self._make_session()
        with tempfile.TemporaryDirectory() as td:
            ref = _write_ref(Path(td))
            with self._federation_patches():
                rc = session.add_instance_profile_token("ip_plain", {"reference_file": str(ref)})
        self.assertEqual(rc, 1)
        # plain instance principal -> no obo header
        self.assertNotIn("opc-obo-token", session.credentials["signer"].generic_headers)
        payload = json.loads(session.data_master.fetch_cred(7, "ip_plain")["session_creds"])
        self.assertNotIn("delegation_token_file", payload)

    def test_inline_delegation_token_stored_inline(self):
        session = self._make_session()
        with tempfile.TemporaryDirectory() as td:
            ref = _write_ref(Path(td))
            with self._federation_patches():
                rc = session.add_instance_profile_token("ip_inline", {
                    "reference_file": str(ref), "delegation_token": "INLINE.OBO",
                })
        self.assertEqual(rc, 1)
        payload = json.loads(session.data_master.fetch_cred(7, "ip_inline")["session_creds"])
        self.assertEqual(payload["delegation_token"], "INLINE.OBO")
        self.assertEqual(payload["delegation_token_file"], "")

    def test_missing_mode_fails_even_with_delegation(self):
        session = self._make_session()
        with self._federation_patches():
            rc = session.add_instance_profile_token("ip_nomode", {"delegation_token": "X"})
        self.assertIsNone(rc)

    def test_on_host_with_delegation_uses_sdk_signer(self):
        session = self._make_session()
        session._detect_instance_region = lambda **_k: "us-phoenix-1"
        session._detect_instance_tenancy_ocid = lambda **_k: "ocid1.tenancy.oc1..host"
        captured = {}

        class _FakeSdkDelegationSigner:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        fake_oci = SimpleNamespace(auth=SimpleNamespace(signers=SimpleNamespace(InstancePrincipalsDelegationTokenSigner=_FakeSdkDelegationSigner)))
        with tempfile.TemporaryDirectory() as td:
            tok = Path(td) / "delegation_token"
            tok.write_text("HOST.OBO", encoding="utf-8")
            with patch.object(AUTH_MOD, "oci", fake_oci):
                rc = session.add_instance_profile_token("ip_host", {
                    "on_host": True, "delegation_token_file": str(tok),
                })
        self.assertEqual(rc, 1)
        self.assertEqual(captured.get("delegation_token"), "HOST.OBO")
        payload = json.loads(session.data_master.fetch_cred(7, "ip_host")["session_creds"])
        self.assertEqual(payload["mode"], "on-host")

    def test_session_tenancy_resolved_from_delegation_token(self):
        """The delegation session tenancy is resolved from the delegation token."""
        import base64 as _b64
        session = self._make_session()
        user_tenancy = "ocid1.tenancy.oc1..aaaaaaaauser"
        payload = _b64.urlsafe_b64encode(json.dumps(
            {"tenant": user_tenancy, "own": "ocid1.tenancy.oc1..aaaaaaaainstance", "exp": 9999999999}
        ).encode()).decode().rstrip("=")
        jwt = f"h.{payload}.s"
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ref = _write_ref(base, tenancy="ocid1.tenancy.oc1..aaaaaaaainstance")  # cert = instance tenancy
            tok = base / "delegation_token"
            tok.write_text(jwt, encoding="utf-8")
            with self._federation_patches():
                rc = session.add_instance_profile_token("ip_ten", {
                    "reference_file": str(ref), "delegation_token_file": str(tok),
                })
        self.assertEqual(rc, 1)
        # session targets the USER tenancy, not the instance cert tenancy
        self.assertEqual(session.tenant_id, user_tenancy)
        self.assertEqual(session.compartment_id, user_tenancy)
        self.assertEqual(session.credentials["config"]["tenancy"], user_tenancy)

    def test_reload_honors_stored_log_requests_flag_from_first_trace_line(self):
        """A credential reload (no explicit debug_http kwarg -- e.g. resume/
        set_active_creds) must still trace from its very FIRST _ipdbg call if the
        credential's own stored record has log_requests=true. The stored flag must
        be merged into self.debug_http before that first _ipdbg call fires, or a
        reload with a stored debug flag would silently drop that trace line."""
        session = self._make_session()
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ref = _write_ref(base)
            rec = CredRecord(credname="ip_trace", credtype="instance-principal", session_creds=json.dumps({
                "mode": "reference-file", "reference_file": str(ref),
                "region": "us-phoenix-1", "tenancy_id": "ocid1.tenancy.oc1..unit",
                "log_requests": True,
            }))
            with self._federation_patches():
                import io
                import contextlib
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = session._load_instance_profile_from_record(rec, force_refresh=True)
        self.assertEqual(rc, 1)
        self.assertIn("start _load_instance_profile_from_record", buf.getvalue())

    def test_force_refresh_rereads_rotated_delegation_token(self):
        session = self._make_session()
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ref = _write_ref(base)
            tok = base / "delegation_token"
            tok.write_text("OLD.OBO", encoding="utf-8")
            rec = CredRecord(credname="ip_rotate", credtype="instance-principal", session_creds=json.dumps({
                "mode": "reference-file", "reference_file": str(ref),
                "region": "us-phoenix-1", "tenancy_id": "ocid1.tenancy.oc1..unit",
                "delegation_token_file": str(tok), "delegation_token": "",
            }))
            tok.write_text("NEW.OBO", encoding="utf-8")  # Cloud Shell rotated the file
            with self._federation_patches():
                rc = session._load_instance_profile_from_record(rec, force_refresh=True)
        self.assertEqual(rc, 1)
        req = SimpleNamespace(headers={})
        session.credentials["signer"].do_request_sign(req)
        self.assertEqual(req.headers["opc-obo-token"], "NEW.OBO")


if __name__ == "__main__":
    unittest.main()
