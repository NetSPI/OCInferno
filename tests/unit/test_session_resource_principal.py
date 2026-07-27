from __future__ import annotations

import importlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.unit._session_helpers import (
    FakeDataMaster as _FakeDataMaster,
    FakeSigner as _FakeSigner,
    _import_session_module,
    jwt_with_tenancy as _jwt_with_tenancy,
)

SESSION_MOD = _import_session_module()
AUTH_MOD = importlib.import_module("ocinferno.core.auth")
SessionUtility = SESSION_MOD.SessionUtility
CredRecord = SESSION_MOD.CredRecord


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
            with patch.object(AUTH_MOD, "SecurityTokenSigner", _FakeSigner):
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

    def test_add_resource_profile_token_accepts_filepath_or_reference_file_alias(self):
        # `reference_file` and `filepath` are pure aliases for the same kwarg
        # (add_resource_profile_token treats them interchangeably).
        for dict_key, credname, region in (
            ("filepath", "rp_file", "us-ashburn-1"),
            ("reference_file", "rp_ref_alias", "us-chicago-1"),
        ):
            with self.subTest(dict_key=dict_key):
                session = self._make_session()
                tenancy = f"ocid1.tenancy.oc1..{dict_key}"
                token = _jwt_with_tenancy(tenancy)

                with tempfile.TemporaryDirectory() as td:
                    base = Path(td)
                    token_file = base / "rpst.txt"
                    key_file = base / "rp_key.pem"
                    ref_file = base / "rp.conf"

                    token_file.write_text(token, encoding="utf-8")
                    key_file.write_text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n", encoding="utf-8")
                    ref_file.write_text(
                        f"token_file={token_file}\nprivate_key_file={key_file}\nregion={region}\n",
                        encoding="utf-8",
                    )

                    with patch.object(SESSION_MOD.serialization, "load_pem_private_key", return_value=object()):
                        with patch.object(AUTH_MOD, "SecurityTokenSigner", _FakeSigner):
                            rc = session.add_resource_profile_token(credname, {dict_key: str(ref_file)})

                self.assertEqual(rc, 1)
                self.assertEqual(session.region, region)
                self.assertEqual(session.tenant_id, tenancy)
                stored = session.data_master.fetch_cred(11, credname)
                payload = json.loads(stored["session_creds"])
                self.assertTrue(payload.get("rpst_file"))
                self.assertTrue(payload.get("private_pem_file"))

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
                with patch.object(AUTH_MOD, "SecurityTokenSigner", _FakeSigner):
                    rc = session._load_resource_profile_from_record(rec, force_refresh=True)

        self.assertEqual(rc, 1)
        self.assertEqual(session.credentials["signer"].token, new_token)
        self.assertEqual(session.credentials_type, "resource-principal")


if __name__ == "__main__":
    unittest.main()
