from __future__ import annotations

import importlib
import sys
import types
import unittest


def _install_oci_stub_with_base_client() -> None:
    class _DynamicStub:
        def __init__(self, name: str = "stub"):
            self._name = name

        def __getattr__(self, item: str):
            return _DynamicStub(f"{self._name}.{item}")

        def __call__(self, *args, **kwargs):
            return _DynamicStub(f"{self._name}()")

        def __iter__(self):
            return iter(())

    class _FakeServiceError(Exception):
        def __init__(self, status: int, message: str, request_endpoint: str = ""):
            super().__init__(message)
            self.status = status
            self.request_endpoint = request_endpoint
            self.opc_request_id = f"req-{status}"

    class _FakeResponse:
        def __init__(self, status: int = 200, headers: dict | None = None):
            self.status = status
            self.headers = headers or {}

    class BaseClient:
        call_count = 0

        def __init__(self):
            self.endpoint = "https://identity.us-phoenix-1.oraclecloud.com"

        def call_api(self, *args, **kwargs):
            BaseClient.call_count += 1
            if BaseClient.call_count < 3:
                raise _FakeServiceError(
                    status=429,
                    message="TooManyRequests",
                    request_endpoint="GET https://identity.us-phoenix-1.oraclecloud.com/20160918/users/ocid1.user.oc1..abc",
                )
            return _FakeResponse(status=200, headers={"opc-request-id": "req-success"})

    oci_mod = types.ModuleType("oci")
    auth_mod = types.ModuleType("oci.auth")
    cert_mod = types.ModuleType("oci.auth.certificate_retriever")
    fed_mod = types.ModuleType("oci.auth.federation_client")
    sks_mod = types.ModuleType("oci.auth.session_key_supplier")
    sign_mod = types.ModuleType("oci.auth.signers")
    cfg_mod = types.ModuleType("oci.config")
    exc_mod = types.ModuleType("oci.exceptions")
    util_mod = types.ModuleType("oci.util")
    base_client_mod = types.ModuleType("oci.base_client")

    cert_mod.PEMStringCertificateRetriever = type("PEMStringCertificateRetriever", (), {})
    fed_mod.X509FederationClient = type("X509FederationClient", (), {})
    sks_mod.SessionKeySupplier = type("SessionKeySupplier", (), {})
    sign_mod.SecurityTokenSigner = type("SecurityTokenSigner", (), {})
    sign_mod.X509FederationClientBasedSecurityTokenSigner = type("X509FederationClientBasedSecurityTokenSigner", (), {})
    cfg_mod.from_file = lambda **_kwargs: {}
    cfg_mod.validate_config = lambda _cfg: True
    exc_mod.ConfigFileNotFound = type("ConfigFileNotFound", (Exception,), {})
    exc_mod.InvalidKeyFilePath = type("InvalidKeyFilePath", (Exception,), {})
    exc_mod.ProfileNotFound = type("ProfileNotFound", (Exception,), {})
    util_mod.to_dict = lambda obj: obj
    base_client_mod.BaseClient = BaseClient

    auth_mod.certificate_retriever = cert_mod
    auth_mod.federation_client = fed_mod
    auth_mod.session_key_supplier = sks_mod
    auth_mod.signers = sign_mod

    oci_mod.auth = auth_mod
    oci_mod.config = cfg_mod
    oci_mod.exceptions = exc_mod
    oci_mod.util = util_mod
    oci_mod.base_client = base_client_mod
    oci_mod.retry = types.SimpleNamespace(DEFAULT_RETRY_STRATEGY=None)
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
    sys.modules["oci.base_client"] = base_client_mod


class TestSessionRetryAndForensics(unittest.TestCase):
    def test_global_oci_hook_retries_and_records_attempt_metadata(self):
        _install_oci_stub_with_base_client()
        sys.modules.pop("ocinferno.core.session", None)
        session_mod = importlib.import_module("ocinferno.core.session")
        SessionUtility = session_mod.SessionUtility
        BaseClient = importlib.import_module("oci.base_client").BaseClient

        SessionUtility._GLOBAL_OCI_PATCHED = False
        SessionUtility._GLOBAL_OCI_OWNER = None
        BaseClient.call_count = 0

        logs: list[dict] = []

        class _Logger:
            enabled = True

            def record(self, **kwargs):
                logs.append(kwargs)

        s = SessionUtility.__new__(SessionUtility)
        s.api_logger = _Logger()
        s.credname = "credA"
        s.active_module_name = "enum_identity_users"
        s.config_rate_limit_seconds = 0.0
        s.config_http_retry_enabled = True
        s.config_http_retry_max_attempts = 3
        s.config_http_retry_base_delay_seconds = 0.0
        s.config_http_retry_max_delay_seconds = 0.0
        s.config_http_retry_jitter_seconds = 0.0
        s.config_http_retry_statuses = [429]

        s._install_global_oci_api_logging_hook()

        client = BaseClient()
        resp = client.call_api(
            resource_path="/20160918/users/{userId}",
            method="GET",
            operation_name="GetUser",
            endpoint=client.endpoint,
            path_params={"userId": "ocid1.user.oc1..abc"},
            query_params={"limit": 10},
            header_params={"Authorization": "Bearer secret"},
        )

        self.assertEqual(resp.status, 200)
        self.assertEqual(BaseClient.call_count, 3)
        self.assertEqual(len(logs), 3)
        self.assertEqual(logs[0]["event_type"], "oci_api_retry")
        self.assertEqual(logs[0]["retry_attempt"], 1)
        self.assertTrue(logs[0]["retry_scheduled"])
        self.assertEqual(logs[1]["event_type"], "oci_api_retry")
        self.assertEqual(logs[1]["retry_attempt"], 2)
        self.assertTrue(logs[1]["retry_scheduled"])
        self.assertEqual(logs[2]["event_type"], "oci_api_call")
        self.assertEqual(logs[2]["retry_attempt"], 3)
        self.assertFalse(logs[2]["retry_scheduled"])
        self.assertEqual(logs[2]["retry_max"], 3)
        self.assertEqual(logs[2]["module_run"], "enum_identity_users")
        self.assertIn("/20160918/users/ocid1.user.oc1..abc", logs[2]["url"])


if __name__ == "__main__":
    unittest.main()
