from __future__ import annotations

import sys
import types


def _install_oci_stub() -> None:
    if "oci" in sys.modules:
        return
    oci_mod = types.ModuleType("oci")
    util_mod = types.ModuleType("oci.util")
    util_mod.to_dict = lambda obj: obj
    oci_mod.util = util_mod
    sys.modules["oci"] = oci_mod
    sys.modules["oci.util"] = util_mod


_install_oci_stub()

from ocinferno.cli.module_actions import _execute_module_for_target
from ocinferno.cli import module_actions
from ocinferno.core.contracts import ConfigError, ErrorCode
from ocinferno.core.contracts import OperationResult


class _FakeSession:
    active_module_name = ""
    compartment_id = ""


class _FakeModule:
    @staticmethod
    def run_module(*_args, **_kwargs):
        raise ValueError("boom")


def test_operation_result_from_exception_with_typed_error():
    exc = ConfigError(code=ErrorCode.CONFIG_VALUE_INVALID, message="bad value", details={"key": "rate_limit_seconds"})
    res = OperationResult.from_exception(exc)
    assert res.ok is False
    assert res.error_code == ErrorCode.CONFIG_VALUE_INVALID
    assert res.message == "bad value"
    assert res.data.get("key") == "rate_limit_seconds"


def test_operation_result_from_exception_with_generic_error():
    res = OperationResult.from_exception(ValueError("oops"), fallback_code=ErrorCode.UNKNOWN)
    assert res.ok is False
    assert res.error_code == ErrorCode.UNKNOWN
    assert "ValueError: oops" in res.message


def test_module_execution_failure_returns_machine_code():
    session = _FakeSession()
    result = _execute_module_for_target(
        session,
        _FakeModule(),
        mod_short="unit_mod",
        target_cid="ocid1.compartment.oc1..test",
        passthrough_args=[],
    )
    assert result.ok is False
    assert result.error_code == ErrorCode.MODULE_EXECUTION_FAILED


def test_operation_result_from_exception_service_error_is_concise():
    class ServiceError(Exception):
        target_service = "identity"
        operation_name = "get_compartment"
        status = 404
        code = "NotAuthorizedOrNotFound"
        message = "Authorization failed or requested resource not found"

    res = OperationResult.from_exception(ServiceError("ignored"), fallback_code=ErrorCode.MODULE_EXECUTION_FAILED)
    assert res.ok is False
    assert res.error_code == ErrorCode.MODULE_EXECUTION_FAILED
    assert "ServiceError(" in res.message
    assert "service=identity" in res.message
    assert "operation=get_compartment" in res.message
    assert "status=404" in res.message
    assert "code=NotAuthorizedOrNotFound" in res.message


def test_interact_with_module_continues_other_targets_after_failure(monkeypatch):
    class _FlakyModule:
        def __init__(self):
            self.calls = []

        def run_module(self, user_args, session):
            self.calls.append((list(user_args), getattr(session, "compartment_id", "")))
            if len(self.calls) == 1:
                raise RuntimeError("first target fails")
            return {"ok": True}

    flaky = _FlakyModule()
    real_import = module_actions.importlib.import_module

    def _fake_import(name, package=None):
        if name == "ocinferno.modules.fake.enumeration.enum_fake":
            return flaky
        return real_import(name, package)

    monkeypatch.setattr(module_actions.importlib, "import_module", _fake_import)

    session = types.SimpleNamespace(
        credentials={"config": {"region": "us-phoenix-1"}, "signer": None},
        compartment_id="ocid1.compartment.oc1..root",
        global_compartment_list=[],
        config_module_auto_save=False,
        active_module_name="",
        debug=False,
        individual_run_debug=False,
        add_proxy_config=lambda *args, **kwargs: None,
    )

    rc = module_actions.interact_with_module(
        session,
        "ocinferno.modules/fake/enumeration/enum_fake",
        [
            "--cids",
            "ocid1.compartment.oc1..target1",
            "ocid1.compartment.oc1..target2",
        ],
    )

    assert rc == -1
    assert len(flaky.calls) == 2
    assert flaky.calls[0][1] == "ocid1.compartment.oc1..target1"
    assert flaky.calls[1][1] == "ocid1.compartment.oc1..target2"
