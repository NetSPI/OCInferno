from __future__ import annotations

from types import SimpleNamespace

from ocinferno.cli import module_actions


def test_module_parse_meta_detects_wrapper_save_for_enum_identity():
    module_actions._module_parse_meta.cache_clear()
    meta = module_actions._module_parse_meta("ocinferno.modules.identityclient.enumeration.enum_identity")

    assert "--save" in meta.supported_common_flags
    # enum_identity sets include_get=False in parse_wrapper_args(...)
    assert "--get" not in meta.supported_common_flags


class _CaptureModule:
    def __init__(self) -> None:
        self.calls = []

    def run_module(self, user_args, session):
        self.calls.append(list(user_args))
        return {"ok": True}


def test_enum_identity_auto_save_passthrough(monkeypatch):
    module_actions._module_parse_meta.cache_clear()
    capture = _CaptureModule()
    real_import = module_actions.importlib.import_module

    def _fake_import(name, package=None):
        if name == "ocinferno.modules.identityclient.enumeration.enum_identity":
            return capture
        return real_import(name, package)

    monkeypatch.setattr(module_actions.importlib, "import_module", _fake_import)

    session = SimpleNamespace(
        credentials={"config": {"region": "us-phoenix-1"}, "signer": None},
        compartment_id="ocid1.compartment.oc1..example",
        global_compartment_list=[{"name": "example", "compartment_id": "ocid1.compartment.oc1..example"}],
        config_module_auto_save=True,
        active_module_name="",
        debug=False,
        individual_run_debug=False,
        add_proxy_config=lambda *args, **kwargs: None,
    )

    rc = module_actions.interact_with_module(
        session,
        "ocinferno.modules/identityclient/enumeration/enum_identity",
        ["--current-cid"],
    )

    assert rc == 0
    assert len(capture.calls) == 1
    assert "--save" in capture.calls[0]
