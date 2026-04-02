from __future__ import annotations

from types import SimpleNamespace

from ocinferno.cli import module_actions


class _CaptureModule:
    def __init__(self) -> None:
        self.calls = []

    def run_module(self, user_args, session):
        self.calls.append(list(user_args))
        return {"ok": True}


def _session(compartment_id: str, rows):
    return SimpleNamespace(
        credentials={"config": {"region": "us-phoenix-1"}, "signer": None},
        compartment_id=compartment_id,
        global_compartment_list=list(rows),
        config_module_auto_save=False,
        active_module_name="",
        debug=False,
        individual_run_debug=False,
        add_proxy_config=lambda *args, **kwargs: None,
    )


def _install_import_stub(monkeypatch, capture_module: _CaptureModule):
    real_import = module_actions.importlib.import_module

    def _fake_import(name, package=None):
        if name == "ocinferno.modules.everything.enumeration.enum_all":
            return capture_module
        return real_import(name, package)

    monkeypatch.setattr(module_actions.importlib, "import_module", _fake_import)


def test_enum_all_current_scope_forces_no_recursive(monkeypatch):
    tenancy = "ocid1.tenancy.oc1..example"
    rows = [
        {"name": "tenant", "compartment_id": tenancy},
        {"name": "child", "compartment_id": "ocid1.compartment.oc1..child"},
    ]
    session = _session(tenancy, rows)
    capture = _CaptureModule()
    _install_import_stub(monkeypatch, capture)
    monkeypatch.setattr(module_actions.UtilityTools, "ask_all_or_current_with_preview", lambda *_args, **_kwargs: "current")

    rc = module_actions.interact_with_module(
        session,
        "ocinferno.modules/everything/enumeration/enum_all",
        ["--download"],
    )

    assert rc == 0
    assert len(capture.calls) == 1
    assert "--download" in capture.calls[0]
    assert "--no-recursive-compartments" in capture.calls[0]
    assert session.target_root_cids == [tenancy]


def test_enum_all_download_tokens_passthrough(monkeypatch):
    tenancy = "ocid1.tenancy.oc1..example"
    rows = [
        {"name": "tenant", "compartment_id": tenancy},
        {"name": "child", "compartment_id": "ocid1.compartment.oc1..child"},
    ]
    session = _session(tenancy, rows)
    capture = _CaptureModule()
    _install_import_stub(monkeypatch, capture)
    monkeypatch.setattr(module_actions.UtilityTools, "ask_all_or_current_with_preview", lambda *_args, **_kwargs: "current")

    rc = module_actions.interact_with_module(
        session,
        "ocinferno.modules/everything/enumeration/enum_all",
        ["--download", "buckets", "api_specs"],
    )

    assert rc == 0
    assert len(capture.calls) == 1
    assert "--download" in capture.calls[0]
    assert "buckets" in capture.calls[0]
    assert "api_specs" in capture.calls[0]


def test_enum_all_all_scope_keeps_recursive_default(monkeypatch):
    tenancy = "ocid1.tenancy.oc1..example"
    rows = [
        {"name": "tenant", "compartment_id": tenancy},
        {"name": "child", "compartment_id": "ocid1.compartment.oc1..child"},
    ]
    session = _session(tenancy, rows)
    capture = _CaptureModule()
    _install_import_stub(monkeypatch, capture)
    monkeypatch.setattr(module_actions.UtilityTools, "ask_all_or_current_with_preview", lambda *_args, **_kwargs: "all")

    rc = module_actions.interact_with_module(
        session,
        "ocinferno.modules/everything/enumeration/enum_all",
        [],
    )

    assert rc == 0
    assert len(capture.calls) == 1
    assert "--no-recursive-compartments" not in capture.calls[0]
    assert session.target_root_cids == ["__ALL_DISCOVERED__"]


def test_enum_all_current_cid_selector_forces_no_recursive(monkeypatch):
    compartment = "ocid1.compartment.oc1..example"
    rows = [{"name": "single", "compartment_id": compartment}]
    session = _session(compartment, rows)
    capture = _CaptureModule()
    _install_import_stub(monkeypatch, capture)

    rc = module_actions.interact_with_module(
        session,
        "ocinferno.modules/everything/enumeration/enum_all",
        ["--current-cid"],
    )

    assert rc == 0
    assert len(capture.calls) == 1
    assert "--no-recursive-compartments" in capture.calls[0]
    assert session.target_root_cids == [compartment]


def test_enum_all_implicit_current_does_not_force_no_recursive(monkeypatch):
    tenancy = "ocid1.tenancy.oc1..example"
    rows = [{"name": "tenant", "compartment_id": tenancy}]
    session = _session(tenancy, rows)
    capture = _CaptureModule()
    _install_import_stub(monkeypatch, capture)

    rc = module_actions.interact_with_module(
        session,
        "ocinferno.modules/everything/enumeration/enum_all",
        ["--comp"],
    )

    assert rc == 0
    assert len(capture.calls) == 1
    assert "--no-recursive-compartments" not in capture.calls[0]
    assert "--comp" in capture.calls[0]
