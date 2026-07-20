"""run_standard_enum_component: the standard list->get->print->save flow, and the
soft_skip_statuses option used by often-disabled services (e.g. Cloud Guard)."""
from __future__ import annotations

from types import SimpleNamespace

from ocinferno.core.utils.service_runtime import run_standard_enum_component


class _ServiceError(Exception):
    def __init__(self, status=None, code=None, message=""):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _session():
    return SimpleNamespace(compartment_id="ocid1.compartment.oc1..x", debug=False, individual_run_debug=False)


def test_happy_path_lists_and_counts():
    saved = {}
    res = run_standard_enum_component(
        user_args=[],
        session=_session(),
        component_key="widgets",
        list_rows=lambda cid: [{"id": "a"}, {"id": "b"}],
        save_rows_fn=lambda rows: saved.setdefault("rows", rows),
        print_columns=["id"],
        module_name="enum_x",
    )
    assert res["ok"] is True
    assert res["widgets"] == 2
    assert res["saved"] is True
    assert len(saved["rows"]) == 2


def test_non_authz_error_is_hard_failure(capsys):
    # A 500 is a genuine error (not the 401/403/404 authz-or-missing case) -> hard failure.
    res = run_standard_enum_component(
        user_args=[],
        session=_session(),
        component_key="widgets",
        list_rows=lambda cid: (_ for _ in ()).throw(_ServiceError(status=500, code="InternalError", message="boom")),
        print_columns=["id"],
        module_name="enum_x",
    )
    assert res["ok"] is False
    assert res["component"] == "widgets"
    assert "skipped" in capsys.readouterr().out  # prints the loud skip line


def test_403_404_soft_skip_by_default_and_visible(capsys):
    # By DEFAULT (401,403,404) are soft-skipped (denied/not-found), returned as empty-ok,
    # and PRINTED so the operator sees the API was attempted.
    for status in (401, 403, 404):
        res = run_standard_enum_component(
            user_args=[],
            session=_session(),
            component_key="widgets",
            list_rows=lambda cid: (_ for _ in ()).throw(_ServiceError(status=status, code="NotAuthorizedOrNotFound", message="d")),
            print_columns=["id"],
            module_name="enum_x",
        )
        assert res["ok"] is True and res["widgets"] == 0 and res["skipped"] is True
        out = capsys.readouterr().out
        assert "API attempted" in out and str(status) in out  # visible feedback


def test_empty_soft_skip_forces_hard_failure_on_404(capsys):
    # Passing () opts back into hard-erroring on 404.
    res = run_standard_enum_component(
        user_args=[],
        session=_session(),
        component_key="widgets",
        list_rows=lambda cid: (_ for _ in ()).throw(_ServiceError(status=404, code="NotFound", message="x")),
        print_columns=["id"],
        module_name="enum_x",
        soft_skip_statuses=(),
    )
    assert res["ok"] is False


def test_soft_skip_does_not_swallow_other_statuses():
    # A 500 is NOT in soft_skip_statuses -> still a hard failure.
    res = run_standard_enum_component(
        user_args=[],
        session=_session(),
        component_key="widgets",
        list_rows=lambda cid: (_ for _ in ()).throw(_ServiceError(status=500, code="X", message="server")),
        print_columns=["id"],
        module_name="enum_cloudguard",
        soft_skip_statuses=(401, 403, 404),
    )
    assert res["ok"] is False
