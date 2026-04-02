from __future__ import annotations

from types import SimpleNamespace

from ocinferno.modules.identityclient.enumeration import enum_comp


def test_enum_comp_get_root_failure_does_not_stop_listing(monkeypatch):
    calls = {
        "list_compartments": 0,
    }
    captured = {
        "rows": [],
    }

    class _FakeOps:
        def __init__(self, session):
            self.session = session

        @staticmethod
        def is_tenancy_root(root: str) -> bool:
            return root.startswith("ocid1.tenancy.")

        def get_compartment(self, *, compartment_id: str):
            if compartment_id.startswith("ocid1.tenancy."):
                raise RuntimeError("simulated get root failure")
            return {
                "id": compartment_id,
                "name": "child-from-get",
                "lifecycle_state": "ACTIVE",
            }

        def list_compartments(self, *, compartment_id: str, lifecycle_state: str, subtree: bool):
            calls["list_compartments"] += 1
            assert lifecycle_state == "ACTIVE"
            assert subtree is True
            return [
                {
                    "id": "ocid1.compartment.oc1..childaaaa",
                    "name": "child-from-list",
                    "lifecycle_state": "ACTIVE",
                }
            ]

    def _capture_print_results(rows, **_kwargs):
        captured["rows"] = list(rows or [])

    monkeypatch.setattr(enum_comp, "IdentityResourceClient", _FakeOps)
    monkeypatch.setattr(enum_comp, "print_results_table", _capture_print_results)

    session = SimpleNamespace(compartment_id="ocid1.tenancy.oc1..rootaaaa", debug=False)
    rc = enum_comp.run_module(["--recursive", "--get-all-comps"], session)

    assert rc == 0
    assert calls["list_compartments"] == 1
    assert any(r.get("id") == "ocid1.compartment.oc1..childaaaa" for r in captured["rows"])
