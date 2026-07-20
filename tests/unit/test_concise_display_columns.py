"""concise_display_columns: stdout tables show a concise 3-4 column subset while the
full COLUMNS set is still saved to the DB. --wide restores all columns."""
from __future__ import annotations

from ocinferno.core.utils.service_runtime import concise_display_columns


def test_returns_all_when_already_small():
    cols = ["id", "display_name", "lifecycle_state"]
    assert concise_display_columns(cols) == cols


def test_caps_at_limit_and_prefers_name_state_salient():
    cols = [
        "id", "display_name", "lifecycle_state", "time_created", "compartment_id",
        "primary_endpoint_ip_address", "primary_fqdn", "node_count", "software_version",
    ]
    picked = concise_display_columns(cols)
    assert len(picked) == 4
    assert picked[0] == "display_name"          # human name wins the identity slot
    assert picked[1] == "lifecycle_state"        # state next
    # remaining slots come from salient exposure/type fields, NOT compartment_id
    assert "compartment_id" not in picked
    assert any(c in picked for c in ("primary_fqdn", "primary_endpoint_ip_address"))


def test_falls_back_to_id_when_no_name():
    cols = ["id", "lifecycle_state", "severity", "cve_reference", "time_created", "compartment_id"]
    picked = concise_display_columns(cols)
    assert picked[0] == "id"                      # no name -> id takes identity slot
    assert "severity" in picked and "cve_reference" in picked


def test_custom_limit():
    cols = ["display_name", "lifecycle_state", "fqdn", "version", "shape", "time_created"]
    assert len(concise_display_columns(cols, limit=3)) == 3


def test_run_components_prints_concise_and_wide_prints_all(capsys):
    # A resource with many columns: default enumeration prints the concise subset,
    # --wide prints them all; saved rows always carry the full set.
    from types import SimpleNamespace

    from ocinferno.core.resource import OciListResource
    from ocinferno.core.utils.enum_framework import Component, run_components

    saved = {}

    class _FakeRes(OciListResource):
        COLUMNS = ["id", "display_name", "lifecycle_state", "primary_fqdn",
                   "node_count", "software_version", "subnet_id", "compartment_id"]

        def __init__(self, session=None, **kw):
            self.session = session

        def list(self, *, compartment_id, **kw):
            return [{"id": "ocid1.x.oc1..aaa", "display_name": "res1", "lifecycle_state": "ACTIVE",
                     "primary_fqdn": "r.example.com", "node_count": "3", "software_version": "7.0",
                     "subnet_id": "ocid1.subnet.oc1..bbb", "compartment_id": compartment_id}]

        def save(self, rows):
            saved["rows"] = rows

    comps = [Component("things", _FakeRes, cache_table=None)]
    sess = SimpleNamespace(compartment_id="ocid1.compartment.oc1..c", debug=False,
                           individual_run_debug=False, active_module_name="enum_fake")

    run_components([], sess, comps, module_name="enum_fake", description="d")
    concise_out = capsys.readouterr().out
    assert "Display_name" in concise_out and "Primary_fqdn" in concise_out
    assert "Subnet_id" not in concise_out          # trimmed from stdout (not a salient col)
    # but the FULL row was saved
    assert set(saved["rows"][0].keys()) >= set(_FakeRes.COLUMNS)

    run_components(["--wide"], sess, comps, module_name="enum_fake", description="d")
    wide_out = capsys.readouterr().out
    assert "Software_version" in wide_out and "Subnet_id" in wide_out
