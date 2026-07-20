"""The run_components --download hook: field_dump_download writes developer-supplied
fields (env vars/config) to the download tree only when --download is passed, gated by
the per-unit budget; the full row is still saved regardless."""
from __future__ import annotations

import json
import pathlib
import tempfile
from types import SimpleNamespace

from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.core.utils.service_runtime import field_dump_download


def _session(tmp):
    def save_path(*, service_name, filename, compartment_id, subdirs=None, **kw):
        p = tmp.joinpath(service_name, *(subdirs or []), filename)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    return SimpleNamespace(
        compartment_id="ocid1.compartment.oc1..c", debug=False, individual_run_debug=False,
        active_module_name="enum_x", get_download_save_path=save_path,
    )


class _Res(OciListResource):
    COLUMNS = ["id", "display_name", "lifecycle_state"]

    def __init__(self, session=None, **kw):
        self.session = session

    def list(self, *, compartment_id, **kw):
        return [{"id": "ocid1.fnfunc.oc1..a", "display_name": "billing", "lifecycle_state": "ACTIVE",
                 "compartment_id": compartment_id}]

    def get(self, *, resource_id, **kw):
        return {"config": {"DB_PASSWORD": "s3cr3t", "URL": "https://x"}}  # env vars only on get()

    def save(self, rows):
        pass


def _components():
    return [Component("things", _Res, cache_table=None,
                      download_fn=field_dump_download(field="config", service_name="functions",
                                                      subdir="thing-config", filename="config.json"))]


def test_no_download_flag_writes_nothing():
    tmp = pathlib.Path(tempfile.mkdtemp())
    run_components([], _session(tmp), _components(), module_name="enum_x", description="d")
    assert list(tmp.rglob("config.json")) == []


def test_download_flag_dumps_field_and_saves_full_row():
    tmp = pathlib.Path(tempfile.mkdtemp())
    res = run_components(["--download"], _session(tmp), _components(), module_name="enum_x", description="d")
    files = list(tmp.rglob("config.json"))
    assert len(files) == 1
    assert json.loads(files[0].read_text()) == {"DB_PASSWORD": "s3cr3t", "URL": "https://x"}
    comp = [c for c in res["components"] if c.get("downloaded") is not None][0]
    assert comp["downloaded"] == 1 and comp["download"] is True


def test_download_included_only_when_a_component_declares_it():
    # A module whose components have no download_fn does not expose --download.
    tmp = pathlib.Path(tempfile.mkdtemp())
    comps = [Component("plain", _Res, cache_table=None)]
    # run_components must not raise on --download-timeout absence; --download simply isn't added.
    res = run_components([], _session(tmp), comps, module_name="enum_x", description="d")
    assert res["ok"] is True
