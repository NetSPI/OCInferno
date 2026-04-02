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

from ocinferno.modules.objectstorage.enumeration import enum_objectstorage as mod


class _Namespaces:
    COLUMNS = ["compartment_id", "namespace"]

    def __init__(self, session):
        self.session = session

    def list(self, *, compartment_id: str):
        return [{"compartment_id": compartment_id, "namespace": "ns1"}]

    def get(self, *, resource_id: str):
        return {}

    def save(self, rows):
        return None


class _Buckets:
    COLUMNS = ["namespace", "name"]

    def __init__(self, session):
        self.session = session

    def resolve_namespaces(self, *, namespace_args):
        raise RuntimeError("simulated bucket namespace resolution failure")

    def list(self, *, compartment_id: str, namespaces):
        return []

    def get(self, *, resource_id: str, namespace: str):
        return {}

    def save(self, rows):
        return None


class _Objects:
    COLUMNS = ["bucket_name", "namespace", "name"]

    def __init__(self, session):
        self.session = session

    def resolve_bucket_rows(self, *, compartment_id: str, namespaces, buckets):
        return []

    def list(self, **kwargs):
        return []

    def get(self, **kwargs):
        return {}

    def save(self, rows):
        return None

    def download(self, **kwargs):
        return True


def test_enum_objectstorage_component_failure_does_not_abort_other_components(monkeypatch):
    monkeypatch.setattr(mod, "ObjectStorageNamespacesResource", _Namespaces)
    monkeypatch.setattr(mod, "ObjectStorageBucketsResource", _Buckets)
    monkeypatch.setattr(mod, "ObjectStorageObjectsResource", _Objects)

    session = types.SimpleNamespace(
        compartment_id="ocid1.compartment.oc1..example",
        region="us-phoenix-1",
        OUTPUT_DIR_NAMES={"downloads": "downloads"},
        get_workspace_output_root=lambda mkdir=False: None,
        debug=False,
        individual_run_debug=False,
        active_module_name="enum_objectstorage",
        get_resource_fields=lambda *args, **kwargs: [],
    )

    out = mod.run_module([], session)
    components = out.get("components") or []

    ns = [c for c in components if isinstance(c, dict) and c.get("namespaces") is not None]
    bucket_fail = [c for c in components if isinstance(c, dict) and c.get("component") == "buckets"]
    objs = [c for c in components if isinstance(c, dict) and c.get("objects") is not None]

    assert ns and ns[0].get("ok") is True
    assert bucket_fail and bucket_fail[0].get("ok") is False
    assert objs and objs[0].get("ok") is True
