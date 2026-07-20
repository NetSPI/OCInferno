from __future__ import annotations

import sys
import types


def _install_oci_stub() -> None:
    # Only stub when the real SDK is genuinely not installed -- unconditionally
    # installing a fake module here would permanently shadow the real `oci` for the
    # rest of the pytest session for any other test file that needs it (collection
    # order dependent; see the analogous oci_lexer_parser fix elsewhere in tests/).
    try:
        import oci  # noqa: F401
        return
    except ImportError:
        pass
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


class _Pars:
    COLUMNS = ["namespace", "bucket_name", "id", "name", "access_type", "object_name"]

    def __init__(self, session):
        self.session = session

    def list(self, *, namespace: str, bucket_name: str):
        return [{"namespace": namespace, "bucket_name": bucket_name, "id": "par1", "name": "leak"}]

    def save(self, rows):
        return None


class _BucketsWithGet:
    COLUMNS = ["namespace", "name", "kms_key_id", "get_run"]

    def __init__(self, session):
        self.session = session
        self.saved_rows = None

    def resolve_namespaces(self, *, namespace_args):
        return ["ns1"]

    def list(self, *, compartment_id: str, namespaces):
        return [{"namespace": "ns1", "name": "bucket1"}]

    def get(self, *, resource_id: str, namespace: str):
        # Simulates a real GetBucket response: no kms_key_id, no get_run key.
        return {"namespace": namespace, "name": resource_id, "kms_key_id": ""}

    def save(self, rows):
        self.saved_rows = rows


def test_enum_objectstorage_buckets_get_stamps_get_run(monkeypatch):
    # Regression: config_audit's OBJECT_STORAGE_BUCKET_CMK_NOT_SET_UP check only
    # fires when a bucket row carries get_run=True (to avoid false-positiving on
    # list-only rows, which never carry kms_key_id at all). enum_objectstorage's
    # buckets --get loop must stamp this, mirroring every other --get-capable
    # enum module (enum_core_compute, enum_core_network, enum_core_block_storage,
    # enum_logs).
    buckets_stub = _BucketsWithGet(session=None)
    monkeypatch.setattr(mod, "ObjectStorageNamespacesResource", _Namespaces)
    monkeypatch.setattr(mod, "ObjectStorageBucketsResource", lambda session: buckets_stub)
    monkeypatch.setattr(mod, "ObjectStorageObjectsResource", _Objects)
    monkeypatch.setattr(mod, "ObjectStoragePreauthenticatedRequestsResource", _Pars)

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

    mod.run_module(["--buckets", "--get"], session)

    assert buckets_stub.saved_rows
    assert all(row.get("get_run") is True for row in buckets_stub.saved_rows)


def test_enum_objectstorage_component_failure_does_not_abort_other_components(monkeypatch):
    monkeypatch.setattr(mod, "ObjectStorageNamespacesResource", _Namespaces)
    monkeypatch.setattr(mod, "ObjectStorageBucketsResource", _Buckets)
    monkeypatch.setattr(mod, "ObjectStorageObjectsResource", _Objects)
    monkeypatch.setattr(mod, "ObjectStoragePreauthenticatedRequestsResource", _Pars)

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

    pars = [c for c in components if isinstance(c, dict) and c.get("pars") is not None]

    assert ns and ns[0].get("ok") is True
    assert bucket_fail and bucket_fail[0].get("ok") is False
    assert objs and objs[0].get("ok") is True
    # New PARs component runs independently too (bucket failure didn't abort it).
    assert pars and pars[0].get("ok") is True
