from __future__ import annotations

import importlib
import sys
import types


class _LocalServiceError(Exception):
    def __init__(
        self,
        *,
        status: int = 500,
        code: str = "ServiceError",
        message: str = "service error",
        opc_request_id: str | None = None,
        request_endpoint: str | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.opc_request_id = opc_request_id
        self.request_endpoint = request_endpoint


def _install_oci_stub() -> None:
    oci_mod = sys.modules.get("oci")
    if oci_mod is None:
        oci_mod = types.ModuleType("oci")
        sys.modules["oci"] = oci_mod

    util_mod = sys.modules.get("oci.util")
    if util_mod is None:
        util_mod = types.ModuleType("oci.util")
        sys.modules["oci.util"] = util_mod
    util_mod.to_dict = lambda obj: obj

    exc_mod = sys.modules.get("oci.exceptions")
    if exc_mod is None:
        exc_mod = types.ModuleType("oci.exceptions")
        sys.modules["oci.exceptions"] = exc_mod
    # Force deterministic exception type for this test module even when real OCI
    # SDK modules were imported earlier in the same test process.
    exc_mod.ServiceError = _LocalServiceError

    oci_mod.util = util_mod
    oci_mod.exceptions = exc_mod


_install_oci_stub()

import ocinferno.modules.objectstorage.utilities.helpers as objectstorage_helpers
objectstorage_helpers = importlib.reload(objectstorage_helpers)

from ocinferno.modules.objectstorage.utilities.helpers import ObjectStorageNamespacesResource


class _Response:
    def __init__(self, data: str):
        self.data = data
        self.headers = {}


class _Client:
    def __init__(self, *, scoped_error: Exception | None = None, unscoped_error: Exception | None = None):
        self.scoped_error = scoped_error
        self.unscoped_error = unscoped_error
        self.calls: list[tuple[str, str | None]] = []

    def get_namespace(self, compartment_id: str | None = None):
        if compartment_id is None:
            self.calls.append(("unscoped", None))
            if self.unscoped_error is not None:
                raise self.unscoped_error
            return _Response("ns-unscoped")
        self.calls.append(("scoped", compartment_id))
        if self.scoped_error is not None:
            raise self.scoped_error
        return _Response("ns-scoped")


def _svc_error(status: int, code: str, message: str):
    _install_oci_stub()
    helper_oci = getattr(objectstorage_helpers, "oci", None)
    helper_exc = getattr(helper_oci, "exceptions", None) if helper_oci is not None else None
    cls = getattr(helper_exc, "ServiceError", None)
    if cls is None:
        cls = _LocalServiceError
        if helper_exc is not None:
            helper_exc.ServiceError = cls
    return cls(status=status, code=code, message=message)


def test_fetch_live_namespace_uses_scoped_call_by_default():
    session = types.SimpleNamespace(
        tenant_id="ocid1.tenancy.oc1..tenantA",
        compartment_id="ocid1.compartment.oc1..childA",
        credentials={"config": {"tenancy": "ocid1.tenancy.oc1..tenantA"}},
    )
    client = _Client()

    got = ObjectStorageNamespacesResource.fetch_live_namespace(
        client=client,
        session=session,
        explicit_compartment_id="ocid1.compartment.oc1..childA",
    )

    assert got == "ns-scoped"
    assert client.calls == [("scoped", "ocid1.compartment.oc1..childA")]


def test_fetch_live_namespace_falls_back_to_unscoped_when_same_tenancy():
    session = types.SimpleNamespace(
        tenant_id="ocid1.tenancy.oc1..tenantA",
        compartment_id="ocid1.compartment.oc1..childA",
        credentials={"config": {"tenancy": "ocid1.tenancy.oc1..tenantA"}},
        global_compartment_list=[
            {"compartment_id": "ocid1.compartment.oc1..childA", "parent_compartment_id": "ocid1.tenancy.oc1..tenantA"},
            {"compartment_id": "ocid1.tenancy.oc1..tenantA", "parent_compartment_id": "N/A"},
        ],
    )
    client = _Client()

    got = ObjectStorageNamespacesResource.fetch_live_namespace(
        client=client,
        session=session,
        explicit_compartment_id="ocid1.compartment.oc1..childA",
    )

    assert got == "ns-unscoped"
    assert client.calls == [("unscoped", None)]


def test_fetch_live_namespace_tries_scoped_after_unscoped_fails():
    unscoped_err = _svc_error(404, "NotAuthorizedOrNotFound", "unscoped denied")
    session = types.SimpleNamespace(
        tenant_id="ocid1.tenancy.oc1..tenantA",
        compartment_id="ocid1.compartment.oc1..childA",
        credentials={"config": {"tenancy": "ocid1.tenancy.oc1..tenantA"}},
        global_compartment_list=[
            {"compartment_id": "ocid1.compartment.oc1..childA", "parent_compartment_id": "ocid1.tenancy.oc1..tenantA"},
            {"compartment_id": "ocid1.tenancy.oc1..tenantA", "parent_compartment_id": "N/A"},
        ],
    )
    client = _Client(unscoped_error=unscoped_err)

    got = ObjectStorageNamespacesResource.fetch_live_namespace(
        client=client,
        session=session,
        explicit_compartment_id="ocid1.compartment.oc1..childA",
    )

    assert got == "ns-scoped"
    assert client.calls == [
        ("unscoped", None),
        ("scoped", "ocid1.compartment.oc1..childA"),
    ]


def test_fetch_live_namespace_unscoped_allowed_even_if_session_tenant_differs():
    session = types.SimpleNamespace(
        tenant_id="ocid1.tenancy.oc1..differentTenant",
        compartment_id="ocid1.compartment.oc1..childA",
        credentials={"config": {"tenancy": "ocid1.tenancy.oc1..tenantA"}},
        global_compartment_list=[
            {"compartment_id": "ocid1.compartment.oc1..childA", "parent_compartment_id": "ocid1.tenancy.oc1..tenantA"},
            {"compartment_id": "ocid1.tenancy.oc1..tenantA", "parent_compartment_id": "N/A"},
        ],
    )
    client = _Client()

    got = ObjectStorageNamespacesResource.fetch_live_namespace(
        client=client,
        session=session,
        explicit_compartment_id="ocid1.compartment.oc1..childA",
    )

    assert got == "ns-unscoped"
    assert client.calls == [("unscoped", None)]


def test_fetch_live_namespace_does_not_fallback_when_tenancy_mismatch():
    scoped_err = _svc_error(404, "CompartmentIdNotFound", "compartment not found")
    session = types.SimpleNamespace(
        tenant_id="ocid1.tenancy.oc1..tenantA",
        compartment_id="ocid1.compartment.oc1..childB",
        credentials={"config": {"tenancy": "ocid1.tenancy.oc1..tenantB"}},
    )
    client = _Client(scoped_error=scoped_err)

    try:
        ObjectStorageNamespacesResource.fetch_live_namespace(
            client=client,
            session=session,
            explicit_compartment_id="ocid1.compartment.oc1..childB",
        )
        assert False, "expected RuntimeError"
    except RuntimeError as err:
        assert "compartment-scoped call" in str(err)
        assert "request.compartment_id=ocid1.compartment.oc1..childB" in str(err)
        assert "caller_tenant_id=ocid1.tenancy.oc1..tenantB" in str(err)

    assert client.calls == [("scoped", "ocid1.compartment.oc1..childB")]
