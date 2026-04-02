from __future__ import annotations

import sys
import types


def _install_oci_stub() -> None:
    class _DynamicStub:
        def __init__(self, name: str = "stub"):
            self._name = name

        def __getattr__(self, item: str):
            return _DynamicStub(f"{self._name}.{item}")

        def __call__(self, *args, **kwargs):
            return _DynamicStub(f"{self._name}()")

    class _FakeServiceError(Exception):
        pass

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
    exc_mod.ServiceError = _FakeServiceError

    pag_mod = sys.modules.get("oci.pagination")
    if pag_mod is None:
        pag_mod = types.ModuleType("oci.pagination")
        sys.modules["oci.pagination"] = pag_mod
    pag_mod.list_call_get_all_results = lambda fn, **kwargs: types.SimpleNamespace(data=fn(**kwargs))

    oci_mod.util = util_mod
    oci_mod.exceptions = exc_mod
    oci_mod.pagination = pag_mod
    oci_mod.retry = types.SimpleNamespace(DEFAULT_RETRY_STRATEGY=None)
    oci_mod.__getattr__ = lambda attr: _DynamicStub(f"oci.{attr}")


_install_oci_stub()


def test_enum_identity_help_includes_principal_lane_flags(capsys):
    import ocinferno.modules.identityclient.enumeration.enum_identity as mod

    try:
        mod._parse_args(["--help"])
        assert False, "expected --help to exit"
    except SystemExit as exc:
        assert int(getattr(exc, "code", 0)) == 0

    out = capsys.readouterr().out
    assert "--classic" in out
    assert "--idd" in out
    assert "--memberships" in out


def test_enum_identity_principals_classic_alias_runs_memberships_by_default(monkeypatch):
    import ocinferno.modules.identityclient.utilities.helpers as helpers

    calls = {"list_users": 0, "list_memberships": 0}

    class _FakeIdentityResourceClient:
        def __init__(self, session):
            self.session = session

        def list_users(self, *, compartment_id: str):
            calls["list_users"] += 1
            return [{"id": "ocid1.user.oc1..example", "name": "alice@example.com"}]

        def list_groups(self, *, compartment_id: str):
            return []

        def list_dynamic_groups(self, *, compartment_id: str):
            return []

        def list_memberships(self, *, compartment_id: str, user_id: str):
            calls["list_memberships"] += 1
            return [{"id": "m1", "user_id": user_id, "group_id": "g1", "lifecycle_state": "ACTIVE"}]

        def save_users(self, users):
            return None

        def save_groups(self, groups):
            return None

        def save_dynamic_groups(self, dynamic_groups):
            return None

        def save_memberships(self, memberships):
            return None

    monkeypatch.setattr(helpers, "IdentityResourceClient", _FakeIdentityResourceClient)

    session = types.SimpleNamespace(
        compartment_id="ocid1.compartment.oc1..example",
        tenant_id="ocid1.tenancy.oc1..example",
        debug=False,
        individual_run_debug=False,
    )

    resource = helpers.IdentityPrincipalsResource(session=session)
    result = resource.list(user_args=["--classic"])

    assert result.get("ok") is True
    assert int(result.get("classic_memberships", 0)) == 1
    assert calls["list_users"] == 1
    assert calls["list_memberships"] == 1


def test_enum_identity_principals_no_lane_flags_runs_both_idd_and_classic(monkeypatch):
    import ocinferno.modules.identityclient.utilities.helpers as helpers

    calls = {"idd_users": 0, "classic_users": 0}

    class _FakeIdentityResourceClient:
        def __init__(self, session):
            self.session = session

        def list_users(self, *, compartment_id: str):
            calls["classic_users"] += 1
            return [{"id": "ocid1.user.oc1..classic", "name": "classic-user"}]

        def list_groups(self, *, compartment_id: str):
            return []

        def list_dynamic_groups(self, *, compartment_id: str):
            return []

        def list_memberships(self, *, compartment_id: str, user_id: str):
            return []

        def save_users(self, users):
            return None

        def save_groups(self, groups):
            return None

        def save_dynamic_groups(self, dynamic_groups):
            return None

        def save_memberships(self, memberships):
            return None

    class _FakeIdentityDomainResourceClient:
        def __init__(self, session, service_endpoint: str):
            self.session = session
            self.service_endpoint = service_endpoint

        def list_identity_domain_users(self):
            calls["idd_users"] += 1
            return [{"id": "idd-user-1", "ocid": "ocid1.user.oc1..idd", "user_name": "idd-user"}]

        def list_identity_domain_groups(self):
            return []

        def list_identity_domain_dynamic_groups(self):
            return []

        def apply_domain_context(self, row, **kwargs):
            if isinstance(row, dict):
                row.setdefault("domain_ocid", kwargs.get("domain_id", ""))
                row.setdefault("identity_domain_name", kwargs.get("domain_name", ""))

        def save_idd_users(self, rows):
            return None

        def save_idd_groups(self, rows):
            return None

        def save_idd_dynamic_groups(self, rows):
            return None

        def save_idd_memberships(self, rows):
            return None

    monkeypatch.setattr(helpers, "IdentityResourceClient", _FakeIdentityResourceClient)
    monkeypatch.setattr(helpers, "IdentityDomainResourceClient", _FakeIdentityDomainResourceClient)

    session = types.SimpleNamespace(
        compartment_id="ocid1.compartment.oc1..example",
        tenant_id="ocid1.tenancy.oc1..example",
        debug=False,
        individual_run_debug=False,
    )

    resource = helpers.IdentityPrincipalsResource(session=session)

    def _fake_load_domains(*, all_saved_domains: bool = False, domain_filter: str = ""):
        _ = (all_saved_domains, domain_filter)
        return (
            session.compartment_id,
            [
                {
                    "id": "ocid1.domain.oc1..example",
                    "display_name": "Default",
                    "url": "https://idcs.example.com",
                    "compartment_id": session.compartment_id,
                }
            ],
            "db",
        )

    monkeypatch.setattr(resource, "_load_domains_from_cache", _fake_load_domains)

    result = resource.list(user_args=[])

    assert result.get("ok") is True
    assert int(result.get("idd_users", 0)) == 1
    assert int(result.get("classic_users", 0)) == 1
    assert calls["idd_users"] == 1
    assert calls["classic_users"] == 1
