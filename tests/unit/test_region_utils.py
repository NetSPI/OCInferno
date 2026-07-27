"""Region utilities: subscription awareness (caching + error detection) and
multi-region primitives (resolve_regions selector semantics + CompartmentScopedSession)."""
from __future__ import annotations

from types import SimpleNamespace

from ocinferno.core.utils import regions
from ocinferno.core.utils import regions as R
from ocinferno.core.utils.scoped_session import CompartmentScopedSession


# ---------------------------------------------------------------------------
# Subscription awareness: caching + not-subscribed error detection
# ---------------------------------------------------------------------------

class _Err(Exception):
    def __init__(self, status=None, code=None, message=""):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def test_not_subscribed_error_detection():
    assert regions.is_region_not_subscribed_error(_Err(code="RegionNotSupported"))
    assert regions.is_region_not_subscribed_error(_Err(message="Tenancy is not subscribed to this region"))
    assert regions.is_region_not_subscribed_error(_Err(message="Region is not enabled for tenancy"))
    # A plain 404 on a resource must NOT be treated as a subscription problem.
    assert not regions.is_region_not_subscribed_error(_Err(status=404, code="NotAuthorizedOrNotFound", message="bucket x not found"))
    assert not regions.is_region_not_subscribed_error(_Err(message="generic boom"))


def test_subscribed_regions_cached_and_fail_open(monkeypatch):
    calls = {"n": 0}

    def _fake_fetch(session, *, proxy=None):
        calls["n"] += 1
        return ["us-phoenix-1", "us-ashburn-1"]

    monkeypatch.setattr(regions, "fetch_subscribed_regions", _fake_fetch)
    session = SimpleNamespace()

    assert regions.subscribed_regions(session) == ["us-phoenix-1", "us-ashburn-1"]
    # Second call is served from the session cache (no re-fetch).
    assert regions.subscribed_regions(session) == ["us-phoenix-1", "us-ashburn-1"]
    assert calls["n"] == 1

    assert regions.is_region_subscribed(session, "us-phoenix-1")
    assert not regions.is_region_subscribed(session, "eu-frankfurt-1")

    # refresh=True re-fetches.
    regions.subscribed_regions(session, refresh=True)
    assert calls["n"] == 2


def test_unknown_subscription_set_does_not_block(monkeypatch):
    monkeypatch.setattr(regions, "fetch_subscribed_regions", lambda session, *, proxy=None: [])
    session = SimpleNamespace()
    # Empty/unknown set => fail-open, every region allowed.
    assert regions.is_region_subscribed(session, "any-region-1")
    assert not regions.should_skip_region(session, "any-region-1")


def test_runtime_unavailable_cache(monkeypatch):
    monkeypatch.setattr(regions, "fetch_subscribed_regions", lambda session, *, proxy=None: ["us-phoenix-1"])
    session = SimpleNamespace()

    assert not regions.region_unavailable(session, "us-phoenix-1")
    regions.mark_region_unavailable(session, "us-phoenix-1")
    assert regions.region_unavailable(session, "us-phoenix-1")
    # Even a subscribed region is skipped once marked unavailable at runtime.
    assert regions.should_skip_region(session, "us-phoenix-1")
    # And a non-subscribed region is skipped by the authoritative list.
    assert regions.should_skip_region(session, "eu-frankfurt-1")


# ---------------------------------------------------------------------------
# Multi-region primitives: resolve_regions + CompartmentScopedSession
# ---------------------------------------------------------------------------


def _session(current="us-ashburn-1", subscribed=("us-ashburn-1", "us-phoenix-1", "eu-frankfurt-1")):
    s = SimpleNamespace(config_current_default_region=current, region=current)
    # pre-seed the region cache so resolve_regions doesn't try a live API call
    s._region_cache = {"subscribed": list(subscribed), "unavailable": set()}
    return s


def test_default_and_current_resolve_to_current_region_only():
    s = _session()
    assert R.resolve_regions(s, None) == ["us-ashburn-1"]
    assert R.resolve_regions(s, "current") == ["us-ashburn-1"]
    assert R.resolve_regions(s, []) == ["us-ashburn-1"]


def test_all_resolves_to_subscribed():
    s = _session()
    assert R.resolve_regions(s, "all") == ["us-ashburn-1", "us-phoenix-1", "eu-frankfurt-1"]
    assert R.resolve_regions(s, ["all"]) == ["us-ashburn-1", "us-phoenix-1", "eu-frankfurt-1"]


def test_explicit_list_validated_against_subscription():
    s = _session()
    # csv, space, and list forms all normalize; unsubscribed regions are dropped
    assert R.resolve_regions(s, "us-phoenix-1,eu-frankfurt-1") == ["us-phoenix-1", "eu-frankfurt-1"]
    assert R.resolve_regions(s, ["us-phoenix-1", "ap-tokyo-1"]) == ["us-phoenix-1"]  # tokyo not subscribed


def test_unknown_region_falls_back_to_current():
    s = _session()
    assert R.resolve_regions(s, "ap-tokyo-1") == ["us-ashburn-1"]  # none valid -> current


def test_unknown_subscription_is_fail_open():
    # When the subscription list is unknown/empty, explicit regions are NOT filtered.
    s = _session(subscribed=())
    assert R.resolve_regions(s, "ap-tokyo-1,sa-saopaulo-1") == ["ap-tokyo-1", "sa-saopaulo-1"]


def test_region_scoped_session_overrides_region_locally():
    base = SimpleNamespace(
        compartment_id="ocid1.compartment.oc1..root",
        config_current_default_region="us-ashburn-1",
        region="us-ashburn-1",
        credentials={"config": {"region": "us-ashburn-1"}, "signer": None},
    )
    view = CompartmentScopedSession(base, "ocid1.compartment.oc1..child", "us-phoenix-1")

    # The view reports the scoped compartment + region...
    assert view.compartment_id == "ocid1.compartment.oc1..child"
    assert view.config_current_default_region == "us-phoenix-1"
    assert view.region == "us-phoenix-1"
    # ...while the shared base is untouched (isolation for concurrent region workers).
    assert base.compartment_id == "ocid1.compartment.oc1..root"
    assert base.config_current_default_region == "us-ashburn-1"


def test_region_scoped_session_without_region_is_unchanged():
    base = SimpleNamespace(compartment_id="root", config_current_default_region="us-ashburn-1")
    view = CompartmentScopedSession(base, "child")  # no region -> back-compat
    assert view.compartment_id == "child"
    # region not overridden -> delegates to base
    assert view.config_current_default_region == "us-ashburn-1"
