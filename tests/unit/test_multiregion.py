"""Multi-region primitives: resolve_regions selector semantics + the region-scoped
session view that retargets clients without touching the shared base session."""
from __future__ import annotations

from types import SimpleNamespace

from ocinferno.core.utils import regions as R
from ocinferno.core.utils.scoped_session import CompartmentScopedSession


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
