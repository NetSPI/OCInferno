"""Region-subscription awareness: caching + not-subscribed error detection."""
from __future__ import annotations

from types import SimpleNamespace

from ocinferno.core.utils import regions


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
