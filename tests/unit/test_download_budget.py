#!/usr/bin/env python3
"""Unit tests for the per-download-unit wall-clock cap (DownloadBudget)."""
from __future__ import annotations

import time
import types

import pytest

from ocinferno.core.utils.download_budget import DownloadBudget


def _session(budget):
    return types.SimpleNamespace(download_time_budget=budget)


@pytest.mark.parametrize(
    "session_or_obj",
    [
        pytest.param(_session(0), id="zero-budget"),
        pytest.param(object(), id="missing-attr"),
        pytest.param(_session("not-an-int"), id="garbage-budget"),
    ],
)
def test_degrades_to_unlimited(session_or_obj):
    b = DownloadBudget(session_or_obj, label="x")
    assert b.budget == 0
    assert b.exceeded() is False
    assert b.remaining() == float("inf")


def test_not_exceeded_before_cap():
    b = DownloadBudget(_session(1000), label="x")
    assert b.exceeded() is False
    assert 0.0 < b.remaining() <= 1000.0


def test_exceeded_after_cap_and_announces_once(capsys):
    b = DownloadBudget(_session(1), label="my-unit")
    # Force the clock into the past so we're beyond the 1s cap.
    b._start = time.perf_counter() - 5.0
    assert b.exceeded() is True
    out = capsys.readouterr().out
    assert "[!]" in out and "my-unit" in out
    # Second call still True but does not re-announce.
    assert b.exceeded() is True
    assert capsys.readouterr().out == ""


def test_remaining_never_negative():
    b = DownloadBudget(_session(1), label="x")
    b._start = time.perf_counter() - 5.0
    assert b.remaining() == 0.0


def test_start_resets_clock():
    b = DownloadBudget(_session(1), label="x")
    b._start = time.perf_counter() - 5.0
    assert b.exceeded() is True
    b.start()
    assert b.exceeded() is False
