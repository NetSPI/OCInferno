#!/usr/bin/env python3
"""Per-download-unit wall-clock cap for enum downloads.

A tiny, dependency-light (``time`` only) helper: create ONE per download UNIT (a
whole download type like "vault secret bundles", OR a finer unit like a single
object-storage bucket) at the START of that unit's download loop, then call
:meth:`exceeded` before each
item. Once the unit has run longer than the session's ``download_time_budget``
seconds (set by the module's ``--download-timeout`` flag; ``0``/unset =
unlimited), :meth:`exceeded` returns ``True`` -- printing a one-time ``[!]``
notice -- so the caller skips the REST of that unit and moves on.

The clock resets per instance, so a fast unit isn't penalized by a slow one
(object storage makes this per-bucket; most services make it per-type). The
read path is thread-safe (``perf_counter``); the one-time notice is best-effort
under concurrency (a rare double-print is harmless).

This class is intentionally best-effort: it NEVER raises and MUST NOT break a
normal (untimed, ``budget=0``) run -- a missing/garbage ``download_time_budget``
degrades to "unlimited".
"""

from __future__ import annotations

from time import perf_counter
from typing import Any


class DownloadBudget:
    """Wall-clock cap for one download unit; ``exceeded()`` gates the loop."""

    def __init__(self, session: Any, *, label: str) -> None:
        try:
            self.budget = int(getattr(session, "download_time_budget", 0) or 0)
        except (TypeError, ValueError):
            self.budget = 0
        self.label = str(label or "downloads")
        self._start = perf_counter()
        self._announced = False

    def start(self) -> None:
        """Reset the clock (rarely needed; the timer starts at construction)."""
        self._start = perf_counter()
        self._announced = False

    def elapsed(self) -> float:
        """Seconds since this budget's clock started."""
        return perf_counter() - self._start

    def remaining(self) -> float:
        """Seconds left before the cap (``inf`` when unlimited; never negative)."""
        if self.budget <= 0:
            return float("inf")
        return max(0.0, self.budget - self.elapsed())

    def exceeded(self) -> bool:
        """True once the unit has run past its cap; prints a one-time ``[!]`` notice.

        Always ``False`` when the budget is unlimited (``<= 0``). Best-effort and
        never raises.
        """
        if self.budget <= 0:
            return False
        if self.elapsed() <= self.budget:
            return False
        if not self._announced:
            self._announced = True
            try:
                from ocinferno.core.console import UtilityTools

                print(
                    f"{UtilityTools.YELLOW}[!] Download time budget ({self.budget}s) reached for "
                    f"{self.label}; skipping the rest and moving on.{UtilityTools.RESET}"
                )
            except Exception:
                print(
                    f"[!] Download time budget ({self.budget}s) reached for "
                    f"{self.label}; skipping the rest and moving on."
                )
        return True
