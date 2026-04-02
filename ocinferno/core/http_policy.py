from __future__ import annotations

import random
import threading
import time
from typing import Any, Callable, Dict, List


class HttpPolicyService:
    """
    Centralized HTTP policy controls:
      - global request pacing (rate limit)
      - retry classification + backoff delay calculation
    """

    def __init__(
        self,
        *,
        get_rate_limit_seconds: Callable[[], float],
        get_rate_limit_jitter_seconds: Callable[[], float] | None = None,
    ):
        self._get_rate_limit_seconds = get_rate_limit_seconds
        self._get_rate_limit_jitter_seconds = get_rate_limit_jitter_seconds
        self._lock = threading.Lock()
        self._last_request_ts: float = 0.0

    def wait_for_rate_limit(self) -> None:
        delay = 0.0
        try:
            delay = float(self._get_rate_limit_seconds() or 0.0)
        except Exception:
            delay = 0.0
        jitter = 0.0
        if self._get_rate_limit_jitter_seconds is not None:
            try:
                jitter = max(0.0, float(self._get_rate_limit_jitter_seconds() or 0.0))
            except Exception:
                jitter = 0.0
        if delay <= 0 and jitter <= 0:
            return
        with self._lock:
            now = time.monotonic()
            last = self._last_request_ts
            target_gap = max(0.0, delay) + (random.uniform(0.0, jitter) if jitter > 0 else 0.0)
            if last > 0:
                wait = target_gap - (now - last)
                if wait > 0:
                    time.sleep(wait)
                    now = time.monotonic()
            self._last_request_ts = now

    def reset_rate_limit_window(self) -> None:
        with self._lock:
            self._last_request_ts = 0.0

    @staticmethod
    def exception_status_code(exc: Exception) -> int:
        try:
            return int(getattr(exc, "status", 0) or 0)
        except Exception:
            return 0

    @classmethod
    def is_retryable_exception(cls, exc: Exception, retry_statuses: List[int]) -> bool:
        status = cls.exception_status_code(exc)
        if status and status in (retry_statuses or []):
            return True
        marker = f"{type(exc).__name__}: {exc}".lower()
        hints = ("timeout", "temporarily unavailable", "connection reset", "connection aborted", "service unavailable")
        return any(h in marker for h in hints)

    @staticmethod
    def compute_retry_delay(*, attempt: int, base_delay: float, max_delay: float, jitter: float) -> float:
        exp_delay = float(base_delay or 0.0) * (2 ** max(0, int(attempt) - 1))
        bounded = min(exp_delay, float(max_delay or 0.0) if float(max_delay or 0.0) > 0 else exp_delay)
        if float(jitter or 0.0) > 0:
            bounded += random.uniform(0, float(jitter))
        return max(0.0, bounded)

    @staticmethod
    def default_retry_policy(
        *,
        enabled: bool,
        max_attempts: int,
        base_delay_seconds: float,
        max_delay_seconds: float,
        jitter_seconds: float,
        statuses: List[int],
    ) -> Dict[str, Any]:
        return {
            "enabled": bool(enabled),
            "max_attempts": int(max_attempts),
            "base_delay_seconds": float(base_delay_seconds),
            "max_delay_seconds": float(max_delay_seconds),
            "jitter_seconds": float(jitter_seconds),
            "statuses": list(statuses or []),
        }
