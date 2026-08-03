"""Thread-pool fan-out + cooperative cancellation.

``parallel_map`` runs a worker across items on a bounded pool. A single Ctrl+C
sets a process-wide cancel flag that every fan-out loop honors, so the pool stops
launching NEW work immediately (rather than draining its whole queue) and the
in-flight workers finish before control returns.

THREADING INVARIANT: OCInferno's DataController is lock-serialized
(check_same_thread=False + a process-wide RLock), so worker-thread DB writes are
safe here. Workers may enumerate + save directly.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable, List

_CANCEL_EVENT = threading.Event()


def request_cancel() -> None:
    """Signal all cooperative fan-out loops to stop launching new work ASAP."""
    _CANCEL_EVENT.set()


def clear_cancel() -> None:
    """Reset the cancel flag at the start of a fresh run."""
    _CANCEL_EVENT.clear()


def cancel_requested() -> bool:
    """True once request_cancel() fired (until clear_cancel())."""
    return _CANCEL_EVENT.is_set()


def parallel_map(
    items: Iterable[Any],
    worker: Callable[[Any], Any],
    *,
    threads: int = 3,
    progress_label: str | None = None,
    show_progress: bool = True,
) -> List[Any]:
    """Apply ``worker`` to each item across a thread pool, preserving input order.

    A failing worker yields ``None`` in that slot (errors swallowed) so one bad
    unit doesn't sink the batch. Pool size = min(threads, 32, len(items)); a size
    of 1 runs serially. Honors the process-wide cancel flag (one Ctrl+C stops it).
    """
    entries = list(items or [])
    if not entries:
        return []

    label = str(progress_label or "Progress").strip() or "Progress"
    total = len(entries)

    def _progress_token(item: Any) -> str:
        token = str(item)
        return token if len(token) <= 64 else token[:61] + "..."

    def _should_emit(completed: int) -> bool:
        if total <= 50:
            return True
        if completed in (1, total):
            return True
        step = max(5, total // 20)
        return completed % step == 0

    if show_progress:
        print(f"[*] {label}: starting {total} work item(s)")

    try:
        parsed_threads = int(threads)
    except Exception:
        parsed_threads = 3
    if parsed_threads < 1:
        parsed_threads = 1
    worker_count = min(parsed_threads, 32, len(entries))

    if worker_count <= 1:
        output: List[Any] = []
        for idx, item in enumerate(entries, start=1):
            if cancel_requested():
                break
            output.append(worker(item))
            if show_progress and _should_emit(idx):
                print(f"[*] {label}: {idx}/{total} completed (last={_progress_token(item)})")
        # Pad with None to match the parallel path's shape (same length as input).
        while len(output) < len(entries):
            output.append(None)
        return output

    results: List[Any] = [None] * len(entries)
    executor = ThreadPoolExecutor(max_workers=worker_count)
    try:
        future_to_context = {executor.submit(worker, item): (idx, item) for idx, item in enumerate(entries)}
        completed = 0
        for future in as_completed(future_to_context):
            idx, item = future_to_context[future]
            try:
                results[idx] = future.result()
            except Exception:
                results[idx] = None
            finally:
                completed += 1
                if show_progress and _should_emit(completed):
                    print(f"[*] {label}: {completed}/{total} completed (last={_progress_token(item)})")
            if cancel_requested():
                break
    except BaseException:
        # Any abnormal exit -- KeyboardInterrupt, or e.g. executor.submit() raising
        # mid dict-comprehension after some workers are already running -- must not
        # let already-submitted workers keep executing past this function's return.
        # Force the shutdown below to wait for them (cancel_requested() gates the
        # wait= below) instead of returning control while they're still touching
        # shared state (the DB connection/cursor, etc.) from another thread.
        request_cancel()
        raise
    finally:
        # cancel_futures drops still-queued items; on the cancel path we wait for the
        # <=worker_count in-flight calls so nothing prints after control returns.
        executor.shutdown(wait=cancel_requested(), cancel_futures=True)
    return results
