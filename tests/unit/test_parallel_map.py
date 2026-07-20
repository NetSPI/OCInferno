"""parallel_map must not let already-running worker threads keep executing past
its own return on ANY abnormal exit, not just KeyboardInterrupt -- e.g. if
executor.submit() itself raises mid dict-comprehension after some workers are
already running. Any exception must force a waiting shutdown so control never
returns while background threads are still touching shared state (the DB
connection/cursor) from another thread."""
from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from ocinferno.core.utils.parallel import cancel_requested, clear_cancel, parallel_map


class TestParallelMap(unittest.TestCase):
    def setUp(self):
        clear_cancel()

    def tearDown(self):
        # _CANCEL_EVENT is process-wide/module-level state -- never leak it into
        # other tests regardless of how this test exits.
        clear_cancel()

    def test_normal_completion_runs_every_worker(self):
        seen = []
        results = parallel_map(list(range(5)), lambda x: seen.append(x) or x * 2, threads=3, show_progress=False)
        self.assertEqual(sorted(seen), [0, 1, 2, 3, 4])
        self.assertEqual(results, [0, 2, 4, 6, 8])
        self.assertFalse(cancel_requested())

    def test_worker_exception_is_swallowed_as_none_not_propagated(self):
        def worker(x):
            if x == 2:
                raise ValueError("boom")
            return x

        results = parallel_map(list(range(4)), worker, threads=2, show_progress=False)
        self.assertEqual(results, [0, 1, None, 3])
        self.assertFalse(cancel_requested())

    def test_submit_time_exception_requests_cancel_and_reraises(self):
        """Simulates executor.submit() itself failing (not a worker exception) after
        some work is already queued -- must set the cancel flag (so the finally
        block's shutdown waits for in-flight workers) and must not swallow the
        exception."""
        real_submit = ThreadPoolExecutor.submit
        call_count = {"n": 0}

        def flaky_submit(self, fn, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise RuntimeError("submit exploded")
            return real_submit(self, fn, *args, **kwargs)

        with patch.object(ThreadPoolExecutor, "submit", flaky_submit):
            with self.assertRaises(RuntimeError):
                parallel_map(list(range(5)), lambda x: x, threads=3, show_progress=False)

        self.assertTrue(cancel_requested())


if __name__ == "__main__":
    unittest.main()
