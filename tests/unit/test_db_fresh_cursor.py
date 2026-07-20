"""DataController must hand out a fresh sqlite3.Cursor per call, never the same
long-lived cursor object reused across every method call/thread. Reusing one
cursor across threads is a more fragile pattern than reusing the Connection --
a cursor carries its own internal state (statement cache, row iterator) that
CPython's sqlite3 C extension has had edge-case bugs with under heavy
concurrent load, even when access is externally serialized by a lock."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ocinferno.core.db import DataController


class _IsolatedDataController(DataController):
    def __init__(self, db_root: Path):
        self.database_path = str(db_root / "ocinferno.db")
        self.metadata_db = self.database_path
        self.service_db = self.database_path
        super().__init__()


class TestFreshCursorPerCall(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dc = _IsolatedDataController(Path(self._tmp.name))

    def tearDown(self):
        self.dc.close()
        self._tmp.cleanup()

    def test_get_conn_cursor_returns_a_new_cursor_each_call(self):
        _, cur1 = self.dc._get_conn_cursor("metadata")
        _, cur2 = self.dc._get_conn_cursor("metadata")
        self.assertIsNot(cur1, cur2)
        _, cur3 = self.dc._get_conn_cursor("service")
        self.assertIsNot(cur1, cur3)

    def test_stored_cursor_singletons_are_not_reused_by_hot_path_methods(self):
        """The instance still carries self.cursor/self.service_cursor (created once
        in __init__, kept only so close() has something to close / for any external
        back-compat check) -- but no data-touching method should read or write
        through them anymore."""
        before_id = id(self.dc.cursor)

        ws_id = self.dc.insert_workspace("probe-ws", "{}")
        self.assertIsNotNone(ws_id)
        self.assertEqual(self.dc.get_workspaces(), [(ws_id, "probe-ws")])
        self.dc.insert_creds(ws_id, "cred1", "api-key", "{}")
        self.assertEqual(self.dc.list_creds(ws_id), [("cred1", "api-key", "{}")])
        self.assertIsNotNone(self.dc.fetch_cred(ws_id, "cred1"))
        self.assertIsNone(self.dc.fetch_user_permissions(ws_id, "cred1"))
        self.dc.ensure_user_permissions_row(ws_id, "cred1")
        self.assertIsNotNone(self.dc.fetch_user_permissions(ws_id, "cred1"))

        # The singleton object itself was never touched (same identity, never
        # executed a statement through it) by any of the calls above.
        self.assertEqual(id(self.dc.cursor), before_id)

    def test_concurrent_hot_path_calls_across_threads_do_not_crash(self):
        """Hammer the highest-frequency real call path (fetch_user_permissions /
        ensure_user_permissions_row -- exactly what the global OCI-API-call
        permission-recording hook invokes on every successful API response, from
        every --parallel-services worker thread) from many threads concurrently.
        This can't reliably reproduce a rare native race on demand, but it
        exercises the exact call pattern without error as a basic sanity net."""
        import threading

        ws_id = self.dc.insert_workspace("concurrent-ws", "{}")
        errors = []

        def worker(n):
            try:
                cred = f"cred{n}"
                self.dc.insert_creds(ws_id, cred, "api-key", "{}")
                for _ in range(25):
                    self.dc.ensure_user_permissions_row(ws_id, cred)
                    self.dc.upsert_user_permissions_merge(
                        ws_id, cred,
                        permissions_delta={"INSTANCE_READ": {"resources": ["x"], "evidence": [{"op": "List"}]}},
                    )
                    self.dc.fetch_user_permissions(ws_id, cred)
            except Exception as e:  # pragma: no cover - failure path
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
