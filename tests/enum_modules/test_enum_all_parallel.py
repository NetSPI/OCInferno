"""Parallel enum_all: fan-out, resumable ledger, cooperative cancel, and the
multi-region (region, compartment, module) unit expansion.

These exercise the parallel machinery in isolation (the ledger helpers +
``_run_execution_plan_parallel``) with an in-memory fake DataController, so no
network or real SQLite is involved.
"""
from __future__ import annotations

import threading

from tests.enum_modules.harness import import_module, runtime_session, stub_optional_dependencies

MODULE = "ocinferno.modules.everything.enumeration.enum_all"


class _FakeDataMaster:
    """Minimal stand-in for DataController: just the two ledger methods."""

    def __init__(self):
        self.rows = {}  # (run_id, region, compartment_id, module) -> row dict
        self._lock = threading.Lock()

    def save_dict_row(self, db, table_name, row, on_conflict="replace", **kwargs):
        key = (row.get("run_id"), row.get("region"), row.get("compartment_id"), row.get("module"))
        with self._lock:
            self.rows[key] = dict(row)
        return True

    def fetch_column_from_table(self, db, table_name, columns=None, where=None, as_dict=False):
        where = where or {}
        out = []
        with self._lock:
            values = list(self.rows.values())
        for r in values:
            if all(str(r.get(k)) == str(v) for k, v in where.items()):
                if isinstance(columns, list):
                    out.append(tuple(r.get(c) for c in columns))
                else:
                    out.append(r.get(columns))
        return out


def _session_with_ledger():
    session = runtime_session()
    session.data_master = _FakeDataMaster()
    session.workspace_id = 1
    return session


def _plan(modules, service="logging"):
    # execution_plan is a list of (service_name, should_run, [module dotted names]).
    # Default to a REGIONAL service ("logging"); "identity" is global (home-only).
    return [(service, True, list(modules))]


def test_parallel_runs_all_units_and_records_ledger():
    with stub_optional_dependencies():
        mod = import_module(MODULE)
        session = _session_with_ledger()
        args = mod._parse_args(["--modules", "logging", "--parallel-services", "3"])

        calls = []
        lock = threading.Lock()

        def _fake_run_other(sess, user_args, module_name):
            with lock:
                calls.append((sess.compartment_id, module_name))
            return {"ok": True}

        mod._run_other_module = _fake_run_other

        targets = ["ocid1.compartment.oc1..a", "ocid1.compartment.oc1..b"]
        plan = _plan(["modA", "modB"])

        mod.clear_cancel()
        mod._run_execution_plan_parallel(
            session, args, targets, plan,
            download_all=False, module_download_extras=None,
            run_id="tok-1", threads=3, skip_units=set(),
            scan_regions=[""], home_region=None,
        )

    # 2 compartments x 2 modules = 4 units, each scoped to its own compartment.
    assert len(calls) == 4
    assert set(calls) == {
        ("ocid1.compartment.oc1..a", "modA"), ("ocid1.compartment.oc1..a", "modB"),
        ("ocid1.compartment.oc1..b", "modA"), ("ocid1.compartment.oc1..b", "modB"),
    }
    # All 4 recorded done in the ledger.
    done = mod._ledger_done_units(session, "tok-1")
    assert len(done) == 4


def test_resume_skips_completed_units():
    with stub_optional_dependencies():
        mod = import_module(MODULE)
        session = _session_with_ledger()
        args = mod._parse_args(["--modules", "logging", "--parallel-services", "2", "--resume", "tok-9"])

        targets = ["ocid1.compartment.oc1..a", "ocid1.compartment.oc1..b"]
        plan = _plan(["modA"])

        # Pre-mark compartment A / modA as done.
        mod._ledger_mark(session, "tok-9", "", "ocid1.compartment.oc1..a", "modA", "done")

        calls = []
        mod._run_other_module = lambda sess, ua, mn: calls.append((sess.compartment_id, mn))

        skip = mod._ledger_done_units(session, "tok-9")
        mod.clear_cancel()
        mod._run_execution_plan_parallel(
            session, args, targets, plan,
            download_all=False, module_download_extras=None,
            run_id="tok-9", threads=2, skip_units=skip,
            scan_regions=[""], home_region=None,
        )

    # Only the un-done compartment B ran.
    assert calls == [("ocid1.compartment.oc1..b", "modA")]


def test_cancel_stops_launching_new_units():
    with stub_optional_dependencies():
        mod = import_module(MODULE)
        session = _session_with_ledger()
        args = mod._parse_args(["--modules", "logging", "--parallel-services", "1"])

        targets = [f"ocid1.compartment.oc1..c{i}" for i in range(10)]
        plan = _plan(["modA"])

        calls = []

        def _fake_run_other(sess, ua, mn):
            calls.append(sess.compartment_id)
            mod.request_cancel()  # trip the cooperative cancel after the first unit
            return {"ok": True}

        mod._run_other_module = _fake_run_other

        mod.clear_cancel()
        # threads=1 => serial; cancel after unit 1 should stop the rest.
        mod._run_execution_plan_parallel(
            session, args, targets, plan,
            download_all=False, module_download_extras=None,
            run_id="tok-c", threads=1, skip_units=set(),
            scan_regions=[""], home_region=None,
        )
        mod.clear_cancel()

    assert len(calls) < len(targets)


def test_list_tokens_aggregates_progress():
    with stub_optional_dependencies():
        mod = import_module(MODULE)
        session = _session_with_ledger()
        mod._ledger_mark(session, "tok-A", "", "c1", "modA", "done")
        mod._ledger_mark(session, "tok-A", "", "c1", "modB", "done")
        mod._ledger_mark(session, "tok-B", "", "c1", "modA", "done")

        tokens = mod._ledger_list_tokens(session)

    by_id = {t["run_id"]: t for t in tokens}
    assert by_id["tok-A"]["done"] == 2
    assert by_id["tok-B"]["done"] == 1


def test_failed_unit_recorded_and_not_marked_done():
    with stub_optional_dependencies():
        mod = import_module(MODULE)
        session = _session_with_ledger()
        args = mod._parse_args(["--modules", "logging", "--parallel-services", "2"])

        targets = ["ocid1.compartment.oc1..ok", "ocid1.compartment.oc1..boom"]
        plan = _plan(["modA"])

        def _fake_run_other(sess, ua, mn):
            if sess.compartment_id.endswith("boom"):
                raise RuntimeError("kaboom")
            return {"ok": True}

        mod._run_other_module = _fake_run_other

        mod.clear_cancel()
        mod._run_execution_plan_parallel(
            session, args, targets, plan,
            download_all=False, module_download_extras=None,
            run_id="tok-f", threads=2, skip_units=set(),
            scan_regions=[""], home_region=None,
        )

        # Only the successful unit is "done"; the failed one is NOT (so --resume re-runs it).
        done = mod._ledger_done_units(session, "tok-f")
        assert mod._unit_key("", "ocid1.compartment.oc1..ok", "modA") in done
        assert mod._unit_key("", "ocid1.compartment.oc1..boom", "modA") not in done

        # --list-tokens surfaces the failure + the error summary is captured.
        rec = {t["run_id"]: t for t in mod._ledger_list_tokens(session)}["tok-f"]
        assert rec["failed"] == 1 and rec["done"] == 1
    failed_row = session.data_master.rows[("tok-f", "", "ocid1.compartment.oc1..boom", "modA")]
    assert failed_row["status"] == "failed" and "kaboom" in failed_row["error"]


# ---- Multi-region unit expansion ------------------------------------------------

def test_multiregion_doubles_regional_units_and_keys_by_region():
    with stub_optional_dependencies():
        mod = import_module(MODULE)
        session = _session_with_ledger()
        args = mod._parse_args(["--modules", "logging", "--parallel-services", "3"])

        calls = []
        lock = threading.Lock()

        def _fake_run_other(sess, ua, mn):
            with lock:
                # config_current_default_region is overridden per region by the scoped view
                calls.append((sess.config_current_default_region, sess.compartment_id, mn))
            return {"ok": True}

        mod._run_other_module = _fake_run_other

        targets = ["ocid1.compartment.oc1..a"]
        plan = _plan(["modA"])  # "logging" == regional

        mod.clear_cancel()
        mod._run_execution_plan_parallel(
            session, args, targets, plan,
            download_all=False, module_download_extras=None,
            run_id="tok-mr", threads=3, skip_units=set(),
            scan_regions=["us-ashburn-1", "us-phoenix-1"], home_region="us-ashburn-1",
        )

    # 1 compartment x 1 module x 2 regions == 2 units, one per region.
    regions_seen = {c[0] for c in calls}
    assert regions_seen == {"us-ashburn-1", "us-phoenix-1"}
    assert len(calls) == 2
    # Ledger units are keyed by region -> both survive without collision.
    done = mod._ledger_done_units(session, "tok-mr")
    assert mod._unit_key("us-ashburn-1", "ocid1.compartment.oc1..a", "modA") in done
    assert mod._unit_key("us-phoenix-1", "ocid1.compartment.oc1..a", "modA") in done


def test_multiregion_global_service_runs_home_region_only():
    with stub_optional_dependencies():
        mod = import_module(MODULE)
        session = _session_with_ledger()
        args = mod._parse_args(["--modules", "identity", "--parallel-services", "2"])

        calls = []
        lock = threading.Lock()
        mod._run_other_module = lambda sess, ua, mn: (
            lock.acquire(), calls.append(sess.config_current_default_region), lock.release()
        )

        targets = ["ocid1.compartment.oc1..a"]
        plan = _plan(["modIAM"], service="identity")  # global service

        mod.clear_cancel()
        mod._run_execution_plan_parallel(
            session, args, targets, plan,
            download_all=False, module_download_extras=None,
            run_id="tok-g", threads=2, skip_units=set(),
            scan_regions=["us-ashburn-1", "us-phoenix-1"], home_region="us-ashburn-1",
        )

    # Global service runs ONCE, only in the home region.
    assert calls == ["us-ashburn-1"]
