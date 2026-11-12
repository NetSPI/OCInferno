"""Tests for the scaled-back config_audit framework + the shipped example auditor.

process_config_check is intentionally minimal: it ships ONE example auditor
(ExamplePublicBucketAuditor) as a template. These tests cover the framework
(ServiceAuditor.get_rows caching, run_audit, print_audit_report) and the example,
so the extension point stays exercised. Operator-authored auditors are out of scope.
"""
import unittest

try:
    from ocinferno.modules.everything.utilities.config_audit import (
        DEFAULT_SERVICE_AUDITORS,
        ExamplePublicBucketAuditor,
        ServiceAuditor,
        print_audit_report,
        run_audit,
    )
    _CONFIG_AUDIT_AVAILABLE = True
except Exception:  # pragma: no cover - optional deps (oci) may be missing
    _CONFIG_AUDIT_AVAILABLE = False


class _Session:
    """Minimal stand-in exposing get_resource_fields over in-memory tables."""

    def __init__(self, tables):
        self._tables = tables
        self.calls = 0

    def get_resource_fields(self, table_name, where_conditions=None, columns=None):
        self.calls += 1
        rows = list(self._tables.get(table_name, []))
        if where_conditions:
            rows = [
                r for r in rows
                if all(r.get(k) == v for k, v in where_conditions.items())
            ]
        return rows


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit not importable")
class TestServiceAuditorFramework(unittest.TestCase):

    def test_get_rows_caches_per_table_and_conditions(self):
        session = _Session({"t": [{"id": "a"}, {"id": "b"}]})
        auditor = ServiceAuditor(session=session)
        first = auditor.get_rows("t")
        second = auditor.get_rows("t")
        self.assertEqual(first, [{"id": "a"}, {"id": "b"}])
        self.assertIs(first, second)                 # same cached list object
        self.assertEqual(session.calls, 1)           # only one DB hit
        # A different where-condition key is cached separately.
        auditor.get_rows("t", where_conditions={"id": "a"})
        self.assertEqual(session.calls, 2)


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit not importable")
class TestExamplePublicBucketAuditor(unittest.TestCase):

    def _run(self, buckets):
        session = _Session({"object_storage_buckets": buckets})
        return ExamplePublicBucketAuditor(session=session).run_checks()

    def test_flags_public_bucket(self):
        res = self._run([{
            "id": "ocid1.bucket.oc1..pub", "name": "pub",
            "compartment_id": "ocid1.compartment.oc1..c",
            "public_access_type": "ObjectRead",
        }])
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f.issue_code, "OBJECT_STORAGE_PUBLIC_BUCKET")
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.location["entity_id"], "ocid1.bucket.oc1..pub")

    def test_no_finding_for_private_bucket(self):
        res = self._run([{
            "id": "ocid1.bucket.oc1..priv", "name": "priv",
            "compartment_id": "ocid1.compartment.oc1..c",
            "public_access_type": "NoPublicAccess",
        }])
        self.assertEqual(res.findings, [])

    def test_no_finding_when_field_absent(self):
        res = self._run([{"id": "ocid1.bucket.oc1..x", "name": "x"}])
        self.assertEqual(res.findings, [])


@unittest.skipUnless(_CONFIG_AUDIT_AVAILABLE, "config_audit not importable")
class TestRunAndReport(unittest.TestCase):

    def test_registry_contains_example(self):
        self.assertIn(ExamplePublicBucketAuditor, DEFAULT_SERVICE_AUDITORS)

    def test_run_audit_and_print(self):
        session = _Session({"object_storage_buckets": [{
            "id": "ocid1.bucket.oc1..pub", "name": "pub",
            "compartment_id": "ocid1.compartment.oc1..c",
            "public_access_type": "ObjectReadWithoutList",
        }]})
        report = run_audit(session=session)
        self.assertEqual(report.total_findings(), 1)
        # print_audit_report should not raise on a populated report.
        print_audit_report(report)

    def test_run_audit_include_filter_excludes_other_services(self):
        session = _Session({"object_storage_buckets": [{
            "id": "b", "name": "b", "compartment_id": "c",
            "public_access_type": "ObjectRead",
        }]})
        report = run_audit(session=session, include_services=["some_other_service"])
        self.assertEqual(report.total_findings(), 0)


if __name__ == "__main__":
    unittest.main()
