from __future__ import annotations

import csv
import json
import sqlite3
import sys
import tempfile
import types
import unittest
import unittest.mock
import zipfile
from pathlib import Path


def _install_oci_stub() -> None:
    # Only stub when the real SDK is genuinely not installed -- unconditionally
    # installing a fake module here would permanently shadow the real `oci` for
    # the rest of the pytest session for any other test file that needs it
    # (collection-order dependent).
    try:
        import oci  # noqa: F401
        return
    except ImportError:
        pass

    class _DynamicStub:
        def __init__(self, name: str = "stub"):
            self._name = name

        def __getattr__(self, item: str):
            return _DynamicStub(f"{self._name}.{item}")

        def __call__(self, *args, **kwargs):
            return _DynamicStub(f"{self._name}()")

    oci_mod = types.ModuleType("oci")
    auth_mod = types.ModuleType("oci.auth")
    cert_mod = types.ModuleType("oci.auth.certificate_retriever")
    fed_mod = types.ModuleType("oci.auth.federation_client")
    sks_mod = types.ModuleType("oci.auth.session_key_supplier")
    sign_mod = types.ModuleType("oci.auth.signers")
    cfg_mod = types.ModuleType("oci.config")
    exc_mod = types.ModuleType("oci.exceptions")
    util_mod = types.ModuleType("oci.util")

    cert_mod.PEMStringCertificateRetriever = type("PEMStringCertificateRetriever", (), {})
    fed_mod.X509FederationClient = type("X509FederationClient", (), {})
    sks_mod.SessionKeySupplier = type("SessionKeySupplier", (), {})
    sign_mod.SecurityTokenSigner = type("SecurityTokenSigner", (), {})
    sign_mod.X509FederationClientBasedSecurityTokenSigner = type("X509FederationClientBasedSecurityTokenSigner", (), {})

    cfg_mod.from_file = lambda **_kwargs: {}
    cfg_mod.validate_config = lambda _cfg: True
    exc_mod.ConfigFileNotFound = type("ConfigFileNotFound", (Exception,), {})
    exc_mod.InvalidKeyFilePath = type("InvalidKeyFilePath", (Exception,), {})
    exc_mod.ProfileNotFound = type("ProfileNotFound", (Exception,), {})
    util_mod.to_dict = lambda obj: obj

    auth_mod.certificate_retriever = cert_mod
    auth_mod.federation_client = fed_mod
    auth_mod.session_key_supplier = sks_mod
    auth_mod.signers = sign_mod

    oci_mod.auth = auth_mod
    oci_mod.config = cfg_mod
    oci_mod.exceptions = exc_mod
    oci_mod.util = util_mod
    oci_mod.retry = types.SimpleNamespace(DEFAULT_RETRY_STRATEGY=None)
    oci_mod.core = types.SimpleNamespace(models=_DynamicStub("oci.core.models"))
    oci_mod.__getattr__ = lambda attr: _DynamicStub(f"oci.{attr}")
    auth_mod.__getattr__ = lambda attr: _DynamicStub(f"oci.auth.{attr}")

    sys.modules["oci"] = oci_mod
    sys.modules["oci.auth"] = auth_mod
    sys.modules["oci.auth.certificate_retriever"] = cert_mod
    sys.modules["oci.auth.federation_client"] = fed_mod
    sys.modules["oci.auth.session_key_supplier"] = sks_mod
    sys.modules["oci.auth.signers"] = sign_mod
    sys.modules["oci.config"] = cfg_mod
    sys.modules["oci.exceptions"] = exc_mod
    sys.modules["oci.util"] = util_mod


_install_oci_stub()

from ocinferno.core.utils.module_helpers import (
    export_compartment_tree_image,
    export_sqlite_db_to_excel,
    export_sqlite_dbs_to_excel_blob,
    export_sqlite_dbs_to_csv_blob,
    export_sqlite_dbs_to_json_blob,
)


def _build_db(path: Path, table_name: str, rows: list[tuple[str, str]]) -> None:
    conn = sqlite3.connect(str(path))
    cur = conn.cursor()
    try:
        cur.execute(f'CREATE TABLE "{table_name}" (id TEXT, name TEXT)')
        cur.executemany(f'INSERT INTO "{table_name}" (id, name) VALUES (?, ?)', rows)
        conn.commit()
    finally:
        cur.close()
        conn.close()


def _xlsx_xml_blob(path: str) -> str:
    with zipfile.ZipFile(path, "r") as zf:
        parts = []
        for name in zf.namelist():
            if not name.endswith(".xml"):
                continue
            try:
                parts.append(zf.read(name).decode("utf-8", errors="ignore"))
            except Exception:
                continue
    return "\n".join(parts)


# Excel export relies on the optional [excel] extra (pandas + xlsxwriter). Skip
# those cases when it isn't installed so the base `.[dev]` test run stays green.
try:
    import pandas  # noqa: F401
    import xlsxwriter  # noqa: F401

    _HAS_EXCEL = True
except Exception:
    _HAS_EXCEL = False

_EXCEL_SKIP_REASON = "requires the optional Excel extra (pip install ocinferno[excel])"


class TestDataExports(unittest.TestCase):
    def test_export_sqlite_dbs_to_csv_blob_includes_resource_column(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_one = root / "service_info.db"
            db_two = root / "organization_metadata.db"
            out_csv = root / "sqlite_blob.csv"

            _build_db(db_one, "alpha_table", [("1", "a1"), ("2", "a2")])
            _build_db(db_two, "beta_table", [("9", "b9")])

            result = export_sqlite_dbs_to_csv_blob(
                db_paths=[str(db_one), str(db_two)],
                out_csv_path=str(out_csv),
            )

            self.assertTrue(result["ok"])
            self.assertEqual(result["tables"], 2)
            self.assertEqual(result["rows"], 3)
            self.assertTrue(out_csv.exists())

            with out_csv.open("r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                self.assertIsNotNone(reader.fieldnames)
                self.assertIn("Database", list(reader.fieldnames or []))
                self.assertIn("resource", list(reader.fieldnames or []))
                rows = list(reader)

            self.assertEqual(len(rows), 3)
            self.assertEqual({r["resource"] for r in rows}, {"alpha_table", "beta_table"})
            self.assertEqual(
                {r["Database"] for r in rows},
                {"service_info", "organization_metadata"},
            )

    def test_export_sqlite_dbs_to_json_blob_includes_resource_key_per_row(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_one = root / "service_info.db"
            out_json = root / "sqlite_blob.json"

            _build_db(db_one, "alpha_table", [("1", "a1"), ("2", "a2")])

            result = export_sqlite_dbs_to_json_blob(
                db_paths=[str(db_one)],
                out_json_path=str(out_json),
            )

            self.assertTrue(result["ok"])
            self.assertEqual(result["tables"], 1)
            self.assertEqual(result["rows"], 2)
            self.assertTrue(out_json.exists())

            blob = json.loads(out_json.read_text(encoding="utf-8"))
            db_rows = blob["databases"]["service_info"]["alpha_table"]
            self.assertEqual(len(db_rows), 2)
            self.assertTrue(all(r.get("resource") == "alpha_table" for r in db_rows))

            records = blob["records"]
            self.assertEqual(len(records), 2)
            self.assertTrue(all(r.get("resource") == "alpha_table" for r in records))
            self.assertTrue(all((r.get("row") or {}).get("resource") == "alpha_table" for r in records))

    @unittest.skipUnless(_HAS_EXCEL, _EXCEL_SKIP_REASON)
    def test_export_sqlite_db_to_excel_includes_resource_column(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_one = root / "service_info.db"
            out_xlsx = root / "sqlite_export.xlsx"

            _build_db(db_one, "alpha_table", [("1", "a1")])

            result = export_sqlite_db_to_excel(
                db_path=str(db_one),
                out_xlsx_path=str(out_xlsx),
                single_sheet=True,
            )

            self.assertTrue(result["ok"])
            self.assertEqual(result.get("format"), "xlsx")
            self.assertTrue(Path(result["xlsx_path"]).exists())
            xml_blob = _xlsx_xml_blob(result["xlsx_path"])
            self.assertIn("all_tables", xml_blob)
            self.assertIn("resource", xml_blob)
            self.assertIn("alpha_table", xml_blob)

    @unittest.skipUnless(_HAS_EXCEL, _EXCEL_SKIP_REASON)
    def test_export_sqlite_dbs_to_excel_blob_is_single_file_with_database_and_resource(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_one = root / "service_info.db"
            db_two = root / "organization_metadata.db"
            out_xlsx = root / "sqlite_blob.xlsx"

            _build_db(db_one, "alpha_table", [("1", "a1"), ("2", "a2")])
            _build_db(db_two, "beta_table", [("9", "b9")])

            result = export_sqlite_dbs_to_excel_blob(
                db_paths=[str(db_one), str(db_two)],
                out_xlsx_path=str(out_xlsx),
                single_sheet=True,
            )

            self.assertTrue(result["ok"])
            self.assertEqual(result.get("format"), "xlsx")
            self.assertTrue(Path(result["xlsx_path"]).exists())
            self.assertEqual(result["databases"], 2)
            self.assertEqual(result["tables"], 2)
            self.assertEqual(result["rows"], 3)
            xml_blob = _xlsx_xml_blob(result["xlsx_path"])
            self.assertIn("all_tables", xml_blob)
            self.assertIn("Database", xml_blob)
            self.assertIn("resource", xml_blob)
            self.assertIn("service_info", xml_blob)
            self.assertIn("organization_metadata", xml_blob)
            self.assertIn("alpha_table", xml_blob)
            self.assertIn("beta_table", xml_blob)

    @unittest.skipUnless(_HAS_EXCEL, _EXCEL_SKIP_REASON)
    def test_export_sqlite_dbs_to_excel_blob_condensed_shape(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_one = root / "service_info.db"
            out_xlsx = root / "sqlite_blob_condensed.xlsx"

            conn = sqlite3.connect(str(db_one))
            cur = conn.cursor()
            try:
                cur.execute('CREATE TABLE "resource_compartments" (compartment_id TEXT, name TEXT)')
                cur.execute(
                    'INSERT INTO "resource_compartments" (compartment_id, name) VALUES (?, ?)',
                    ("ocid1.compartment.oc1..aaaa", "Prod"),
                )
                cur.execute(
                    'CREATE TABLE "compute_instances" (id TEXT, name TEXT, compartment_id TEXT, shape TEXT, metadata_json TEXT)'
                )
                cur.execute(
                    'INSERT INTO "compute_instances" (id, name, compartment_id, shape, metadata_json) VALUES (?, ?, ?, ?, ?)',
                    (
                        "ocid1.instance.oc1..aaaa",
                        "app1",
                        "ocid1.compartment.oc1..aaaa",
                        "VM.Standard.E4.Flex",
                        '{"enabled":true,"ports":[443,80]}',
                    ),
                )
                conn.commit()
            finally:
                cur.close()
                conn.close()

            result = export_sqlite_dbs_to_excel_blob(
                db_paths=[str(db_one)],
                out_xlsx_path=str(out_xlsx),
                single_sheet=True,
                condensed=True,
            )

            self.assertTrue(result["ok"])
            self.assertTrue(result.get("condensed"))
            self.assertEqual(result.get("format"), "xlsx")
            self.assertTrue(Path(result["xlsx_path"]).exists())
            self.assertEqual(result["rows"], 2)
            xml_blob = _xlsx_xml_blob(result["xlsx_path"])
            self.assertIn("all_resources", xml_blob)
            self.assertIn("Table Name", xml_blob)
            self.assertIn("Compartment ID", xml_blob)
            self.assertIn("Compartment Name", xml_blob)
            self.assertIn("Service Category", xml_blob)
            self.assertIn("Resource Category", xml_blob)
            self.assertIn("Resource Display Name", xml_blob)
            self.assertIn("Remaining JSON", xml_blob)
            self.assertIn("compute_instances", xml_blob)
            self.assertIn("Compute Instance", xml_blob)
            self.assertIn("Compute", xml_blob)
            self.assertIn("Prod", xml_blob)
            self.assertIn("app1", xml_blob)
            self.assertIn("ocid1.instance.oc1..aaaa", xml_blob)
            self.assertIn('"metadata_json"', xml_blob)

    @unittest.skipUnless(_HAS_EXCEL, _EXCEL_SKIP_REASON)
    def test_single_sheet_export_splits_into_multiple_sheets_past_excel_row_limit(self):
        """A single-sheet export whose row count would exceed Excel's real per-sheet
        limit (1,048,576 rows, previously an unrecoverable crash reported as a
        misleading "install pandas/xlsxwriter" error) must split into multiple numbered
        sheets instead of raising. Uses a monkeypatched threshold so the test runs fast
        without generating a million real rows."""
        from ocinferno.core.utils import exports as exports_mod

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_one = root / "service_info.db"
            out_xlsx = root / "sqlite_chunked.xlsx"

            _build_db(db_one, "alpha_table", [(str(i), f"a{i}") for i in range(10)])

            with unittest.mock.patch.object(exports_mod, "_EXCEL_MAX_DATA_ROWS_PER_SHEET", 3):
                result = export_sqlite_dbs_to_excel_blob(
                    db_paths=[str(db_one)],
                    out_xlsx_path=str(out_xlsx),
                    single_sheet=True,
                )

            self.assertTrue(result["ok"])
            self.assertEqual(result["rows"], 10)
            xml_blob = _xlsx_xml_blob(result["xlsx_path"])
            # 10 rows / 3-per-sheet -> 4 sheets: all_tables, all_tables_2, _3, _4
            self.assertIn("all_tables", xml_blob)
            self.assertIn("all_tables_2", xml_blob)
            self.assertIn("all_tables_3", xml_blob)
            self.assertIn("all_tables_4", xml_blob)

    @unittest.skipUnless(_HAS_EXCEL, _EXCEL_SKIP_REASON)
    def test_writer_failure_message_reports_real_cause_not_missing_dependency(self):
        """A write-time failure (row limit, disk space, etc -- anything other than a
        genuinely missing pandas/xlsxwriter, which is guarded separately at the top of
        the function) must surface its real exception type/message, not the old
        catch-all "Ensure pandas and xlsxwriter are installed" text that was actively
        misleading when the dependencies were already installed."""
        from ocinferno.core.utils import exports as exports_mod

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_one = root / "service_info.db"
            out_xlsx = root / "sqlite_writer_fail.xlsx"
            _build_db(db_one, "alpha_table", [("1", "a1")])

            def _boom(*a, **kw):
                raise ValueError("This sheet is too large! boom")

            with unittest.mock.patch.object(exports_mod, "_write_records_chunked", side_effect=_boom):
                with self.assertRaises(RuntimeError) as ctx:
                    export_sqlite_dbs_to_excel_blob(
                        db_paths=[str(db_one)],
                        out_xlsx_path=str(out_xlsx),
                        single_sheet=True,
                    )
            msg = str(ctx.exception)
            self.assertIn("ValueError", msg)
            self.assertIn("too large", msg)
            self.assertNotIn("Ensure pandas and xlsxwriter are installed", msg)

    @unittest.skipUnless(_HAS_EXCEL, _EXCEL_SKIP_REASON)
    def test_condensed_display_name_falls_back_to_service_specific_name_column(self):
        """vault_secret (and ~50 other tables) have no display_name/name column --
        just a service-specific one like secret_name. The fallback must pick it up
        rather than leaving Resource Display Name blank."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_one = root / "service_info.db"
            out_xlsx = root / "sqlite_blob_secret.xlsx"

            conn = sqlite3.connect(str(db_one))
            cur = conn.cursor()
            try:
                cur.execute(
                    'CREATE TABLE "vault_secret" (id TEXT, compartment_id TEXT, secret_name TEXT)'
                )
                cur.execute(
                    'INSERT INTO "vault_secret" (id, compartment_id, secret_name) VALUES (?, ?, ?)',
                    ("ocid1.vaultsecret.oc1..aaaa", "ocid1.compartment.oc1..aaaa", "db-password"),
                )
                conn.commit()
            finally:
                cur.close()
                conn.close()

            result = export_sqlite_dbs_to_excel_blob(
                db_paths=[str(db_one)],
                out_xlsx_path=str(out_xlsx),
                single_sheet=True,
                condensed=True,
            )

            self.assertTrue(result["ok"])
            xml_blob = _xlsx_xml_blob(result["xlsx_path"])
            self.assertIn("db-password", xml_blob)

    @unittest.skipUnless(_HAS_EXCEL, _EXCEL_SKIP_REASON)
    def test_condensed_lifecycle_state_column_populated_and_excluded_from_remaining_json(self):
        """lifecycle_state must land in its own "Lifecycle State" column (so Excel's
        autofilter can filter out TERMINATED/DELETED rows in two clicks) and must NOT
        also be duplicated inside the Remaining JSON blob."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_one = root / "service_info.db"
            out_xlsx = root / "sqlite_blob_lifecycle.xlsx"

            conn = sqlite3.connect(str(db_one))
            cur = conn.cursor()
            try:
                cur.execute(
                    'CREATE TABLE "compute_instances" '
                    '(id TEXT, name TEXT, compartment_id TEXT, lifecycle_state TEXT)'
                )
                cur.execute(
                    'INSERT INTO "compute_instances" (id, name, compartment_id, lifecycle_state) '
                    "VALUES (?, ?, ?, ?)",
                    (
                        "ocid1.instance.oc1..aaaa",
                        "app1",
                        "ocid1.compartment.oc1..aaaa",
                        "TERMINATED",
                    ),
                )
                conn.commit()
            finally:
                cur.close()
                conn.close()

            result = export_sqlite_dbs_to_excel_blob(
                db_paths=[str(db_one)],
                out_xlsx_path=str(out_xlsx),
                single_sheet=True,
                condensed=True,
            )

            self.assertTrue(result["ok"])
            xml_blob = _xlsx_xml_blob(result["xlsx_path"])
            self.assertIn("Lifecycle State", xml_blob)
            self.assertIn("TERMINATED", xml_blob)
            # Excel's built-in filter dropdown must cover the data rows, not just the header.
            self.assertIn("autoFilter", xml_blob)

            with zipfile.ZipFile(result["xlsx_path"], "r") as zf:
                sheet_xml = next(
                    zf.read(n).decode("utf-8") for n in zf.namelist() if n.startswith("xl/worksheets/sheet")
                )
            # lifecycle_state must not be duplicated inside the Remaining JSON cell text.
            self.assertNotIn('"lifecycle_state"', sheet_xml)

    def test_export_compartment_tree_image_svg(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_one = root / "service_info.db"
            out_svg = root / "compartment_tree.svg"

            conn = sqlite3.connect(str(db_one))
            cur = conn.cursor()
            try:
                cur.execute(
                    'CREATE TABLE "resource_compartments" (compartment_id TEXT, parent_compartment_id TEXT, name TEXT)'
                )
                cur.execute(
                    'INSERT INTO "resource_compartments" (compartment_id, parent_compartment_id, name) VALUES (?, ?, ?)',
                    ("ocid1.tenancy.oc1..root", "", "Root"),
                )
                cur.execute(
                    'INSERT INTO "resource_compartments" (compartment_id, parent_compartment_id, name) VALUES (?, ?, ?)',
                    ("ocid1.compartment.oc1..child", "ocid1.tenancy.oc1..root", "Prod"),
                )
                cur.execute(
                    'INSERT INTO "resource_compartments" (compartment_id, parent_compartment_id, name) VALUES (?, ?, ?)',
                    (
                        "ocid1.compartment.oc1..unknownname",
                        "ocid1.tenancy.oc1..root",
                        "ocid1.compartment.oc1..unknownname",
                    ),
                )
                conn.commit()
            finally:
                cur.close()
                conn.close()

            result = export_compartment_tree_image(
                db_path=str(db_one),
                out_path=str(out_svg),
            )

            self.assertTrue(result["ok"])
            self.assertEqual(result.get("format"), "svg")
            self.assertTrue(Path(result["image_path"]).exists())
            svg_text = Path(result["image_path"]).read_text(encoding="utf-8")
            self.assertIn("<svg", svg_text)
            self.assertIn("<rect", svg_text)
            self.assertIn("id=\"viewport\"", svg_text)
            self.assertIn("marker-end=\"url(#arrow)\"", svg_text)
            self.assertIn("Root", svg_text)
            self.assertIn("Prod", svg_text)
            self.assertIn("NAME_UNKNOWN", svg_text)
            self.assertIn("ocid1.tenancy.oc1..root", svg_text)
            self.assertIn("ocid1.compartment.oc1..c", svg_text)

if __name__ == "__main__":
    unittest.main()
