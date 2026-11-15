from __future__ import annotations

import importlib
import unittest
from pathlib import Path

from tests.unit._oci_stub import _stub_optional_dependencies as _stub_oci_only

# This module only needs to stub oci, not oci_lexer_parser.
def _stub_optional_dependencies():
    return _stub_oci_only(prefixes=("oci",))


class _ResponseLike:
    def __init__(self, content: bytes):
        self.content = content

    def __str__(self) -> str:
        return "<Response [200]>"


class _WrapperLike:
    def __init__(self, data):
        self.data = data

    def __str__(self) -> str:
        return "<Wrapper [200]>"


class TestResourceManagerBlobWrite(unittest.TestCase):
    def test_templates_writer_uses_response_content_bytes(self):
        with _stub_optional_dependencies():
            module = importlib.import_module("ocinferno.modules.resourcemanager.utilities.helpers")
            out_file = Path("tests/.tmp_template_blob.bin")
            if out_file.exists():
                out_file.unlink()
            self.addCleanup(lambda: out_file.unlink(missing_ok=True))

            ok = module._write_blob(_ResponseLike(b"PK\x03\x04zip-bytes"), str(out_file))

        self.assertTrue(ok)
        self.assertTrue(out_file.exists())
        self.assertEqual(out_file.read_bytes(), b"PK\x03\x04zip-bytes")

    def test_templates_writer_unwraps_nested_data_wrapper(self):
        with _stub_optional_dependencies():
            module = importlib.import_module("ocinferno.modules.resourcemanager.utilities.helpers")
            out_file = Path("tests/.tmp_template_blob_nested.bin")
            if out_file.exists():
                out_file.unlink()
            self.addCleanup(lambda: out_file.unlink(missing_ok=True))

            wrapped = _WrapperLike(_ResponseLike(b"\x89PNG\r\nbinary"))
            ok = module._write_blob(wrapped, str(out_file))

        self.assertTrue(ok)
        self.assertTrue(out_file.exists())
        self.assertEqual(out_file.read_bytes(), b"\x89PNG\r\nbinary")


if __name__ == "__main__":
    unittest.main()
