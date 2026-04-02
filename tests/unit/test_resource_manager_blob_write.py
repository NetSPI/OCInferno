from __future__ import annotations

import contextlib
import importlib
import importlib.abc
import importlib.machinery
import sys
import unittest
from pathlib import Path


class _DynamicStub:
    def __init__(self, name: str = "stub"):
        self._name = name

    def __getattr__(self, item: str):
        return _DynamicStub(f"{self._name}.{item}")

    def __call__(self, *args, **kwargs):
        return _DynamicStub(f"{self._name}()")

    def __iter__(self):
        return iter(())

    def __bool__(self):
        return False


class _OptionalDependencyStubFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    PREFIXES = ("oci",)

    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == p or fullname.startswith(f"{p}.") for p in self.PREFIXES):
            return importlib.machinery.ModuleSpec(fullname, self, is_package=True)
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module_name = module.__name__
        module.__file__ = "<stub>"
        module.__path__ = []

        def __getattr__(attr):
            return _DynamicStub(f"{module_name}.{attr}")

        module.__getattr__ = __getattr__

        if module_name == "oci.exceptions":
            class ServiceError(Exception):
                def __init__(self, status=None, code=None, message=""):
                    super().__init__(message)
                    self.status = status
                    self.code = code
                    self.message = message

            module.ServiceError = ServiceError

        if module_name == "oci":
            module.exceptions = importlib.import_module("oci.exceptions")


@contextlib.contextmanager
def _stub_optional_dependencies():
    finder = _OptionalDependencyStubFinder()
    baseline = set(sys.modules)
    sys.meta_path.insert(0, finder)
    try:
        yield
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        for name in list(sys.modules):
            is_stubbed = name == "oci" or name.startswith("oci.")
            if is_stubbed and name not in baseline:
                sys.modules.pop(name, None)


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

            ok = module.ResourceManagerTemplatesResource._write_blob(_ResponseLike(b"PK\x03\x04zip-bytes"), str(out_file))

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
            ok = module.ResourceManagerTemplatesResource._write_blob(wrapped, str(out_file))

        self.assertTrue(ok)
        self.assertTrue(out_file.exists())
        self.assertEqual(out_file.read_bytes(), b"\x89PNG\r\nbinary")


if __name__ == "__main__":
    unittest.main()
