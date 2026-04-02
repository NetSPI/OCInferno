from __future__ import annotations

import contextlib
import importlib
import importlib.abc
import importlib.machinery
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch


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
    PREFIXES = ("oci", "oci_lexer_parser")

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
            is_stubbed = (
                name == "oci"
                or name.startswith("oci.")
                or name == "oci_lexer_parser"
                or name.startswith("oci_lexer_parser.")
            )
            if is_stubbed and name not in baseline:
                sys.modules.pop(name, None)


class TestApiGatewaySdks(unittest.TestCase):
    def test_enum_sdks_skips_unscoped_list_call(self):
        with _stub_optional_dependencies():
            module = importlib.import_module("ocinferno.modules.apigateway.enumeration.enum_apigateway")
            session = SimpleNamespace(
                compartment_id="ocid1.compartment.oc1..example",
                debug=False,
                individual_run_debug=False,
            )

            class _NoScopeSdksResource:
                COLUMNS = []

                def __init__(self, session):
                    self.session = session

                def resolve_sdk_api_ids(self, args, *, debug=False):
                    _ = (args, debug)
                    return []

                def list(self, *, sdk_id="", api_ids=None):
                    _ = (sdk_id, api_ids)
                    raise AssertionError("list() should not be called without sdk_id/api_ids scope")

                def get(self, *, resource_id):
                    _ = resource_id
                    return {}

                def save(self, rows):
                    _ = rows
                    return None

                def download(self, *, sdk_row, out_path):
                    _ = (sdk_row, out_path)
                    return False

                @staticmethod
                def filename_for_sdk_artifact(_sdk_row):
                    return "sdk.zip"

            with patch.object(module, "ApiGatewaySdksResource", _NoScopeSdksResource), patch.object(
                module, "append_cached_component_counts", return_value=None
            ):
                result = module.run_module(["--sdks"], session)

        self.assertTrue(result.get("ok"))
        components = result.get("components") or []
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0].get("sdks"), 0)


if __name__ == "__main__":
    unittest.main()
