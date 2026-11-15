"""Shared OCI SDK stub infrastructure for unit tests that run without the real SDK.

Usage:
    from tests.unit._oci_stub import _stub_optional_dependencies

    class MyTest(unittest.TestCase):
        def test_something(self):
            with _stub_optional_dependencies():
                module = importlib.import_module("ocinferno.modules.foo.bar")
                ...

The context manager installs a MetaPathFinder that intercepts imports for the oci
(and optionally oci_lexer_parser) packages, provides _DynamicStub objects for every
attribute access, and cleans up all stubbed modules on exit so subsequent tests in
other files see the real (or absent) SDK.

Pass prefixes=("oci",) to avoid stubbing oci_lexer_parser (default stubs both).
"""
from __future__ import annotations

import contextlib
import importlib
import importlib.abc
import importlib.machinery
import sys


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
    def __init__(self, prefixes: tuple[str, ...] = ("oci", "oci_lexer_parser")):
        self._prefixes = prefixes

    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == p or fullname.startswith(f"{p}.") for p in self._prefixes):
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
def _stub_optional_dependencies(prefixes: tuple[str, ...] = ("oci", "oci_lexer_parser")):
    """Context manager: stubs the given package prefixes for the duration of the block,
    then restores sys.modules to its baseline state on exit."""
    finder = _OptionalDependencyStubFinder(prefixes=prefixes)
    baseline = set(sys.modules)
    sys.meta_path.insert(0, finder)
    try:
        yield
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        for name in list(sys.modules):
            is_stubbed = any(
                name == p or name.startswith(f"{p}.") for p in prefixes
            )
            if is_stubbed and name not in baseline:
                sys.modules.pop(name, None)
