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


class TestVaultEnumChaining(unittest.TestCase):
    def test_secrets_receives_vault_scope_from_same_run_vaults(self):
        with _stub_optional_dependencies():
            mod = importlib.import_module("ocinferno.modules.vault.enumeration.enum_vault")
            session = SimpleNamespace(compartment_id="ocid1.compartment.oc1..example")

            seen = {"vault_ids": None}

            class _FakeVaultsResource:
                COLUMNS = []

                def __init__(self, session):
                    self.session = session

                def list(self):
                    return [{"id": "ocid1.vault.oc1.phx.example"}]

                def save(self, rows):
                    _ = rows
                    return None

            class _FakeKeysResource:
                COLUMNS = []
                VERSION_COLUMNS = []

                def __init__(self, session):
                    self.session = session

                def resolve_vault_ids(self, *, vault_ids, vault_endpoint=None):
                    _ = vault_endpoint
                    return list(vault_ids or [])

                def save_manual_vaults(self, *, vault_ids, vault_endpoint):
                    _ = (vault_ids, vault_endpoint)
                    return None

                def save_manual_keys(self, *, key_ids, fallback_vault_id):
                    _ = (key_ids, fallback_vault_id)
                    return None

                def list(self, *, vault_ids):
                    _ = vault_ids
                    return []

                def save(self, rows):
                    _ = rows
                    return None

                def list_versions(self, *, key_ids, vault_id_by_key_id=None):
                    _ = (key_ids, vault_id_by_key_id)
                    return []

                def save_versions(self, rows):
                    _ = rows
                    return None

            class _FakeSecretsResource:
                COLUMNS = []
                VERSION_COLUMNS = []
                DUMP_COLUMNS = []

                def __init__(self, session):
                    self.session = session

                def resolve_vault_ids(self, *, vault_ids):
                    seen["vault_ids"] = list(vault_ids or [])
                    return list(vault_ids or [])

                def list(self, *, vault_ids):
                    _ = vault_ids
                    return []

                def save(self, rows):
                    _ = rows
                    return None

                def list_versions(self, *, secret_ids, do_get_requests=False):
                    _ = (secret_ids, do_get_requests)
                    return []

                def save_versions(self, rows):
                    _ = rows
                    return None

                def save_bundle_metadata(self, *, secrets, secret_versions):
                    _ = (secrets, secret_versions)
                    return []

                def dump(self, **kwargs):
                    _ = kwargs
                    return []

                def save_dump_artifacts(self, rows):
                    _ = rows
                    return None

                @staticmethod
                def display_path(path_value):
                    return str(path_value)

            with patch.object(mod, "VaultVaultsResource", _FakeVaultsResource), patch.object(
                mod, "VaultKeysResource", _FakeKeysResource
            ), patch.object(mod, "VaultSecretsResource", _FakeSecretsResource), patch.object(
                mod, "append_cached_component_counts", return_value=None
            ):
                out = mod.run_module([], session)

        self.assertTrue(out.get("ok"))
        self.assertEqual(seen["vault_ids"], ["ocid1.vault.oc1.phx.example"])


if __name__ == "__main__":
    unittest.main()
