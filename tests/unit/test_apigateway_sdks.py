from __future__ import annotations

import importlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.unit._oci_stub import _stub_optional_dependencies


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
