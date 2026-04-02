from __future__ import annotations

import ast
import contextlib
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class FlagSpec:
    flag: str
    takes_value: bool = False
    value: str = "example"


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
def stub_optional_dependencies() -> Iterator[None]:
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


class DummyOps:
    VAULT_TABLE_NAME = "vault_vaults"
    SECRET_TABLE_NAME = "vault_secret"

    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, name):
        if name in {"COLUMNS", "TABLE_NAME"} or name.isupper():
            return []
        if name in {"resolve_output_path", "get_download_save_path", "get_workspace_output_root"}:
            return lambda *args, **kwargs: Path(tempfile.gettempdir()) / "ocinferno_dummy_artifact.bin"
        if name.startswith("out_path"):
            return lambda *args, **kwargs: Path(tempfile.gettempdir()) / "ocinferno_dummy_artifact.bin"
        if name.startswith("download"):
            return lambda *args, **kwargs: False
        if name.startswith("save"):
            return lambda *args, **kwargs: None
        if name.startswith("unique"):
            return lambda rows=None, *args, **kwargs: list(rows or [])
        if name.startswith("pick_latest"):
            return lambda rows=None, *args, **kwargs: list(rows or [])[:1]
        if name == "record_hash":
            return lambda *args, **kwargs: "dummy_hash"
        if name == "display_path":
            return lambda value=None, *args, **kwargs: value

        def _noop(*args, **kwargs):
            return []

        return _noop


def runtime_session() -> Any:
    tmp_handle = tempfile.TemporaryDirectory(prefix="ocinferno-enum-tests-")
    tmpdir = Path(tmp_handle.name)
    return SimpleNamespace(
        compartment_id="ocid1.compartment.oc1..example",
        tenancy_id="ocid1.tenancy.oc1..example",
        region="us-ashburn-1",
        config_current_default_region="us-ashburn-1",
        credentials={"config": {"region": "us-ashburn-1"}, "signer": None},
        debug=False,
        individual_run_debug=False,
        active_module_name="",
        last_scope_choice="current",
        enum_all_scanned_cids=set(),
        global_compartment_list=[],
        config_audit_report=None,
        add_proxy_config=lambda *args, **kwargs: None,
        get_resource_fields=lambda *args, **kwargs: [],
        execute_query=lambda *args, **kwargs: [],
        save_resources=lambda *args, **kwargs: None,
        resolve_output_path=lambda requested_path="", service_name="", filename="output.json", compartment_id=None, subdirs=None, target="export": (
            Path(requested_path) if requested_path else (tmpdir / (filename or "output.json"))
        ),
        get_download_save_path=lambda service_name="", filename="download.bin", compartment_id=None, subdirs=None: (
            tmpdir / (filename or "download.bin")
        ),
        get_workspace_output_root=lambda mkdir=False: tmpdir,
        set_logging_context=lambda **kwargs: None,
        unset_logging_context=lambda: None,
        # Keep a strong reference so TemporaryDirectory cleanup runs when the
        # session object is released at test end.
        _tmpdir_handle=tmp_handle,
    )


def import_module(module_name: str):
    sys.modules.pop(module_name, None)
    return importlib.import_module(module_name)


def _module_path(module_name: str) -> Path:
    spec = importlib.util.find_spec(module_name)
    if not spec or not spec.origin:
        raise RuntimeError(f"Unable to resolve module path for {module_name}")
    return Path(spec.origin)


def _literal(node: ast.AST):
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _kw(call: ast.Call, name: str):
    for kw in call.keywords or []:
        if kw.arg == name:
            return kw.value
    return None


def _sample_value(
    flag: str,
    *,
    choices: Optional[Sequence[Any]] = None,
    type_name: Optional[str] = None,
) -> str:
    if choices:
        return str(next((c for c in choices if isinstance(c, (str, int, float))), choices[0]))

    lowered = flag.lower()
    if "drop-no-cond-perms" in lowered:
        return "all"
    if type_name == "int":
        return "1"
    if type_name == "float":
        return "1.0"
    if lowered.endswith("-id") or lowered.endswith("-ids") or "ocid" in lowered:
        return "ocid1.test.oc1..example"
    if "region" in lowered:
        return "us-ashburn-1"
    if "lifecycle" in lowered:
        return "ACTIVE"
    if "modules" in lowered:
        return "identity"
    if "download" in lowered:
        return "all"
    if "services" in lowered:
        return "identity"
    if "version-range" in lowered:
        return "1-3"
    if "version-number" in lowered:
        return "1"
    if "path" in lowered or "dir" in lowered or "file" in lowered or "out" in lowered:
        return "example"
    if "name" in lowered:
        return "example"
    return "example"


def _flag_specs_from_add_argument_calls(source_path: Path) -> Dict[str, FlagSpec]:
    tree = ast.parse(source_path.read_text(encoding="utf-8", errors="ignore"), filename=str(source_path))
    specs: Dict[str, FlagSpec] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "add_argument"):
            continue

        flags: List[str] = []
        for arg in node.args:
            val = _literal(arg)
            if isinstance(val, str) and val.startswith("--"):
                flags.append(val)
        if not flags:
            continue

        flag = flags[0]
        action = _literal(_kw(node, "action"))
        choices = _literal(_kw(node, "choices"))
        nargs = _literal(_kw(node, "nargs"))
        type_kw = _kw(node, "type")
        type_name: Optional[str] = None
        if isinstance(type_kw, ast.Name):
            type_name = str(type_kw.id)
        elif isinstance(type_kw, ast.Attribute):
            type_name = str(type_kw.attr)
        else:
            type_lit = _literal(type_kw) if type_kw is not None else None
            if callable(type_lit):
                type_name = getattr(type_lit, "__name__", None)

        takes_value = True
        if isinstance(action, str) and action in {
            "store_true",
            "store_false",
            "count",
            "help",
            "version",
            "append_const",
            "store_const",
        }:
            takes_value = False
        if nargs == 0:
            takes_value = False

        specs[flag] = FlagSpec(
            flag=flag,
            takes_value=takes_value,
            value=_sample_value(
                flag,
                choices=choices if isinstance(choices, (list, tuple)) else None,
                type_name=type_name,
            ),
        )

    return specs


def _wrapper_common_flags(source_path: Path) -> Dict[str, FlagSpec]:
    tree = ast.parse(source_path.read_text(encoding="utf-8", errors="ignore"), filename=str(source_path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Name) and func.id == "parse_wrapper_args"):
            continue

        include_get = True
        include_save = True
        include_download = False

        kw_get = _literal(_kw(node, "include_get"))
        kw_save = _literal(_kw(node, "include_save"))
        kw_download = _literal(_kw(node, "include_download"))

        if isinstance(kw_get, bool):
            include_get = kw_get
        if isinstance(kw_save, bool):
            include_save = kw_save
        if isinstance(kw_download, bool):
            include_download = kw_download

        flags: Dict[str, FlagSpec] = {}
        if include_get:
            flags["--get"] = FlagSpec(flag="--get", takes_value=False)
        if include_save:
            flags["--save"] = FlagSpec(flag="--save", takes_value=False)
        if include_download:
            flags["--download"] = FlagSpec(flag="--download", takes_value=False)
        return flags

    return {}


def _component_flags(module) -> Dict[str, FlagSpec]:
    flags: Dict[str, FlagSpec] = {}
    components = list(getattr(module, "COMPONENTS", []) or [])
    for item in components:
        if not isinstance(item, (list, tuple)) or not item:
            continue
        key = item[0]
        if isinstance(key, str) and key:
            flag = f"--{key.replace('_', '-')}"
            flags[flag] = FlagSpec(flag=flag, takes_value=False)
    return flags


def collect_module_flag_specs(module_name: str) -> List[FlagSpec]:
    source_path = _module_path(module_name)
    with stub_optional_dependencies():
        module = import_module(module_name)

    specs: Dict[str, FlagSpec] = {}
    specs.update(_flag_specs_from_add_argument_calls(source_path))
    specs.update(_wrapper_common_flags(source_path))
    specs.update(_component_flags(module))

    # Keep the test focused on real module flags, not global argparse defaults.
    specs.pop("--help", None)
    return sorted(specs.values(), key=lambda x: x.flag)


def assert_module_flags_parse(module_name: str) -> None:
    with stub_optional_dependencies():
        module = import_module(module_name)
        for spec in collect_module_flag_specs(module_name):
            argv = [spec.flag]
            if spec.takes_value:
                argv.append(spec.value)

            try:
                parsed = module._parse_args(argv)
            except SystemExit as exc:
                raise AssertionError(f"{module_name}: failed parsing {argv!r} (SystemExit {exc.code})") from exc

            if isinstance(parsed, tuple):
                # parse_wrapper_args-style: (args, remainder)
                assert len(parsed) >= 1


@contextlib.contextmanager
def _patched_offline_runtime(module, module_name: str):
    with contextlib.ExitStack() as stack:
        # Replace resource/client classes with local no-network stubs.
        for attr_name, attr_value in vars(module).items():
            if (
                isinstance(attr_value, type)
                and (
                    attr_name.endswith("Ops")
                    or attr_name.endswith("Resource")
                    or attr_name.endswith("ResourceClient")
                    or attr_name.endswith("ClientBase")
                )
            ):
                stack.enter_context(patch.object(module, attr_name, DummyOps))

        # Keep wrapper cache-summary helper from touching DB state.
        if hasattr(module, "append_cached_component_counts"):
            stack.enter_context(patch.object(module, "append_cached_component_counts", return_value=None))

        # Special-case heavy orchestrators.
        if module_name == "ocinferno.modules.everything.enumeration.enum_all":
            stack.enter_context(patch.object(module, "_run_other_module", return_value={"ok": True}))
            stack.enter_context(
                patch.object(
                    module,
                    "_summarize_resources_by_compartment",
                    return_value={"totals": [], "detailed": {}},
                )
            )
            stack.enter_context(patch.object(module, "_print_compartment_tree", return_value=None))
            stack.enter_context(patch.object(module, "_expand_compartments", return_value=None))

        if module_name == "ocinferno.modules.everything.enumeration.enum_config_check":
            class _Report:
                def to_dict(self):
                    return {"findings": [], "summary": {}}

            stack.enter_context(patch.object(module, "run_audit", return_value=_Report()))
            stack.enter_context(patch.object(module, "print_audit_report", return_value=None))

        if module_name == "ocinferno.modules.opengraph.enumeration.enum_oracle_cloud_hound_data":
            stack.enter_context(patch.object(module, "push_custom_node_attributes", return_value={"ok": True}))

        yield


def module_smoke_args(module_name: str) -> List[str]:
    if module_name == "ocinferno.modules.everything.enumeration.enum_all":
        return ["--modules", "identity", "--no-recursive-compartments"]
    if module_name == "ocinferno.modules.everything.enumeration.enum_config_check":
        return ["--quiet"]
    if module_name == "ocinferno.modules.opengraph.enumeration.enum_oracle_cloud_hound_data":
        return ["--export-only"]
    return []


def assert_module_runs_offline(module_name: str) -> None:
    with stub_optional_dependencies():
        module = import_module(module_name)
        session = runtime_session()
        args = module_smoke_args(module_name)

        with _patched_offline_runtime(module, module_name):
            result = module.run_module(list(args), session)

        assert isinstance(result, (dict, int, list)), f"Unexpected return type: {type(result).__name__}"
