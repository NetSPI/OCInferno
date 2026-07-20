from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _defines_run_module(tree: ast.Module) -> bool:
    """A module satisfies the contract if it defines ``run_module`` at top level OR
    binds the name there via an import/assignment (opengraph shims re-export it)."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "run_module":
            return True
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if any((alias.asname or alias.name) == "run_module" for alias in node.names):
                return True
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "run_module" for t in node.targets):
                return True
    return False


def _module_files():
    files = []
    for path in sorted((REPO_ROOT / "ocinferno" / "modules").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))
        if any(isinstance(n, ast.FunctionDef) and n.name == "run_module" for n in tree.body):
            files.append(path)
    return files


MODULE_FILES = _module_files()


@pytest.mark.parametrize("module_path", MODULE_FILES, ids=lambda p: p.relative_to(REPO_ROOT).as_posix())
def test_module_argument_parser_has_no_invalid_output_format_kwarg(module_path: Path) -> None:
    """No module should pass output_format= to ArgumentParser (a real bug class)."""
    tree = ast.parse(module_path.read_text(encoding="utf-8", errors="ignore"), filename=str(module_path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "ArgumentParser":
            continue
        invalid = any(isinstance(kw, ast.keyword) and kw.arg == "output_format" for kw in (node.keywords or []))
        assert invalid is False, f"{module_path}: ArgumentParser(output_format=...) is invalid"


def test_run_module_signature_is_two_positional() -> None:
    """Every module's run_module must be (user_args, session) -- exactly the 2-arg
    contract the dispatcher (invoke_run_module) calls with."""
    offenders = []
    for path in MODULE_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "run_module":
                a = node.args
                required = [p for p in a.args if p.arg != "self"]
                # Reject a 3rd required positional (e.g. the old output_format drift).
                defaulted = len(a.defaults)
                if len(required) - defaulted > 2:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: run_module{tuple(p.arg for p in a.args)}")
    assert not offenders, "run_module must be (user_args, session):\n" + "\n".join(offenders)


def test_all_mapped_modules_exist_and_define_run_module() -> None:
    """Every location in module_mappings.json must resolve to a file that defines
    run_module -- guards the registry against drift (dead paths / missing contract)."""
    payload = json.loads((REPO_ROOT / "ocinferno" / "mappings" / "module_mappings.json").read_text(encoding="utf-8"))
    locations = [str(m.get("location") or "").strip() for m in payload.get("modules", []) if isinstance(m, dict)]
    locations = [loc for loc in locations if loc]
    assert locations, "module_mappings.json has no module locations"

    for location in locations:
        module_file = REPO_ROOT / Path(*location.split(".")).with_suffix(".py")
        assert module_file.exists(), f"Missing module file for {location}"
        tree = ast.parse(module_file.read_text(encoding="utf-8", errors="ignore"), filename=str(module_file))
        assert _defines_run_module(tree), f"Mapped module {location} does not define run_module"
