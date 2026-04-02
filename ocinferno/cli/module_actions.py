#!/usr/bin/env python3
# module_actions.py
from __future__ import annotations

import argparse
import ast
import importlib
import importlib.util
import inspect
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Optional, Sequence, List, Dict, Any, Set

from ocinferno.core.contracts import ErrorCode
from ocinferno.core.contracts import OperationResult
from ocinferno.core.console import UtilityTools


# =============================================================================
# Policy models
# =============================================================================

class AuthMode(str, Enum):
    AUTH = "auth"
    UNAUTH = "unauth"


class ExecMode(str, Enum):
    ONCE = "once"
    PER_TARGET = "per_target"


class ContextMode(str, Enum):
    """
    How to choose ONE context compartment_id for ONCE modules.
    """
    NONE = "none"
    PICK_ONE = "pick_one"
    DEFAULT = "default"


@dataclass(frozen=True)
class ModuleAction:
    auth_mode: AuthMode
    exec_mode: ExecMode
    context_mode: ContextMode
    accepts_cid_flags: bool = True


@dataclass(frozen=True)
class ModuleParseMeta:
    supported_common_flags: Set[str]
    accepts_unknown_args: bool


@dataclass
class RunnerArgs:
    cids: List[str]
    current_cid: bool
    all_cids: bool
    proxy: Optional[str]
    debug: bool
    save: bool
    no_save: bool
    get: bool
    download: bool
    download_values: List[str] = field(default_factory=list)
    explicit_common_flags: Set[str] = field(default_factory=set)
    passthrough: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ModulePolicySpec:
    exec_mode: ExecMode
    context_mode: ContextMode
    accepts_cid_flags: bool = True


@dataclass(frozen=True)
class ExecutionPlan:
    run_once: bool
    context_cid: Optional[str]
    target_cids: List[str]
    target_root_cids: List[str]


COMMON_MODULE_FLAGS = (
    ("--save", "save"),
    ("--get", "get"),
    ("--download", "download"),
)

NO_COMPARTMENTS_MSG = (
    f"{UtilityTools.RED}[X] No compartments discovered yet. "
    f"Provide --cids/--current-cid or run enum_comp first.{UtilityTools.RESET}"
)

DEFAULT_MODULE_POLICY = ModulePolicySpec(
    exec_mode=ExecMode.PER_TARGET,
    context_mode=ContextMode.NONE,
    accepts_cid_flags=True,
)

MODULE_POLICY_REGISTRY: Dict[str, ModulePolicySpec] = {
    "enum_all": ModulePolicySpec(
        exec_mode=ExecMode.ONCE,
        context_mode=ContextMode.DEFAULT,
        accepts_cid_flags=True,
    ),
    "enum_oracle_cloud_hound_data": ModulePolicySpec(
        exec_mode=ExecMode.ONCE,
        context_mode=ContextMode.NONE,
        accepts_cid_flags=False,
    ),
}


# =============================================================================
# Runner-args parsing (GLOBAL flags shared by all modules)
# =============================================================================

def _parse_runner_args(argv: Sequence[str]) -> RunnerArgs:
    """
    Runner-level flags are consumed here and NOT passed to modules.
    Everything else becomes passthrough args.
    """
    raw_argv = [str(x) for x in (argv or [])]

    def _flag_present(*names: str) -> bool:
        for tok in raw_argv:
            for name in names:
                if tok == name or tok.startswith(f"{name}="):
                    return True
        return False

    explicit_common_flags: Set[str] = set()
    if _flag_present("--save"):
        explicit_common_flags.add("--save")
    if _flag_present("--get"):
        explicit_common_flags.add("--get")
    if _flag_present("--download"):
        explicit_common_flags.add("--download")

    p = argparse.ArgumentParser(add_help=False, allow_abbrev=False)

    p.add_argument(
        "--cids",
        action="extend",
        nargs="+",
        type=lambda s: [x.strip() for x in str(s).split(",") if x.strip()],
        help="Target compartment OCIDs (space or comma separated). Overrides prompts.",
    )
    p.add_argument("--current-cid", action="store_true", help="Target ONLY current session CID (no prompts).")
    p.add_argument("--all-cids", action="store_true", help="Target ALL already-discovered CIDs (no prompts).")

    p.add_argument("--proxy", help="Proxy address (e.g. http://127.0.0.1:8080).")
    p.add_argument("--save", action="store_true", help="Pass --save to modules that support it.")
    p.add_argument("--no-save", action="store_true", help="Do not pass --save for this run.")
    p.add_argument("--get", action="store_true", help="Pass --get to modules that support it.")
    p.add_argument(
        "--download",
        nargs="*",
        default=None,
        help=(
            "Pass --download to modules that support it. "
            "For enum_all, optional tokens are supported (for example: --download buckets api_specs)."
        ),
    )
    p.add_argument("-v", "--debug", action="store_true", help="Enable verbose debug output.")

    known, rest = p.parse_known_args(list(argv))
    save_effective = bool(getattr(known, "save", False))
    if bool(getattr(known, "no_save", False)):
        save_effective = False

    return RunnerArgs(
        cids=_normalize_cids(known.cids or []),
        current_cid=bool(known.current_cid),
        all_cids=bool(known.all_cids),
        proxy=known.proxy,
        debug=bool(known.debug),
        save=save_effective,
        no_save=bool(getattr(known, "no_save", False)),
        get=bool(getattr(known, "get", False)),
        download=(getattr(known, "download", None) is not None),
        download_values=[
            str(x).strip()
            for x in (list(getattr(known, "download", []) or []))
            if str(x).strip()
        ],
        explicit_common_flags=explicit_common_flags,
        passthrough=list(rest),
    )


@lru_cache(maxsize=512)
def _module_parse_meta(module_import_path: str) -> ModuleParseMeta:
    try:
        spec = importlib.util.find_spec(module_import_path)
    except Exception:
        return ModuleParseMeta(supported_common_flags=set(), accepts_unknown_args=False)
    if spec is None or not spec.origin or not str(spec.origin).endswith(".py"):
        return ModuleParseMeta(supported_common_flags=set(), accepts_unknown_args=False)
    try:
        text = Path(spec.origin).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ModuleParseMeta(supported_common_flags=set(), accepts_unknown_args=False)
    parsed_flags: Set[str] = set()
    accepts_unknown = False
    try:
        tree = ast.parse(text, filename=str(spec.origin))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "parse_known_args":
                accepts_unknown = True
            if isinstance(func, ast.Name) and func.id == "parse_known_args":
                accepts_unknown = True
            # Wrapper helper pattern used by many enum modules.
            # parse_wrapper_args(...) supports include_get/include_save/include_download
            # and internally uses parse_known_args.
            is_wrapper_call = False
            if isinstance(func, ast.Name) and func.id == "parse_wrapper_args":
                is_wrapper_call = True
            elif isinstance(func, ast.Attribute) and func.attr == "parse_wrapper_args":
                is_wrapper_call = True
            if is_wrapper_call:
                accepts_unknown = True
                include_get = True
                include_save = True
                include_download = False
                for kw in (node.keywords or []):
                    if not isinstance(kw, ast.keyword) or not kw.arg:
                        continue
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool):
                        if kw.arg == "include_get":
                            include_get = bool(kw.value.value)
                        elif kw.arg == "include_save":
                            include_save = bool(kw.value.value)
                        elif kw.arg == "include_download":
                            include_download = bool(kw.value.value)
                if include_get:
                    parsed_flags.add("--get")
                if include_save:
                    parsed_flags.add("--save")
                if include_download:
                    parsed_flags.add("--download")
            if not (isinstance(func, ast.Attribute) and func.attr == "add_argument"):
                continue
            for arg in (node.args or []):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("--"):
                    parsed_flags.add(arg.value)
    except Exception:
        # Fallback: permissive scan if AST parse fails.
        for flag, _ in COMMON_MODULE_FLAGS:
            if flag in text:
                parsed_flags.add(flag)
    return ModuleParseMeta(
        supported_common_flags={flag for flag, _ in COMMON_MODULE_FLAGS if flag in parsed_flags},
        accepts_unknown_args=accepts_unknown,
    )


def _merge_common_module_flags(module_import_path: str, runner: RunnerArgs, passthrough_args: Sequence[str]) -> List[str]:
    out = list(passthrough_args or [])
    parse_meta = _module_parse_meta(module_import_path)
    supported = parse_meta.supported_common_flags
    accepts_unknown = parse_meta.accepts_unknown_args
    explicit_flags = set(runner.explicit_common_flags or [])
    is_enum_all = module_import_path.endswith(".enum_all")

    def _append_enum_all_download_values() -> None:
        if not is_enum_all:
            return
        for token in list(getattr(runner, "download_values", []) or []):
            t = str(token).strip()
            if not t:
                continue
            out.append(t)

    for flag, runner_key in COMMON_MODULE_FLAGS:
        if not bool(getattr(runner, runner_key, False)):
            continue
        if flag in out:
            if flag == "--download":
                _append_enum_all_download_values()
            continue
        # If the user explicitly provided this common flag, preserve intent.
        # This avoids silent drops where enumeration wrappers parse options indirectly.
        if flag in explicit_flags:
            out.append(flag)
            if flag == "--download":
                _append_enum_all_download_values()
            continue
        if accepts_unknown or flag in supported:
            out.append(flag)
            if flag == "--download":
                _append_enum_all_download_values()
    return out


# =============================================================================
# Helpers
# =============================================================================

@contextmanager
def _temporary_compartment(session, cid: Optional[str]):
    old = getattr(session, "compartment_id", None)
    if cid is not None:
        session.compartment_id = cid
    try:
        yield
    finally:
        session.compartment_id = old


def _normalize_cids(raw: Sequence[Any]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []

    def _emit(value: Any) -> None:
        if value is None:
            return

        if isinstance(value, (list, tuple, set)):
            for item in value:
                _emit(item)
            return

        text = str(value).strip()
        if not text:
            return

        for token in [t.strip() for t in text.split(",") if t.strip()]:
            if token in seen:
                continue
            seen.add(token)
            out.append(token)

    for x in raw or []:
        _emit(x)

    return out


def _all_known_cids(session) -> List[str]:
    rows = getattr(session, "global_compartment_list", None) or []
    out: List[str] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        cid = r.get("compartment_id") or r.get("id")
        if cid:
            out.append(cid)
    return _normalize_cids(out)


def _choose_one_compartment(session) -> Optional[str]:
    rows = getattr(session, "global_compartment_list", None) or []
    if not rows:
        print(NO_COMPARTMENTS_MSG)
        return None

    def _label(r):
        cid = r.get("compartment_id") or r.get("id") or ""
        name = r.get("name") or r.get("display_name") or cid
        return f"{UtilityTools.CYAN}{name}{UtilityTools.RESET} {UtilityTools.BRIGHT_BLACK}({cid}){UtilityTools.RESET}"

    picked = UtilityTools._choose_from_list("Select a compartment", rows, _label)
    if not picked:
        return None
    return picked.get("compartment_id") or picked.get("id")


def _deterministic_context(session, cids: List[str]) -> Optional[str]:
    if not cids:
        return None
    for cid in cids:
        if isinstance(cid, str) and cid.startswith("ocid1.tenancy"):
            return cid
    cur = getattr(session, "compartment_id", None)
    if cur and cur in cids:
        return cur
    return cids[0]


def _ask_scope_choice(session, current_cid: Optional[str], rows: Sequence[Dict[str, Any]]) -> str:
    if current_cid:
        return UtilityTools.ask_all_or_current_with_preview(current_cid, rows, max_preview=10)
    return UtilityTools.ask_all_or_current_with_preview(None, rows, max_preview=10)


def resolve_context_cid(session, *, mode: ContextMode) -> Optional[str]:
    """
    Returns ONE cid for ONCE modules, but ALSO stores the user's scope choice on session:
      session.last_scope_choice = "all" | "current" | None
    """
    # reset each time we ask
    try:
        session.last_scope_choice = None
    except Exception:
        pass
    try:
        session.last_scope_choice_explicit = False
    except Exception:
        pass

    if mode == ContextMode.NONE:
        return None

    if mode == ContextMode.PICK_ONE:
        # PICK_ONE is explicit "select a compartment" (number prompt)
        try:
            session.last_scope_choice = "current"
            session.last_scope_choice_explicit = True
        except Exception:
            pass
        return _choose_one_compartment(session)

    # DEFAULT
    rows = getattr(session, "global_compartment_list", None) or []
    cur = getattr(session, "compartment_id", None)

    if cur:
        if len(rows) > 1:
            choice = UtilityTools.ask_all_or_current_with_preview(cur, rows, max_preview=10)  # "all" or "current"
            try:
                session.last_scope_choice = choice
                session.last_scope_choice_explicit = True
            except Exception:
                pass
            if choice == "all":
                return _deterministic_context(session, _all_known_cids(session))
            return cur
        try:
            session.last_scope_choice = "current"
            session.last_scope_choice_explicit = False
        except Exception:
            pass
        return cur

    if not rows:
        print(NO_COMPARTMENTS_MSG)
        return None

    choice = _ask_scope_choice(session, None, rows)
    try:
        session.last_scope_choice = choice
        session.last_scope_choice_explicit = True
    except Exception:
        pass

    if choice == "all":
        return _deterministic_context(session, _all_known_cids(session))

    return _choose_one_compartment(session)


def resolve_targets_for_per_target(session, runner: RunnerArgs) -> List[str]:
    explicit = runner.cids or []
    if explicit:
        return _normalize_cids(list(explicit))

    if runner.all_cids:
        targets = _all_known_cids(session)
        if not targets:
            print(
                f"{UtilityTools.RED}[X] --all-cids requested but no compartments discovered yet. "
                f"Run enum_comp first.{UtilityTools.RESET}"
            )
        return targets

    if runner.current_cid:
        cur = getattr(session, "compartment_id", None)
        if not cur:
            print(
                f"{UtilityTools.RED}[X] --current-cid requested but session.compartment_id is not set.{UtilityTools.RESET}"
            )
        return [cur] if cur else []

    rows = getattr(session, "global_compartment_list", None) or []
    if not rows:
        print(NO_COMPARTMENTS_MSG)
        return []

    all_ids = _all_known_cids(session)
    cur = getattr(session, "compartment_id", None)

    if cur:
        if len(rows) > 1:
            choice = _ask_scope_choice(session, cur, rows)
            return all_ids if choice == "all" else [cur]
        return [cur]

    choice = _ask_scope_choice(session, None, rows)
    if choice == "all":
        return all_ids

    cid = _choose_one_compartment(session)
    return [cid] if cid else []


def _invoke_run_module(module, passthrough_args: Sequence[str], session):
    fn = getattr(module, "run_module", None)
    if not callable(fn):
        raise AttributeError("Module does not export run_module")

    sig = inspect.signature(fn)
    params = list(sig.parameters.values())

    def _pname(i: int) -> str:
        return params[i].name if i < len(params) else ""

    if len(params) >= 2:
        p0, p1 = _pname(0), _pname(1)

        if p0 in ("user_args", "argv", "args") and p1 in ("session",):
            return fn(list(passthrough_args), session)

        if p0 in ("session",) and p1 in ("args", "argv", "user_args", "namespace", "parsed"):
            return fn(session, list(passthrough_args))

    try:
        return fn(list(passthrough_args), session)
    except TypeError:
        return fn(session, list(passthrough_args))


def _execute_module_for_target(session, module, *, mod_short: str, target_cid: Optional[str], passthrough_args: Sequence[str]) -> OperationResult:
    label = target_cid if target_cid else "N/A"
    UtilityTools._log_action("module", f"START {mod_short} for {label}" if target_cid else f"START {mod_short}", "N/A")
    prev_mod = str(getattr(session, "active_module_name", "") or "")
    try:
        session.active_module_name = mod_short
        with _temporary_compartment(session, target_cid):
            _invoke_run_module(module, passthrough_args, session)
        return OperationResult.success("module_run_ok", module=mod_short, compartment_id=target_cid or "")
    except Exception as e:
        return OperationResult.from_exception(
            e,
            fallback_code=ErrorCode.MODULE_EXECUTION_FAILED,
            module=mod_short,
            compartment_id=target_cid or "",
        )
    finally:
        session.active_module_name = prev_mod
        UtilityTools._log_action("module", f"END {mod_short} for {label}" if target_cid else f"END {mod_short}", "N/A")


# =============================================================================
# Registry
# =============================================================================

def get_module_action(module_import_path: str) -> ModuleAction:
    key = module_import_path.replace("/", ".").split(".")[-1]
    auth = AuthMode.UNAUTH if ("Unauthenticated" in module_import_path or "OpenGraph" in module_import_path) else AuthMode.AUTH
    spec = MODULE_POLICY_REGISTRY.get(key, DEFAULT_MODULE_POLICY)

    return ModuleAction(
        auth_mode=auth,
        exec_mode=spec.exec_mode,
        context_mode=spec.context_mode,
        accepts_cid_flags=spec.accepts_cid_flags,
    )


def _cid_selector_count(runner: RunnerArgs) -> int:
    return sum(1 for used in (bool(runner.cids), bool(runner.current_cid), bool(runner.all_cids)) if used)


def _sanitize_cid_selectors_for_action(action: ModuleAction, runner: RunnerArgs, mod_short: str) -> None:
    if action.accepts_cid_flags:
        return
    if runner.cids or runner.current_cid or runner.all_cids:
        print(
            f"{UtilityTools.YELLOW}[!] {mod_short} ignores compartment selectors "
            f"(--cids/--current-cid/--all-cids). Running once.{UtilityTools.RESET}"
        )
    runner.cids = []
    runner.current_cid = False
    runner.all_cids = False


def _has_flag(args: Sequence[str], flag: str) -> bool:
    for tok in args or []:
        if tok == flag or tok.startswith(f"{flag}="):
            return True
    return False


def _apply_enum_all_scope_defaults(
    session,
    runner: RunnerArgs,
    mod_short: str,
    passthrough_args: Sequence[str],
) -> List[str]:
    out = list(passthrough_args or [])
    if mod_short != "enum_all":
        return out

    # "Current only" must mean root-only scan for enum_all.
    if _has_flag(out, "--no-recursive-compartments"):
        return out

    force_current_only = bool(runner.current_cid)
    if (not force_current_only) and (not runner.cids) and (not runner.all_cids):
        force_current_only = (
            getattr(session, "last_scope_choice", None) == "current"
            and bool(getattr(session, "last_scope_choice_explicit", False))
        )

    if force_current_only:
        out.append("--no-recursive-compartments")

    return out


def _plan_execution(session, action: ModuleAction, runner: RunnerArgs, mod_short: str) -> tuple[Optional[ExecutionPlan], Optional[str]]:
    if action.exec_mode == ExecMode.ONCE:
        ctx = resolve_context_cid(session, mode=action.context_mode)
        if action.context_mode != ContextMode.NONE and ctx is None:
            return None, f"{UtilityTools.RED}[X] No compartment selected.{UtilityTools.RESET}"

        roots: List[str] = []
        if runner.cids:
            roots = _normalize_cids(list(runner.cids))
        elif runner.current_cid:
            cur = getattr(session, "compartment_id", None)
            roots = [cur] if cur else []
        elif runner.all_cids:
            roots = ["__ALL_DISCOVERED__"]
        else:
            if mod_short == "enum_all" and getattr(session, "last_scope_choice", None) == "all":
                roots = ["__ALL_DISCOVERED__"]
            else:
                roots = [ctx] if ctx else []

        return (
            ExecutionPlan(
                run_once=True,
                context_cid=ctx,
                target_cids=[],
                target_root_cids=roots,
            ),
            None,
        )

    targets = resolve_targets_for_per_target(session, runner)
    if not targets:
        return None, f"{UtilityTools.RED}[X] No target compartments selected.{UtilityTools.RESET}"
    return (
        ExecutionPlan(
            run_once=False,
            context_cid=None,
            target_cids=targets,
            target_root_cids=[],
        ),
        None,
    )


# =============================================================================
# Entry point
# =============================================================================

def interact_with_module(session, module_path: str, module_args: Sequence[str]) -> int:
    def _safe_setattr(obj: Any, attr: str, value: Any) -> None:
        try:
            setattr(obj, attr, value)
        except Exception:
            pass

    try:
        runner = _parse_runner_args(module_args)
        passthrough_args = list(runner.passthrough)

        # Workspace default: auto-pass --save unless explicitly disabled for this run.
        if not runner.save and not runner.no_save:
            try:
                runner.save = bool(getattr(session, "config_module_auto_save", True))
            except Exception:
                runner.save = True

        # Apply runner-level flags globally
        if runner.debug:
            _safe_setattr(session, "debug", True)
            _safe_setattr(session, "individual_run_debug", True)
            if hasattr(UtilityTools, "set_debug"):
                try:
                    UtilityTools.set_debug(True)
                except Exception:
                    pass

        if runner.proxy:
            _safe_setattr(session, "individual_run_proxy", runner.proxy)

        module_import_path = module_path.replace("/", ".")
        passthrough_args = _merge_common_module_flags(module_import_path, runner, passthrough_args)
        action = get_module_action(module_import_path)
        mod_short = module_import_path.split(".")[-1]

        has_cid_selector_count = _cid_selector_count(runner)
        if has_cid_selector_count > 1:
            print(
                f"{UtilityTools.RED}[X] Use only one CID selector: "
                f"--cids OR --current-cid OR --all-cids.{UtilityTools.RESET}"
            )
            return -1

        _sanitize_cid_selectors_for_action(action, runner, mod_short)

        # Auth gate
        if action.auth_mode == AuthMode.AUTH and getattr(session, "credentials", None) is None:
            print(
                f"{UtilityTools.RED}{UtilityTools.BOLD}[X] [{ErrorCode.AUTH_REQUIRED}] "
                f"Credentials are None. Load creds or run an unauth module.{UtilityTools.RESET}"
            )
            return -1

        module = importlib.import_module(module_import_path)

        # Help passthrough
        if "-h" in passthrough_args or "--help" in passthrough_args:
            _invoke_run_module(module, passthrough_args, session)
            return 0

        plan, plan_error = _plan_execution(session, action, runner, mod_short)
        if not plan:
            print(plan_error or f"{UtilityTools.RED}[X] Failed to plan module execution.{UtilityTools.RESET}")
            return -1

        passthrough_args = _apply_enum_all_scope_defaults(session, runner, mod_short, passthrough_args)

        _safe_setattr(session, "target_root_cids", list(plan.target_root_cids))

        if plan.run_once:
            run_res = _execute_module_for_target(
                session,
                module,
                mod_short=mod_short,
                target_cid=plan.context_cid,
                passthrough_args=passthrough_args,
            )
            if not run_res.ok:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] "
                    f"[{run_res.error_code or ErrorCode.MODULE_EXECUTION_FAILED}] "
                    f"Module run failed: {run_res.message}{UtilityTools.RESET}"
                )
                return -1
            return 0

        failures: List[tuple[str, OperationResult]] = []

        for cid in plan.target_cids:
            run_res = _execute_module_for_target(
                session,
                module,
                mod_short=mod_short,
                target_cid=cid,
                passthrough_args=passthrough_args,
            )
            if not run_res.ok:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] "
                    f"[{run_res.error_code or ErrorCode.MODULE_EXECUTION_FAILED}] "
                    f"Module run failed for {cid}: {run_res.message}{UtilityTools.RESET}"
                )
                failures.append((cid, run_res))

        if failures:
            print(
                f"{UtilityTools.YELLOW}[!] {mod_short} completed with failures on "
                f"{len(failures)}/{len(plan.target_cids)} target compartments.{UtilityTools.RESET}"
            )
            return -1

        return 0

    except KeyboardInterrupt:
        return 0
    except Exception:
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] [{ErrorCode.MODULE_EXECUTION_FAILED}] "
            f"A generic error occurred while executing the module. Details below:{UtilityTools.RESET}"
        )
        print(traceback.format_exc())
        return -1
