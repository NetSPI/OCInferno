import argparse
import json
import sys
from importlib import resources
from typing import List, Tuple, Optional

# Patch socket.getaddrinfo BEFORE any OCI SDK imports so DNS resolution for
# non-existent regional endpoints times out quickly (10 s) instead of blocking
# for 30-90 s (glibc retries search-domain variants against every nameserver).
# The DnsTimeoutError raised here is NOT an OSError subclass, which prevents the
# OCI pagination DEFAULT_RETRY_STRATEGY from treating it as a retriable
# ConnectionError (else it would retry 8× for a 80+ s total hang).
from ocinferno.core.net_util import install_dns_timeout
install_dns_timeout()

from ocinferno.cli.workspace_instructions import workspace_instructions
from ocinferno.core.db import DataController
from ocinferno.core.console import UtilityTools

def create_workspace(dc: DataController, workspace_name: str) -> Optional[int]:
    workspace_name = (workspace_name or "").strip()
    if workspace_name.isdigit():
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Workspace name cannot be numeric-only."
            f" Use a descriptive name (for example: TEST, PROD, LAB).{UtilityTools.RESET}"
        )
        return None

    existing_names = dc.fetch_all_workspace_names()
    if workspace_name in existing_names:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] A workspace with that name already exists.{UtilityTools.RESET}")
        return None

    starting_config_data = {
        "proxy": None,
        "current_default_region": "",
        "module_auto_save": True,
    }

    starting_config_data_json_blob = json.dumps(starting_config_data)

    workspace_id = dc.insert_workspace(workspace_name, starting_config_data_json_blob)
    if workspace_id:
        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Workspace '{workspace_name}' created.{UtilityTools.RESET}")
        return workspace_id

    print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed to create workspace.{UtilityTools.RESET}")
    return None

def prompt_new_workspace(dc: DataController) -> Tuple[str, int]:
    while True:
        try:
            name = input("> New workspace name: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            raise SystemExit(0)
        if 1 <= len(name) <= 80:
            workspace_id = create_workspace(dc, name)
            if workspace_id:
                return name, workspace_id
        else:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Name must be between 1 and 80 characters.{UtilityTools.RESET}")

def list_workspaces(workspaces: List[Tuple[int, str]]) -> None:
    # Exit sentinel is max DB primary key + 1 so it never collides with a real
    # workspace ID after rows have been deleted (IDs are not necessarily 1..N).
    exit_num = max(idx for idx, _ in workspaces) + 1 if workspaces else 1
    print("[*] Found existing sessions:")
    print("  [0] Create new workspace")
    for idx, name in workspaces:
        print(f"  [{idx}] {name}")
    print(f"  [{exit_num}] Exit")
    return exit_num

def choose_workspace(
    workspaces: List[Tuple[int, str]],
    dc: DataController,
    startup_auth_proxy: Optional[str] = None,
    startup_silent: bool = False,
) -> None:
    workspace_map = {idx: name for idx, name in workspaces}
    exit_num = max(workspace_map) + 1 if workspace_map else 1

    while True:
        try:
            choice = int(input("Choose an option: ").strip())
            break
        except ValueError:
            print("Please enter a valid number.")
        except (EOFError, KeyboardInterrupt):
            print()
            raise SystemExit(0)

    if choice == 0:
        name, workspace_id = prompt_new_workspace(dc)
        workspace_instructions(
            workspace_id,
            name,
            startup_auth_proxy=startup_auth_proxy,
            startup_silent=startup_silent,
        )
    elif choice == exit_num:
        exit()
    elif choice in workspace_map:
        workspace_instructions(
            choice,
            workspace_map[choice],
            startup_auth_proxy=startup_auth_proxy,
            startup_silent=startup_silent,
        )
    else:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Invalid workspace selected. Quitting...{UtilityTools.RESET}")
        exit()


# =============================================================================
# Non-interactive `--module` passthrough (scripting / CI / one-shot runs)
# =============================================================================

def _load_module_lookup() -> dict:
    """Build {short module_name|dotted location -> dotted location} from the registry.

    Mirrors the resolution the REPL uses (CommandProcessor._module_name_to_path) but
    keys by BOTH the short name and the full location so either token resolves. Reads
    the packaged mappings resource (works for wheel install and repo source).
    """
    try:
        candidate = resources.files("ocinferno.mappings").joinpath("module_mappings.json")
        rows = json.loads(candidate.read_text(encoding="utf-8")).get("modules", []) or []
    except Exception:
        return {}
    lookup: dict = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("module_name") or "").strip()
        location = str(row.get("location") or "").strip()
        if not location:
            continue
        if name:
            lookup[name] = location
        lookup[location] = location
    return lookup


def _resolve_module_path(module_token: str) -> str:
    """Resolve a user-supplied module token to a dotted import path, or "" if unknown.

    Accepts a registered short name (e.g. ``enum_comp``), a full dotted import path, or
    the trailing short name of a dotted path. Falls back to any dotted token (an import
    error surfaces later) so an unregistered-but-valid path still runs.
    """
    token = str(module_token or "").strip().replace("/", ".")
    if not token:
        return ""
    lookup = _load_module_lookup()
    if token in lookup:
        return lookup[token]
    short_name = token.split(".")[-1]
    if short_name in lookup:
        return lookup[short_name]
    return token if "." in token else ""


def _resolve_workspace_by_name(dc: DataController, workspace_name: str) -> Optional[Tuple[int, str]]:
    """Return (workspace_id, name) for an existing workspace matched by exact name, else None."""
    target = str(workspace_name or "").strip()
    if not target:
        return None
    for workspace_id, name in dc.get_workspaces() or []:
        if str(name or "").strip() == target:
            return int(workspace_id), str(name)
    return None


def _close_session(session) -> None:
    """Best-effort close of a session's DataController (process is exiting anyway)."""
    try:
        data_master = getattr(session, "data_master", None)
        if data_master is not None:
            data_master.close()
    except Exception:
        pass


def run_authenticated_module_passthrough(
    module_name: str,
    module_args: List[str],
    *,
    workspace_name: str,
    credname: str,
    startup_auth_proxy: Optional[str] = None,
) -> int:
    """Run one module non-interactively against a stored credential; return a process exit code.

    The "drive-through": resolve the module and the named workspace, load the named
    credential into a real SessionUtility (resume mode -> load_stored_creds sets
    .credentials / .compartment_id), then dispatch via interact_with_module. Compartment
    scope flows through the module args (--cids / --current-cid / --all-cids), which the
    runner in module_actions consumes. Returns 0 only when the module succeeds. Prints
    actionable errors (with the available workspaces / credentials) on a bad name.
    """
    from ocinferno.cli.module_actions import interact_with_module
    from ocinferno.core.session import SessionUtility

    if not str(workspace_name or "").strip():
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] --workspace <name> is required (the workspace that holds the credential).{UtilityTools.RESET}")
        return 1
    if not str(credname or "").strip():
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] --cred <credname> is required (the stored credential to load).{UtilityTools.RESET}")
        return 1

    module_import_path = _resolve_module_path(module_name)
    if not module_import_path:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Unknown module: {module_name}{UtilityTools.RESET}")
        known = sorted(key for key in _load_module_lookup().keys() if not key.startswith("ocinferno.modules."))
        if known:
            print(f"[*] Available modules: {', '.join(known)}")
        return 1

    with DataController() as dc:
        resolved = _resolve_workspace_by_name(dc, workspace_name)
        if not resolved:
            available = sorted(str(name or "").strip() for _, name in (dc.get_workspaces() or []))
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] No workspace named '{workspace_name}'.{UtilityTools.RESET}")
            available = [name for name in available if name]
            if available:
                print(f"[*] Available workspaces: {', '.join(available)}")
            else:
                print("[*] No workspaces exist yet. Create one via the interactive REPL first.")
            return 1
        workspace_id, resolved_name = resolved
        available_creds = sorted(
            {str(row[0]).strip() for row in (dc.list_creds(workspace_id) or []) if row and row[0]}
        )

    session = None
    try:
        session = SessionUtility(
            workspace_id,
            resolved_name,
            credname,
            None,
            resume=True,
            startup_auth_proxy=startup_auth_proxy,
        )
    except Exception as exc:
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed to load credential '{credname}' "
            f"in workspace '{resolved_name}': {exc}{UtilityTools.RESET}"
        )
        _close_session(session)
        return 1

    if getattr(session, "credentials", None) is None:
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Could not load credential '{credname}' "
            f"in workspace '{resolved_name}'.{UtilityTools.RESET}"
        )
        if available_creds:
            print(f"[*] Available credentials in '{resolved_name}': {', '.join(available_creds)}")
        else:
            print(f"[*] Workspace '{resolved_name}' has no stored credentials; add one via the interactive REPL first.")
        _close_session(session)
        return 1

    cleaned_args = list(module_args or [])
    if cleaned_args and cleaned_args[0] == "--":
        cleaned_args = cleaned_args[1:]

    print(
        f"[*] Drive-through: workspace='{resolved_name}' (id={workspace_id}) "
        f"cred='{session.credname}' compartment='{session.compartment_id}'"
    )
    print(f"[*] Running module: {module_import_path}")
    try:
        result = interact_with_module(session, module_import_path, cleaned_args)
        return 0 if result == 0 else 1
    finally:
        _close_session(session)


def _add_arguments(parser: argparse.ArgumentParser) -> None:
    """Register the shared startup + passthrough flags on a parser."""
    parser.add_argument(
        "--auth-proxy",
        dest="auth_proxy",
        default=None,
        help=(
            "Startup-only proxy for credential auth exchanges during add/load at launch "
            "(does not apply to module API traffic, set that in configs or per proxy). "
            "Format: host:port or http(s)://host:port."
        ),
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Start OCInferno without printing the initial help banner.",
    )
    parser.add_argument(
        "--module",
        dest="module_name",
        default=None,
        help=(
            "Run a single module non-interactively (no REPL). Requires --workspace <name> "
            "and --cred <credname>. Accepts a short module name (e.g. enum_comp) or a full "
            "dotted import path. Unknown flags pass through to the module (e.g. --cids, "
            "--current-cid, --all-cids, --get)."
        ),
    )
    parser.add_argument(
        "--workspace",
        dest="workspace_name",
        default="",
        help="Non-interactive drive-through: name of the workspace that holds the credential.",
    )
    parser.add_argument(
        "--cred",
        "--credname",
        dest="credname",
        default="",
        help="Non-interactive drive-through: name of the stored credential to load (requires --workspace).",
    )

def main() -> None:
    raw_argv = list(sys.argv[1:])

    # First pass (no --help, tolerate unknown flags) detects `--module`. When present we
    # dispatch a one-shot module run and SystemExit with its code, forwarding every
    # unknown flag straight to the module (so e.g. --cids / --get reach the runner).
    passthrough_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    _add_arguments(passthrough_parser)
    passthrough_args, unknown_args = passthrough_parser.parse_known_args(raw_argv)

    if passthrough_args.module_name:
        raise SystemExit(
            run_authenticated_module_passthrough(
                passthrough_args.module_name,
                list(unknown_args),
                workspace_name=passthrough_args.workspace_name,
                credname=passthrough_args.credname,
                startup_auth_proxy=passthrough_args.auth_proxy,
            )
        )

    parser = argparse.ArgumentParser(add_help=True)
    _add_arguments(parser)
    args = parser.parse_args(raw_argv)

    dc = DataController()
    try:
        workspaces = dc.get_workspaces()

        # If we have no existing workspaces prompt for a new one
        if not workspaces:
            print("[*] No workspaces detected. Please create your first workspace.")
            name, workspace_id = prompt_new_workspace(dc)
            workspace_instructions(
                workspace_id,
                name,
                startup_auth_proxy=args.auth_proxy,
                startup_silent=args.silent,
            )

        # If workspaces exist present options and have user choose one
        else:
            list_workspaces(workspaces)
            choose_workspace(
                workspaces,
                dc,
                startup_auth_proxy=args.auth_proxy,
                startup_silent=args.silent,
            )
    finally:
        dc.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Interrupted. Exiting.")
        raise SystemExit(130)
