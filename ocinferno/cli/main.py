import argparse
from typing import List, Tuple, Optional
import json

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
        name = input("> New workspace name: ").strip()
        if 1 <= len(name) <= 80:
            workspace_id = create_workspace(dc, name)
            if workspace_id:
                return name, workspace_id
        else:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Name must be between 1 and 80 characters.{UtilityTools.RESET}")

def list_workspaces(workspaces: List[Tuple[int, str]]) -> None:
    print("[*] Found existing sessions:")
    print("  [0] Create new workspace")
    for idx, name in workspaces:
        print(f"  [{idx}] {name}")
    print(f"  [{len(workspaces)+1}] Exit")

def choose_workspace(
    workspaces: List[Tuple[int, str]],
    dc: DataController,
    startup_auth_proxy: Optional[str] = None,
    startup_silent: bool = False,
) -> None:
    workspace_map = {idx: name for idx, name in workspaces}

    while True:
        try:
            choice = int(input("Choose an option: ").strip())
            break
        except ValueError:
            print("Please enter a valid number.")

    if choice == 0:
        name, workspace_id = prompt_new_workspace(dc)
        workspace_instructions(
            workspace_id,
            name,
            startup_auth_proxy=startup_auth_proxy,
            startup_silent=startup_silent,
        )
    elif choice == len(workspaces) + 1:
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

def main() -> None:
    parser = argparse.ArgumentParser(add_help=True)
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
    args = parser.parse_args()

    dc = DataController()
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
    
    # If workspaces exist presetn options and have user choose one
    else:
        list_workspaces(workspaces)
        choose_workspace(
            workspaces,
            dc,
            startup_auth_proxy=args.auth_proxy,
            startup_silent=args.silent,
        )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Interrupted. Exiting.")
        raise SystemExit(130)
