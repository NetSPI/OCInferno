# Standard libraries
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import re
import shlex
import subprocess
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from importlib import resources

from ocinferno.cli.module_actions import interact_with_module
from ocinferno.core.config import CONFIG_VALUE_CHOICES, KNOWN_OCI_REGIONS, WORKSPACE_CONFIG_KEYS
from ocinferno.core.session import SessionUtility
from ocinferno.core.console import UtilityTools
from ocinferno.core.db import DataController
from ocinferno.core.utils.module_helpers import (
    export_compartment_tree_image,
    export_sqlite_dbs_to_csv_blob,
    export_sqlite_dbs_to_excel_blob,
    export_sqlite_dbs_to_json_blob,
)


def help_banner():
    banner = r"""
                   (  .      )
              )           (              )
                   )   )      (   (
            (   (  (  .  '   .   '  .  '  .   )  )
             )  )  )   )    (   )    (   (  (   (
          (   .   (   .  )  (  .  )  (   )  .   )
            . '  )  )  (  )  )  (  (  )  (  '  .
         )  (  .  (   )  .  (   .   )  (   )  (  (
       (_,) . ), ) _) _,')  (, ) '. )  ,. (' )
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
           Welcome to OCInferno.
       Shed light. Enumerate everything.

OCInferno (O-C-Inferno) - https://github.com/NetSPI/ocinferno
Written and researched by Scott Weston (@WebbinRoot) of NetSPI

Like Pacu for AWS, this tool is built for red teamers and offensive security pros.
Wiki: https://github.com/NetSPI/gcpwn/wiki

─────────────────────────────────────────────
OCInferno Commands:

    creds
        me/me-full/list/list-full/db-row         Active credential/Active credential with secrets/List all credentials/List all credentials with secrets/List raw stored credential JSON (sensitive)
        swap [<credname>]                          Swap credentials (interactive if omitted)

    modules
        list                                        List all modules
        search <keyword>                            Search module by keyword
        run <module_name> [--cids ...]              Execute a module

    compartments
        list                                        Print known compartment tree
        add  <compartment_id>                       Add compartment to known list
        set  [<compartment_id>]                     Set current compartment (pick if omitted)
        rm   <compartment_id>                       Remove compartment from known list

    data
        export <csv|json|excel|treeimage> [--out-dir ...] [--out-file ...]
                                                    Unified data export command
                                                    csv: service DB rows in one flat CSV (includes resource=table name)
                                                    json: service DB tables as JSON blob (rows include resource)
                                                    excel: one workbook for service DB (single-sheet condensed format)
                                                    treeimage: compartment hierarchy graph (SVG with built-in pan/zoom)
        sql --db <service|metadata> <SQL>
                                                    Run SQL directly against SQLite tables
                                                    example: data sql --db service "SELECT * FROM compute_instances LIMIT 25"
        wipe-service [--all-workspaces] [--yes]
                                                    Delete rows from service DB tables
                                                    default scope: ALL service tables for current workspace_id
                                                    (tables without workspace_id are skipped)
                                                    add --all-workspaces to wipe all workspace rows

    configs
        list | set | unset | regions list           Workspace configs / known regions

        Keys:
          proxy | current_default_region
          rate_limit_seconds            (float seconds; default 0)
          rate_limit_jitter_seconds     (float seconds; default 0)
          api_logging_enabled            (true/false; default false)
          api_logging_file_path          (path; defaults to ./ocinferno_output/<slug>/tool_logs/telemetry_api.log)
          api_logging_verbosity          (basic|standard|verbose; default standard)
          api_logging_attributes         (comma list; e.g. "ts,url,method,status,args,duration_ms")
          std_output_format              (table|txt; default table)
          note: unknown default regions are allowed with warning (for dedicated/private realms)

    help / ?                                      Show this help banner
    exit / quit                                   Exit OCInferno
─────────────────────────────────────────────
Welcome to your workspace! Type 'help' or '?' to get started.
    """
    print(banner)

class CommandProcessor:

    # Path to where module defintions are
    @staticmethod
    def _resolve_module_mappings_path() -> str:
        # Load only packaged resource path (works for both installed wheel and repo source).
        try:
            candidate = resources.files("ocinferno.mappings").joinpath("module-mappings.json")
            if candidate.is_file():
                return str(candidate)
        except Exception as exc:
            raise FileNotFoundError(
                "Required resource 'mappings/module-mappings.json' is missing. "
                "Reinstall/upgrade OCInferno in a clean environment."
            ) from exc
        raise FileNotFoundError(
            "Required resource 'mappings/module-mappings.json' is missing. "
            "Reinstall/upgrade OCInferno in a clean environment."
        )

    # List of commands and flags allowed
    CREDS_SUBCOMMANDS = ["me", "me-full", "list", "list-full", "db-row", "swap"]
    MODULES_SUBCOMMANDS = ["list", "search", "run"]
    COMPARTMENTS_SUBCOMMANDS = ["list", "add", "set", "rm"]
    CONFIGS_SUBCOMMANDS = ["list", "set", "unset", "regions"]
    DATA_SUBCOMMANDS = ["export", "sql", "wipe-service"]
    EXPORT_FORMATS = ["csv", "json", "excel", "treeimage"]
    EXPORT_FLAGS = ["--out-dir", "--out-file"]
    DATA_SQL_HINTS = ["--db", "service", "metadata"]
    DATA_WIPE_FLAGS = ["--all-workspaces", "--yes"]

    def __init__(self, workspace_id: int, session: SessionUtility):

        # Store incoming workspace info and session to class as class
        # will be re-used in infinite loop for user input
        self.workspace_id = int(workspace_id)
        self.session = session

        # create caches to be used later
        self._user_display_name_cache: Dict[str, str] = {}
        self._compartment_name_cache: Dict[str, str] = {}
        self._identity_domain_for_user_cache: Dict[str, Dict[str, str]] = {}
        self._module_cli_flag_cache: Dict[str, List[str]] = {}

        # Load in all our module info and build a name --> path for easy caching later
        self.MODULE_MAPPINGS_JSON_PATH = self._resolve_module_mappings_path()
        self._module_rows: List[Dict[str, str]] = json.loads(
            Path(self.MODULE_MAPPINGS_JSON_PATH).read_text(encoding="utf-8")
        )["modules"]
        self._module_name_to_path: Dict[str, str] = {
            str(row["module_name"]): str(row["location"])
            for row in self._module_rows
        }
        self._module_names: List[str] = sorted(self._module_name_to_path.keys())

        # Setup a parser object to parse incoming user arguments
        self.parser = argparse.ArgumentParser(prog="OCInferno", description="OCInferno CLI")
        self.subparsers = self.parser.add_subparsers(dest="subcommand")

        # Create the main sub-commands for later use in setup_parsers
        self.command_handlers = {
            "creds": self.process_creds_command,
            "modules": self.process_modules_command,
            "configs": self.process_configs_command,
            "data": self.process_data_command,
            "compartments": self.process_compartments_command,
            "oci": self.run_passthrough_command,
            "help": lambda *_: help_banner(),
            "?": lambda *_: help_banner(),
            "exit": lambda *_: -1,
            "quit": lambda *_: -1,
        }

        self.setup_parsers()

    # -----------------------------
    # Readline completion
    # -----------------------------
    @property
    def _top_level_commands(self) -> List[str]:
        return [
            "creds",
            "modules",
            "compartments",
            "configs",
            "data",
            "oci",
            "help",
            "?",
            "exit",
            "quit",
        ]

    @staticmethod
    def _match_prefix(candidates: List[str], prefix: str) -> List[str]:
        p = (prefix or "").strip()
        out = [c for c in candidates if c.startswith(p)]
        return sorted(out)

    def _complete_simple_subcommands(self, args: List[str], trailing_space: bool, subcommands: List[str]) -> List[str]:
        if not args and trailing_space:
            return subcommands
        if len(args) == 1 and not trailing_space:
            return self._match_prefix(subcommands, args[0])
        return []

    def _complete_modules(self, args: List[str], trailing_space: bool) -> List[str]:
        basic = self._complete_simple_subcommands(args, trailing_space, self.MODULES_SUBCOMMANDS)
        if basic:
            return basic
        if not args:
            return []
        subcmd = args[0]
        if len(args) == 1 and trailing_space and subcmd == "run":
            return self._module_names
        if len(args) == 2 and not trailing_space and subcmd == "run":
            return self._match_prefix(self._module_names, args[1])
        return []

    def _complete_creds(self, args: List[str], trailing_space: bool) -> List[str]:
        return self._complete_simple_subcommands(args, trailing_space, self.CREDS_SUBCOMMANDS)

    def _complete_compartments(self, args: List[str], trailing_space: bool) -> List[str]:
        return self._complete_simple_subcommands(args, trailing_space, self.COMPARTMENTS_SUBCOMMANDS)

    def _complete_configs(self, args: List[str], trailing_space: bool) -> List[str]:
        basic = self._complete_simple_subcommands(args, trailing_space, self.CONFIGS_SUBCOMMANDS)
        if basic:
            return basic
        if not args:
            return []

        subcmd = args[0]
        keys = list(WORKSPACE_CONFIG_KEYS)
        if subcmd == "regions":
            if len(args) == 1 and trailing_space:
                return ["list"]
            if len(args) == 2 and not trailing_space:
                return self._match_prefix(["list"], args[1])
            return []

        if subcmd in ("set", "unset"):
            if len(args) == 1 and trailing_space:
                return keys
            if len(args) == 2 and not trailing_space:
                return self._match_prefix(keys, args[1])

            if subcmd == "set" and len(args) >= 2:
                key = args[1]
                if key in CONFIG_VALUE_CHOICES:
                    vals = list(CONFIG_VALUE_CHOICES[key])
                    if len(args) == 2 and trailing_space:
                        return vals
                    if len(args) == 3 and not trailing_space:
                        return self._match_prefix(vals, args[2])
                if key == "current_default_region":
                    regions = list(KNOWN_OCI_REGIONS)
                    if len(args) == 2 and trailing_space:
                        return regions
                    if len(args) == 3 and not trailing_space:
                        return self._match_prefix(regions, args[2].lower())
        return []

    def _complete_data(self, args: List[str], trailing_space: bool) -> List[str]:
        basic = self._complete_simple_subcommands(args, trailing_space, self.DATA_SUBCOMMANDS)
        if basic:
            return basic
        if not args:
            return []
        subcmd = args[0]
        if subcmd == "export":
            if len(args) == 1 and trailing_space:
                return self.EXPORT_FORMATS
            if len(args) == 2 and not trailing_space:
                return self._match_prefix(self.EXPORT_FORMATS, args[1])
            if len(args) >= 2:
                current = args[-1]
                if trailing_space:
                    return self.EXPORT_FLAGS
                if current.startswith("-"):
                    return self._match_prefix(self.EXPORT_FLAGS, current)
            return []
        if subcmd == "sql" and len(args) == 1 and trailing_space:
            return self.DATA_SQL_HINTS
        if subcmd == "wipe-service":
            if len(args) == 1 and trailing_space:
                return self.DATA_WIPE_FLAGS
            if len(args) == 2 and not trailing_space:
                return self._match_prefix(self.DATA_WIPE_FLAGS, args[1])
        return []

    def _command_candidates(self, line_buffer: str) -> List[str]:
        line = (line_buffer or "").lstrip()
        tokens = line.split()
        trailing_space = line.endswith(" ")

        # Empty prompt -> top-level commands
        if not tokens:
            return self._top_level_commands

        # Completing first token
        if len(tokens) == 1 and not trailing_space:
            return self._match_prefix(self._top_level_commands, tokens[0])

        cmd = tokens[0]
        args = tokens[1:]
        handlers = {
            "modules": self._complete_modules,
            "creds": self._complete_creds,
            "compartments": self._complete_compartments,
            "configs": self._complete_configs,
            "data": self._complete_data,
        }
        handler = handlers.get(cmd)
        if not handler:
            return []
        return handler(args, trailing_space)

    def readline_complete(self, text: str, state: int):
        import readline

        line = readline.get_line_buffer()
        candidates = self._command_candidates(line)
        if not candidates:
            return None
        if state < len(candidates):
            return candidates[state]
        return None

    def process_command(self, command: str):
        try:
            args = self.parser.parse_args(shlex.split(command))
            cmd = args.subcommand
            handler = self.command_handlers.get(cmd)
            if handler:
                return handler(args)
            print(f"[X] Unknown command '{cmd}'. Type 'help'")
        except SystemExit:
            pass
        except Exception as e:
            print(f"[X] Failed to process command: {e}")

    def setup_parsers(self):

        # Add a parser for each of these commands that either prints or exists
        for cmd in ["help", "?", "exit", "quit"]:
            self.subparsers.add_parser(cmd)

        # Add parser for oci to just run oci commands and add argumetn as rest of commands
        oci_p = self.subparsers.add_parser("oci")
        oci_p.add_argument("oci_args", nargs=argparse.REMAINDER)

        # Setup each parser for creds, modules, data, configs, and compartments
        self.setup_creds_parsers()
        self.setup_module_parsers()
        self.setup_data_parsers()
        self.setup_configs_parsers()
        self.setup_compartment_parsers()

    def run_passthrough_command(self, args):
        cmd_list = getattr(args, "oci_args", []) or []
        if cmd_list:
            try:
                subprocess.run(["oci", *cmd_list], check=False)
            except OSError as e:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed to run `oci`:{UtilityTools.RESET} "
                    f"{type(e).__name__}: {e}"
                )
        else:
            print("[X] No arguments passed to `oci`.")

    # -----------------------------
    # Creds parsers
    # -----------------------------
    def setup_creds_parsers(self):
        creds = self.subparsers.add_parser("creds")
        sub = creds.add_subparsers(dest="creds_subcommand")

        sub.add_parser("me")
        sub.add_parser("me-full")
        sub.add_parser("list")
        sub.add_parser("list-full")
        sub.add_parser("db-row").add_argument("credname", nargs="?")
        sub.add_parser("swap").add_argument("credname", nargs="?")

    # -----------------------------
    # Module parsers
    # -----------------------------
    def setup_module_parsers(self):
        mods = self.subparsers.add_parser("modules")
        sub = mods.add_subparsers(dest="modules_subcommand")

        sub.add_parser("list")
        sub.add_parser("search").add_argument("search_term")

        run = sub.add_parser("run")
        run.add_argument("module_name")
        run.add_argument("module_args", nargs=argparse.REMAINDER)

    # -----------------------------
    # Data parsers (placeholder)
    # -----------------------------
    def setup_data_parsers(self):
        data = self.subparsers.add_parser("data")
        sub = data.add_subparsers(dest="data_subcommand")

        export = sub.add_parser("export")
        export.add_argument(
            "format",
            choices=("csv", "json", "excel", "treeimage"),
            help="Export format.",
        )
        export.add_argument(
            "--out-dir",
            default="",
            help="Output directory (default: workspace export path).",
        )
        export.add_argument(
            "--out-file",
            default="",
            help="Single output path (format-specific).",
        )

        sql = sub.add_parser("sql")
        sql.add_argument(
            "--db",
            choices=("service", "metadata"),
            default="service",
            help="Target SQLite DB (default: service).",
        )
        sql.add_argument(
            "query",
            nargs=argparse.REMAINDER,
            help="SQL query to execute (wrap in quotes).",
        )

        wipe = sub.add_parser("wipe-service")
        wipe.add_argument(
            "--all-workspaces",
            action="store_true",
            help="Wipe service DB rows for all workspaces (tables with workspace_id only).",
        )
        wipe.add_argument(
            "--yes",
            action="store_true",
            help="Skip interactive confirmation prompt.",
        )

    # -----------------------------
    # Config parsers (UPDATED)
    # -----------------------------
    def setup_configs_parsers(self):
        config = self.subparsers.add_parser("configs")
        sub = config.add_subparsers(dest="configs_subcommand")

        sub.add_parser("list")

        set_cmd = sub.add_parser("set")
        set_cmd.add_argument(
            "key",
            help=(
                " | ".join(WORKSPACE_CONFIG_KEYS)
            ),
        )
        set_cmd.add_argument("value", help="Value to set")

        unset_cmd = sub.add_parser("unset")
        unset_cmd.add_argument(
            "key",
            help=(
                " | ".join(WORKSPACE_CONFIG_KEYS)
            ),
        )

        regions_cmd = sub.add_parser("regions", help="Region helpers")
        regions_sub = regions_cmd.add_subparsers(dest="configs_regions_subcommand")
        regions_sub.add_parser("list", help="List known OCI regions")

    def _print_known_regions(self) -> None:
        cfg = self.session.get_config_keys(self.workspace_id) or {}
        default_region = str(cfg.get("current_default_region") or "").strip().lower()
        gov_regions = {"us-langley-1", "us-luke-1"}
        commercial = [r for r in sorted(KNOWN_OCI_REGIONS) if r not in gov_regions]
        government = [r for r in sorted(KNOWN_OCI_REGIONS) if r in gov_regions]

        def _print_region(region_name: str) -> None:
            if region_name == default_region:
                print(f"  - {UtilityTools.BOLD}{UtilityTools.RED}{region_name}{UtilityTools.RESET}")
            else:
                print(f"  - {region_name}")

        print(f"{UtilityTools.BOLD}[*] Known OCI regions:{UtilityTools.RESET}")
        print(f"{UtilityTools.BOLD}  Commercial:{UtilityTools.RESET}")
        for region_name in commercial:
            _print_region(region_name)

        print(f"{UtilityTools.BOLD}  Government:{UtilityTools.RESET}")
        for region_name in government:
            _print_region(region_name)

    # -----------------------------
    # Compartment parsers
    # -----------------------------
    def setup_compartment_parsers(self):
        compartments = self.subparsers.add_parser("compartments")
        sub = compartments.add_subparsers(dest="compartments_subcommand")

        sub.add_parser("list")

        add_cmd = sub.add_parser("add")
        add_cmd.add_argument("compartment_id", help="Compartment OCID (required)")

        set_cmd = sub.add_parser("set")
        set_cmd.add_argument("compartment_id", nargs="?", help="Compartment OCID (optional; pick if omitted)")

        rm_cmd = sub.add_parser("rm")
        rm_cmd.add_argument("compartment_id", help="Compartment OCID (required)")

    # =========================================================================
    # Compartments printing + helpers (unchanged)
    # =========================================================================
    def print_compartment_hierarchy(self, rows, current_compartment_id=None):
        nodes = {}
        children = {}
        parent_of = {}

        for r in rows:
            if not isinstance(r, dict):
                continue
            cid = r.get("compartment_id") or r.get("id")
            if not isinstance(cid, str) or not cid:
                continue

            pid = r.get("parent_compartment_id") or None
            if isinstance(pid, str) and pid.strip().upper() == "N/A":
                pid = None

            is_tenant = UtilityTools.is_tenancy_ocid(cid)
            name = r.get("name") or r.get("display_name") or cid

            nodes[cid] = {"id": cid, "parent": pid, "is_tenant": is_tenant, "name": name}
            parent_of[cid] = pid
            children.setdefault(pid, []).append(cid)

        for pid, kid_list in children.items():
            kid_list.sort(key=lambda k: nodes[k]["name"].lower())

        roots = [cid for cid, n in nodes.items() if n["parent"] is None or n["is_tenant"]]
        roots.sort(key=lambda k: nodes[k]["name"].lower())

        tee, elbow, pipe, space = "├─ ", "└─ ", "│  ", "   "

        def label(node):
            base = node["name"] + " (" + node["id"] + ")"
            if node["is_tenant"]:
                base = f"{UtilityTools.BOLD}{UtilityTools.CYAN}{base} [TENANCY]{UtilityTools.RESET}"
            if node["id"] == current_compartment_id:
                base = f"{UtilityTools.BOLD}{UtilityTools.RED}{base}{UtilityTools.RESET}"
            return base

        def dfs(cid, prefix="", is_last=True, seen=None):
            if seen is None:
                seen = set()
            if cid in seen:
                print(prefix + (elbow if is_last else tee) + f"(cycle) {nodes[cid]['name']}")
                return
            seen.add(cid)

            branch = elbow if is_last else tee
            print(prefix + branch + label(nodes[cid]))

            kids = children.get(cid, [])
            for i, kid in enumerate(kids):
                last = (i == len(kids) - 1)
                new_prefix = prefix + (space if is_last else pipe)
                dfs(kid, new_prefix, last, seen)

        if current_compartment_id and current_compartment_id in nodes:
            trail = []
            cur = current_compartment_id
            while cur is not None:
                trail.append(nodes[cur]["name"])
                cur = parent_of.get(cur)
            trail = " / ".join(reversed(trail))
            print(f"{UtilityTools.BOLD}{UtilityTools.BRIGHT_GREEN}[*] Current path:{UtilityTools.RESET} {trail}")

        for ri, root in enumerate(roots):
            print(label(nodes[root]))
            kids = children.get(root, [])
            for i, kid in enumerate(kids):
                last = (i == len(kids) - 1)
                dfs(kid, "", last)
            if ri < len(roots) - 1:
                print()

    def add_compartment(self, cid: str) -> None:
        if not cid:
            return
        existing = [comp.get("compartment_id") for comp in self.session.global_compartment_list if isinstance(comp, dict)]
        if cid in existing:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {cid} already exists in the list.{UtilityTools.RESET}")
            return
        self.session.add_cid(cid)
        print(f"{UtilityTools.GREEN}[*] Added compartment: {cid}{UtilityTools.RESET}")

    def set_current_compartment(self, cid: str) -> None:
        if not cid:
            return
        existing = [comp.get("compartment_id") for comp in self.session.global_compartment_list if isinstance(comp, dict)]
        if cid not in existing:
            print(f"[!] {cid} not in known list. Adding...")
            self.session.add_cid(cid)
        self.session.compartment_id = cid
        print(f"{UtilityTools.GREEN}[*] Current compartment set to: {cid}{UtilityTools.RESET}")

    def remove_compartment(self, cid: str) -> None:
        if not cid:
            return
        self.session.purge_cid(cid)
        if self.session.compartment_id == cid:
            self.session.compartment_id = None
        print(f"{UtilityTools.GREEN}[*] Removed compartment: {cid}{UtilityTools.RESET}")

    def _comp_label(self, r: Dict[str, Any]) -> str:
        name = r.get("name") or r.get("display_name") or "<Unknown_Name>"
        cid = r.get("compartment_id") or r.get("id") or "unknown-ocid"
        return f"{UtilityTools.CYAN}{name}{UtilityTools.RESET}  {UtilityTools.BRIGHT_BLACK}({cid}){UtilityTools.RESET}"

    # =========================================================================
    # Command handlers
    # =========================================================================
    def process_compartments_command(self, args):
        subcmd = args.compartments_subcommand
        cid = getattr(args, "compartment_id", None)

        if subcmd in (None, "list"):
            self.print_compartment_hierarchy(
                self.session.global_compartment_list,
                current_compartment_id=self.session.compartment_id,
            )
            return

        if subcmd == "add":
            self.add_compartment(cid)
            return

        if subcmd == "set":
            if not cid:
                picked = UtilityTools._choose_from_list(
                    "Select a compartment to SET as current",
                    self.session.global_compartment_list,
                    self._comp_label,
                )
                if not picked:
                    return
                cid = picked.get("compartment_id") or picked.get("id")
            self.set_current_compartment(cid)
            return

        if subcmd == "rm":
            self.remove_compartment(cid)
            return

    # -----------------------------
    # Creds command (unchanged)
    # -----------------------------
    def _detect_auth_type(self, c: Dict[str, Any]) -> str:
        if c.get("auth_type"):
            return str(c["auth_type"]).lower()
        if c.get("key_content") or c.get("key_file") or c.get("fingerprint"):
            return "api_key"
        if c.get("delegation_token"):
            return "delegation_token"
        if c.get("security_token") or c.get("token"):
            return "security_token"
        if c.get("instance_principal") or c.get("use_instance_principal"):
            return "instance_principal"
        if c.get("resource_principal") or c.get("use_resource_principal"):
            return "resource_principal"
        return "unknown"

    def _ocid_short(self, ocid: Optional[str]) -> str:
        if not ocid or "ocid1." not in ocid:
            return "-"
        return f"{ocid[:12]}...{ocid[-6:]}"

    def _ocid_with_name(self, ocid: Optional[str], name: Optional[str]) -> str:
        oid = str(ocid or "").strip()
        if not oid:
            return "-"
        nm = str(name or "").strip()
        return f"{oid} ({nm})" if nm else oid

    def _safe_short(self, s: Optional[str], front=12, back=8) -> str:
        if not s:
            return "-"
        s = str(s)
        return s if len(s) <= front + back + 3 else f"{s[:front]}...{s[-back:]}"

    def _maybe_time(self, s: Optional[str]) -> str:
        if not s:
            return "-"
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt).strftime("%Y-%m-%d %H:%MZ")
            except Exception:
                pass
        return str(s)

    def _normalize_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for rec in records or []:
            outer_name = rec.get("credname")
            outer_compartment = rec.get("default_compartment_id")
            sc = rec.get("session_creds")

            if isinstance(sc, str):
                try:
                    sc = json.loads(sc)
                except Exception:
                    continue

            if isinstance(sc, list):
                for idx, entry in enumerate(sc, 1):
                    merged = dict(entry)
                    merged.setdefault("credname", outer_name)
                    merged.setdefault("default_compartment_id", outer_compartment)
                    merged["outer_credname"] = outer_name
                    merged["index"] = idx
                    out.append(merged)
            elif isinstance(sc, dict):
                merged = dict(sc)
                merged.setdefault("credname", outer_name)
                merged.setdefault("default_compartment_id", outer_compartment)
                merged["outer_credname"] = outer_name
                out.append(merged)
        return out

    def _lookup_user_display_name(self, user_ocid: str) -> str:
        oid = str(user_ocid or "").strip()
        if not oid:
            return ""
        if oid in self._user_display_name_cache:
            return self._user_display_name_cache[oid]

        resolved = ""
        try:
            rows = self.session.get_resource_fields(
                "identity_domain_users",
                columns=["display_name", "user_name"],
                where_conditions={"ocid": oid},
            ) or []
            if rows and isinstance(rows[0], dict):
                resolved = str(rows[0].get("display_name") or rows[0].get("user_name") or "").strip()
        except Exception:
            pass
        if not resolved:
            try:
                rows = self.session.get_resource_fields(
                    "identity_users",
                    columns=["name"],
                    where_conditions={"id": oid},
                ) or []
                if rows and isinstance(rows[0], dict):
                    resolved = str(rows[0].get("name") or "").strip()
            except Exception:
                pass

        self._user_display_name_cache[oid] = resolved
        return resolved

    def _lookup_compartment_name(self, compartment_ocid: str) -> str:
        cid = str(compartment_ocid or "").strip()
        if not cid:
            return ""
        if cid in self._compartment_name_cache:
            return self._compartment_name_cache[cid]

        resolved = ""
        try:
            rows = self.session.get_resource_fields(
                "resource_compartments",
                columns=["name", "display_name"],
                where_conditions={"compartment_id": cid},
            ) or []
            if rows and isinstance(rows[0], dict):
                resolved = str(rows[0].get("name") or rows[0].get("display_name") or "").strip()
        except Exception:
            pass
        self._compartment_name_cache[cid] = resolved
        return resolved

    def _lookup_identity_domain_for_user(self, user_ocid: str) -> Dict[str, str]:
        oid = str(user_ocid or "").strip()
        if not oid:
            return {"identity_domain_ocid": "", "identity_domain_name": ""}
        if oid in self._identity_domain_for_user_cache:
            return dict(self._identity_domain_for_user_cache[oid])

        domain_ocid = ""
        domain_name = ""
        try:
            rows = self.session.get_resource_fields(
                "identity_domain_users",
                columns=["domain_ocid", "identity_domain_name"],
                where_conditions={"ocid": oid},
            ) or []
            if rows and isinstance(rows[0], dict):
                domain_ocid = str(rows[0].get("domain_ocid") or "").strip()
                domain_name = str(rows[0].get("identity_domain_name") or "").strip()
        except Exception:
            pass

        if domain_ocid and not domain_name:
            try:
                rows = self.session.get_resource_fields(
                    "identity_domains",
                    columns=["display_name", "name"],
                    where_conditions={"id": domain_ocid},
                ) or []
                if rows and isinstance(rows[0], dict):
                    domain_name = str(rows[0].get("display_name") or rows[0].get("name") or "").strip()
            except Exception:
                pass

        resolved = {
            "identity_domain_ocid": domain_ocid,
            "identity_domain_name": domain_name,
        }
        self._identity_domain_for_user_cache[oid] = dict(resolved)
        return resolved

    def _resolve_cred_labels(self, c: Dict[str, Any]) -> Dict[str, str]:
        user_ocid = str(c.get("user") or c.get("user_ocid") or "").strip()
        tenancy_ocid = str(c.get("tenancy") or c.get("tenancy_ocid") or "").strip()
        compartment_ocid = str(c.get("default_compartment_id") or c.get("compartment_id") or "").strip()

        user_display_name = str(c.get("user_display_name") or "").strip() or self._lookup_user_display_name(user_ocid)
        tenancy_name = str(c.get("tenancy_display_name") or "").strip() or self._lookup_compartment_name(tenancy_ocid)
        compartment_name = str(c.get("default_compartment_name") or "").strip() or self._lookup_compartment_name(compartment_ocid)
        idd_ocid = str(c.get("identity_domain_ocid") or "").strip()
        idd_name = str(c.get("identity_domain_name") or "").strip()
        if not idd_ocid:
            idd_ctx = self._lookup_identity_domain_for_user(user_ocid)
            idd_ocid = str(idd_ctx.get("identity_domain_ocid") or "").strip()
            idd_name = str(idd_ctx.get("identity_domain_name") or "").strip()

        outer_credname = str(c.get("outer_credname") or c.get("credname") or "").strip()
        if outer_credname:
            self.session.update_cred_session_metadata(
                outer_credname,
                {
                    "user_display_name": user_display_name,
                    "tenancy_display_name": tenancy_name,
                    "default_compartment_name": compartment_name,
                    "identity_domain_ocid": idd_ocid,
                    "identity_domain_name": idd_name,
                },
            )

        return {
            "user_ocid": user_ocid,
            "tenancy_ocid": tenancy_ocid,
            "compartment_ocid": compartment_ocid,
            "user_display_name": user_display_name,
            "tenancy_display_name": tenancy_name,
            "compartment_name": compartment_name,
            "identity_domain_ocid": idd_ocid,
            "identity_domain_name": idd_name,
        }

    def _apply_filter(self, creds: List[Dict[str, Any]], credname: Optional[str]) -> List[Dict[str, Any]]:
        if credname is None:
            return creds
        cn = credname.lower()
        return [
            c
            for c in creds
            if (str(c.get("outer_credname", "")).lower() == cn)
            or (str(c.get("credname", "")).lower() == cn)
            or (str(c.get("name", "")).lower() == cn)
        ]

    def _credential_label(self, c: Dict[str, Any], index: int) -> str:
        label = c.get("outer_credname") or c.get("credname") or c.get("name") or f"cred-{index}"
        if "index" in c:
            label = f"{label} [{c['index']}]"
        return str(label)

    def _print_credential_entry(self, c: Dict[str, Any], label: str, *, include_sensitive: bool) -> None:
        auth = self._detect_auth_type(c)
        labels = self._resolve_cred_labels(c)
        user = self._ocid_with_name(labels["user_ocid"], labels["user_display_name"])
        ten = self._ocid_with_name(labels["tenancy_ocid"], labels["tenancy_display_name"])
        comp = self._ocid_with_name(labels["compartment_ocid"], labels["compartment_name"])
        reg = c.get("region") or "-"
        fpr = c.get("fingerprint") or c.get("key_id") or "-"
        exp = self._maybe_time(c.get("expires_at") or c.get("expiration") or c.get("token_expiry"))
        tok = c.get("security_token") or c.get("delegation_token") or c.get("token")

        print(f"- credname: {label}")
        print(f"  • auth_type: {auth}")
        print(f"  • user: {user}")
        print(f"  • tenancy: {ten}")
        if labels["identity_domain_ocid"]:
            print(f"  • identity_domain: {self._ocid_with_name(labels['identity_domain_ocid'], labels['identity_domain_name'])}")
        if include_sensitive:
            if labels["compartment_ocid"]:
                print(f"  • default_compartment: {comp}")
        elif comp != "-":
            print(f"  • default_compartment: {comp}")
        print(f"  • region: {reg}")
        print(f"  • fingerprint/key_id: {fpr}")

        if include_sensitive:
            if exp != "-":
                print(f"  • expires: {exp}")
            if tok:
                print(f"  • token: {tok}")

            if c.get("key_content"):
                print("  • key_content (PEM):")
                for line in str(c["key_content"]).strip().splitlines():
                    print(f"      {line}")
            elif c.get("key_file"):
                print(f"  • key_file: {c['key_file']}")
            else:
                print("  • key_content: -")
            print()
            return

        tokp = "-"
        if auth in ("security_token", "delegation_token"):
            tokp = self._safe_short(tok)
        if tokp != "-":
            print(f"  • token: {tokp}")
        if exp != "-":
            print(f"  • expires: {exp}")
        print()

    def _print_credential_listing(self, records: List[Dict[str, Any]], credname: Optional[str], *, include_sensitive: bool) -> None:
        flat = self._apply_filter(self._normalize_records(records), credname)
        if not flat:
            print(f"[*] No credentials found{' for ' + credname if credname else ''}.")
            return

        print(f"[*] Showing {len(flat)} credential set(s){' for ' + credname if credname else ''}.\n")
        for i, c in enumerate(flat, 1):
            self._print_credential_entry(c, self._credential_label(c, i), include_sensitive=include_sensitive)

    def creds_list_bullets(self, records: List[Dict[str, Any]], credname: Optional[str] = None) -> None:
        self._print_credential_listing(records, credname, include_sensitive=False)

    def creds_list_full_bullets(self, records: List[Dict[str, Any]], credname: Optional[str] = None) -> None:
        self._print_credential_listing(records, credname, include_sensitive=True)

    def creds_list_verbose(self, records: List[Dict[str, Any]], credname: Optional[str] = None) -> None:
        filtered = self._apply_filter(records or [], credname)
        if not filtered:
            print(f"[*] No credentials found{' for ' + credname if credname else ''}.")
            return

        print(
            f"{UtilityTools.YELLOW}[!] db-row mode prints sensitive credential material "
            f"(private keys/tokens) from local DB.{UtilityTools.RESET}"
        )
        print(f"[*] Showing {len(filtered)} stored credential record(s){' for ' + credname if credname else ''}.\n")

        for rec in filtered:
            outer = rec.get("credname") or rec.get("name") or "unnamed"
            ctype = rec.get("credtype") or "unknown"
            print(f"- credname: {outer}")
            print(f"  • credtype: {ctype}")

            raw = rec.get("session_creds")
            if isinstance(raw, str):
                try:
                    raw_obj = json.loads(raw)
                except Exception:
                    raw_obj = raw
            else:
                raw_obj = raw
            try:
                rendered = json.dumps(raw_obj, indent=2, ensure_ascii=False)
            except Exception:
                rendered = str(raw_obj)
            print("  • session_creds_raw:")
            for line in str(rendered).splitlines():
                print(f"      {line}")
            print()

    def creds_swap(self, records: List[Dict[str, Any]], credname: Optional[str] = None) -> Optional[Dict[str, Any]]:
        flat = self._normalize_records(records)
        if not flat:
            print(f"{UtilityTools.RED}[X] No credentials available to select.{UtilityTools.RESET}")
            return None

        if credname:
            matches = self._apply_filter(flat, credname)
            if not matches:
                print(f"{UtilityTools.RED}[X] No credentials found for '{credname}'.{UtilityTools.RESET}")
                return None
            picked = matches[0]
            target_credname = (
                str(picked.get("outer_credname") or "").strip()
                or str(picked.get("credname") or "").strip()
                or str(picked.get("name") or "").strip()
                or str(credname)
            )
            self.session.set_active_creds(target_credname)
            print(f"{UtilityTools.GREEN}[*] Active credentials set to: {target_credname}{UtilityTools.RESET}")
            return picked

        items = []
        for c in flat:
            target_credname = (
                str(c.get("outer_credname") or "").strip()
                or str(c.get("credname") or "").strip()
                or str(c.get("name") or "").strip()
            )
            if not target_credname:
                continue
            label = target_credname
            if "index" in c:
                label = f"{label} [{c['index']}]"
            items.append({"label": label, "cred": c, "credname": target_credname})

        selected = UtilityTools._choose_from_list("Select credentials to use", items, to_label=lambda it: it["label"])
        if not selected:
            return None

        target_credname = str(selected.get("credname") or "").strip()
        self.session.set_active_creds(target_credname)
        print(f"{UtilityTools.GREEN}[*] Active credentials set to: {target_credname}{UtilityTools.RESET}")
        return selected["cred"]

    def process_creds_command(self, args):
        subcmd = args.creds_subcommand
        all_cred_info = self.session.get_all_creds()
        active_credname = str(getattr(self.session, "credname", "") or "").strip()

        if subcmd in (None, "me"):
            if not active_credname:
                print(f"{UtilityTools.YELLOW}[!] No active credentials set. Use `creds swap [credname]` first.{UtilityTools.RESET}")
                return
            self.creds_list_bullets(all_cred_info, credname=active_credname)
            return
        if subcmd == "me-full":
            if not active_credname:
                print(f"{UtilityTools.YELLOW}[!] No active credentials set. Use `creds swap [credname]` first.{UtilityTools.RESET}")
                return
            self.creds_list_full_bullets(all_cred_info, credname=active_credname)
            return
        if subcmd == "list":
            self.creds_list_bullets(all_cred_info)
            return
        if subcmd == "list-full":
            self.creds_list_full_bullets(all_cred_info)
            return
        if subcmd == "db-row":
            self.creds_list_verbose(all_cred_info, credname=args.credname)
            return
        if subcmd == "swap":
            self.creds_swap(all_cred_info, credname=args.credname)
            return

        print("[X] Unknown creds subcommand.")

    # -----------------------------
    # modules command
    # -----------------------------
    def print_modules(self, search_term: Optional[str] = None):
        header_color = UtilityTools.BOLD
        category_color = UtilityTools.BLUE + UtilityTools.BOLD
        module_color = UtilityTools.YELLOW
        reset = UtilityTools.RESET

        term = str(search_term or "").strip().lower()
        rows = []
        for module in self._module_rows:
            module_name = str(module.get("module_name") or "")
            service = str(module.get("service") or "Unknown")
            category = str(module.get("module_category") or "Uncategorized")
            location = str(module.get("location") or "")
            info_blurb = str(module.get("info_blurb") or "")

            matched_flags: List[str] = []
            if term:
                metadata_blob = " ".join([module_name, service, category, location, info_blurb]).lower()
                module_flags = self._module_cli_flags(location)
                matched_flags = [f for f in module_flags if term in f.lower()]
                if term not in metadata_blob and not matched_flags:
                    continue

            rows.append(
                {
                    "service": service,
                    "category": category,
                    "module": module_name,
                    "matched_flags": matched_flags,
                }
            )

        if not rows:
            print(f"{UtilityTools.RED}No matching modules found.{reset}")
            return

        row_tuples = [(r["service"], r["category"], r["module"]) for r in rows]
        col_widths = [max(map(len, col)) for col in zip(*row_tuples)]
        header = ("Service", "Category", "Module")
        col_widths = [max(w, len(h)) for w, h in zip(col_widths, header)]
        sep_line = "-" * (sum(col_widths) + 6)

        print(
            f"{header_color}{header[0]:<{col_widths[0]}} | "
            f"{header[1]:<{col_widths[1]}} | "
            f"{header[2]:<{col_widths[2]}}{reset}"
        )
        print(sep_line)

        last_service = last_category = None
        for row in rows:
            service = row["service"]
            category = row["category"]
            module = row["module"]
            matched_flags = list(row.get("matched_flags") or [])
            new_service = service != last_service
            new_category = category != last_category or new_service

            if new_service and last_service is not None:
                print(sep_line)

            if new_service:
                print(
                    f"{UtilityTools.GREEN + UtilityTools.BOLD}{service:<{col_widths[0]}}{reset} | "
                    f"{category_color}{category:<{col_widths[1]}}{reset} | "
                    f"{module_color}{module:<{col_widths[2]}}{reset}"
                )
            elif new_category:
                print(f"{' ' * (col_widths[0] + 1)}{'-' * (len(sep_line) - col_widths[0] - 1)}")
                print(
                    f"{' ' * col_widths[0]} | "
                    f"{category_color}{category:<{col_widths[1]}}{reset} | "
                    f"{module_color}{module:<{col_widths[2]}}{reset}"
                )
            else:
                print(
                    f"{' ' * col_widths[0]} | "
                    f"{' ' * col_widths[1]} | "
                    f"{module_color}{module:<{col_widths[2]}}{reset}"
                )

            if term and matched_flags:
                print(
                    f"{' ' * col_widths[0]} | "
                    f"{UtilityTools.BRIGHT_BLACK}matched flags: {', '.join(sorted(matched_flags))}{reset}"
                )

            last_service = service
            last_category = category

    @staticmethod
    def _flags_in_python_file(path: Path) -> Set[str]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text, filename=str(path))
        except Exception:
            return set()

        out: Set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "add_argument"):
                continue
            for arg in (node.args or []):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("-"):
                    out.add(str(arg.value))
        return out

    def _module_cli_flags(self, module_import_path: str) -> List[str]:
        key = str(module_import_path or "").strip()
        if not key:
            return []
        cached = self._module_cli_flag_cache.get(key)
        if cached is not None:
            return list(cached)

        try:
            spec = importlib.util.find_spec(key)
        except Exception:
            spec = None
        if spec is None or not spec.origin:
            self._module_cli_flag_cache[key] = []
            return []

        module_file = Path(spec.origin)
        candidates = [module_file]

        # Also scan service Utilities parsers for modules that delegate argparse there.
        service_root = module_file.parent.parent
        utilities_dir = service_root / "Utilities"
        if utilities_dir.exists() and utilities_dir.is_dir():
            candidates.extend(sorted(utilities_dir.rglob("*.py")))

        flags: Set[str] = set()
        for file_path in candidates:
            flags |= self._flags_in_python_file(file_path)

        out = sorted(flags)
        self._module_cli_flag_cache[key] = out
        return list(out)

    def process_modules_command(self, args):
        command = args.modules_subcommand

        if command in (None, "list"):
            self.print_modules()
            return

        if command == "search":
            self.print_modules(search_term=args.search_term)
            return

        if command == "run":
            module_path = self._module_name_to_path.get(args.module_name)
            if module_path:
                interact_with_module(self.session, module_path, args.module_args)
            else:
                print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Module \"{args.module_name}\" not found.{UtilityTools.RESET}")
            return

        print("[X] Unknown modules subcommand.")

    # -----------------------------
    # Data command
    # -----------------------------
    def process_data_command(self, args):
        subcmd = args.data_subcommand
        handlers = {
            "wipe-service": self._handle_data_wipe_service,
            "sql": self._handle_data_sql,
            "export": self._handle_data_export,
        }
        handler = handlers.get(subcmd)
        if not handler:
            print("[*] data command not implemented yet.")
            return
        return handler(args)

    def _handle_data_wipe_service(self, args) -> None:
        all_workspaces = bool(getattr(args, "all_workspaces", False))
        force_yes = bool(getattr(args, "yes", False))
        target_ws = int(getattr(self, "workspace_id", 0) or 0)
        try:
            plan = self.session.data_master.plan_service_wipe(target_ws, all_workspaces=all_workspaces)
            if not (plan.get("plans") or []):
                print("[*] No service tables found.")
                return

            total_rows = int(plan.get("total_rows") or 0)
            candidate_tables = list(plan.get("candidate_tables") or [])
            non_workspace_tables = list(plan.get("non_workspace_tables") or [])
            tables_with_rows = list(plan.get("tables_with_rows") or [])
            scope_label = str(plan.get("scope_label") or ("all workspaces" if all_workspaces else f"workspace_id={target_ws}"))

            print(f"[*] Service DB: {plan.get('db_path')}")
            print(f"[*] Wipe scope: {scope_label}")
            print(f"[*] Candidate tables (have workspace_id): {len(candidate_tables)}")
            print(f"[*] Candidate rows to delete: {total_rows}")
            if non_workspace_tables:
                print(f"[!] Skipping tables without workspace_id: {len(non_workspace_tables)}")

            if total_rows <= 0:
                print("[*] Nothing to delete for selected scope.")
                return

            if not force_yes:
                confirm = input(
                    f"[!] This will delete {total_rows} row(s) from service DB ({scope_label}). Type WIPE to continue: "
                ).strip()
                if confirm != "WIPE":
                    print("[*] Wipe cancelled.")
                    return

            result = self.session.data_master.wipe_service_rows(
                target_ws,
                all_workspaces=all_workspaces,
                planned_tables_with_rows=tables_with_rows,
            )
            print(
                f"{UtilityTools.GREEN}[*] Wipe complete.{UtilityTools.RESET} "
                f"Deleted {int(result.get('deleted_rows') or 0)} row(s) "
                f"from {int(result.get('deleted_tables') or 0)} table(s)."
            )
        except Exception as e:
            try:
                self.session.data_master.rollback("service")
            except Exception:
                pass
            print(
                f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Service wipe failed:{UtilityTools.RESET} "
                f"{type(e).__name__}: {e}"
            )

    def _handle_data_sql(self, args) -> None:
        max_rows = 200
        db_choice = str(getattr(args, "db", "service") or "service").strip().lower()
        query = " ".join(list(getattr(args, "query", []) or [])).strip()

        if not query:
            print(
                f"{UtilityTools.RED}[X] Missing SQL query. Example:{UtilityTools.RESET} "
                f"data sql --db service \"SELECT * FROM identity_domain_users LIMIT 20\""
            )
            return

        dc = self.session.data_master
        db_path = dc.service_db if db_choice == "service" else dc.metadata_db

        print(f"[*] Running SQL on {db_choice} DB: {db_path}")

        try:
            result = dc.run_sql_query(db_choice, query, max_rows=max_rows)

            if str(result.get("query_type") or "") == "write":
                affected = int(result.get("affected_rows") or 0)
                print(f"{UtilityTools.GREEN}[*] SQL executed successfully.{UtilityTools.RESET} Rows affected: {affected}")
                return

            columns = [str(c) for c in (result.get("columns") or [])]
            display_rows = list(result.get("rows") or [])
            total = int(result.get("row_count") or 0)
            truncated = bool(result.get("truncated"))

            if truncated:
                print(f"[*] Query returned at least {total} row(s).")
            else:
                print(f"[*] Query returned {total} row(s).")
            if display_rows:
                UtilityTools.print_limited_table(display_rows, columns, sort_key=None)
            else:
                print("[*] No rows.")

            if truncated:
                print(
                    f"{UtilityTools.YELLOW}[!] Display truncated to first {max_rows} rows. "
                    f"Use LIMIT/OFFSET for paging.{UtilityTools.RESET}"
                )

            return
        except Exception as e:
            print(
                f"{UtilityTools.RED}{UtilityTools.BOLD}[X] SQL execution failed:{UtilityTools.RESET} "
                f"{type(e).__name__}: {e}"
            )
            return

    def _handle_data_export(self, args) -> None:
        export_format = str(getattr(args, "format", "") or "").lower().strip()
        out_dir_arg = str(getattr(args, "out_dir", "") or "")
        out_file_arg = str(getattr(args, "out_file", "") or "")

        def _default_out_dir(subdir: str) -> Path:
            if out_dir_arg:
                out = Path(out_dir_arg).expanduser()
            else:
                out = (
                    self.session.get_workspace_output_root(mkdir=True)
                    / "exports"
                    / "data"
                    / "global"
                    / str(subdir or "resource_reports")
                )
            out.mkdir(parents=True, exist_ok=True)
            return out

        dc = self.session.data_master

        if export_format == "csv":
            out_dir = _default_out_dir("sqlite_csv")
            csv_out = Path(out_file_arg).expanduser() if out_file_arg else out_dir / "sqlite_blob.csv"
            if csv_out.suffix.lower() != ".csv":
                csv_out = csv_out.with_suffix(".csv")

            db_paths = [dc.service_db]
            print(f"[*] Exporting service SQLite DB to flat CSV: {csv_out}")
            try:
                result = export_sqlite_dbs_to_csv_blob(
                    db_paths=db_paths,
                    out_csv_path=str(csv_out),
                )
            except Exception as e:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed exporting CSV data blob:{UtilityTools.RESET} "
                    f"{type(e).__name__}: {e}"
                )
                return

            print(
                f"{UtilityTools.GREEN}[*] CSV export complete -> {result['csv_path']}{UtilityTools.RESET} "
                f"(databases={result['databases']}, tables={result['tables']}, rows={result['rows']})"
            )
            return

        if export_format == "json":
            if out_file_arg:
                out_file = Path(out_file_arg).expanduser()
            else:
                out_file = _default_out_dir("sqlite_json") / "sqlite_blob.json"
            out_file.parent.mkdir(parents=True, exist_ok=True)

            db_paths = [dc.service_db]
            print(f"[*] Exporting service SQLite DB to JSON blob: {out_file}")
            try:
                result = export_sqlite_dbs_to_json_blob(
                    db_paths=db_paths,
                    out_json_path=str(out_file),
                )
            except Exception as e:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed exporting JSON blob:{UtilityTools.RESET} "
                    f"{type(e).__name__}: {e}"
                )
                return

            print(
                f"{UtilityTools.GREEN}[*] JSON export complete -> {result['json_path']}{UtilityTools.RESET} "
                f"(databases={result['databases']}, tables={result['tables']}, rows={result['rows']})"
            )
            return

        if export_format == "excel":
            single_sheet = True
            condensed_excel = True
            if out_file_arg:
                out_file = Path(out_file_arg).expanduser()
            else:
                out_dir = _default_out_dir("sqlite_excel")
                out_file = out_dir / "sqlite_blob.xlsx"

            db_paths = [dc.service_db]
            print(f"[*] Exporting service SQLite DB to one Excel workbook: {out_file}")
            try:
                result = export_sqlite_dbs_to_excel_blob(
                    db_paths=db_paths,
                    out_xlsx_path=str(out_file),
                    single_sheet=single_sheet,
                    condensed=condensed_excel,
                )
            except Exception as e:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed exporting Excel workbook:{UtilityTools.RESET} "
                    f"{type(e).__name__}: {e}"
                )
                return

            print(
                f"{UtilityTools.GREEN}[*] Excel export complete -> {result['xlsx_path']}{UtilityTools.RESET} "
                f"(format={result.get('format','xlsx')}, databases={result['databases']}, tables={result['tables']}, rows={result['rows']}, single_sheet={result['single_sheet']}, condensed={result.get('condensed', False)})"
            )
            return

        if export_format == "treeimage":
            out_dir = _default_out_dir("resource_reports")
            if out_file_arg:
                out_file = Path(out_file_arg).expanduser()
            else:
                out_file = out_dir / "compartment_tree.svg"
            if out_file.suffix.lower() != ".svg":
                out_file = out_file.with_suffix(".svg")

            print(f"[*] Exporting compartment hierarchy graph from service DB: {dc.service_db}")
            try:
                result = export_compartment_tree_image(
                    db_path=dc.service_db,
                    out_path=str(out_file),
                )
            except Exception as e:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed exporting compartment hierarchy graph:{UtilityTools.RESET} "
                    f"{type(e).__name__}: {e}"
                )
                return

            print(
                f"{UtilityTools.GREEN}[*] Compartment tree export complete -> {result['image_path']}{UtilityTools.RESET} "
                f"(format={result.get('format')}, renderer={result.get('renderer')}, compartments={result.get('compartments', 0)})"
            )
            return

        print(f"{UtilityTools.RED}[X] Unsupported export format: {export_format}{UtilityTools.RESET}")

    # -----------------------------
    # Config command (UPDATED)
    # -----------------------------
    def process_configs_command(self, args):
        command = args.configs_subcommand

        if command in (None, "list"):
            self.session.list_configs(self.workspace_id)
            return

        if command == "regions":
            subcommand = str(getattr(args, "configs_regions_subcommand", "") or "list").strip().lower()
            if subcommand in ("", "list"):
                self._print_known_regions()
                return
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Unknown configs regions command: {subcommand}{UtilityTools.RESET}")
            return

        if command == "set":
            key = args.key
            value = args.value
            result = self.session.set_config_key_result(self.workspace_id, key, value)
            if result.ok:
                self.session.list_configs(self.workspace_id)
            return

        if command == "unset":
            key = args.key
            result = self.session.unset_config_key_result(self.workspace_id, key)
            if result.ok:
                self.session.list_configs(self.workspace_id)
            return


def list_all_creds_for_user(available_creds):
    if available_creds is None:
        print("\n[-] No creds found")
        return
    print("\n[*] Listing existing credentials...")
    for index, cred in enumerate(available_creds):
        name, type_of_cred = cred[0], cred[1]
        print(f"  [{index+1}] {name} ({type_of_cred})")
    print("\n")


def is_integer_within_bounds(user_input, upper_bound):
    try:
        user_input_int = int(user_input)
        return 1 <= user_input_int <= upper_bound
    except ValueError:
        return False


def initial_instructions(
    workspace_id: int,
    workspace_name: str,
    startup_auth_proxy: Optional[str] = None,
    startup_silent: bool = False,
):
    import textwrap

    # Some terminals emit raw ANSI escape sequences (for example arrow keys)
    # unless readline is initialized before input(). Keep startup prompt UX
    # consistent with the main REPL loop.
    try:
        import readline  # type: ignore

        readline.parse_and_bind("tab: complete")
    except Exception:
        readline = None  # type: ignore

    # fetch all our current creds
    with DataController() as dc:
        available_creds = dc.list_creds(workspace_id) or []

    # Create a new session object with necessary info
    # in a wrapper so we can add workspace info. init of Session object
    # adds/gets/loads the creds
    def _new_session(
        credname: Optional[str] = None,
        auth_type: Optional[str] = None,
        *,
        resume: bool = False,
        extra_args: Optional[Dict[str, Any]] = None,
    ) -> SessionUtility:
        return SessionUtility(
            workspace_id,
            workspace_name,
            credname,
            auth_type,
            resume=resume,
            extra_args=extra_args,
            startup_auth_proxy=startup_auth_proxy,
        )

    def prompt_user():
        if not startup_silent:
            help_banner()
        list_all_creds_for_user(available_creds)

        prompt = textwrap.dedent(
            """
        Submit the name or index of an existing credential from above, or add NEW credentials via:
            [1] profile            <credential_name> --filepath <file_path> [--profile <profile_name>]
            [2] api-key            <credential_name> --user <user_ocid> --fingerprint <fingerprint> --tenancy-id <tenancy_ocid> --region <oci_region> (--private-key <pem_or_path> | --private-key-file <path>)
            [3] session-token      <credential_name> (--token <token_or_path> | --token-file <path>) --region <oci_region> [--tenancy-id <tenancy_ocid>] (--private-key <pem_or_path> | --private-key-file <path>)
            [4] instance-principal <credential_name> (--reference-file <reference_file> | --on-host) [--region <oci_region>] [--imdsv1|--imdsv2] [--proxy <host:port|url>]
            [5] resource-principal <credential_name> [--reference-file <reference_file>] [--token <rpst_or_path> | --token-file <path>] [--private-key <pem_or_path> | --private-key-file <path>] [--region <oci_region>]

        To proceed with no credentials, just hit ENTER.
        """
        )
        print(prompt)
        return input("[*] Credential Input > ").strip()

    try:
        answer = prompt_user()
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Credential prompt cancelled.")
        return None
    # Fallback: strip accidental ANSI escape sequences from arrow keys/home/end.
    answer = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", answer).strip()

    # if no response create session object with no creds
    if not answer:
        return _new_session()

    # if user chose pre-existing creds then create session with 
    # Example input/output:
    #   input : answer="TEST" and available_creds contains ("TEST", "Profile - API Key - DEFAULT")
    #   output: resume existing credential "TEST" (loads stored creds without re-entering auth args)
    if available_creds and any(answer == x[0] for x in available_creds):
        return _new_session(answer, None, resume=True)

    # If user chose pre-existing creds (via number index) then create session with it
    if available_creds and is_integer_within_bounds(answer, len(available_creds)):
        credname = available_creds[int(answer) - 1][0]
        return _new_session(credname, None, resume=True)

    # If user did not choose pre-existing creds, parse shell-style arguments.
    # This preserves quoted values (for example fingerprints/OCIDs wrapped in quotes)
    # and avoids passing literal quote characters to downstream validators.
    try:
        arguments = shlex.split(answer)
    except ValueError:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed to parse credentials. Check for unmatched quotes.{UtilityTools.RESET}")
        return _new_session()

    def _build_startup_credential_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Add credentials", exit_on_error=False)
        subparsers = parser.add_subparsers(dest="command", required=True)

        # Profile Auth
        profile_parser = subparsers.add_parser("profile", help="Use existing profile in ~/.oci/config")
        profile_parser.add_argument("credential_name", help="Name to save this credential under")
        profile_parser.add_argument("--profile", dest="profile_name", default=None, help="Profile name to use (optional)")
        profile_parser.add_argument("--filepath", dest="filepath", default=None, help="Path to config file (optional)")

        # API Key Auth (explicit fields, no ~/.oci/config profile required)
        api_key_parser = subparsers.add_parser("api-key", help="Use explicit API key values")
        api_key_parser.add_argument("credential_name", help="Name to save this credential under")
        api_key_parser.add_argument("--user", dest="user", default=None, help="OCI user OCID")
        api_key_parser.add_argument("--fingerprint", dest="fingerprint", default=None, help="API key fingerprint")
        api_key_parser.add_argument("--tenancy-id", dest="tenancy_id", default=None, help="Tenancy OCID")
        api_key_parser.add_argument("--region", dest="region", default=None, help="OCI region (e.g. us-phoenix-1)")
        api_key_parser.add_argument("--private-key", dest="private_key", default=None, help="Private key PEM value or file path")
        api_key_parser.add_argument("--private-key-file", dest="private_key_file", default=None, help="Path to private key PEM file")
        api_key_parser.add_argument("--passphrase", dest="passphrase", default=None, help="Private key passphrase (optional)")
        api_key_parser.add_argument("--passphrase-file", dest="passphrase_file", default=None, help="Path to private key passphrase file (optional)")

        # Session Token Auth (explicit fields, no ~/.oci/config profile required)
        token_parser = subparsers.add_parser("session-token", help="Use explicit session-token values")
        token_parser.add_argument("credential_name", help="Name to save this credential under")
        token_parser.add_argument("--token", dest="token", default=None, help="Session token value or token file path")
        token_parser.add_argument("--token-file", dest="token_file", default=None, help="Path to session token file")
        token_parser.add_argument("--private-key", dest="private_key", default=None, help="Private key PEM value or file path")
        token_parser.add_argument("--private-key-file", dest="private_key_file", default=None, help="Path to private key PEM file")
        token_parser.add_argument("--tenancy-id", dest="tenancy_id", default=None, help="Tenancy OCID override (optional; auto-extracted from token when possible)")
        token_parser.add_argument("--region", dest="region", default=None, help="OCI region (e.g. us-phoenix-1)")
        token_parser.add_argument("--passphrase", dest="passphrase", default=None, help="Private key passphrase (optional)")
        token_parser.add_argument("--passphrase-file", dest="passphrase_file", default=None, help="Path to private key passphrase file (optional)")

        # Instance Principal Auth
        instance_principal_parser = subparsers.add_parser("instance-principal", help="Use instance profile certs/X509")
        instance_principal_parser.add_argument("credential_name", help="Name to save this credential under")
        ip_scope = instance_principal_parser.add_mutually_exclusive_group(required=False)
        ip_scope.add_argument("--reference-file", dest="reference_file", default=None, help="Path to instance-principal reference file")
        ip_scope.add_argument("--on-host", dest="on_host", action="store_true", help="Use compute instance metadata + instance principals signer")
        instance_principal_parser.add_argument("--region", dest="region", default=None, help="OCI region (e.g. us-phoenix-1)")
        ip_imds = instance_principal_parser.add_mutually_exclusive_group(required=False)
        ip_imds.add_argument("--imdsv1", dest="imds_version", action="store_const", const="v1", help="Prefer IMDSv1 /opc/v1 metadata endpoints")
        ip_imds.add_argument("--imdsv2", dest="imds_version", action="store_const", const="v2", help="Prefer IMDSv2 /opc/v2 metadata endpoints")
        instance_principal_parser.add_argument("--proxy", dest="proxy", default=None, help="Proxy for instance-principal setup traffic")
        instance_principal_parser.add_argument("--debug-http", dest="debug_http", action="store_true", help="Enable HTTP debug logging for instance-principal federation")

        # Resource Principal Auth
        resource_principal_parser = subparsers.add_parser("resource-principal", help="Use resource principal token")
        resource_principal_parser.add_argument("credential_name", help="Name to save this credential under")
        resource_principal_parser.add_argument("--reference-file", dest="reference_file", default=None, help="Path to resource-principal reference file (optional)")
        resource_principal_parser.add_argument("--token", dest="token", default=None, help="RPST token value or token file path")
        resource_principal_parser.add_argument("--token-file", dest="token_file", default=None, help="Path to RPST token file")
        resource_principal_parser.add_argument("--private-key", dest="private_key", default=None, help="Private key PEM value or private key file path")
        resource_principal_parser.add_argument("--private-key-file", dest="private_key_file", default=None, help="Path to private key PEM file")
        resource_principal_parser.add_argument("--region", dest="region", default=None, help="OCI region (e.g. us-phoenix-1)")
        resource_principal_parser.add_argument("--tenancy-id", dest="tenancy_id", default=None, help="Tenancy OCID override (optional)")
        resource_principal_parser.add_argument("--passphrase", dest="passphrase", default=None, help="Private key passphrase (optional)")
        resource_principal_parser.add_argument("--passphrase-file", dest="passphrase_file", default=None, help="Path to private key passphrase file (optional)")
        resource_principal_parser.add_argument("--proxy", dest="proxy", default=None, help="Proxy for resource-principal setup traffic")
        resource_principal_parser.add_argument("--debug-http", dest="debug_http", action="store_true", help="Enable debug logs for signer setup")
        return parser

    parser = _build_startup_credential_parser()

    try:
        args = parser.parse_args(arguments)
    except Exception:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed to parse credentials. Proceeding with no credentials.{UtilityTools.RESET}")
        return _new_session()

    # Normalize startup parser output once so every auth flow uses the same
    # shape: command + credential_name + extra_args(dict of remaining args).
    parsed_args = dict(vars(args))
    auth_command = parsed_args.get("command")
    credential_name = parsed_args.get("credential_name")
    extra_args = {
        key: value
        for key, value in parsed_args.items()
        if key not in {"command", "credential_name"}
    }

    if not auth_command or not credential_name:
        return _new_session()
    
    # We have all necessary values needed to create a session object. Call _new_session
    # with values we needed. _new_session will return Session object.
    return _new_session(credential_name, auth_command, extra_args=extra_args)


def short_ocid(ocid: str, length: int = 8) -> str:
    if not isinstance(ocid, str) or "ocid1." not in ocid:
        return "UNKNOWN"
    prefix = "TENANT-" if UtilityTools.is_tenancy_ocid(ocid) else ""
    return f"{prefix}{ocid[-length:]}"

# Takes in a workspace ID, name and startup auth options from main.py. Might be pre-existing or one we just created.
def workspace_instructions(
    workspace_id,
    workspace_name,
    startup_auth_proxy: Optional[str] = None,
    startup_silent: bool = False,
):

    # Handle the user choosing existing creds or adding new creds
    # Returns a Session object with all auth info configured if needed along with config info
    session = initial_instructions(
        workspace_id,
        workspace_name,
        startup_auth_proxy=startup_auth_proxy,
        startup_silent=startup_silent,
    )
    if session is None:
        return

    # Pass in our workspace ID + Session object populated with our auth into command processor
    # this exposed process_command which will be run later as we are looping through user info, 
    # and will have the workspace/auth/config context needed to execute on user's input
    command_processor = CommandProcessor(workspace_id, session)

    # Add tab completion + history
    import readline
    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" \t\n")
    readline.set_completer(command_processor.readline_complete)
    readline.set_history_length(25)

    # Main loop for interactive prompts
    while True:
        cli_prefix = f"{session.credname}"

        try:
            if session.compartment_id:
                short_compartment_id = short_ocid(session.compartment_id)
            else:
                short_compartment_id = "UNKNOWN"

            user_input = input(f"({short_compartment_id}:{cli_prefix})> ")

            readline.set_auto_history(False)

            keep_running = command_processor.process_command(user_input)
            if keep_running == -1:
                exit()

        except (ValueError, KeyboardInterrupt):
            break

        except Exception:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Program failed for unknown reasons. See below:{UtilityTools.RESET}")
            print(traceback.format_exc())

        finally:
            readline.set_auto_history(True)
