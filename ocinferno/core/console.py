# UtilityController.py
from __future__ import annotations

import inspect
import re
import shutil
import textwrap
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Iterator, Optional, TypeVar

try:
    import oci
except ModuleNotFoundError:  # pragma: no cover - enables offline/local test runs without OCI SDK
    class _OciFallback:
        class util:
            @staticmethod
            def to_dict(obj: Any) -> Any:
                return obj

    oci = _OciFallback()
from prettytable import PrettyTable

T = TypeVar("T")


# =============================================================================
# Small safe helpers (internal)
# =============================================================================

def _safe_oci_to_dict(obj: Any) -> Any:
    try:
        return oci.util.to_dict(obj)
    except Exception:
        return obj


# =============================================================================
# UtilityTools (your existing utilities + small additions)
# =============================================================================

class UtilityTools:
    TABLE_OUTPUT_FORMAT = "table"
    _REDACTED = "<redacted>"
    _SENSITIVE_KEY_TOKENS = (
        "token",
        "secret",
        "password",
        "passphrase",
        "authorization",
        "api_key",
        "api-key",
        "apikey",
        "x-api-key",
        "private_key",
        "security_token",
        "session_creds",
        "credential",
    )

    # -----------------------------
    # ANSI colors / formatting
    # -----------------------------
    RESET = "\033[0m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    DIM = "\033[2m"          # ANSI dim
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    BOLD = "\033[1m"

    # -----------------------------
    # Debug output (use everywhere)
    # -----------------------------
    @staticmethod
    def dlog(debug: bool, message: str, **kv: Any) -> None:
        """
        Structured debug printer.
        Usage:
            UtilityTools.dlog(debug, "listed compartments", count=len(rows), root=is_root)
        """
        if not debug:
            return
        if kv:
            parts = []
            for k, v in kv.items():
                try:
                    sanitized = UtilityTools.sanitize_args(v)
                    if "url" in str(k).lower() and isinstance(sanitized, str):
                        sanitized = UtilityTools.sanitize_url(sanitized)
                    s = repr(sanitized)
                    if len(s) > 280:
                        s = s[:277] + "..."
                    parts.append(f"{k}={s}")
                except Exception:
                    parts.append(f"{k}=<unrepr>")
            print(f"[DEBUG] {message} :: " + " ".join(parts))
        else:
            print(f"[DEBUG] {message}")

    # -----------------------------
    # OCID condensation (printing)
    # -----------------------------
    @staticmethod
    def condense_ocid(s: str, *, head: int = 3, tail: int = 3) -> str:
        """
        Condense OCI OCIDs for display:
          ocid1.<type>.<realm>.<region?>.. <unique>
        Keeps everything up to (and including) the last '.' before the unique segment,
        then shows only first/last N of the unique segment.

        Example:
          ocid1.tenancy.oc1..aaaaaaaagmct...snxfsaa
          -> ocid1.tenancy.oc1..aaa…saa
        """
        if not isinstance(s, str):
            return ""
        if not s.startswith("ocid1."):
            return s

        parts = s.split(".")
        if len(parts) < 2:
            return s

        unique = parts[-1] if parts else ""
        if not unique:
            return s

        if len(unique) <= (head + tail + 1):
            return s

        prefix = ".".join(parts[:-1]) + "."
        return f"{prefix}{unique[:head]}…{unique[-tail:]}"


    @staticmethod
    def _is_sensitive_key(key: Any) -> bool:
        ks = str(key or "").strip().lower()
        if not ks:
            return False
        return any(tok in ks for tok in UtilityTools._SENSITIVE_KEY_TOKENS)

    @staticmethod
    def sanitize_url(url: str) -> str:
        """
        Redact sensitive query-string values while preserving URL shape.
        """
        try:
            parsed = urlparse(str(url or ""))
            if not parsed.query:
                return str(url or "")
            redacted_q = []
            for k, v in parse_qsl(parsed.query, keep_blank_values=True):
                if UtilityTools._is_sensitive_key(k):
                    redacted_q.append((k, UtilityTools._REDACTED))
                else:
                    redacted_q.append((k, v))
            return urlunparse(parsed._replace(query=urlencode(redacted_q, doseq=True)))
        except Exception:
            return str(url or "")

    @staticmethod
    def sanitize_args(obj: Any, *, max_str_len: int = 1024) -> Any:
        """
        Best-effort recursive sanitizer for logs/debug output.
        """
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if UtilityTools._is_sensitive_key(k):
                    out[k] = UtilityTools._REDACTED
                elif str(k).strip().lower() == "url" and isinstance(v, str):
                    out[k] = UtilityTools.sanitize_url(v)
                else:
                    out[k] = UtilityTools.sanitize_args(v, max_str_len=max_str_len)
            return out
        if isinstance(obj, list):
            return [UtilityTools.sanitize_args(x, max_str_len=max_str_len) for x in obj]
        if isinstance(obj, tuple):
            return tuple(UtilityTools.sanitize_args(x, max_str_len=max_str_len) for x in obj)
        if isinstance(obj, str):
            s = obj
            # Redact obvious Authorization/Bearer token strings.
            if "bearer " in s.lower():
                return UtilityTools._REDACTED
            if len(s) > max_str_len:
                return s[: max_str_len - 3] + "..."
            return s
        return obj

    # -----------------------------
    # Module action logger
    # -----------------------------
    @staticmethod
    def _log_action(type_of_log: str, action: str, permission: str) -> None:
        """
        Minimal action logger used by module runner(s).
        """
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        print(
            f"{UtilityTools.BRIGHT_BLACK}[LOG {ts}] {type_of_log}: {action} "
            f"(perm={permission}){UtilityTools.RESET}"
        )

    @staticmethod
    def progress_iter(
        items: Iterable[T],
        *,
        label: str = "GET",
        enabled: bool = True,
        min_items: int = 16,
    ) -> Iterator[T]:
        """
        Yield items while printing in-place progress (e.g., 1/4, 2/4).
        Intended for large GET/detail loops.
        """
        if not enabled:
            for item in items:
                yield item
            return

        total: Optional[int]
        try:
            total = len(items)  # type: ignore[arg-type]
        except Exception:
            total = None

        if total is None or total < int(min_items):
            for item in items:
                yield item
            return

        count = 0
        for count, item in enumerate(items, 1):
            if total and total > 0:
                print(f"\r[*] {label}: {count}/{total}", end="", flush=True)
            else:
                print(f"\r[*] {label}: {count}", end="", flush=True)
            yield item

        if count:
            print()

    # -----------------------------
    # Input helpers
    # -----------------------------
    @staticmethod
    def _enter_string_value(
        prompt: str,
        allow_empty: bool = False,
        validator: Optional[Callable[[str], None]] = None,
    ) -> str:
        """
        Prompt the user for a string. Optionally validate with a callable that raises ValueError.
        """
        while True:
            value = input(f"{prompt}: ").strip()

            if not value and not allow_empty:
                print("[X] Value cannot be empty.")
                continue

            if validator:
                try:
                    validator(value)
                except ValueError as e:
                    print(f"[X] {e}")
                    continue

            return value

    @staticmethod
    def _choose_from_list(title: str, items: list[Any], to_label: Callable[[Any], str]):
        """
        items: list of objects
        to_label: func(item)->str
        returns selected item or None (cancel)
        """
        if not items:
            print(f"{UtilityTools.RED}[X] Nothing to choose from.{UtilityTools.RESET}")
            return None

        print(f"{UtilityTools.BOLD}{UtilityTools.BRIGHT_GREEN}[*] {title}{UtilityTools.RESET}")
        for i, it in enumerate(items, 1):
            print(f"  [{i}] {to_label(it)}")

        while True:
            choice = input("Select a number (or ENTER to cancel): ").strip()
            if choice == "":
                print("[*] Cancelled.")
                return None
            if not choice.isdigit():
                print(f"{UtilityTools.RED}[X] Enter a valid number.{UtilityTools.RESET}")
                continue
            idx = int(choice)
            if 1 <= idx <= len(items):
                return items[idx - 1]
            print(f"{UtilityTools.RED}[X] Out of range (1..{len(items)}).{UtilityTools.RESET}")

    # -----------------------------
    # OCI helpers
    # -----------------------------
    @staticmethod
    def is_tenancy_ocid(ocid: str) -> bool:
        return isinstance(ocid, str) and ocid.startswith("ocid1.tenancy.")

    @staticmethod
    def ask_all_or_current_with_preview(current_id: str, comp_rows: list[dict[str, Any]], max_preview: int = 10) -> str:
        """
        Show 'Current' vs 'All' with a nicely aligned preview.
        Returns 'all' or 'current'.
        """
        print(f"{UtilityTools.BOLD}{UtilityTools.BRIGHT_GREEN}Choose scan scope:{UtilityTools.RESET}")

        cur_label = current_id or f"{UtilityTools.BRIGHT_BLACK}None set{UtilityTools.RESET}"
        print(f"{UtilityTools.YELLOW}- Current Compartment:{UtilityTools.RESET} {cur_label}")
        print(f"{UtilityTools.YELLOW}- All Compartments:{UtilityTools.RESET}")

        preview = comp_rows[:max_preview]

        rows: list[tuple[str, str, bool]] = []
        for r in preview:
            ocid = r.get("compartment_id") or r.get("id") or ""
            name = r.get("name") or r.get("display_name") or ""
            is_tenant = UtilityTools.is_tenancy_ocid(ocid)
            prefix = "[TENANT] - " if is_tenant else ""
            disp_name = f"{prefix}{name or ocid}"
            rows.append((disp_name, ocid, is_tenant))

        term_width = shutil.get_terminal_size(fallback=(100, 24)).columns
        ocid_col_min = 36
        name_col_max = max((len(n) for n, _, _ in rows), default=0)
        name_col = min(name_col_max, max(24, term_width - ocid_col_min - 6))

        for name_txt, ocid_txt, _ in rows:
            if len(name_txt) > name_col:
                name_txt = textwrap.shorten(name_txt, width=name_col, placeholder="…")
            padded = f"{name_txt:<{name_col}}"
            print(
                f"    {UtilityTools.CYAN}{padded}{UtilityTools.RESET} "
                f"{UtilityTools.BRIGHT_BLACK}({ocid_txt}){UtilityTools.RESET}"
            )

        if len(comp_rows) > max_preview:
            print(f"    ... ({len(comp_rows) - max_preview} more)")

        while True:
            ans = input("Scan (A)ll or (C)urrent only? [A/C]: ").strip().lower()
            if ans in ("a", "c"):
                return "all" if ans == "a" else "current"
            print(f"{UtilityTools.RED}[X] Please enter 'A' or 'C'.{UtilityTools.RESET}")

    # -----------------------------
    # Table printing
    # -----------------------------
    @staticmethod
    def _humanize_table_label(raw: str) -> str:
        s = str(raw or "").strip().replace("-", "_")
        if not s:
            return ""
        s = re.sub(r"[^A-Za-z0-9_ ]+", " ", s)
        s = re.sub(r"\s+", " ", s).strip()
        if "_" in s:
            s = " ".join(p for p in s.split("_") if p)
        if not s:
            return ""
        return " ".join(tok.capitalize() for tok in s.split())

    @staticmethod
    def _infer_table_title(rows: list[dict[str, Any]], fields: list[str], resource_type: Optional[str]) -> str:
        if resource_type:
            human = UtilityTools._humanize_table_label(resource_type)
            if human:
                return human

        try:
            stack = inspect.stack()
            service_name = ""
            resource_name = ""
            for fr in stack[2:10]:
                fpath = str(getattr(fr, "filename", "") or "")
                parts = fpath.replace("\\", "/").split("/")
                if "modules" in parts:
                    idx = parts.index("modules")
                    if idx + 1 < len(parts):
                        service_name = UtilityTools._humanize_table_label(parts[idx + 1])
                        if service_name:
                            break
            for fr in stack[2:12]:
                fn = str(getattr(fr, "function", "") or "").strip()
                if not fn:
                    continue
                if fn.startswith("_run_"):
                    resource_name = UtilityTools._humanize_table_label(fn[len("_run_"):])
                    break
                if fn.startswith("enum_") and fn != "enum_all":
                    resource_name = UtilityTools._humanize_table_label(fn[len("enum_"):])
                    break
            if service_name and resource_name:
                return f"{service_name} - {resource_name}"
            if service_name:
                return f"{service_name} - Results"
        except Exception:
            pass

        for key in ("resource", "table_name", "resource_type", "type"):
            vals = []
            for r in rows[:20]:
                v = r.get(key)
                if isinstance(v, str) and v.strip():
                    vals.append(v.strip())
            uniq = list(dict.fromkeys(vals))
            if len(uniq) == 1:
                human = UtilityTools._humanize_table_label(uniq[0])
                if human:
                    return human

        fset = {str(f).strip().lower() for f in (fields or [])}
        if {"cidr_block", "vcn_id"}.issubset(fset):
            return "Subnets"
        if "cidr_block" in fset:
            return "Virtual Cloud Networks"
        if {"drg_id", "vcn_id"}.issubset(fset):
            return "DRG Attachments"
        if {"is_enabled", "vcn_id"}.issubset(fset):
            return "Internet Gateways"
        if {"block_traffic", "vcn_id"}.issubset(fset):
            return "NAT Gateways"

        try:
            frame = inspect.stack()[2]
            caller_file = os.path.basename(str(frame.filename or ""))
            stem = caller_file.rsplit(".", 1)[0]
            if stem:
                stem_h = UtilityTools._humanize_table_label(stem.replace("enum_", "").replace("helper", ""))
                if stem_h:
                    return f"{stem_h} - Results"
        except Exception:
            pass
        return "Results"

    @staticmethod
    def print_limited_table(
        data: Iterable[Any],
        fields: list[str],
        *,
        title: Optional[str] = None,
        auto_title: bool = True,
        resource_type: Optional[str] = None,
        sort_key: Optional[str] = None,
        reverse: bool = False,
        max_rows: int = 50,
        truncate: int = 120,
        condense_ocids: bool = True,
        ocid_head: int = 3,
        ocid_tail: int = 3,
        auto_wrap_to_terminal: bool = True,
        min_col_width: int = 10,
        max_col_width: int = 120,
        align: Optional[str] = None,
    ) -> None:
        """
        PrettyTable helper that:
          - supports OCI SDK objects or dicts
          - prints only the first `max_rows`
          - (optionally) condenses OCI OCIDs to save width
          - truncates very long fields
        """
        rows: list[dict[str, Any]] = []
        for x in data:
            d = x if isinstance(x, dict) else _safe_oci_to_dict(x)
            if not isinstance(d, dict):
                d = {"value": str(d)}
            rows.append(d)

        if sort_key:
            try:
                rows.sort(key=lambda r: str(r.get(sort_key, "")), reverse=reverse)
            except Exception:
                pass

        section_title = ""
        if isinstance(title, str) and title.strip():
            section_title = title.strip()
        elif auto_title:
            section_title = UtilityTools._infer_table_title(rows, fields, resource_type)
        if section_title:
            print(f"\n[*] {section_title}")

        output_format = str(getattr(UtilityTools, "TABLE_OUTPUT_FORMAT", "table") or "table").strip().lower()
        if not rows:
            if resource_type:
                print(f"{UtilityTools.BOLD}Resource Type:{UtilityTools.RESET} {resource_type}")
            print("[*] No resources found.")
            return

        # Hide local filesystem path columns in table output to reduce noise.
        # (Download paths are still available via explicit download log lines.)
        hidden_path_fields = {
            "file_path",
            "filepath",
            "output_path",
            "save_path",
            "local_path",
            "download_path",
        }
        fields = [
            f for f in fields
            if str(f or "").strip().lower() not in hidden_path_fields
        ]

        # Auto-hide columns that are empty across the entire result set.
        def _has_value(v: Any) -> bool:
            if v is None:
                return False
            if isinstance(v, str):
                return bool(v.strip())
            return True

        filtered_fields: list[str] = [
            f for f in fields
            if any(_has_value(r.get(f)) for r in rows)
        ]
        if filtered_fields:
            fields = filtered_fields

        if output_format in {"txt", "text"}:
            shown = rows[:max_rows]
            headers = [f.capitalize() for f in fields]
            if resource_type:
                print(f"{UtilityTools.BOLD}Resource Type:{UtilityTools.RESET} {resource_type}")
            print(f"{UtilityTools.BOLD}Columns:{UtilityTools.RESET} " + " | ".join(headers))
            print(f"{UtilityTools.BOLD}Rows:{UtilityTools.RESET} showing {len(shown)} of {len(rows)}")
            if shown:
                print("")
            for idx, entry in enumerate(shown, start=1):
                print(f"{UtilityTools.BOLD}- item {idx}{UtilityTools.RESET}")
                for f in fields:
                    v = entry.get(f, "")
                    s = "" if v is None else str(v)
                    field_name = str(f or "").strip().lower()
                    is_path_field = field_name.endswith("path") or ("path" in field_name)

                    if condense_ocids and isinstance(s, str) and s.startswith("ocid1."):
                        try:
                            s = UtilityTools.condense_ocid(s, head=ocid_head, tail=ocid_tail)
                        except Exception:
                            pass

                    if truncate and len(s) > truncate and not is_path_field:
                        s = s[: truncate - 1] + "…"

                    print(f"    {f}: {s}")
                if idx != len(shown):
                    print("")

            if len(rows) > max_rows:
                print(f"{UtilityTools.BRIGHT_BLACK}... ({len(rows) - max_rows} more rows){UtilityTools.RESET}")
            return

        headers = [f.capitalize() for f in fields]
        table = PrettyTable()
        table.field_names = headers
        if align in ("l", "c", "r"):
            table.align = align

        shown = rows[:max_rows]
        rendered_rows: list[list[str]] = []
        for entry in shown:
            row_vals = []
            for f in fields:
                v = entry.get(f, "")
                s = "" if v is None else str(v)

                # Condense OCIDs early (before truncation)
                if condense_ocids and isinstance(s, str) and s.startswith("ocid1."):
                    try:
                        s = UtilityTools.condense_ocid(s, head=ocid_head, tail=ocid_tail)
                    except Exception:
                        pass

                # Final safety truncation
                if truncate and len(s) > truncate:
                    s = s[: truncate - 1] + "…"

                row_vals.append(s)

            rendered_rows.append(row_vals)

        if auto_wrap_to_terminal and headers:
            try:
                term_width = shutil.get_terminal_size(fallback=(120, 24)).columns
                # Terminal size detection can under-report in some shells/runtimes.
                # Keep a generous floor to avoid premature wrapping.
                effective_term_width = max(180, int(term_width))

                # Approximate PrettyTable width budget:
                # sum(col_widths) + (3 * ncols) + 1
                ncols = len(headers)
                target_total = max(40, effective_term_width - (3 * ncols) - 1)

                widths: list[int] = []
                max_col_width = max(min_col_width, int(max_col_width))
                min_col_width = max(6, int(min_col_width))

                for idx, h in enumerate(headers):
                    col_vals = [r[idx] for r in rendered_rows if idx < len(r)]
                    observed = max([len(h)] + [len(v) for v in col_vals]) if col_vals else len(h)
                    widths.append(min(max_col_width, max(min_col_width, observed)))

                current_total = sum(widths)
                while current_total > target_total:
                    reducible = [i for i, w in enumerate(widths) if w > min_col_width]
                    if not reducible:
                        break
                    i = max(reducible, key=lambda j: widths[j])
                    widths[i] -= 1
                    current_total -= 1

                table.max_width = {headers[i]: widths[i] for i in range(len(headers))}
            except Exception:
                pass

        for row_vals in rendered_rows:
            table.add_row(row_vals)

        print(table)
        if len(rows) > max_rows:
            print(f"{UtilityTools.BRIGHT_BLACK}... ({len(rows) - max_rows} more rows){UtilityTools.RESET}")
