"""Session-independent output-path policy.

The canonical on-disk layout
    <cwd>/ocinferno_output/<workspace_id>_<workspace_slug>/{downloads,exports,reports,tool_logs}/...
extracted out of the SessionUtility god-object so path policy isn't coupled to it.
SessionUtility keeps thin delegating wrappers (get_workspace_output_root /
get_download_save_path / get_export_save_path / resolve_output_path), so callers are
unchanged. Pure path computation -- no credentials, no session state beyond the
workspace id/name passed in.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import List, Optional, Union

OUTPUT_ROOT_DIR_NAME = "ocinferno_output"
OUTPUT_DIR_NAMES = {
    "downloads": "downloads",
    "exports": "exports",
    "reports": "reports",
    "logs": "tool_logs",
}


def safe_path_component(x: str) -> str:
    x = str(x or "")
    x = x.replace("/", "_").replace("\\", "_").replace(":", "_")
    x = re.sub(r"\s+", "_", x)
    return re.sub(r"[^A-Za-z0-9_.\-]", "", x).strip("._-")


def compact_filename_component(filename: str, *, max_len: int = 128) -> str:
    safe_name = safe_path_component(filename) or "file"
    if len(safe_name) <= max_len:
        return safe_name

    stem, dot, ext = safe_name.rpartition(".")
    if not stem:
        stem, ext = safe_name, ""

    digest = hashlib.sha1(safe_name.encode("utf-8")).hexdigest()[:12]
    ext_len = (len(ext) + 1) if ext else 0
    keep = max(24, max_len - ext_len - len(digest) - 2)
    compact_stem = stem[:keep]
    compact = f"{compact_stem}__{digest}"
    return f"{compact}.{ext}" if ext else compact


def compact_compartment_path_component(x: str) -> str:
    safe = safe_path_component(x)
    if not safe:
        return "global"
    if len(safe) <= 64:
        return safe
    digest = hashlib.sha1(safe.encode("utf-8")).hexdigest()[:10]
    head = safe[:24]
    tail = safe[-8:]
    return f"{head}__{tail}__{digest}"


_OCID_RE = re.compile(r"^ocid1\.([a-z0-9]+)\.", re.IGNORECASE)


def _ocid_tail(ocid: str, last: int = 4) -> str:
    """Last `last` alphanumeric chars of an OCID (OCIDs end in the unique part)."""
    alnum = re.sub(r"[^A-Za-z0-9]", "", str(ocid or ""))
    return alnum[-last:] if alnum else ""


def friendly_component(name: Optional[str], ocid: str, *, last: int = 4, max_name: int = 48) -> str:
    """Readable folder name: `<SIMPLE_NAME>_<last4-of-ocid>` when a name is known,
    else `<ocid-type>_<last4>` (e.g. `tenancy_sfaa`, `ormstack_xf6a`). Falls back to the
    compacted OCID if the value is not an OCID and has no name."""
    tail = _ocid_tail(ocid, last)
    nm = safe_path_component(name or "")
    if nm:
        nm = nm[:max_name]
        return f"{nm}_{tail}" if tail else nm
    m = _OCID_RE.match(str(ocid or ""))
    if m:
        return f"{m.group(1)}_{tail}" if tail else m.group(1)
    return compact_compartment_path_component(ocid)


def shorten_ocid_path_component(x: str, *, last: int = 4) -> str:
    """Sanitize a path component, collapsing a bare OCID to `<type>_<last4>`."""
    s = str(x or "")
    if _OCID_RE.match(s):
        return friendly_component(None, s, last=last)
    return safe_path_component(s)


def default_output_base_root() -> Path:
    """Base output directory: <cwd>/ocinferno_output."""
    return Path.cwd() / OUTPUT_ROOT_DIR_NAME


def workspace_output_root(workspace_id: int, workspace_name: str, *, mkdir: bool = True) -> Path:
    workspace_dir = f"{workspace_id}_{safe_path_component(workspace_name)}"
    out = default_output_base_root() / workspace_dir
    if mkdir:
        try:
            out.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Fallback to home if the current directory is not writable.
            out = Path.home() / OUTPUT_ROOT_DIR_NAME / workspace_dir
            out.mkdir(parents=True, exist_ok=True)
    return out


def download_save_path(
    workspace_id: int,
    workspace_name: str,
    *,
    service_name: str,
    filename: str,
    compartment_id: str,
    compartment_label: Optional[str] = None,
    resource_name: Optional[str] = None,
    subdirs: Optional[List[str]] = None,
    mkdir: bool = True,
) -> Path:
    """<root>/<workspace>/downloads/<service>/<compartment>/<subdirs...>/<filename>.

    `compartment_label` (e.g. `NAME_last4`) replaces the raw-OCID compartment folder
    when the caller can resolve a friendly name."""
    compartment_dir = safe_path_component(compartment_label) if compartment_label else compact_compartment_path_component(compartment_id)
    parts = [
        workspace_output_root(workspace_id, workspace_name, mkdir=mkdir),
        OUTPUT_DIR_NAMES["downloads"],
        safe_path_component(service_name),
        compartment_dir or compact_compartment_path_component(compartment_id),
    ]
    for raw_part in (subdirs or []):
        cleaned = shorten_ocid_path_component(raw_part)
        if cleaned:
            parts.append(cleaned)

    output_filename = compact_filename_component(filename)
    if resource_name:
        name_hint = safe_path_component(resource_name)
        if name_hint:
            dot = output_filename.rfind(".")
            stem, ext = (output_filename[:dot], output_filename[dot:]) if dot > 0 else (output_filename, "")
            if name_hint not in stem:
                stem = compact_filename_component(f"{stem}__{name_hint}")
                output_filename = f"{stem}{ext}"

    out = Path(*parts) / output_filename
    if mkdir:
        out.parent.mkdir(parents=True, exist_ok=True)
    return out


def export_save_path(
    workspace_id: int,
    workspace_name: str,
    *,
    service_name: str,
    filename: str,
    compartment_id: Optional[str] = None,
    compartment_label: Optional[str] = None,
    subdirs: Optional[List[str]] = None,
    mkdir: bool = True,
) -> Path:
    """<root>/<workspace>/exports/<service>/<compartment|global>/<subdirs...>/<filename>."""
    if compartment_label:
        comp = safe_path_component(compartment_label) or compact_compartment_path_component(compartment_id)
    else:
        comp = safe_path_component(compartment_id or "global")
    parts = [
        workspace_output_root(workspace_id, workspace_name, mkdir=mkdir),
        OUTPUT_DIR_NAMES["exports"],
        safe_path_component(service_name),
        comp,
    ]
    for raw_part in (subdirs or []):
        cleaned = shorten_ocid_path_component(raw_part)
        if cleaned:
            parts.append(cleaned)

    out = Path(*parts) / compact_filename_component(filename)
    if mkdir:
        out.parent.mkdir(parents=True, exist_ok=True)
    return out


def resolve_output_path(
    workspace_id: int,
    workspace_name: str,
    *,
    requested_path: Union[str, Path, None] = None,
    service_name: str,
    filename: str,
    compartment_id: Optional[str] = None,
    current_compartment: Optional[str] = None,
    compartment_label: Optional[str] = None,
    subdirs: Optional[List[str]] = None,
    target: str = "export",
    mkdir: bool = True,
) -> Path:
    """Central output-path resolver: an explicit requested_path wins; otherwise the
    session-managed export/download layout."""
    if requested_path:
        out = Path(requested_path).expanduser()
        if mkdir:
            out.parent.mkdir(parents=True, exist_ok=True)
        return out

    bucket = str(target or "export").strip().lower()
    if bucket == "download":
        comp = compartment_id or current_compartment or "global"
        return download_save_path(
            workspace_id, workspace_name,
            service_name=service_name, filename=filename, compartment_id=comp,
            compartment_label=compartment_label, subdirs=subdirs, mkdir=mkdir,
        )

    return export_save_path(
        workspace_id, workspace_name,
        service_name=service_name,
        filename=filename,
        compartment_id=compartment_id if compartment_id is not None else current_compartment,
        compartment_label=compartment_label, subdirs=subdirs, mkdir=mkdir,
    )
