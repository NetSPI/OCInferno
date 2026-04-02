from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


class ArtifactRegistryRepositoriesResource:
    TABLE_NAME = "ar_repositories"
    COLUMNS = ["id", "display_name", "repository_type", "lifecycle_state"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = _init_client(oci.artifacts.ArtifactsClient, session=session, service_name="Artifacts")
        target_region = region or getattr(session, "region", None)
        if target_region:
            try:
                self.client.base_client.set_region(target_region)
            except Exception:
                pass

    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_repositories, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_repository(repository_id=resource_id).data) or {}

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class ArtifactRegistryArtifactsResource:
    TABLE_NAME = "ar_generic_artifact"
    COLUMNS = ["id", "artifact_path", "version", "sha256", "lifecycle_state", "time_created", "repository_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = _init_client(oci.artifacts.ArtifactsClient, session=session, service_name="Artifacts")
        self.content_client = _init_client(
            oci.generic_artifacts_content.GenericArtifactsContentClient,
            session=session,
            service_name="GenericArtifactsContent",
        )
        target_region = region or getattr(session, "region", None)
        if target_region:
            for client in (self.client, self.content_client):
                try:
                    client.base_client.set_region(target_region)
                except Exception:
                    pass

    def list_repositories(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_repositories, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    def list(self, *, compartment_id: str, repository_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_generic_artifacts,
            compartment_id=compartment_id,
            repository_id=repository_id,
        )
        return oci.util.to_dict(resp.data) or []

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_generic_artifact(artifact_id=resource_id).data) or {}

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    @staticmethod
    def _write_stream_to_file(payload: Any, out_file: str, chunk_size: int) -> bool:
        if payload is None:
            return False

        os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)

        if isinstance(payload, (bytes, bytearray)):
            with open(out_file, "wb") as handle:
                handle.write(payload)
            return os.path.getsize(out_file) > 0

        if hasattr(payload, "read") and callable(getattr(payload, "read")):
            with open(out_file, "wb") as handle:
                while True:
                    chunk = payload.read(chunk_size)
                    if not chunk:
                        break
                    handle.write(chunk)
            return os.path.getsize(out_file) > 0

        if hasattr(payload, "iter_content") and callable(getattr(payload, "iter_content")):
            with open(out_file, "wb") as handle:
                for chunk in payload.iter_content(chunk_size=chunk_size):
                    if chunk:
                        handle.write(chunk)
            return os.path.getsize(out_file) > 0

        raw = getattr(payload, "raw", None)
        if raw is not None and hasattr(raw, "read") and callable(getattr(raw, "read")):
            with open(out_file, "wb") as handle:
                while True:
                    chunk = raw.read(chunk_size)
                    if not chunk:
                        break
                    handle.write(chunk)
            return os.path.getsize(out_file) > 0

        return False

    def download_by_path(
        self,
        *,
        repository_id: str,
        artifact_path: str,
        version: str,
        out_file: str,
        chunk_size: int = 1024 * 1024,
    ) -> bool:
        if not repository_id or not artifact_path or not version:
            return False
        resp = self.content_client.get_generic_artifact_content_by_path(
            repository_id=repository_id,
            artifact_path=artifact_path,
            version=version,
        )
        return self._write_stream_to_file(getattr(resp, "data", None), out_file, chunk_size)

    def download_by_id(self, *, artifact_id: str, out_file: str, chunk_size: int = 1024 * 1024) -> bool:
        if not artifact_id:
            return False
        resp = self.content_client.get_generic_artifact_content(artifact_id=artifact_id)
        return self._write_stream_to_file(getattr(resp, "data", None), out_file, chunk_size)

    @staticmethod
    def sanitize_relpath(value: str) -> str:
        cleaned = (value or "").strip().lstrip("/").replace("\\", "/")
        cleaned = cleaned.replace("..", "")
        cleaned = re.sub(r"/{2,}", "/", cleaned).strip("/")
        return cleaned or "artifact"

    @classmethod
    def version_key(cls, version: str):
        text = (version or "").strip()
        if not text:
            return (0,)

        parts = re.split(r"([0-9]+)", text)
        key = []
        for part in parts:
            if not part:
                continue
            if part.isdigit():
                key.append((1, int(part)))
            else:
                key.append((0, part.lower()))
        return tuple(key)

    @classmethod
    def pick_latest_per_path(cls, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        best: Dict[tuple, Dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            repository_id = row.get("repository_id") or ""
            artifact_path = row.get("artifact_path") or ""
            version = row.get("version") or ""
            if not repository_id or not artifact_path or not version:
                continue
            key = (repository_id, artifact_path)
            existing = best.get(key)
            if not existing or cls.version_key(version) > cls.version_key(existing.get("version") or ""):
                best[key] = row
        return list(best.values())

    @classmethod
    def out_path(cls, out_dir: str, repository_id: str, artifact_path: str, version: str) -> str:
        repo_dir = cls.sanitize_relpath(repository_id)
        artifact_rel = cls.sanitize_relpath(artifact_path)
        target_dir = os.path.join(out_dir, repo_dir, os.path.dirname(artifact_rel))
        os.makedirs(target_dir, exist_ok=True)

        base = os.path.basename(artifact_rel) or "artifact"
        name, ext = os.path.splitext(base)
        filename = f"{name}__{version}{ext}" if ext else f"{base}__{version}"
        return os.path.join(target_dir, filename)

    @classmethod
    def out_path_via_session(
        cls,
        session,
        repository_id: str,
        artifact_path: str,
        version: str,
        compartment_id: str,
    ) -> str:
        artifact_rel = cls.sanitize_relpath(artifact_path)
        base = os.path.basename(artifact_rel) or "artifact"
        name, ext = os.path.splitext(base)
        filename = f"{name}__{version}{ext}" if ext else f"{base}__{version}"

        subdirs: List[str] = ["generic_artifacts", cls.sanitize_relpath(repository_id)]
        parent = os.path.dirname(artifact_rel)
        if parent:
            subdirs.extend([part for part in parent.split("/") if part])

        return str(
            session.get_download_save_path(
                service_name="artifactregistry",
                filename=filename,
                compartment_id=(compartment_id or getattr(session, "compartment_id", "") or "global"),
                subdirs=subdirs,
            )
        )
