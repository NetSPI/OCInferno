#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import oci
import yaml

from ocinferno.core.utils.module_helpers import (
    dedupe_strs,
    download_url_to_file,
    ids_from_db,
    parse_csv_args,
    safe_path_component,
    save_rows,
    unique_rows_by_id,
    write_bytes_file,
)
from ocinferno.core.utils.service_runtime import _init_client


_PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")


def build_apigateway_client(session, client_cls, service_name: str = "API Gateway", region: Optional[str] = None):
    """Initialize one API Gateway client with shared signer/proxy/session behavior."""
    client = _init_client(client_cls, session=session, service_name=service_name)
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class ApiGatewayGatewaysResource:
    TABLE_NAME = "apigw_gateways"
    COLUMNS = ["id", "display_name", "lifecycle_state", "endpoint_type", "subnet_id", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_apigateway_client(session, oci.apigateway.GatewayClient, region=region)

    # List gateways in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_gateways, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one gateway by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_gateway(gateway_id=resource_id).data) or {}

    # Save gateway rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)

    # No binary download endpoint for gateway rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class ApiGatewayApisResource:
    TABLE_NAME = "apigw_apis"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_apigateway_client(session, oci.apigateway.ApiGatewayClient, region=region)

    @staticmethod
    def response_data_to_bytes(data: Any) -> bytes:
        if data is None:
            return b""
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        if isinstance(data, str):
            return data.encode("utf-8", errors="ignore")
        text = getattr(data, "text", None)
        if isinstance(text, str):
            return text.encode("utf-8", errors="ignore")
        if hasattr(data, "read") and callable(getattr(data, "read")):
            try:
                blob = data.read()
                if isinstance(blob, (bytes, bytearray)):
                    return bytes(blob)
                if isinstance(blob, str):
                    return blob.encode("utf-8", errors="ignore")
            except Exception:
                return b""
        raw = getattr(data, "raw", None)
        if raw is not None and hasattr(raw, "read"):
            try:
                blob = raw.read()
                if isinstance(blob, (bytes, bytearray)):
                    return bytes(blob)
                if isinstance(blob, str):
                    return blob.encode("utf-8", errors="ignore")
            except Exception:
                return b""
        return b""

    @staticmethod
    def _parse_openapi_blob(blob: bytes) -> Optional[Dict[str, Any]]:
        text = (blob or b"").decode("utf-8", errors="ignore")
        if not text.strip():
            return None
        try:
            parsed = yaml.safe_load(text)
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None

    @staticmethod
    def _resolve_ref(schema: Dict[str, Any], spec: Dict[str, Any]) -> Dict[str, Any]:
        ref = schema.get("$ref")
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return schema
        cur: Any = spec
        for part in ref[2:].split("/"):
            if not isinstance(cur, dict):
                return schema
            cur = cur.get(part)
        return cur if isinstance(cur, dict) else schema

    @classmethod
    def _mock_value_from_schema(cls, schema: Dict[str, Any], spec: Dict[str, Any]) -> Any:
        schema = cls._resolve_ref(schema, spec)

        if "example" in schema:
            return schema.get("example")
        enum_vals = schema.get("enum")
        if isinstance(enum_vals, list) and enum_vals:
            return enum_vals[0]

        for key_name in ("oneOf", "anyOf", "allOf"):
            value = schema.get(key_name)
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return cls._mock_value_from_schema(value[0], spec)

        schema_type = schema.get("type")
        if schema_type == "object" or isinstance(schema.get("properties"), dict):
            out: Dict[str, Any] = {}
            for field_name, field_schema in (schema.get("properties") or {}).items():
                if isinstance(field_schema, dict):
                    out[field_name] = cls._mock_value_from_schema(field_schema, spec)
            return out
        if schema_type == "array":
            items = schema.get("items")
            if isinstance(items, dict):
                return [cls._mock_value_from_schema(items, spec)]
            return ["value"]
        if schema_type in ("integer", "number"):
            return 1
        if schema_type == "boolean":
            return True
        if schema_type == "string":
            fmt = str(schema.get("format") or "").lower()
            if fmt == "date-time":
                return "2026-01-01T00:00:00Z"
            if fmt == "uuid":
                return "00000000-0000-0000-0000-000000000000"
            return "example"
        return "value"

    @classmethod
    def _operation_body_template(cls, op: Dict[str, Any], spec: Dict[str, Any]) -> str:
        request_body = op.get("requestBody")
        if not isinstance(request_body, dict):
            return ""
        content = request_body.get("content")
        if not isinstance(content, dict):
            return ""

        media: Optional[Dict[str, Any]] = None
        for candidate in ("application/json", "application/*+json"):
            c = content.get(candidate)
            if isinstance(c, dict):
                media = c
                break
        if media is None:
            for media_type, media_value in content.items():
                if isinstance(media_type, str) and "json" in media_type.lower() and isinstance(media_value, dict):
                    media = media_value
                    break
        if not isinstance(media, dict):
            return ""

        schema = media.get("schema")
        if not isinstance(schema, dict):
            return ""
        try:
            return json.dumps(cls._mock_value_from_schema(schema, spec), separators=(",", ":"), ensure_ascii=False)
        except Exception:
            return ""

    @staticmethod
    def _server_urls(spec: Dict[str, Any], base_url: str) -> List[str]:
        out: List[str] = []
        servers = spec.get("servers")
        if isinstance(servers, list):
            for server in servers:
                if isinstance(server, dict):
                    url = server.get("url")
                    if isinstance(url, str) and url.strip():
                        out.append(url.strip())

        if not out and base_url:
            out = [base_url.strip()]
        if not out:
            out = ["https://<gateway-host>"]

        normalized: List[str] = []
        for url in out:
            if url.startswith("/"):
                if base_url:
                    normalized.append(urljoin(base_url.rstrip("/") + "/", url.lstrip("/")))
                else:
                    normalized.append("https://<gateway-host>" + url)
            else:
                normalized.append(url)
        return normalized

    @staticmethod
    def _replace_path_params(path: str) -> str:
        return _PATH_PARAM_RE.sub(lambda match: f"sample_{match.group(1)}", path)

    @staticmethod
    def _query_template(op: Dict[str, Any], path_item: Dict[str, Any]) -> str:
        params: List[Dict[str, Any]] = []
        for src in (path_item, op):
            p = src.get("parameters") if isinstance(src, dict) else None
            if isinstance(p, list):
                params.extend([x for x in p if isinstance(x, dict)])

        seen: set[str] = set()
        parts: List[str] = []
        for param in params:
            if param.get("in") != "query":
                continue
            name = param.get("name")
            if not isinstance(name, str) or not name or name in seen:
                continue
            seen.add(name)
            parts.append(f"{name}=sample_{name}")
        return ("?" + "&".join(parts)) if parts else ""

    @classmethod
    def build_curl_script(cls, spec: Dict[str, Any], *, base_url: str = "", api_id: str = "") -> str:
        paths = spec.get("paths")
        if not isinstance(paths, dict):
            return "# No paths found in OpenAPI content.\n"

        servers = cls._server_urls(spec, base_url)
        lines: List[str] = [
            "#!/usr/bin/env bash",
            f"# Generated curl templates for API: {api_id or 'unknown'}",
            "",
        ]

        for raw_path, path_item in paths.items():
            if not isinstance(raw_path, str) or not isinstance(path_item, dict):
                continue
            for method in ("get", "post"):
                op = path_item.get(method)
                if not isinstance(op, dict):
                    continue

                op_id = op.get("operationId") if isinstance(op.get("operationId"), str) else ""
                path_no_vars = cls._replace_path_params(raw_path)
                query = cls._query_template(op, path_item)
                body = cls._operation_body_template(op, spec) if method == "post" else ""
                lines.append(f"# {method.upper()} {raw_path}" + (f" ({op_id})" if op_id else ""))

                for server_url in servers:
                    url = server_url.rstrip("/") + "/" + path_no_vars.lstrip("/") + query
                    if body:
                        safe_body = body.replace("'", "'\"'\"'")
                        lines.append(
                            "curl -i -X POST "
                            + f"'{url}' "
                            + "-H 'Content-Type: application/json' "
                            + f"-d '{safe_body}'"
                        )
                    else:
                        lines.append("curl -i -X GET " + f"'{url}'")
                lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    # List APIs (or specific API IDs if provided).
    def list(self, *, compartment_id: str, api_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        ids = dedupe_strs(api_ids or [])
        if ids:
            rows: List[Dict[str, Any]] = []
            for api_id in ids:
                one = self.get(resource_id=api_id) or {}
                if isinstance(one, dict) and one:
                    rows.append(one)
            return unique_rows_by_id(rows)

        resp = oci.pagination.list_call_get_all_results(self.client.list_apis, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one API by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_api(api_id=resource_id).data) or {}

    # Get API content blob as bytes.
    def get_api_content(self, *, api_id: str) -> bytes:
        try:
            resp = self.client.get_api_content(api_id=api_id)
        except Exception:
            return b""
        return self.response_data_to_bytes(getattr(resp, "data", None))

    # Get API deployment specification blob as bytes.
    def get_api_deployment_specification(self, *, api_id: str) -> bytes:
        try:
            resp = self.client.get_api_deployment_specification(api_id=api_id)
        except Exception:
            return b""
        return self.response_data_to_bytes(getattr(resp, "data", None))

    # Save API rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)

    # Download API content.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        blob = self.get_api_content(api_id=resource_id) or b""
        return bool(blob) and write_bytes_file(out_path, blob)

    # Download API deployment specification.
    def download_deployment_spec(self, *, resource_id: str, out_path: str) -> bool:
        blob = self.get_api_deployment_specification(api_id=resource_id) or b""
        return bool(blob) and write_bytes_file(out_path, blob)


class ApiGatewayDeploymentsResource:
    TABLE_NAME = "apigw_deployments"
    TABLE_GATEWAYS = "apigw_gateways"
    COLUMNS = ["id", "display_name", "lifecycle_state", "gateway_id", "path_prefix", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_apigateway_client(session, oci.apigateway.DeploymentClient, region=region)
        self.gateway_client = build_apigateway_client(session, oci.apigateway.GatewayClient, region=region)

    # Resolve gateway IDs from CLI, DB cache, or live gateway listing.
    def resolve_gateway_ids(self, args, compartment_id: str, *, debug: bool = False) -> List[str]:
        cli_ids = parse_csv_args(getattr(args, "gateway_ids", []) or [])
        if cli_ids:
            return cli_ids

        try:
            db_ids = ids_from_db(self.session, table_name=self.TABLE_GATEWAYS, compartment_id=compartment_id)
        except Exception:
            db_ids = []
        if db_ids:
            return db_ids

        try:
            gw_resp = oci.pagination.list_call_get_all_results(self.gateway_client.list_gateways, compartment_id=compartment_id)
            gw_rows = oci.util.to_dict(gw_resp.data) or []
        except Exception:
            return []

        _ = debug
        return parse_csv_args([r.get("id") for r in gw_rows if isinstance(r, dict) and isinstance(r.get("id"), str)])

    # List deployments, optionally scoped to gateway IDs.
    def list(self, *, compartment_id: str, gateway_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        gids = dedupe_strs(gateway_ids or [])
        rows: List[Dict[str, Any]] = []
        if gids:
            for gid in gids:
                resp = oci.pagination.list_call_get_all_results(
                    self.client.list_deployments,
                    compartment_id=compartment_id,
                    gateway_id=gid,
                )
                rows.extend(oci.util.to_dict(resp.data) or [])
        else:
            resp = oci.pagination.list_call_get_all_results(self.client.list_deployments, compartment_id=compartment_id)
            rows = oci.util.to_dict(resp.data) or []
        return unique_rows_by_id(rows)

    # Get one deployment by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_deployment(deployment_id=resource_id).data) or {}

    # Save deployment rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)

    # No binary download endpoint for deployment rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class ApiGatewaySdksResource:
    TABLE_NAME = "apigw_sdks"
    TABLE_APIS = "apigw_apis"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_apigateway_client(session, oci.apigateway.ApiGatewayClient, region=region)

    @staticmethod
    def filename_for_sdk_artifact(sdk_row: Dict[str, Any]) -> str:
        url = str(sdk_row.get("artifact_url") or "").strip()
        path = urlparse(url).path if url else ""
        base = os.path.basename(path or "")
        if base:
            return safe_path_component(base)
        lang = safe_path_component(str(sdk_row.get("target_language") or "sdk"))
        return f"{lang}.zip"

    # Resolve API IDs from CLI, DB cache, or live API listing.
    def resolve_sdk_api_ids(self, args, *, debug: bool = False) -> List[str]:
        cli_ids = parse_csv_args(getattr(args, "api_ids", []) or [])
        if cli_ids:
            return cli_ids

        comp_id = getattr(self.session, "compartment_id", None)
        if not comp_id:
            return []

        try:
            db_ids = ids_from_db(self.session, table_name=self.TABLE_APIS, compartment_id=comp_id)
        except Exception:
            db_ids = []
        if db_ids:
            return db_ids

        try:
            resp = oci.pagination.list_call_get_all_results(self.client.list_apis, compartment_id=comp_id)
            rows = oci.util.to_dict(resp.data) or []
        except Exception:
            return []

        _ = debug
        return dedupe_strs([r.get("id") for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)])

    # List SDK records by sdk-id or api-id scope.
    def list(self, *, sdk_id: str = "", api_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        sid = str(sdk_id or "").strip()
        ids = dedupe_strs(api_ids or [])

        if sid:
            one = self.get(resource_id=sid) or {}
            return [one] if one else []

        if not ids:
            return []

        rows: List[Dict[str, Any]] = []
        for aid in ids:
            resp = oci.pagination.list_call_get_all_results(self.client.list_sdks, api_id=aid)
            rows.extend(oci.util.to_dict(resp.data) or [])

        rows = unique_rows_by_id(rows)
        api_id_set = set(ids)
        return [r for r in rows if isinstance(r, dict) and r.get("api_id") in api_id_set]

    # Get one SDK by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_sdk(sdk_id=resource_id).data) or {}

    # Save SDK rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)

    # Download SDK artifact.
    def download(self, *, sdk_row: Dict[str, Any], out_path: str) -> bool:
        artifact_url = sdk_row.get("artifact_url")
        if not artifact_url:
            sid = sdk_row.get("id")
            if sid:
                meta = self.get(resource_id=sid)
                if isinstance(meta, dict):
                    sdk_row.update(meta)
                    artifact_url = sdk_row.get("artifact_url")
        if not artifact_url:
            return False
        return bool(download_url_to_file(str(artifact_url), str(out_path)))
