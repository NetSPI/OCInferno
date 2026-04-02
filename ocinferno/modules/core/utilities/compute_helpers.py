import base64
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.service_runtime import _init_client


# Local string normalizer used by plugin/row normalizers.
def _s(value: Any) -> str:
    if value is None:
        return ""
    return value.strip() if isinstance(value, str) else str(value)


# -------------------- Compute Ops (reusable) --------------------

class ComputeResourceClient:
    """
    Reusable wrapper for OCI Compute Instances with pagination, region wiring,
    proxy/timeout wiring, and handy helpers.
    """
    TABLE_COMPUTE_INSTANCES = "compute_instances"
    def __init__(
        self,
        session,
        connect_timeout: int = 5,
        read_timeout: int = 60,
        region: Optional[str] = None,
    ):

        self.session = session
        self.debug = session.individual_run_debug

        self.client = _init_client(
            oci.core.ComputeClient,
            session=session,
            service_name="Compute",
        )

        # Region is mandatory for core/compute calls
        if region:
            try:
                self.client.base_client.set_region(region)
            except Exception:
                pass
        else:
            # If your session has region tracking, use it
            try:
                if getattr(session, "region", None):
                    self.client.base_client.set_region(session.region)
            except Exception:
                pass
        
    # -------- Instances --------

    def list_instances(self, *, compartment_id: str):
  
        rows = self.client.list_instances(
            compartment_id=compartment_id,
        )
        output = oci.util.to_dict(rows.data)
        
        return output

    def get_instance(self, instance_id: str) -> oci.core.models.Instance:
        return oci.util.to_dict(self.client.get_instance(instance_id).data)

    def list_shapes(
        self,
        *,
        compartment_id: str,
        availability_domain: Optional[str] = None,
        image_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if availability_domain:
            kwargs["availability_domain"] = availability_domain
        if image_id:
            kwargs["image_id"] = image_id

        resp = oci.pagination.list_call_get_all_results(
            self.client.list_shapes,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    def launch_instance(self, launch_instance_details: Any) -> Dict[str, Any]:
        resp = self.client.launch_instance(
            launch_instance_details=launch_instance_details,
        )
        return oci.util.to_dict(resp.data) or {}

    def update_instance_metadata(self, *, instance_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        details = oci.core.models.UpdateInstanceDetails(
            metadata=metadata,
        )
        resp = self.client.update_instance(
            instance_id=instance_id,
            update_instance_details=details,
        )
        return oci.util.to_dict(resp.data) or {}

    def instance_action(self, *, instance_id: str, action: str) -> Dict[str, Any]:
        resp = self.client.instance_action(
            instance_id=instance_id,
            action=action,
        )
        return oci.util.to_dict(resp.data) or {}

    # -------- VNIC Attachments (optional but useful) --------

    def list_vnic_attachments(
        self,
        compartment_id: str,
        *,
        instance_id: Optional[str] = None
    ) -> List[oci.core.models.VnicAttachment]:
        paginator = oci.pagination.list_call_get_all_results
        kwargs = {}
        if instance_id:
            kwargs["instance_id"] = instance_id

        resp = paginator(
            self.client.list_vnic_attachments,
            compartment_id=compartment_id,
            **kwargs
        )
        return resp.data or []

    # -------- Regions helper (for all-regions collection) --------

    @staticmethod
    def list_subscribed_regions(session, proxy: Optional[str] = None) -> List[str]:
        """
        Returns region_name list for regions this tenancy is subscribed to.
        """
        identity = oci.identity.IdentityClient(
            session.credentials,
            retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY
        )
        session.add_proxy_config(identity, proxy_address=proxy)

        tenancy_id = getattr(session, "tenancy_id", None) or getattr(session, "compartment_id", None)
        resp = oci.pagination.list_call_get_all_results(
            identity.list_region_subscriptions,
            tenancy_id
        )
        regions = []
        for r in (resp.data or []):
            rn = getattr(r, "region_name", None)
            if rn:
                regions.append(rn)
        return regions

    def save_instances(self, rows) -> None:
        self.session.save_resources(rows or [], self.TABLE_COMPUTE_INSTANCES)







# -------------------- Image Ops (reusable) --------------------

class ImageResourceClient:
    """
    Reusable wrapper for OCI Compute Images.

    Designed to mirror enum_objectstorage --buckets / enum_instances behavior:
      - list_images() returns summary rows (dicts)
      - get_image() returns full metadata (dict)
      - caller decides whether to merge/save
    """
    TABLE_COMPUTE_IMAGES = "compute_images"

    def __init__(
        self,
        session,
        *,
        region: Optional[str] = None,
    ):
        self.session = session
        self.debug = bool(
            getattr(session, "individual_run_debug", False)
            or getattr(session, "debug", False)
        )

        self.client = _init_client(
            oci.core.ComputeClient,
            session=session,
            service_name="Compute",
        )

        # Region wiring (same pattern as ComputeResourceClient)
        if region:
            try:
                self.client.base_client.set_region(region)
            except Exception:
                pass
        else:
            try:
                if getattr(session, "region", None):
                    self.client.base_client.set_region(session.region)
            except Exception:
                pass

    # -------- Images --------

    def list_images(
        self,
        *,
        compartment_id: str,
        display_name: Optional[str] = None,
        operating_system: Optional[str] = None,
        operating_system_version: Optional[str] = None,
        shape: Optional[str] = None,
        lifecycle_state: Optional[str] = None,
        sort_by: Optional[str] = None,
        sort_order: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Wrapper around ComputeClient.list_images.

        Returns list[dict] (ImageSummary rows).
        """

        kwargs: Dict[str, Any] = {}
        if display_name:
            kwargs["display_name"] = display_name
        if operating_system:
            kwargs["operating_system"] = operating_system
        if operating_system_version:
            kwargs["operating_system_version"] = operating_system_version
        if shape:
            kwargs["shape"] = shape
        if lifecycle_state:
            kwargs["lifecycle_state"] = lifecycle_state
        if sort_by:
            kwargs["sort_by"] = sort_by
        if sort_order:
            kwargs["sort_order"] = sort_order

        UtilityTools.dlog(
            self.debug,
            "list_images",
            compartment_id=compartment_id,
            **kwargs,
        )

        resp = self.client.list_images(
            compartment_id=compartment_id,
            **kwargs,
        )

        rows = oci.util.to_dict(resp.data) or []
        if isinstance(rows, dict):
            rows = [rows]

        # Normalize compartment_id into each row for DB joins
        for r in rows:
            if isinstance(r, dict):
                r.setdefault("compartment_id", compartment_id)

        return rows

    def get_image(self, image_id: str) -> Dict[str, Any]:
        """
        Fetch full Image object (details not included in list_images).
        """
        UtilityTools.dlog(self.debug, "get_image", image_id=image_id)

        resp = self.client.get_image(image_id)
        return oci.util.to_dict(resp.data)

    def save_images(self, rows) -> None:
        self.session.save_resources(rows or [], self.TABLE_COMPUTE_IMAGES)


class ComputeInstanceAgentResourceClient:
    """
    Reusable wrapper for OCI Compute Instance Agent command operations.

    Pattern:
      - create/get/list/cancel return dict/list[dict]
      - normalize_* helpers flatten important fields for DB tables
    """

    TABLE_COMMANDS = "compute_instance_agent_commands"
    TABLE_EXECUTIONS = "compute_instance_agent_command_executions"
    TABLE_PLUGINS = "compute_instance_agent_plugins"
    TABLE_AVAILABLE_PLUGINS = "compute_instance_agent_available_plugins"

    def __init__(
        self,
        session,
        *,
        region: Optional[str] = None,
    ):
        self.session = session
        self.debug = bool(
            getattr(session, "individual_run_debug", False)
            or getattr(session, "debug", False)
        )

        self.client = _init_client(
            oci.compute_instance_agent.ComputeInstanceAgentClient,
            session=session,
            service_name="Compute Instance Agent",
        )
        self.plugin_client = _init_client(
            oci.compute_instance_agent.PluginClient,
            session=session,
            service_name="Compute Instance Agent Plugin",
        )
        self.pluginconfig_client = _init_client(
            oci.compute_instance_agent.PluginconfigClient,
            session=session,
            service_name="Compute Instance Agent PluginConfig",
        )

        if region:
            try:
                self.client.base_client.set_region(region)
            except Exception:
                pass
            try:
                self.plugin_client.base_client.set_region(region)
            except Exception:
                pass
            try:
                self.pluginconfig_client.base_client.set_region(region)
            except Exception:
                pass
        elif getattr(session, "region", None):
            try:
                self.client.base_client.set_region(session.region)
            except Exception:
                pass
            try:
                self.plugin_client.base_client.set_region(session.region)
            except Exception:
                pass
            try:
                self.pluginconfig_client.base_client.set_region(session.region)
            except Exception:
                pass

    @staticmethod
    def _as_dict(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        return {}

    def create_instance_agent_command_text(
        self,
        *,
        compartment_id: str,
        instance_id: str,
        command_text: str,
        display_name: str = "",
        execution_timeout_seconds: int = 3600,
    ) -> Dict[str, Any]:
        source = oci.compute_instance_agent.models.InstanceAgentCommandSourceViaTextDetails(
            source_type="TEXT",
            text=command_text,
        )
        output = oci.compute_instance_agent.models.InstanceAgentCommandOutputViaTextDetails(
            output_type="TEXT",
        )
        content = oci.compute_instance_agent.models.InstanceAgentCommandContent(
            source=source,
            output=output,
        )
        target = oci.compute_instance_agent.models.InstanceAgentCommandTarget(
            instance_id=instance_id,
        )
        details = oci.compute_instance_agent.models.CreateInstanceAgentCommandDetails(
            compartment_id=compartment_id,
            display_name=display_name or None,
            content=content,
            target=target,
            execution_time_out_in_seconds=max(1, int(execution_timeout_seconds)),
        )
        resp = self.client.create_instance_agent_command(
            create_instance_agent_command_details=details,
        )
        return oci.util.to_dict(resp.data) or {}

    def get_instance_agent_command(self, *, instance_agent_command_id: str) -> Dict[str, Any]:
        resp = self.client.get_instance_agent_command(
            instance_agent_command_id=instance_agent_command_id,
        )
        return oci.util.to_dict(resp.data) or {}

    def list_instance_agent_commands(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_instance_agent_commands,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    def cancel_instance_agent_command(self, *, instance_agent_command_id: str) -> None:
        self.client.cancel_instance_agent_command(
            instance_agent_command_id=instance_agent_command_id,
        )

    def get_instance_agent_command_execution(
        self,
        *,
        instance_agent_command_id: str,
        instance_id: str,
    ) -> Dict[str, Any]:
        # This maps to:
        # GET /20180530/instanceAgentCommands/{id}/status?instanceId=<instance OCID>
        # On current SDKs the parameter is `instance_id`; keep a fallback for
        # older/generated variants that used `instanceagent_id`.
        variants = [
            {
                "instance_agent_command_id": instance_agent_command_id,
                "instance_id": instance_id,
            },
            {
                "instance_agent_command_id": instance_agent_command_id,
                "instanceagent_id": instance_id,
            },
        ]
        last_type_error: Exception | None = None
        for kwargs in variants:
            try:
                resp = self.client.get_instance_agent_command_execution(**kwargs)
                return oci.util.to_dict(resp.data) or {}
            except (TypeError, ValueError) as e:
                last_type_error = e
                continue
        if last_type_error is not None:
            raise last_type_error
        return {}

    def list_instance_agent_command_executions(
        self,
        *,
        compartment_id: str,
        instance_id: str,
    ) -> List[Dict[str, Any]]:
        # Current SDK expects `instance_id`; keep compatibility fallback.
        variants = [
            {"compartment_id": compartment_id, "instance_id": instance_id},
            {"compartment_id": compartment_id, "instanceagent_id": instance_id},
        ]
        last_type_error: Exception | None = None
        for kwargs in variants:
            try:
                resp = oci.pagination.list_call_get_all_results(
                    self.client.list_instance_agent_command_executions,
                    **kwargs,
                )
                return oci.util.to_dict(resp.data) or []
            except (TypeError, ValueError) as e:
                last_type_error = e
                continue
        if last_type_error is not None:
            raise last_type_error
        return []

    def list_instance_agent_plugins(
        self,
        *,
        compartment_id: str,
        instance_id: str,
    ) -> List[Dict[str, Any]]:
        # SDKs differ on this parameter name (`instanceagent_id` vs `instance_id`).
        # Try both to remain compatible across pinned versions.
        variants = [
            {"compartment_id": compartment_id, "instanceagent_id": instance_id},
            {"compartment_id": compartment_id, "instance_id": instance_id},
        ]
        last_type_error: Exception | None = None
        for kwargs in variants:
            try:
                resp = oci.pagination.list_call_get_all_results(
                    self.plugin_client.list_instance_agent_plugins,
                    **kwargs,
                )
                return oci.util.to_dict(resp.data) or []
            except TypeError as e:
                last_type_error = e
                continue
        if last_type_error is not None:
            raise last_type_error
        return []

    def get_instance_agent_plugin(
        self,
        *,
        compartment_id: str,
        instance_id: str,
        plugin_name: str,
    ) -> Dict[str, Any]:
        variants = [
            {
                "compartment_id": compartment_id,
                "instanceagent_id": instance_id,
                "plugin_name": plugin_name,
            },
            {
                "compartment_id": compartment_id,
                "instance_id": instance_id,
                "plugin_name": plugin_name,
            },
        ]
        last_type_error: Exception | None = None
        for kwargs in variants:
            try:
                resp = self.plugin_client.get_instance_agent_plugin(**kwargs)
                return oci.util.to_dict(resp.data) or {}
            except TypeError as e:
                last_type_error = e
                continue
        if last_type_error is not None:
            raise last_type_error
        return {}

    def list_instanceagent_available_plugins(
        self,
        *,
        compartment_id: str,
        os_name: str = "",
        os_version: str = "",
    ) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if os_name:
            kwargs["os_name"] = os_name
        if os_version:
            kwargs["os_version"] = os_version
        resp = oci.pagination.list_call_get_all_results(
            self.pluginconfig_client.list_instanceagent_available_plugins,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    @classmethod
    def normalize_command_row(
        cls,
        command: Dict[str, Any],
        *,
        command_text: str = "",
        source: str = "simulation",
    ) -> Dict[str, Any]:
        c = cls._as_dict(command)
        target = cls._as_dict(c.get("target"))
        content = cls._as_dict(c.get("content"))
        source_obj = cls._as_dict(content.get("source"))
        output_obj = cls._as_dict(content.get("output"))
        command_id = (
            c.get("id")
            or c.get("instance_agent_command_id")
            or c.get("instanceagent_command_id")
            or c.get("command_id")
        )
        target_instance_id = (
            target.get("instance_id")
            or target.get("instanceagent_id")
            or c.get("instance_id")
        )
        command_text_value = command_text or source_obj.get("text") or c.get("command_text")

        return {
            "id": command_id,
            "compartment_id": c.get("compartment_id"),
            "display_name": c.get("display_name"),
            "lifecycle_state": c.get("lifecycle_state"),
            "delivery_state": c.get("delivery_state"),
            "execution_time_out_in_seconds": c.get("execution_time_out_in_seconds"),
            "delivery_time_out_in_seconds": c.get("delivery_time_out_in_seconds"),
            "is_canceled": c.get("is_canceled"),
            "time_created": c.get("time_created"),
            "time_updated": c.get("time_updated"),
            "target_instance_id": target_instance_id,
            "target_raw_json": target,
            "content_raw_json": content,
            "command_text": command_text_value,
            "command_source_type": source_obj.get("source_type"),
            "command_output_type": output_obj.get("output_type"),
            "source": source,
        }

    @classmethod
    def normalize_execution_row(
        cls,
        execution: Dict[str, Any],
        *,
        instance_agent_command_id: str,
        instance_id: str,
        source: str = "simulation",
    ) -> Dict[str, Any]:
        e = cls._as_dict(execution)
        content = cls._as_dict(e.get("content"))
        output = cls._as_dict(content.get("output"))
        if output:
            # Keep compatibility with older/newer payload variants where output
            # can be nested under content["output"].
            output_type = output.get("output_type")
            text_output = output.get("text")
            text_sha256 = output.get("text_sha256")
            exit_code = output.get("exit_code", content.get("exit_code"))
            message = output.get("message", content.get("message"))
        else:
            output_type = content.get("output_type")
            text_output = content.get("text")
            text_sha256 = content.get("text_sha256")
            exit_code = content.get("exit_code")
            message = content.get("message")
        execution_key = f"{instance_agent_command_id}:{instance_id}"
        if e.get("sequence_number") not in (None, ""):
            execution_key = f"{execution_key}:{e.get('sequence_number')}"

        return {
            "execution_key": execution_key,
            "instance_agent_command_id": instance_agent_command_id,
            "instance_id": instance_id,
            "compartment_id": e.get("compartment_id"),
            "display_name": e.get("display_name"),
            "lifecycle_state": e.get("lifecycle_state"),
            "delivery_state": e.get("delivery_state"),
            "sequence_number": e.get("sequence_number"),
            "time_created": e.get("time_created"),
            "time_updated": e.get("time_updated"),
            "exit_code": exit_code,
            "message": message or e.get("message"),
            "output_type": output_type,
            "output_text": text_output,
            "output_text_sha256": text_sha256,
            "content_raw_json": content,
            "source": source,
        }

    @classmethod
    def normalize_plugin_row(
        cls,
        plugin: Dict[str, Any],
        *,
        instance_id: str,
        compartment_id: str,
        instance_name: str = "",
        source: str = "enumeration",
    ) -> Dict[str, Any]:
        p = cls._as_dict(plugin)
        plugin_name = _s(p.get("name") or p.get("plugin_name"))
        plugin_key = f"{instance_id}:{plugin_name}" if plugin_name else instance_id
        return {
            "plugin_key": plugin_key,
            "instance_id": instance_id,
            "instance_name": instance_name,
            "compartment_id": compartment_id,
            "name": plugin_name,
            "status": p.get("status"),
            "desired_state": p.get("desired_state"),
            "time_last_update_utc": p.get("time_last_update_utc"),
            "message": p.get("message"),
            "plugin_raw_json": p,
            "source": source,
        }

    @classmethod
    def normalize_available_plugin_row(
        cls,
        plugin: Dict[str, Any],
        *,
        compartment_id: str,
        os_name: str = "",
        os_version: str = "",
        source: str = "enumeration",
    ) -> Dict[str, Any]:
        p = cls._as_dict(plugin)
        plugin_name = _s(p.get("name") or p.get("plugin_name"))
        key_bits = [compartment_id, plugin_name, _s(os_name), _s(os_version)]
        available_plugin_key = ":".join([b for b in key_bits if b]) or plugin_name
        return {
            "available_plugin_key": available_plugin_key,
            "compartment_id": compartment_id,
            "name": plugin_name,
            "os_name": os_name or p.get("os_name"),
            "os_version": os_version or p.get("os_version"),
            "plugin_raw_json": p,
            "source": source,
        }

# ---- Compute enum helper functions ----

def _extract_command_id(row: Dict[str, Any]) -> str:
    return str(
        (row.get("id") or row.get("instance_agent_command_id") or row.get("instanceagent_command_id") or row.get("command_id") or "")
    ).strip()


def _extract_command_text(row: Dict[str, Any]) -> str:
    content = row.get("content")
    if isinstance(content, dict):
        source = content.get("source")
        if isinstance(source, dict) and source.get("text") is not None:
            return str(source.get("text"))
    content_raw = row.get("content_raw_json")
    if isinstance(content_raw, dict):
        source = content_raw.get("source")
        if isinstance(source, dict) and source.get("text") is not None:
            return str(source.get("text"))
    if row.get("command_text") is not None:
        return str(row.get("command_text"))
    return ""


def _extract_command_output_text(row: Dict[str, Any]) -> str:
    content = row.get("content")
    if not isinstance(content, dict):
        content = row.get("content_raw_json")
    if not isinstance(content, dict):
        content = {}

    output = content.get("output")
    if not isinstance(output, dict):
        output = {}

    output_type = output.get("output_type") or output.get("outputType") or row.get("command_output_type")
    text_val = output.get("text")
    if text_val is None and row.get("output_text") is not None:
        text_val = row.get("output_text")
    if text_val is None:
        return ""

    if output_type and str(output_type).strip().upper() != "TEXT":
        return ""
    return str(text_val)


def _extract_execution_output_text(row: Dict[str, Any]) -> str:
    if row.get("output_text") is not None:
        return str(row.get("output_text"))
    content = row.get("content")
    if isinstance(content, dict):
        output = content.get("output")
        if isinstance(output, dict) and output.get("text") is not None:
            return str(output.get("text"))
        if content.get("text") is not None:
            return str(content.get("text"))
    return ""


def _display_text(text: str) -> str:
    return " ".join(str(text or "").split()).strip()


def _command_preview_15(display_text: str) -> str:
    display_text = str(display_text or "")
    if len(display_text) <= 15:
        return display_text
    return f"{display_text[:15]}[TRUNCATE]"


def _is_cloud_init_metadata_key(key: Any) -> bool:
    k = str(key or "").strip().lower().replace("-", "_")
    if not k:
        return False
    if k == "user_data":
        return True
    if "cloud_init" in k:
        return True
    if "cloudinit" in k:
        return True
    return False


def _decode_base64_text(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw:
        return ""
    padded = raw + ("=" * ((4 - (len(raw) % 4)) % 4))
    try:
        decoded = base64.b64decode(padded, validate=True)
    except Exception:
        try:
            decoded = base64.b64decode(padded)
        except Exception:
            return None
    try:
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _download_instance_metadata_payload(
    session,
    *,
    compartment_id: str,
    instance_row: Dict[str, Any],
) -> Dict[str, Any]:
    instance_id = str((instance_row.get("id") or "unknown_instance")).strip() or "unknown_instance"
    instance_name = str((instance_row.get("display_name") or instance_row.get("name") or "")).strip()
    metadata_map = instance_row.get("metadata") if isinstance(instance_row.get("metadata"), dict) else {}
    extended_map = (
        instance_row.get("extended_metadata")
        if isinstance(instance_row.get("extended_metadata"), dict)
        else {}
    )

    files_written = 0
    user_data_path = ""
    additional_metadata_path = ""

    # Cloud-init/user-data content (decode when possible, write only if non-empty).
    user_data_chunks = []
    for source_name, mapping in (("metadata", metadata_map), ("extended_metadata", extended_map)):
        if not isinstance(mapping, dict) or not mapping:
            continue
        for key, value in mapping.items():
            if not _is_cloud_init_metadata_key(key):
                continue
            raw_text = str(value or "")
            if not raw_text.strip():
                continue
            decoded_text = _decode_base64_text(raw_text)
            final_text = decoded_text if decoded_text is not None else raw_text
            if not str(final_text).strip():
                continue
            user_data_chunks.append(
                {
                    "source": source_name,
                    "key": str(key),
                    "value": final_text,
                }
            )

    if user_data_chunks:
        user_path = session.get_download_save_path(
            service_name="compute",
            filename=f"{instance_id}_user_data.txt",
            compartment_id=compartment_id,
            resource_name=instance_name or None,
            subdirs=["instance_metadata"],
        )
        if len(user_data_chunks) == 1:
            text_out = str(user_data_chunks[0].get("value") or "")
        else:
            parts = []
            for entry in user_data_chunks:
                parts.append(
                    f"source: {entry.get('source')}\nkey: {entry.get('key')}\n\n{entry.get('value')}"
                )
            text_out = "\n\n-----\n\n".join(parts)
        user_path.write_text(text_out if text_out.endswith("\n") else f"{text_out}\n", encoding="utf-8")
        files_written += 1
        user_data_path = str(user_path)

    # Additional metadata excludes cloud-init/user-data keys.
    additional_metadata = {"metadata": {}, "extended_metadata": {}}
    for source_name, mapping in (("metadata", metadata_map), ("extended_metadata", extended_map)):
        if not isinstance(mapping, dict) or not mapping:
            continue
        for key, value in mapping.items():
            if _is_cloud_init_metadata_key(key):
                continue
            if value is None:
                continue
            if isinstance(value, str) and not value.strip():
                continue
            additional_metadata[source_name][str(key)] = value

    if additional_metadata["metadata"] or additional_metadata["extended_metadata"]:
        additional_path = session.get_download_save_path(
            service_name="compute",
            filename=f"{instance_id}_additional_metadata.txt",
            compartment_id=compartment_id,
            resource_name=instance_name or None,
            subdirs=["instance_metadata"],
        )
        additional_path.write_text(
            json.dumps(additional_metadata, indent=2, default=str),
            encoding="utf-8",
        )
        files_written += 1
        additional_metadata_path = str(additional_path)

    return {
        "instance_id": instance_id,
        "user_data_path": user_data_path,
        "additional_metadata_path": additional_metadata_path,
        "files_written": files_written,
    }


def _sequence_rank(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return -1


def _merge_instance_agent_command_rows(
    *,
    command_rows: list[Dict[str, Any]],
    execution_rows: list[Dict[str, Any]],
) -> list[Dict[str, Any]]:
    merged: Dict[tuple[str, str], Dict[str, Any]] = {}

    def _key(instance_id: str, command_id: str, fallback: str) -> tuple[str, str]:
        iid = str(instance_id or "unknown_instance").strip() or "unknown_instance"
        cid = str(command_id or "").strip() or fallback
        return iid, cid

    for row in command_rows or []:
        if not isinstance(row, dict):
            continue
        command_id = _extract_command_id(row)
        instance_id = str((row.get("target_instance_id") or row.get("instance_id") or "unknown_instance")).strip() or "unknown_instance"
        fallback = f"unknown_command:{row.get('display_name') or row.get('time_created') or 'row'}"
        k = _key(instance_id, command_id, fallback)
        rec = merged.setdefault(
            k,
            {
                "instance_id": instance_id,
                "command_id": command_id or fallback,
                "display_name": "",
                "time_created": "",
                "time_updated": "",
                "lifecycle_state": "",
                "delivery_state": "",
                "source_type": "",
                "output_type": "",
                "input_text": "",
                "output_text": "",
                "_exec_rank": (-1, ""),
            },
        )
        rec["display_name"] = rec.get("display_name") or str(row.get("display_name") or "")
        rec["time_created"] = rec.get("time_created") or str(row.get("time_created") or "")
        rec["time_updated"] = rec.get("time_updated") or str(row.get("time_updated") or "")
        rec["source_type"] = rec.get("source_type") or str(row.get("command_source_type") or "")
        rec["output_type"] = rec.get("output_type") or str(row.get("command_output_type") or "")
        if not rec.get("input_text"):
            rec["input_text"] = str(_extract_command_text(row) or "")

    for row in execution_rows or []:
        if not isinstance(row, dict):
            continue
        command_id = str((row.get("instance_agent_command_id") or row.get("command_id") or "")).strip()
        instance_id = str((row.get("instance_id") or "unknown_instance")).strip() or "unknown_instance"
        fallback = f"unknown_command:{row.get('display_name') or row.get('time_updated') or 'exec'}"
        k = _key(instance_id, command_id, fallback)
        rec = merged.setdefault(
            k,
            {
                "instance_id": instance_id,
                "command_id": command_id or fallback,
                "display_name": "",
                "time_created": "",
                "time_updated": "",
                "lifecycle_state": "",
                "delivery_state": "",
                "source_type": "",
                "output_type": "",
                "input_text": "",
                "output_text": "",
                "_exec_rank": (-1, ""),
            },
        )

        new_rank = (
            _sequence_rank(row.get("sequence_number")),
            str(row.get("time_updated") or ""),
        )
        old_rank = rec.get("_exec_rank") or (-1, "")
        if new_rank >= old_rank:
            rec["_exec_rank"] = new_rank
            rec["display_name"] = str(row.get("display_name") or rec.get("display_name") or "")
            rec["time_created"] = str(row.get("time_created") or rec.get("time_created") or "")
            rec["time_updated"] = str(row.get("time_updated") or rec.get("time_updated") or "")
            rec["lifecycle_state"] = str(row.get("lifecycle_state") or rec.get("lifecycle_state") or "")
            rec["delivery_state"] = str(row.get("delivery_state") or rec.get("delivery_state") or "")
            rec["output_type"] = str(row.get("output_type") or rec.get("output_type") or "")
            out_text = _extract_execution_output_text(row)
            if out_text:
                rec["output_text"] = str(out_text)

        if not rec.get("input_text"):
            rec["input_text"] = str(row.get("command_text") or "")

    out = []
    for rec in merged.values():
        rec.pop("_exec_rank", None)
        rec["input_text"] = str(rec.get("input_text") or "")
        rec["output_text"] = str(rec.get("output_text") or "")
        out.append(rec)
    return out


def _write_instance_agent_merged_files(
    session,
    *,
    compartment_id: str,
    command_rows: list[Dict[str, Any]],
    execution_rows: list[Dict[str, Any]],
) -> Dict[str, Any]:
    merged_rows = _merge_instance_agent_command_rows(
        command_rows=command_rows or [],
        execution_rows=execution_rows or [],
    )
    by_instance: Dict[str, list[Dict[str, Any]]] = {}
    for row in merged_rows:
        iid = str(row.get("instance_id") or "unknown_instance").strip() or "unknown_instance"
        by_instance.setdefault(iid, []).append(row)

    download_rows = []
    files_written = 0
    for instance_id, rows in by_instance.items():
        # deterministic order
        rows = sorted(
            rows,
            key=lambda x: (
                str(x.get("time_created") or ""),
                str(x.get("command_id") or ""),
            ),
        )
        blocks = []
        for row in rows:
            input_text = str(row.get("input_text") or "").strip() or "[none]"
            output_text = str(row.get("output_text") or "").strip() or "[none]"
            block = "\n".join(
                [
                    f"command_id: {row.get('command_id') or ''}",
                    f"display_name: {row.get('display_name') or ''}",
                    f"target_instance_id: {instance_id}",
                    f"time_created: {row.get('time_created') or ''}",
                    f"time_updated: {row.get('time_updated') or ''}",
                    f"lifecycle_state: {row.get('lifecycle_state') or ''}",
                    f"delivery_state: {row.get('delivery_state') or ''}",
                    f"source_type: {row.get('source_type') or ''}",
                    f"output_type: {row.get('output_type') or ''}",
                    "input_text:",
                    input_text,
                    "output_text:",
                    output_text,
                ]
            )
            blocks.append(block)

        body = "\n------------------------------\n".join(blocks).strip()
        if not body:
            continue
        out_path = session.get_download_save_path(
            service_name="compute",
            filename=f"{instance_id}_cmds",
            compartment_id=compartment_id,
            resource_name=str((rows[0].get("display_name") or "")).strip() or None,
            subdirs=["instance_agent_commands"],
        )
        out_path.write_text(f"{body}\n", encoding="utf-8")
        files_written += 1
        download_rows.append(
            {
                "instance_id": instance_id,
                "command_count": len(rows),
                "file_path": str(out_path),
            }
        )

    return {
        "files_written": files_written,
        "download_rows": download_rows,
        "merged_record_count": len(merged_rows),
    }


def _download_instance_agent_execution_payload(
    session,
    *,
    compartment_id: str,
    execution_row: Dict[str, Any],
) -> int:
    command_id = _extract_command_id(execution_row) or "unknown_command"
    instance_id = str((execution_row.get("instance_id") or "unknown_instance")).strip() or "unknown_instance"
    sequence = str((execution_row.get("sequence_number") or execution_row.get("time_updated") or "latest")).strip() or "latest"
    files_written = 0
    base_subdirs = ["instance_agent_commands", command_id, "executions", instance_id]

    details_path = session.get_download_save_path(
        service_name="compute",
        filename=f"{sequence}_execution_details.json",
        compartment_id=compartment_id,
        resource_name=str((execution_row.get("display_name") or execution_row.get("instance_name") or "")).strip() or None,
        subdirs=base_subdirs,
    )
    details_path.write_text(json.dumps(execution_row, indent=2, default=str), encoding="utf-8")
    files_written += 1

    output_text = _extract_execution_output_text(execution_row)
    if output_text:
        output_path = session.get_download_save_path(
            service_name="compute",
            filename=f"{sequence}_execution_output.txt",
            compartment_id=compartment_id,
            resource_name=str((execution_row.get("display_name") or execution_row.get("instance_name") or "")).strip() or None,
            subdirs=base_subdirs,
        )
        output_path.write_text(output_text if output_text.endswith("\n") else f"{output_text}\n", encoding="utf-8")
        files_written += 1
    return files_written


