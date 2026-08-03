from __future__ import annotations

import json

import oci

from ocinferno.core.resource import OciListResource


class ContainerInstancesResource(OciListResource):
    CLIENT_CLS = oci.container_instances.ContainerInstanceClient
    SERVICE_NAME = "ContainerInstances"
    TABLE_NAME = "container_instances"
    LIST_METHOD = "list_container_instances"
    GET_METHOD = "get_container_instance"
    GET_ID_PARAM = "container_instance_id"
    COLUMNS = [
        "id", "display_name", "lifecycle_state", "time_created",
        "compartment_id", "freeform_tags",
        "vnics", "volumes", "dns_config", "image_pull_secrets",
        "shape", "shape_config", "graceful_shutdown_timeout_in_seconds",
    ]

    def download_container_configs(self, *, resource_id: str, out_path) -> bool:
        """Export the developer-supplied container config for one container instance.

        A container instance holds a ``containers`` list of refs (each just a
        ``container_id``); the actual environment variables / command / arguments
        live on the per-container object fetched via ``get_container``. This walks
        every container in the instance, collects its config, and writes the combined
        list to ``out_path`` as pretty JSON. Returns True if a file was written.
        """
        if not resource_id:
            return False
        try:
            inst = self.client.get_container_instance(container_instance_id=resource_id).data
        except oci.exceptions.ServiceError as e:
            if e.status in (403, 404):
                return False
            raise
        configs = []
        for ref in (getattr(inst, "containers", None) or []):
            container_id = getattr(ref, "container_id", None)
            if not container_id:
                continue
            try:
                container = self.client.get_container(container_id=container_id).data
            except oci.exceptions.ServiceError as e:
                if e.status in (403, 404):
                    continue
                raise
            configs.append({
                "id": getattr(container, "id", container_id),
                "display_name": getattr(container, "display_name", None),
                "image_url": getattr(container, "image_url", None),
                "environment_variables": getattr(container, "environment_variables", None),
                "command": getattr(container, "command", None),
                "arguments": getattr(container, "arguments", None),
            })
        if not configs:
            return False
        with open(out_path, "w") as fh:
            fh.write(json.dumps(configs, indent=2, default=str))
        return True
