from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class ContainerRegistryRepositoriesResource(OciListResource):
    CLIENT_CLS = oci.artifacts.ArtifactsClient
    SERVICE_NAME = "Artifacts"
    TABLE_NAME = "cr_repositories"
    LIST_METHOD = "list_container_repositories"
    GET_METHOD = "get_container_repository"
    GET_ID_PARAM = "repository_id"
    COLUMNS = ["id", "display_name", "is_public", "lifecycle_state", "time_created"]


class ContainerRegistryImagesResource(OciListResource):
    # Nested under repositories: list(compartment_id=, repository_id=) fans out via
    # nested_list_fn; OciListResource forwards the extra repository_id kwarg to the SDK.
    CLIENT_CLS = oci.artifacts.ArtifactsClient
    SERVICE_NAME = "Artifacts"
    TABLE_NAME = "cr_images"
    LIST_METHOD = "list_container_images"
    GET_METHOD = "get_container_image"
    GET_ID_PARAM = "image_id"
    COLUMNS = ["id", "display_name", "version", "digest", "lifecycle_state", "time_created", "repository_id"]
