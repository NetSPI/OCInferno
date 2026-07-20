#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class OcvpSddcsResource(OciListResource):
    CLIENT_CLS = oci.ocvp.SddcClient
    SERVICE_NAME = "VMware Solution"
    TABLE_NAME = "ocvp_sddcs"
    LIST_METHOD = "list_sddcs"
    GET_METHOD = "get_sddc"
    GET_ID_PARAM = "sddc_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "vcenter_fqdn",
        "nsx_manager_fqdn",
        "hcx_fqdn",
        "vmware_software_version",
        "clusters_count",
        "is_single_host_sddc",
    ]


class OcvpDatastoresResource(OciListResource):
    CLIENT_CLS = oci.ocvp.DatastoreClient
    SERVICE_NAME = "VMware Solution"
    TABLE_NAME = "ocvp_datastores"
    LIST_METHOD = "list_datastores"
    GET_METHOD = "get_datastore"
    GET_ID_PARAM = "datastore_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "sddc_id",
        "cluster_id",
        "capacity_in_gbs",
        "block_volume_ids",
        "availability_domain",
    ]


class OcvpClustersResource(OciListResource):
    CLIENT_CLS = oci.ocvp.ClusterClient
    SERVICE_NAME = "VMware Solution"
    TABLE_NAME = "ocvp_clusters"
    LIST_METHOD = "list_clusters"
    GET_METHOD = "get_cluster"
    GET_ID_PARAM = "cluster_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "sddc_id",
        "vmware_software_version",
        "esxi_hosts_count",
        "initial_host_shape_name",
        "is_shielded_instance_enabled",
        "vsphere_type",
    ]
