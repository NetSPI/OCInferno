#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.core.utils.service_runtime import _init_client


class VirtualNetworkResourceClient:
    """
    Reusable wrapper for OCI Virtual Network via oci.core.VirtualNetworkClient.

    Pattern:
      - list_* returns list[dict]
      - get_* returns dict
      - enum modules decide what to store
    """

    TABLE_VCNS = "virtual_network_vcns"
    TABLE_SUBNETS = "virtual_network_subnets"
    TABLE_ROUTE_TABLES = "virtual_network_route_tables"
    TABLE_SECURITY_LISTS = "virtual_network_security_lists"
    TABLE_NETWORK_SECURITY_GROUPS = "virtual_network_network_security_groups"
    TABLE_INTERNET_GATEWAYS = "virtual_network_internet_gateways"
    TABLE_NAT_GATEWAYS = "virtual_network_nat_gateways"
    TABLE_SERVICE_GATEWAYS = "virtual_network_service_gateways"
    TABLE_DRGS = "virtual_network_drgs"
    TABLE_DRG_ATTACHMENTS = "virtual_network_drg_attachments"
    TABLE_DHCP_OPTIONS = "virtual_network_dhcp_options"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = _init_client(
            oci.core.VirtualNetworkClient,
            session=session,
            service_name="Virtual Network",
        )

        if region:
            try:
                self.client.base_client.set_region(region)
            except Exception:
                pass
        elif getattr(session, "region", None):
            try:
                self.client.base_client.set_region(session.region)
            except Exception:
                pass

    # --------------------
    # VCNs
    # --------------------
    def list_vcns(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_vcns,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    def get_vcn(self, *, vcn_id: str) -> Dict[str, Any]:
        resp = self.client.get_vcn(vcn_id=vcn_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Subnets
    # --------------------
    def list_subnets(self, *, compartment_id: str, vcn_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if vcn_id:
            kwargs["vcn_id"] = vcn_id
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_subnets,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    def get_subnet(self, *, subnet_id: str) -> Dict[str, Any]:
        resp = self.client.get_subnet(subnet_id=subnet_id)
        return oci.util.to_dict(resp.data) or {}

    def get_vnic(self, *, vnic_id: str) -> Dict[str, Any]:
        resp = self.client.get_vnic(vnic_id=vnic_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Route Tables
    # --------------------
    def list_route_tables(self, *, compartment_id: str, vcn_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if vcn_id:
            kwargs["vcn_id"] = vcn_id
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_route_tables,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    def get_route_table(self, *, route_table_id: str) -> Dict[str, Any]:
        resp = self.client.get_route_table(route_table_id=route_table_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Security Lists
    # --------------------
    def list_security_lists(self, *, compartment_id: str, vcn_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if vcn_id:
            kwargs["vcn_id"] = vcn_id
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_security_lists,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    def get_security_list(self, *, security_list_id: str) -> Dict[str, Any]:
        resp = self.client.get_security_list(security_list_id=security_list_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Network Security Groups
    # --------------------
    def list_network_security_groups(self, *, compartment_id: str, vcn_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if vcn_id:
            kwargs["vcn_id"] = vcn_id
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_network_security_groups,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    def get_network_security_group(self, *, nsg_id: str) -> Dict[str, Any]:
        resp = self.client.get_network_security_group(network_security_group_id=nsg_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Internet Gateways
    # --------------------
    def list_internet_gateways(self, *, compartment_id: str, vcn_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if vcn_id:
            kwargs["vcn_id"] = vcn_id
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_internet_gateways,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    def get_internet_gateway(self, *, ig_id: str) -> Dict[str, Any]:
        resp = self.client.get_internet_gateway(internet_gateway_id=ig_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # NAT Gateways
    # --------------------
    def list_nat_gateways(self, *, compartment_id: str, vcn_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if vcn_id:
            kwargs["vcn_id"] = vcn_id
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_nat_gateways,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    def get_nat_gateway(self, *, nat_gateway_id: str) -> Dict[str, Any]:
        resp = self.client.get_nat_gateway(nat_gateway_id=nat_gateway_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Service Gateways
    # --------------------
    def list_service_gateways(self, *, compartment_id: str, vcn_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if vcn_id:
            kwargs["vcn_id"] = vcn_id
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_service_gateways,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    def get_service_gateway(self, *, service_gateway_id: str) -> Dict[str, Any]:
        resp = self.client.get_service_gateway(service_gateway_id=service_gateway_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # DRGs
    # --------------------
    def list_drgs(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_drgs,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    def get_drg(self, *, drg_id: str) -> Dict[str, Any]:
        resp = self.client.get_drg(drg_id=drg_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # DRG Attachments
    # --------------------
    def list_drg_attachments(self, *, compartment_id: str, drg_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if drg_id:
            kwargs["drg_id"] = drg_id
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_drg_attachments,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    def get_drg_attachment(self, *, drg_attachment_id: str) -> Dict[str, Any]:
        resp = self.client.get_drg_attachment(drg_attachment_id=drg_attachment_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # DHCP Options
    # --------------------
    def list_dhcp_options(self, *, compartment_id: str, vcn_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if vcn_id:
            kwargs["vcn_id"] = vcn_id
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_dhcp_options,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    def get_dhcp_options(self, *, dhcp_id: str) -> Dict[str, Any]:
        resp = self.client.get_dhcp_options(dhcp_id=dhcp_id)
        return oci.util.to_dict(resp.data) or {}


def print_section_table(title: str, rows: List[Dict[str, Any]], columns: List[str]) -> None:
    print(f"\n[*] {title}")
    if rows:
        UtilityTools.print_limited_table(rows, columns)
    else:
        print("[*] No resources found.")


fill_missing = fill_missing_fields


class VcnsResource:
    TABLE_NAME = VirtualNetworkResourceClient.TABLE_VCNS
    COLUMNS = ["id", "display_name", "lifecycle_state", "cidr_block"]
    SECTION_TITLE = "Virtual Cloud Networks (VCNs)"

    def __init__(self, ops: VirtualNetworkResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_vcns(compartment_id=compartment_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_vcn(vcn_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class SubnetsResource:
    TABLE_NAME = VirtualNetworkResourceClient.TABLE_SUBNETS
    COLUMNS = ["id", "display_name", "lifecycle_state", "cidr_block", "vcn_id"]
    SECTION_TITLE = "Subnets"

    def __init__(self, ops: VirtualNetworkResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, vcn_id: Optional[str] = None, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_subnets(compartment_id=compartment_id, vcn_id=vcn_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_subnet(subnet_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class RouteTablesResource:
    TABLE_NAME = VirtualNetworkResourceClient.TABLE_ROUTE_TABLES
    COLUMNS = ["id", "display_name", "lifecycle_state", "vcn_id"]
    SECTION_TITLE = "Route Tables"

    def __init__(self, ops: VirtualNetworkResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, vcn_id: Optional[str] = None, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_route_tables(compartment_id=compartment_id, vcn_id=vcn_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_route_table(route_table_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class SecurityListsResource:
    TABLE_NAME = VirtualNetworkResourceClient.TABLE_SECURITY_LISTS
    COLUMNS = ["id", "display_name", "lifecycle_state", "vcn_id"]
    SECTION_TITLE = "Security Lists"

    def __init__(self, ops: VirtualNetworkResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, vcn_id: Optional[str] = None, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_security_lists(compartment_id=compartment_id, vcn_id=vcn_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_security_list(security_list_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class NetworkSecurityGroupsResource:
    TABLE_NAME = VirtualNetworkResourceClient.TABLE_NETWORK_SECURITY_GROUPS
    COLUMNS = ["id", "display_name", "lifecycle_state", "vcn_id"]
    SECTION_TITLE = "Network Security Groups (NSGs)"

    def __init__(self, ops: VirtualNetworkResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, vcn_id: Optional[str] = None, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_network_security_groups(compartment_id=compartment_id, vcn_id=vcn_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_network_security_group(nsg_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class InternetGatewaysResource:
    TABLE_NAME = VirtualNetworkResourceClient.TABLE_INTERNET_GATEWAYS
    COLUMNS = ["id", "display_name", "lifecycle_state", "vcn_id", "is_enabled"]
    SECTION_TITLE = "Internet Gateways"

    def __init__(self, ops: VirtualNetworkResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, vcn_id: Optional[str] = None, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_internet_gateways(compartment_id=compartment_id, vcn_id=vcn_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_internet_gateway(ig_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class NatGatewaysResource:
    TABLE_NAME = VirtualNetworkResourceClient.TABLE_NAT_GATEWAYS
    COLUMNS = ["id", "display_name", "lifecycle_state", "vcn_id", "block_traffic"]
    SECTION_TITLE = "NAT Gateways"

    def __init__(self, ops: VirtualNetworkResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, vcn_id: Optional[str] = None, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_nat_gateways(compartment_id=compartment_id, vcn_id=vcn_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_nat_gateway(nat_gateway_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class ServiceGatewaysResource:
    TABLE_NAME = VirtualNetworkResourceClient.TABLE_SERVICE_GATEWAYS
    COLUMNS = ["id", "display_name", "lifecycle_state", "vcn_id"]
    SECTION_TITLE = "Service Gateways"

    def __init__(self, ops: VirtualNetworkResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, vcn_id: Optional[str] = None, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_service_gateways(compartment_id=compartment_id, vcn_id=vcn_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_service_gateway(service_gateway_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class DrgsResource:
    TABLE_NAME = VirtualNetworkResourceClient.TABLE_DRGS
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]
    SECTION_TITLE = "Dynamic Routing Gateways (DRGs)"

    def __init__(self, ops: VirtualNetworkResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_drgs(compartment_id=compartment_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_drg(drg_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class DrgAttachmentsResource:
    TABLE_NAME = VirtualNetworkResourceClient.TABLE_DRG_ATTACHMENTS
    COLUMNS = ["id", "display_name", "lifecycle_state", "drg_id", "network_details"]
    SECTION_TITLE = "DRG Attachments"

    def __init__(self, ops: VirtualNetworkResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, drg_id: Optional[str] = None, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_drg_attachments(compartment_id=compartment_id, drg_id=drg_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_drg_attachment(drg_attachment_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class DhcpOptionsResource:
    TABLE_NAME = VirtualNetworkResourceClient.TABLE_DHCP_OPTIONS
    COLUMNS = ["id", "display_name", "lifecycle_state", "vcn_id"]
    SECTION_TITLE = "DHCP Options"

    def __init__(self, ops: VirtualNetworkResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, vcn_id: Optional[str] = None, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_dhcp_options(compartment_id=compartment_id, vcn_id=vcn_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_dhcp_options(dhcp_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)
