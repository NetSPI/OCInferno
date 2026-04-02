#!/usr/bin/env python3
"""
enum_oracle_cloud_hound_data.py

Offline builder + exporter for BloodHound OpenGraph ingestion.

Build behavior:
  - Run all build steps each execution (fixed order).
  - Load full IAM/identity context each execution.

Export rules (simplified):
  - Nodes: emit only BloodHound-safe property types:
      * string / number / boolean
      * homogeneous arrays of primitive types (empty arrays allowed)
    Flatten node_properties into dot-delimited keys (key1.key2).
  - Edges: consume normalized edge schema:
      {"edge_category": "...", "edge_inner_properties": {...}}
    and bubble inner properties one level up for OpenGraph output.
"""

import argparse
import json
import os
from collections import Counter, defaultdict

from ocinferno.modules.opengraph.utilities.dynamic_group_membership_graph_builder import build_dynamic_group_membership_edges_offline
from ocinferno.modules.opengraph.utilities.group_membership_graph_builder import build_group_membership_edges_offline
from ocinferno.modules.opengraph.utilities.iam_policy_advanced_relation_graph_builder import build_iam_policy_advanced_relation_edges_offline
from ocinferno.modules.opengraph.utilities.iam_policy_base_relation_graph_builder import build_iam_policy_base_relation_edges_offline
from ocinferno.modules.opengraph.utilities.identity_domain_graph_builder import build_identity_domain_graph_offline
from ocinferno.modules.opengraph.utilities.resource_scope_graph_builder import build_resource_scope_expansion_edges_offline
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    NODE_TYPE_OCI_GENERIC_RESOURCE,
    NODE_TYPE_OCI_DYNAMIC_GROUP,
    NODE_TYPE_OCI_GROUP,
    NODE_TYPE_OCI_USER,
)
from ocinferno.modules.opengraph.utilities.helpers.context import OfflineIamContext, _dlog

NODE_COLUMNS = [
    "node_id",
    "node_type",
    "node_properties",
]

EDGE_COLUMNS = [
    "source_id",
    "destination_id",
    "edge_type",
    "edge_properties",
]

RESOURCE_KINDS = {
    "OCIAllResources",
    "OCIAppUserScope",
    "OCIAppGroupScope",
    "OCICompartment",
    "OCIComputeInstance",
    "OCIFnApps",
    "OCIFnFunctions",
    "OCIIDDApplication",
    "OCIIDDAppRole",
    "OCIPolicyStatement",
    "OCINewComputeInstance",
    "OCINewInstanceAgentCommand",
    "OCIResourceFamily",
    "OCIResourceGroup",
    "OCIRoleCapability",
    "OCITagDefault",
    "OCITagDefinition",
    "OCITagNamespace",
    "OCIVault",
    "OCIVaultKey",
    "OCIVaultSecret",
    NODE_TYPE_OCI_GENERIC_RESOURCE,  # Catch-All Default
}

PRINCIPAL_KINDS = {
    "OCIAnyGroup",
    "OCIAnyUser",
    NODE_TYPE_OCI_DYNAMIC_GROUP,
    NODE_TYPE_OCI_GROUP,
    "OCIService",
    NODE_TYPE_OCI_USER,
}

OPEN_GRAPH_TABLES = ("opengraph_edges", "opengraph_nodes")

BUILD_STEP_SPECS = {
    "groups": {
        "help": "Group membership edges",
        "runner": build_group_membership_edges_offline,
        "kwargs": {"auto_commit": False},
    },
    "dynamic_groups": {
        "help": "Dynamic-group membership edges",
        "runner": build_dynamic_group_membership_edges_offline,
        "kwargs": {"auto_commit": False},
    },
    "iam": {
        "help": "IAM ALLOW edges",
        "runner": build_iam_policy_base_relation_edges_offline,
        "kwargs": {"auto_commit": False},
    },
    "identity_domains": {
        "help": "Identity Domain resources + app role/grant edges",
        "runner": build_identity_domain_graph_offline,
        "kwargs": {"auto_commit": False},
    },
    # Scope expansion must run after identity-domain capability scopes are emitted
    # so new_user-style scope nodes gain subset edges before orphan pruning.
    "resource_scope": {
        "help": "Resource-family / scope expansion edges",
        "runner": build_resource_scope_expansion_edges_offline,
        "kwargs": {"auto_commit": False},
    },
    # Derived consequence paths run last so they can consume all prior
    # raw graph evidence emitted in this execution.
    "iam_derived": {
        "help": "IAM: derived consequence edges from raw IAM edges",
        "runner": build_iam_policy_advanced_relation_edges_offline,
        "kwargs": {"auto_commit": False},
    },
}


CUSTOM_NODE_PAYLOAD = {
    "custom_types": {
        # Principals / Identity Actors
        NODE_TYPE_OCI_USER: {"icon": {"type": "font-awesome", "name": "user", "color": "#43A047"}},
        NODE_TYPE_OCI_GROUP: {"icon": {"type": "font-awesome", "name": "users", "color": "#FB8C00"}},
        NODE_TYPE_OCI_DYNAMIC_GROUP: {"icon": {"type": "font-awesome", "name": "users-between-lines", "color": "#1E88E5"}},
        "OCIService": {"icon": {"type": "font-awesome", "name": "cloud", "color": "#00ACC1"}},
        "OCIAnyUser": {"icon": {"type": "font-awesome", "name": "user-slash", "color": "#D81B60"}},
        "OCIAnyGroup": {"icon": {"type": "font-awesome", "name": "users-slash", "color": "#F9A825"}},
        "OCIRoleCapability": {"icon": {"type": "font-awesome", "name": "arrows-up-down-left-right", "color": "#26A69A"}},

        # Core Compute / DevOps / Serverless Services
        "OCIComputeInstance": {"icon": {"type": "font-awesome", "name": "server", "color": "#00ACC1"}},
        "OCIInstanceAgentCommand": {"icon": {"type": "font-awesome", "name": "terminal", "color": "#00838F"}},
        "OCIInstanceAgentCommandExecution": {"icon": {"type": "font-awesome", "name": "play-circle", "color": "#26A69A"}},
        "OCIInstanceAgentPlugin": {"icon": {"type": "font-awesome", "name": "puzzle-piece", "color": "#5C6BC0"}},
        "OCIContainerInstance": {"icon": {"type": "font-awesome", "name": "boxes-stacked", "color": "#00897B"}},
        "OCIDataFlowRun": {"icon": {"type": "font-awesome", "name": "diagram-project", "color": "#7E57C2"}},
        "OCIResourceSchedule": {"icon": {"type": "font-awesome", "name": "calendar-alt", "color": "#5C6BC0"}},
        "OCIDevOpsDeployPipeline": {"icon": {"type": "font-awesome", "name": "rocket", "color": "#F4511E"}},
        "OCIDevOpsBuildPipeline": {"icon": {"type": "font-awesome", "name": "hammer", "color": "#8D6E63"}},
        "OCIDevOpsRepository": {"icon": {"type": "font-awesome", "name": "code-branch", "color": "#546E7A"}},
        "OCIDevOpsConnection": {"icon": {"type": "font-awesome", "name": "plug", "color": "#6D4C41"}},
        "OCIDevOpsProject": {"icon": {"type": "font-awesome", "name": "diagram-project", "color": "#F4511E"}},

        # IAM / Policy / Identity Domain Resources
        "OCIVault": {"icon": {"type": "font-awesome", "name": "lock", "color": "#00838F"}},
        "OCIVaultKey": {"icon": {"type": "font-awesome", "name": "key", "color": "#00838F"}},
        "OCIVaultSecret": {"icon": {"type": "font-awesome", "name": "vault", "color": "#00838F"}},
        "OCICompartment": {"icon": {"type": "font-awesome", "name": "folder", "color": "#546E7A"}},
        "OCIResourceGroup": {"icon": {"type": "font-awesome", "name": "object-group", "color": "#7E57C2"}},
        "OCIResourceFamily": {"icon": {"type": "font-awesome", "name": "object-ungroup", "color": "#9575CD"}},
        "OCIAllResources": {"icon": {"type": "font-awesome", "name": "dumpster-fire", "color": "#E53935"}},
        "OCIPolicyStatement": {"icon": {"type": "font-awesome", "name": "file-signature", "color": "#6D4C41"}},
        "OCIPolicy": {"icon": {"type": "font-awesome", "name": "file-shield", "color": "#6D4C41"}},
        "OCINewPolicy": {"icon": {"type": "font-awesome", "name": "file-circle-plus", "color": "#8D6E63"}},
        "OCINewComputeInstance": {"icon": {"type": "font-awesome", "name": "server", "color": "#26A69A"}},
        "OCINewInstanceAgentCommand": {"icon": {"type": "font-awesome", "name": "terminal", "color": "#00838F"}},
        "OCIIdentityDomain": {"icon": {"type": "font-awesome", "name": "id-card", "color": "#3949AB"}},
        "OCIIDDApplication": {"icon": {"type": "font-awesome", "name": "id-badge", "color": "#3949AB"}},
        "OCIIDDAppRole": {"icon": {"type": "font-awesome", "name": "link", "color": "#6A1B9A"}},
        "OCIIdentityDomainGrant": {"icon": {"type": "font-awesome", "name": "handshake", "color": "#6A1B9A"}},
        "OCIIdentityDomainUserCredential": {"icon": {"type": "font-awesome", "name": "key", "color": "#546E7A"}},
        "OCIIdentityDomainUserDbCredential": {"icon": {"type": "font-awesome", "name": "key", "color": "#546E7A"}},
        "OCIIdentityDomainUserSmtpCredential": {"icon": {"type": "font-awesome", "name": "envelope", "color": "#546E7A"}},
        "OCIIdentityDomainUserApiKey": {"icon": {"type": "font-awesome", "name": "key", "color": "#546E7A"}},
        "OCIIdentityDomainPasswordPolicy": {"icon": {"type": "font-awesome", "name": "user-shield", "color": "#5C6BC0"}},
        "OCIIdentityDomainAuthFactorSettings": {"icon": {"type": "font-awesome", "name": "shield-keyhole", "color": "#5C6BC0"}},
        "OCIIdentityDomainLockoutPolicy": {"icon": {"type": "font-awesome", "name": "user-lock", "color": "#5C6BC0"}},
        "OCIIdentityDomainSignOnPolicy": {"icon": {"type": "font-awesome", "name": "right-to-bracket", "color": "#5C6BC0"}},
        "OCIIdentityDomainIdentityProvider": {"icon": {"type": "font-awesome", "name": "id-card-clip", "color": "#3949AB"}},
        "OCIComputeImage": {"icon": {"type": "font-awesome", "name": "clone", "color": "#00ACC1"}},
        "OCIFunctionApp": {"icon": {"type": "font-awesome", "name": "bolt", "color": "#7CB342"}},
        "OCIFunctionFunction": {"icon": {"type": "font-awesome", "name": "bolt", "color": "#7CB342"}},

        # API / Registry / Object & File Storage Services
        "OCIAPIGateway": {"icon": {"type": "font-awesome", "name": "tower-broadcast", "color": "#29B6F6"}},
        "OCIAPIApi": {"icon": {"type": "font-awesome", "name": "code", "color": "#29B6F6"}},
        "OCIAPIDeployment": {"icon": {"type": "font-awesome", "name": "rocket", "color": "#29B6F6"}},
        "OCIContainerRegistryRepository": {"icon": {"type": "font-awesome", "name": "box", "color": "#00897B"}},
        "OCIContainerRegistryImage": {"icon": {"type": "font-awesome", "name": "image", "color": "#00897B"}},
        "OCIRegistryRepo": {"icon": {"type": "font-awesome", "name": "box", "color": "#00897B"}},
        "OCIArtifactRegistryArtifact": {"icon": {"type": "font-awesome", "name": "archive", "color": "#00897B"}},
        "OCIOSNamespaces": {"icon": {"type": "font-awesome", "name": "tag", "color": "#FB8C00"}},
        "OCIOSBucket": {"icon": {"type": "font-awesome", "name": "bucket", "color": "#FB8C00"}},
        "OCIOSBucketObject": {"icon": {"type": "font-awesome", "name": "file", "color": "#FB8C00"}},
        "OCINotificationTopic": {"icon": {"type": "font-awesome", "name": "bell", "color": "#F9A825"}},
        "OCINotificationSubscription": {"icon": {"type": "font-awesome", "name": "rss", "color": "#F9A825"}},
        "OCIDnsZone": {"icon": {"type": "font-awesome", "name": "globe", "color": "#42A5F5"}},
        "OCIDnsZoneRecord": {"icon": {"type": "font-awesome", "name": "list", "color": "#42A5F5"}},
        "OCITagDefinition": {"icon": {"type": "font-awesome", "name": "hashtag", "color": "#2E7D32"}},
        "OCIDnsPrivateResolver": {"icon": {"type": "font-awesome", "name": "network-wired", "color": "#42A5F5"}},
        "OCIFileStorageFileSystem": {"icon": {"type": "font-awesome", "name": "hard-drive", "color": "#8D6E63"}},
        "OCIFileStorageMountTargets": {"icon": {"type": "font-awesome", "name": "plug", "color": "#8D6E63"}},
        "OCIFileStorageExportSets": {"icon": {"type": "font-awesome", "name": "share-nodes", "color": "#8D6E63"}},
        "OCIFileStorageExport": {"icon": {"type": "font-awesome", "name": "share", "color": "#8D6E63"}},
        "OCIFileStorageSnapshot": {"icon": {"type": "font-awesome", "name": "history", "color": "#8D6E63"}},

        # Logging / IoT / Streaming Services
        "OCILoggingLog": {"icon": {"type": "font-awesome", "name": "file-lines", "color": "#78909C"}},
        "OCILogsLogGroup": {"icon": {"type": "font-awesome", "name": "folder", "color": "#78909C"}},
        "OCIIoTDomain": {"icon": {"type": "font-awesome", "name": "microchip", "color": "#8E24AA"}},
        "OCIIoTDomainGroup": {"icon": {"type": "font-awesome", "name": "microchip", "color": "#8E24AA"}},
        "OCIIoTDigitalTwinModel": {"icon": {"type": "font-awesome", "name": "cube", "color": "#8E24AA"}},
        "OCIIoTDigitalTwinAdapter": {"icon": {"type": "font-awesome", "name": "plug", "color": "#8E24AA"}},
        "OCIIoTDigitalTwinInstance": {"icon": {"type": "font-awesome", "name": "cube", "color": "#8E24AA"}},
        "OCIIoTDigitalTwinRelationship": {"icon": {"type": "font-awesome", "name": "link", "color": "#8E24AA"}},
        "OCIKafkaCluster": {"icon": {"type": "font-awesome", "name": "wave-square", "color": "#26A69A"}},
        "OCIKafkaClusterConfig": {"icon": {"type": "font-awesome", "name": "sliders", "color": "#26A69A"}},
        "OCIKafkaClusterConfigVersion": {"icon": {"type": "font-awesome", "name": "code-branch", "color": "#26A69A"}},
        "OCIKubernetesCluster": {"icon": {"type": "font-awesome", "name": "cubes", "color": "#1565C0"}},
        "OCIKubernetesNodePool": {"icon": {"type": "font-awesome", "name": "layer-group", "color": "#1565C0"}},
        "OCIKubernetesVirtualNodePool": {"icon": {"type": "font-awesome", "name": "layer-group", "color": "#1565C0"}},
        "OCIKubernetesVirtualNode": {"icon": {"type": "font-awesome", "name": "cube", "color": "#1565C0"}},

        # Database / Network / Security Services
        "OCIMySqlDbSystem": {"icon": {"type": "font-awesome", "name": "database", "color": "#FBC02D"}},
        "OCIOracleDbSystem": {"icon": {"type": "font-awesome", "name": "database", "color": "#D32F2F"}},
        "OCIPostgreSqlDbSystem": {"icon": {"type": "font-awesome", "name": "database", "color": "#1976D2"}},
        "OCINetworkFirewall": {"icon": {"type": "font-awesome", "name": "shield-halved", "color": "#5E35B1"}},
        "OCINetworkFirewallPolicy": {"icon": {"type": "font-awesome", "name": "shield", "color": "#5E35B1"}},
        "OCINetworkFirewallSecurityRule": {"icon": {"type": "font-awesome", "name": "rule", "color": "#5E35B1"}},
        "OCINetworkLoadBalancer": {"icon": {"type": "font-awesome", "name": "scale-balanced", "color": "#1E88E5"}},
        "OCICacheCluster": {"icon": {"type": "font-awesome", "name": "database", "color": "#8BC34A"}},
        "OCICacheConfigSet": {"icon": {"type": "font-awesome", "name": "sliders-h", "color": "#8BC34A"}},
        "OCICacheUser": {"icon": {"type": "font-awesome", "name": "user-cog", "color": "#8BC34A"}},

        # Resource Manager / Governance
        "OCIResourceManagerStack": {"icon": {"type": "font-awesome", "name": "layer-group", "color": "#00838F"}},
        "OCIResourceManagerJobs": {"icon": {"type": "font-awesome", "name": "tasks", "color": "#00838F"}},
        "OCIResourceManagerTemplates": {"icon": {"type": "font-awesome", "name": "file-code", "color": "#00838F"}},
        "OCIResourceManagerPrivateEndpoints": {"icon": {"type": "font-awesome", "name": "network-wired", "color": "#00838F"}},
        "OCIResourceManagerConfigSourceProvider": {"icon": {"type": "font-awesome", "name": "plug", "color": "#00838F"}},
        "OCITagNamespace": {"icon": {"type": "font-awesome", "name": "tags", "color": "#6D4C41"}},
        "OCITagDefault": {"icon": {"type": "font-awesome", "name": "tag", "color": "#6D4C41"}},

        # Vault / KMS Extended Resources
        "OCIVaultHsmCluster": {"icon": {"type": "font-awesome", "name": "lock", "color": "#00838F"}},
        "OCIVaultKeyVersion": {"icon": {"type": "font-awesome", "name": "key", "color": "#00838F"}},
        "OCIVaultSecretBundle": {"icon": {"type": "font-awesome", "name": "key", "color": "#00838F"}},
        "OCIVaultSecretVersion": {"icon": {"type": "font-awesome", "name": "key", "color": "#00838F"}},
    }
}


# --------------------------------------------------------------------------------------
# Data standardization helpers
# --------------------------------------------------------------------------------------
def _standardize(value, *, flatten=False):
    """
    Normalize OpenGraph export values.

    - `flatten=True`: flatten nested dict keys to dot notation while keeping only
      BloodHound-safe values (primitive scalars or primitive arrays).
    - default: scalar/list normalization for property values.
    """
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None

    if flatten:
        result = {}
        stack = [("", value)]
        while stack:
            key_prefix, current = stack.pop()
            if not isinstance(current, dict):
                continue
            for raw_key in sorted(current.keys(), key=lambda x: str(x)):
                raw_val = current.get(raw_key)
                key = str(raw_key).strip()
                if not key:
                    continue
                full_key = f"{key_prefix}.{key}" if key_prefix else key
                if isinstance(raw_val, dict):
                    stack.append((full_key, raw_val))
                    continue
                normalized = _standardize(raw_val)
                if normalized is not None:
                    result[full_key] = normalized
        return {k: result[k] for k in sorted(result.keys())}

    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        if not value:
            return []
        normalized = []
        for item in value:
            if isinstance(item, str):
                item = item.strip()
                if not item:
                    return None
            if isinstance(item, (bool, int, float, str)):
                normalized.append(item)
                continue
            return None
        return normalized
    return None


def _node_to_opengraph(r):
    
    node_id, node_type = r["node_id"], r["node_type"]

    if not node_type:
        kinds = ["OCIUnknown"]
    elif node_type in PRINCIPAL_KINDS:
        kinds = [node_type, "OCIPrincipal"]
    elif node_type in RESOURCE_KINDS or node_type.startswith("OCI"):
        kinds = [node_type, "OCIResource"]
    else:
        kinds = ["OCIUnknown"]

    try:
        raw_props = json.loads((r.get("node_properties") or "").strip() or "{}")
    except Exception:
        raw_props = {}
        
    props = _standardize(raw_props, flatten=True)
    
    props.setdefault("name", display := props.get("name") or node_id)

    props = {k: v for k, v in props.items() if v is not None} or None

    return {
        "id": node_id,
        "kinds": kinds,
        "properties": props,
    }


# --------------------------------------------------------------------------------------
# Edge helpers
# --------------------------------------------------------------------------------------
# Edge payload contract (strict):
# {
#   "edge_category": "GROUP_MEMBERSHIP" | "PERMISSION" | "RESOURCE",
#   "edge_inner_properties": { ... }
# }
#
# edge_inner_properties by category:
# - GROUP_MEMBERSHIP:
#   {
#     "matching_rules": str,
#     "membership_id": str,
#     "group_type": "standard" | "dynamic"
#   }
# - PERMISSION:
#   {
#     "is_priv_escalation": bool,
#     "resolved_statements": list[str],
#     "unresolved_statements": list[str],
#     "resolved_policy": list[str],   # policy OCIDs/IDs fully resolved
#     "unresolved_policy": list[str]  # policy OCIDs/IDs with unresolved conditions
#   }
# - RESOURCE:
#   {
#     "resource_family": bool,
#     "resource_used": bool
#   }
def _edge_to_opengraph(r):
    edge_props = json.loads((r.get("edge_properties") or "").strip() or "{}")
    category, inner = edge_props["edge_category"], edge_props["edge_inner_properties"]

    props = {"edge_category": category}
    for raw_key in sorted(inner.keys(), key=lambda x: str(x)):
        raw_val = inner.get(raw_key)
        key = str(raw_key).strip()
        if not key:
            continue
        value = _standardize(raw_val)
        if value is not None:
            props[key] = value
    props = props or None

    return {
        "start": {"value": r["source_id"]},
        "end": {"value": r["destination_id"]},
        "kind": r["edge_type"],
        "properties": props,
    }


def _collapse_manage_shadowed_permission_edges(edge_rows, *, enabled: bool = True, debug: bool = False):
    """
    Export hygiene:
      - If a source->destination pair has OCI_MANAGE, suppress other PERMISSION
        edges for that same pair from exported JSON.
      - Annotate the retained OCI_MANAGE edge with:
          includes_other_edges: [<suppressed_edge_type>, ...]
        (always present; empty when nothing was suppressed).
    """
    if not enabled:
        return (edge_rows or []), {"pairs_with_manage": 0, "collapsed_edges": 0, "duplicate_manage_edges_pruned": 0}

    rows = [dict(r) for r in (edge_rows or []) if isinstance(r, dict)]
    if not rows:
        return rows, {"pairs_with_manage": 0, "collapsed_edges": 0, "duplicate_manage_edges_pruned": 0}

    grouped = defaultdict(list)
    for idx, row in enumerate(rows):
        src = str(row.get("source_id") or "").strip()
        dst = str(row.get("destination_id") or "").strip()
        grouped[(src, dst)].append(idx)

    keep = [True] * len(rows)
    pairs_with_manage = 0
    collapsed_edges = 0
    duplicate_manage_edges_pruned = 0

    for (_src, _dst), idxs in grouped.items():
        manage_idxs = [i for i in idxs if str(rows[i].get("edge_type") or "").strip() == "OCI_MANAGE"]
        if not manage_idxs:
            continue
        pairs_with_manage += 1

        canonical_idx = manage_idxs[0]
        includes = set()

        for i in idxs:
            if i == canonical_idx:
                continue

            edge_type = str(rows[i].get("edge_type") or "").strip()
            if not edge_type:
                continue

            if edge_type == "OCI_MANAGE":
                keep[i] = False
                duplicate_manage_edges_pruned += 1
                continue

            try:
                raw_payload = json.loads((rows[i].get("edge_properties") or "").strip() or "{}")
            except Exception:
                raw_payload = {}
            category = str((raw_payload or {}).get("edge_category") or "").strip().upper()

            if category == "PERMISSION":
                keep[i] = False
                collapsed_edges += 1
                includes.add(edge_type)

        # Ensure retained OCI_MANAGE edge carries explicit collapse metadata.
        try:
            manage_payload = json.loads((rows[canonical_idx].get("edge_properties") or "").strip() or "{}")
        except Exception:
            manage_payload = {}
        if not isinstance(manage_payload, dict):
            manage_payload = {}
        edge_inner = manage_payload.get("edge_inner_properties")
        if not isinstance(edge_inner, dict):
            edge_inner = {}
        edge_inner["includes_other_edges"] = sorted(includes)
        manage_payload["edge_category"] = str(manage_payload.get("edge_category") or "PERMISSION")
        manage_payload["edge_inner_properties"] = edge_inner
        rows[canonical_idx]["edge_properties"] = json.dumps(manage_payload, separators=(",", ":"), sort_keys=False)

    kept = [rows[i] for i, flag in enumerate(keep) if flag]
    stats = {
        "pairs_with_manage": int(pairs_with_manage),
        "collapsed_edges": int(collapsed_edges),
        "duplicate_manage_edges_pruned": int(duplicate_manage_edges_pruned),
    }
    _dlog(debug, "export: manage edge collapse complete", **stats, before=len(rows), after=len(kept))
    return kept, stats


def push_custom_node_attributes(
    *,
    custom_nodes_url: str,
    custom_nodes_token: str,
):
    token = (custom_nodes_token or "").strip()
    if not token:
        print("[*] Skipping custom-nodes push: token not provided.")
        return {"ok": False, "reason": "missing_token"}

    try:
        import requests
    except Exception:
        print("[*] Skipping custom-nodes push: requests is not installed.")
        return {"ok": False, "reason": "requests_missing"}

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    # Intentionally disable TLS verification for custom-node styling sync workflow.
    verify = False

    try:
        resp = requests.put(custom_nodes_url, headers=headers, json=CUSTOM_NODE_PAYLOAD, verify=verify, timeout=10)
        if resp.status_code in (404, 405):
            resp = requests.post(custom_nodes_url, headers=headers, json=CUSTOM_NODE_PAYLOAD, verify=verify, timeout=10)
        print("custom-nodes complete", resp.status_code, resp.text[:400])
        return {"ok": True, "status_code": int(resp.status_code)}
    except Exception as e:
        print("custom-nodes request failed", f"{type(e).__name__}: {e}")
        return {"ok": False, "reason": "request_failed", "error": f"{type(e).__name__}: {e}"}



# --------------------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------------------
def export_opengraph_json(node_rows, edge_rows, debug=False):
    _dlog(debug, "export: loaded rows", nodes=len(node_rows or []), edges=len(edge_rows or []))

    nodes = [_node_to_opengraph(r) for r in (node_rows or [])]
    edges = [_edge_to_opengraph(r) for r in (edge_rows or [])]
    nodes = sorted(nodes, key=lambda n: str((n or {}).get("id") or ""))
    edges = sorted(
        edges,
        key=lambda e: (
            str(((e or {}).get("start") or {}).get("value") or ""),
            str(((e or {}).get("end") or {}).get("value") or ""),
            str((e or {}).get("kind") or ""),
        ),
    )

    _dlog(debug, "export: final graph", unique_nodes=len(nodes), unique_edges=len(edges))
    return {
        "metadata": {
            "source_kind": "OCIBase",
        },
        "graph": {"nodes": nodes, "edges": edges},
    }


def _prune_orphan_idd_app_nodes(node_rows, edge_rows, *, enabled: bool, debug: bool = False):
    """
    Default export hygiene:
      - Drop OCIIDDApplication nodes that have no incident edges.
      - Keep all nodes untouched when disabled (used by --include-all).
    """
    if not enabled:
        return (node_rows or []), 0

    incident_node_ids = set()
    for edge in (edge_rows or []):
        if not isinstance(edge, dict):
            continue
        src = str(edge.get("source_id") or "").strip()
        dst = str(edge.get("destination_id") or "").strip()
        if src:
            incident_node_ids.add(src)
        if dst:
            incident_node_ids.add(dst)

    kept = []
    pruned = 0
    for node in (node_rows or []):
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("node_id") or "").strip()
        node_type = str(node.get("node_type") or "").strip()
        if node_type == "OCIIDDApplication" and node_id and node_id not in incident_node_ids:
            pruned += 1
            continue
        kept.append(node)

    _dlog(
        debug,
        "export: orphan OCIIDDApplication prune complete",
        enabled=enabled,
        pruned=pruned,
        before=len(node_rows or []),
        after=len(kept),
    )
    return kept, pruned


def _prune_orphan_policy_statement_nodes(node_rows, edge_rows, *, enabled: bool, debug: bool = False):
    """
    Default export hygiene:
      - Drop policy statement nodes that have no incident edges.
      - Keep all nodes untouched when disabled (used by --include-all).
    """
    if not enabled:
        return (node_rows or []), 0

    incident_node_ids = set()
    for edge in (edge_rows or []):
        if not isinstance(edge, dict):
            continue
        src = str(edge.get("source_id") or "").strip()
        dst = str(edge.get("destination_id") or "").strip()
        if src:
            incident_node_ids.add(src)
        if dst:
            incident_node_ids.add(dst)

    policy_stmt_types = {"OCIPolicyStatement", "OCIIdentityDomainPolicyStatement"}
    kept = []
    pruned = 0
    for node in (node_rows or []):
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("node_id") or "").strip()
        node_type = str(node.get("node_type") or "").strip()
        if node_type in policy_stmt_types and node_id and node_id not in incident_node_ids:
            pruned += 1
            continue
        kept.append(node)

    _dlog(
        debug,
        "export: orphan policy statement prune complete",
        enabled=enabled,
        pruned=pruned,
        before=len(node_rows or []),
        after=len(kept),
    )
    return kept, pruned


# --------------------------------------------------------------------------------------
# CLI / runner
# --------------------------------------------------------------------------------------
def _clear_opengraph_tables(session, debug=False):
    for table_name in OPEN_GRAPH_TABLES:
        try:
            session.delete_resource(table_name)
            _dlog(debug, "reset: cleared table", table=table_name)
        except Exception as e:
            print(f"[X] reset failed for {table_name}: {type(e).__name__}: {e}")


def _run_build_steps(session, args, debug=False):
    domain_hint = args.infer_domain or None
    drop_time_no_perms, drop_general_no_perms = args.drop_no_cond_perms

    ctx = OfflineIamContext(
        session=session,
        debug=debug,
        default_domain=domain_hint,
        lazy=False,
        iam_config={
            "expand_inheritance": args.expand_inheritance,
            "conditional_evaluation": args.conditional_evaluation,
            "include_all": args.include_all,
            "infer_domain": bool(domain_hint),
            "drop_time_based_no_effective_permissions": drop_time_no_perms,
            "drop_all_no_effective_permissions": drop_general_no_perms,
        },
    )

    groups_only = bool(getattr(args, "groups_only", False))
    dynamic_groups_only = bool(getattr(args, "dynamic_groups_only", False))
    if groups_only and dynamic_groups_only:
        selected_steps = ("groups", "dynamic_groups")
    elif groups_only:
        selected_steps = ("groups",)
    elif dynamic_groups_only:
        selected_steps = ("dynamic_groups",)
    else:
        selected_steps = tuple(BUILD_STEP_SPECS.keys())

    builder_stats = {}
    for key in selected_steps:
        spec = BUILD_STEP_SPECS[key]
        try:
            result = spec["runner"](session=session, ctx=ctx, debug=debug, **spec.get("kwargs", {}))
        except Exception as e:
            result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        builder_stats[key] = result if isinstance(result, dict) else {"ok": True, "result": result}
        _dlog(debug, "opengraph builder stats", step=key, stats=builder_stats[key])

    try:
        ctx.commit()
    except Exception as e:
        _dlog(debug, "opengraph: final commit failed", err=f"{type(e).__name__}: {e}")

    return builder_stats


def _parse_args(user_args):
    def _parse_drop_no_cond_perms_modes(value):
        raw = str(value or "").strip().lower()
        tokens = {t.strip() for t in raw.split(",") if t.strip()}
        if not tokens:
            return False, False
        allowed = {"time", "general", "all"}
        invalid = sorted(tokens - allowed)
        if invalid:
            raise argparse.ArgumentTypeError(
                f"invalid --drop-no-cond-perms mode(s): {', '.join(invalid)} "
                "(allowed: time,general,all)"
            )
        if "all" in tokens:
            return True, True
        return ("time" in tokens), ("general" in tokens)

    p = argparse.ArgumentParser(description="Build OCI OpenGraph data offline", allow_abbrev=False)
    g_general = p.add_argument_group("General")
    g_general.add_argument("--out", default="", help="Output JSON path (default: session-managed export path)")
    g_general.add_argument("--export-only", action="store_true", help="Skip builds; only export opengraph_* tables")
    g_general.add_argument("--debug", action="store_true", help="Enable debug logging")
    g_general.add_argument("--debug-report", action="store_true", help="Write a debug report JSON alongside output")
    g_general.add_argument("--save", action="store_true", help="Pass-through flag for module-runner consistency (unused here).")
    g_general.add_argument(
        "--groups",
        dest="groups_only",
        action="store_true",
        help="Run only the group membership build step.",
    )
    g_general.add_argument(
        "--dynamic-groups",
        dest="dynamic_groups_only",
        action="store_true",
        help="Run only the dynamic-group membership build step.",
    )

    g_iam = p.add_argument_group("IAM Controls")
    g_iam.add_argument(
        "--infer-domain",
        nargs="?",
        const="Default",
        default=None,
        metavar="DOMAIN",
        help="IAM: infer identity domains (optional domain hint; blank => Default).",
    )
    g_iam.add_argument(
        "--include-all",
        dest="include_all",
        action="store_true",
        help="IAM: include all parsed IAM edges/nodes (not only default allowlist output).",
    )
    g_iam.add_argument(
        "--expand-inherited",
        dest="expand_inheritance",
        action="store_true",
        help="IAM: expand inherited scope/location edges.",
    )
    g_iam.add_argument(
        "--cond-eval",
        dest="conditional_evaluation",
        action="store_true",
        help="IAM: attempt conditional evaluation",
    )
    g_iam.add_argument(
        "--drop-no-cond-perms",
        dest="drop_no_cond_perms",
        nargs="?",
        const="all",
        default=(False, False),
        type=_parse_drop_no_cond_perms_modes,
        metavar="MODES",
        help=(
            "IAM: drop conditionals with no effective permissions. "
            "Modes: time, general, all (comma-separated; blank => all)."
        ),
    )

    g_maint = p.add_argument_group("Maintenance")
    g_maint.add_argument("--reset", action="store_true", help="Delete opengraph tables before build")

    g_bh = p.add_argument_group("BloodHound Custom Nodes")
    g_bh.add_argument(
        "--apply-custom-node-attributes",
        action="store_true",
        help="Push OCI custom node styles to BloodHound custom-nodes API after export.",
    )
    g_bh.add_argument(
        "--custom-nodes-url",
        default=os.getenv("OCINFERNO_CUSTOM_NODES_URL", "http://127.0.0.1:8080/api/v2/custom-nodes"),
        help="BloodHound custom-nodes API endpoint.",
    )
    g_bh.add_argument(
        "--custom-nodes-token",
        default=os.getenv("OCINFERNO_CUSTOM_NODES_TOKEN", ""),
        help="Bearer token for custom-nodes API (or set OCINFERNO_CUSTOM_NODES_TOKEN).",
    )

    return p.parse_args(user_args)


def run_module(user_args, session):
    args = _parse_args(user_args)
    debug = bool(getattr(args, "debug", False))

    if args.reset:
        _clear_opengraph_tables(session, debug)

    builder_stats = {}
    if not args.export_only:
        builder_stats = _run_build_steps(session, args, debug=debug)

    node_rows = session.get_resource_fields("opengraph_nodes", columns=NODE_COLUMNS) or []
    edge_rows = session.get_resource_fields("opengraph_edges", columns=EDGE_COLUMNS) or []
    node_rows, pruned_orphan_idd_apps = _prune_orphan_idd_app_nodes(
        node_rows,
        edge_rows,
        enabled=not bool(args.include_all),
        debug=debug,
    )
    node_rows, pruned_orphan_policy_statements = _prune_orphan_policy_statement_nodes(
        node_rows,
        edge_rows,
        enabled=not bool(args.include_all),
        debug=debug,
    )
    edge_rows, manage_collapse_stats = _collapse_manage_shadowed_permission_edges(
        edge_rows,
        enabled=True,
        debug=debug,
    )

    out = export_opengraph_json(node_rows, edge_rows, debug=debug)

    out_path = session.resolve_output_path(
        requested_path=args.out,
        service_name="opengraph",
        filename="oracle_cloud_hound.json",
        compartment_id=getattr(session, "compartment_id", None),
        subdirs=["bloodhound"],
        target="export",
    )
    out_path.write_text(json.dumps(out, indent=2, sort_keys=False), encoding="utf-8")
    print(f"[*] wrote {out_path}")

    custom_nodes_push = None
    custom_nodes_token = str(getattr(args, "custom_nodes_token", "") or "").strip()
    should_push_custom_nodes = bool(args.apply_custom_node_attributes) or bool(custom_nodes_token)
    if should_push_custom_nodes:
        custom_nodes_push = push_custom_node_attributes(
            custom_nodes_url=args.custom_nodes_url,
            custom_nodes_token=custom_nodes_token,
        )

    if args.debug_report:
        node_type_counts = dict(
            Counter(row.get("node_type") for row in node_rows if isinstance(row, dict) and row.get("node_type"))
        )
        edge_type_counts = dict(
            Counter(row.get("edge_type") for row in edge_rows if isinstance(row, dict) and row.get("edge_type"))
        )
        debug_report = {
            "export_only": bool(args.export_only),
            "builder_stats": builder_stats,
            "custom_nodes_push": custom_nodes_push,
            "pruned_orphan_idd_app_nodes": int(pruned_orphan_idd_apps),
            "pruned_orphan_policy_statement_nodes": int(pruned_orphan_policy_statements),
            "manage_collapse_stats": dict(manage_collapse_stats or {}),
            "node_count": len(node_rows),
            "edge_count": len(edge_rows),
            "node_type_counts": node_type_counts,
            "edge_type_counts": edge_type_counts,
        }
        debug_path = out_path.with_suffix(out_path.suffix + ".debug.json")
        debug_path.write_text(json.dumps(debug_report, indent=2, sort_keys=False), encoding="utf-8")
        print(f"[*] wrote {debug_path}")

    return out
