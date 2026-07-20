# custom_node_sync.py
"""BloodHound custom-node (color/icon) styling payload + push, shared by the standalone
``process_og_node_color_images`` styling module. Kept separate from graph generation so
you can re-style an existing BloodHound instance without regenerating the graph.

Supports both BloodHound auth modes: a **bearer** JWT, or a **signature** API key
(token id + key, from BloodHound -> My Profile -> API Key Management) using the
bhesignature HMAC scheme."""

import base64
import datetime
import hashlib
import hmac
import json
from urllib.parse import urlparse

from ocinferno.modules.opengraph.utilities.helpers.constants import (
    NODE_TYPE_OCI_DYNAMIC_GROUP,
    NODE_TYPE_OCI_GROUP,
    NODE_TYPE_OCI_USER,
)

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
        "OCIManagementAgentInstallKey": {"icon": {"type": "font-awesome", "name": "id-card-clip", "color": "#C62828"}},
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


def _bhe_signature_headers(*, token_id: str, token_key: str, method: str, url: str, body: bytes) -> dict:
    """BloodHound API-key (bhesignature) HMAC headers. The signature chains HMAC-SHA256
    over the operation (method+URI), the request date to the hour, then the body -- so it
    must be recomputed per request (method/body differ between PUT and POST)."""
    parsed = urlparse(url)
    request_uri = str(parsed.path or "/")
    if parsed.query:
        request_uri = f"{request_uri}?{parsed.query}"
    request_date = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

    digester = hmac.new(token_key.encode("utf-8"), None, hashlib.sha256)
    digester.update(f"{method}{request_uri}".encode("utf-8"))
    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    digester.update(request_date[:13].encode("utf-8"))
    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    digester.update(body or b"")
    signature = base64.b64encode(digester.digest()).decode("utf-8")
    return {
        "Authorization": f"bhesignature {token_id}",
        "RequestDate": request_date,
        "Signature": signature,
        "Content-Type": "application/json",
    }


def _auth_headers(*, mode: str, token: str, token_id: str, token_key: str, method: str, url: str, body: bytes) -> dict:
    if mode == "bearer":
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    return _bhe_signature_headers(token_id=token_id, token_key=token_key, method=method, url=url, body=body)


def push_custom_node_attributes(
    *,
    custom_nodes_url: str,
    custom_nodes_token: str = "",
    auth_mode: str = "bearer",
    custom_nodes_token_id: str = "",
    custom_nodes_token_key: str = "",
    verify: bool = True,
):
    """PUT (falling back to POST) the custom-node style payload to BloodHound.

    ``auth_mode`` is ``bearer`` (JWT via ``custom_nodes_token``) or ``signature`` (BloodHound
    API key via ``custom_nodes_token_id`` + ``custom_nodes_token_key``, HMAC-signed).
    ``verify`` controls TLS verification (default True; pass False only for a local
    self-signed BloodHound). Never raises -- returns a small status dict."""
    mode = str(auth_mode or "bearer").strip().lower()
    token = (custom_nodes_token or "").strip()
    token_id = (custom_nodes_token_id or "").strip()
    token_key = (custom_nodes_token_key or "").strip()
    if mode not in {"bearer", "signature"}:
        print(f"[*] Skipping custom-nodes push: unsupported auth mode '{mode}'.")
        return {"ok": False, "reason": "unsupported_auth_mode", "auth_mode": mode}
    if mode == "bearer" and not token:
        print("[*] Skipping custom-nodes push: bearer token not provided.")
        return {"ok": False, "reason": "missing_token"}
    if mode == "signature" and (not token_id or not token_key):
        print("[*] Skipping custom-nodes push: API token id/key not provided for signature auth.")
        return {"ok": False, "reason": "missing_signature_credentials"}

    try:
        import requests
    except Exception:
        print("[*] Skipping custom-nodes push: requests is not installed.")
        return {"ok": False, "reason": "requests_missing"}

    body = json.dumps(CUSTOM_NODE_PAYLOAD, separators=(",", ":")).encode("utf-8")

    def _send(method: str):
        headers = _auth_headers(mode=mode, token=token, token_id=token_id, token_key=token_key,
                                method=method, url=custom_nodes_url, body=body)
        fn = requests.put if method == "PUT" else requests.post
        return fn(custom_nodes_url, headers=headers, data=body, verify=verify, timeout=10)

    try:
        resp = _send("PUT")
        if resp.status_code in (404, 405):
            resp = _send("POST")
        print("custom-nodes complete", resp.status_code, resp.text[:400])
        return {"ok": resp.status_code < 400, "status_code": int(resp.status_code), "auth_mode": mode}
    except Exception as e:
        print("custom-nodes request failed", f"{type(e).__name__}: {e}")
        return {"ok": False, "reason": "request_failed", "error": f"{type(e).__name__}: {e}"}
