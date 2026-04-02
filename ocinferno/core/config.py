from __future__ import annotations

import re
from typing import Any, Dict, List


WORKSPACE_CONFIG_KEYS: List[str] = [
    "proxy",
    "current_default_region",
    "module_auto_save",
    "rate_limit_seconds",
    "rate_limit_jitter_seconds",
    "api_logging_enabled",
    "api_logging_file_path",
    "api_logging_verbosity",
    "api_logging_attributes",
    "std_output_format",
]

CONFIG_VALUE_CHOICES: Dict[str, List[str]] = {
    "std_output_format": ["table", "txt"],
    "api_logging_verbosity": ["standard", "verbose", "basic"],
    "module_auto_save": ["true", "false"],
    "api_logging_enabled": ["true", "false"],
}

# OCI region catalog used for config validation/autocomplete.
# Includes common commercial + gov names; dedicated/private realms may not appear.
KNOWN_OCI_REGIONS: List[str] = sorted([
    "af-casablanca-1",
    "af-johannesburg-1",
    "ap-batam-1",
    "ap-chuncheon-1",
    "ap-hyderabad-1",
    "ap-kulai-2",
    "ap-melbourne-1",
    "ap-mumbai-1",
    "ap-osaka-1",
    "ap-seoul-1",
    "ap-singapore-1",
    "ap-singapore-2",
    "ap-sydney-1",
    "ap-tokyo-1",
    "ca-montreal-1",
    "ca-toronto-1",
    "eu-amsterdam-1",
    "eu-frankfurt-1",
    "eu-jovanovac-1",
    "eu-madrid-1",
    "eu-madrid-3",
    "eu-marseille-1",
    "eu-milan-1",
    "eu-paris-1",
    "eu-stockholm-1",
    "eu-turin-1",
    "eu-zurich-1",
    "il-jerusalem-1",
    "me-abudhabi-1",
    "me-dubai-1",
    "me-jeddah-1",
    "me-riyadh-1",
    "mx-monterrey-1",
    "mx-queretaro-1",
    "sa-bogota-1",
    "sa-santiago-1",
    "sa-saopaulo-1",
    "sa-valparaiso-1",
    "sa-vinhedo-1",
    "uk-cardiff-1",
    "uk-london-1",
    "us-ashburn-1",
    "us-chicago-1",
    "us-langley-1",
    "us-luke-1",
    "us-phoenix-1",
    "us-sanjose-1",
])

KNOWN_OCI_REGION_SET = set(KNOWN_OCI_REGIONS)

_OCI_REGION_PATTERN = re.compile(r"^[a-z]{2,4}-[a-z0-9-]+-\d+$")


def is_region_format_like(region_name: str) -> bool:
    return bool(_OCI_REGION_PATTERN.match(str(region_name or "").strip().lower()))


def default_workspace_config(
    *,
    schema_version: int,
    default_api_log_attributes: List[str],
) -> Dict[str, Any]:
    return {
        "config_schema_version": int(schema_version),
        "proxy": None,
        "current_default_region": "",
        "module_auto_save": True,
        "rate_limit_seconds": 0.0,
        "rate_limit_jitter_seconds": 0.0,
        "api_logging_enabled": False,
        "api_logging_file_path": "",
        "api_logging_verbosity": "standard",
        "api_logging_attributes": list(default_api_log_attributes or []),
        "std_output_format": "table",
    }
