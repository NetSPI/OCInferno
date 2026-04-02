from __future__ import annotations

from collections import Counter
from pathlib import Path
import re

from ocinferno.modules.opengraph.utilities.identity_domain_graph_builder import (
    EDGE_IDD_USER_MANAGER,
    NODE_USER,
    _ensure_user_node_from_ref,
    _run_idd_role_emitters,
)
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    DEFAULT_ALLOW_EDGE_RULES,
    NODE_TYPE_OCI_USER,
)
from ocinferno.modules.opengraph.utilities.helpers.context import OfflineIamContext


class _NodeCaptureCtx:
    def __init__(self):
        self.nodes = []

    def upsert_node(self, **kwargs):
        self.nodes.append(dict(kwargs))
        return kwargs.get("node_id") or ""

    def tenant_for_compartment(self, _cid):
        return "ocid1.tenancy.oc1..test"


class _EdgeCaptureCtx:
    def __init__(self):
        self.edges = []
        self.og_state = {
            "existing_nodes_set": set(),
            "existing_edges_set": set(),
            "existing_node_types": {},
        }

    def write_edge(
        self,
        source_id,
        source_type,
        destination_id,
        destination_type,
        edge_type,
        *,
        edge_properties=None,
        commit=True,
        on_conflict="update",
    ):
        self.edges.append(
            {
                "source_id": source_id,
                "source_type": source_type,
                "destination_id": destination_id,
                "destination_type": destination_type,
                "edge_type": edge_type,
                "edge_properties": edge_properties,
                "commit": commit,
                "on_conflict": on_conflict,
            }
        )
        return True


def test_ensure_user_node_from_ref_prefers_user_name():
    ctx = _NodeCaptureCtx()
    did = "ocid1.domain.oc1..demo"
    user_row = {
        "id": "scim-user-1",
        "ocid": "ocid1.user.oc1..abc123",
        "display_name": "PROD User",
        "user_name": "prod_user",
        "name": "PROD User",
        "compartment_ocid": "ocid1.compartment.oc1..demo",
        "tenancy_ocid": "ocid1.tenancy.oc1..demo",
    }
    user_by_scim = {"scim-user-1": user_row}
    user_by_ocid = {user_row["ocid"]: user_row}

    node_id = _ensure_user_node_from_ref(
        ctx=ctx,
        did=did,
        domain_url="https://idcs.example.invalid",
        user_ref="scim-user-1",
        user_by_scim=user_by_scim,
        user_by_ocid=user_by_ocid,
        default_compartment_id="ocid1.compartment.oc1..fallback",
        default_tenant_id="ocid1.tenancy.oc1..fallback",
    )

    assert node_id == user_row["ocid"]
    assert len(ctx.nodes) == 1
    assert ctx.nodes[0]["display_name"] == "prod_user"


def test_write_principal_node_idd_user_prefers_user_name():
    ctx = OfflineIamContext(session=None, lazy=True)
    captured = {}

    def _capture_upsert_node(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return kwargs.get("node_id") or ""

    ctx.upsert_node = _capture_upsert_node  # type: ignore[method-assign]

    principal = {
        "id": "scim-user-2",
        "ocid": "ocid1.user.oc1..def456",
        "display_name": "PROD User",
        "user_name": "prod_user_2",
        "name": "PROD User",
    }

    node_id = ctx.write_principal_node(
        principal,
        principal_type=NODE_TYPE_OCI_USER,
        identity_domain=True,
        commit=False,
    )

    assert node_id == principal["ocid"]
    assert captured["node_properties"]["name"] == "prod_user_2"


def test_user_manager_excludes_identity_and_user_admin_targets():
    ctx = _EdgeCaptureCtx()
    did = "ocid1.domain.oc1..demo"
    ctx._idd_users_by_domain_cache = {  # noqa: SLF001
        did: [
            ("ocid1.user.oc1..identity_admin", NODE_USER),
            ("ocid1.user.oc1..user_admin", NODE_USER),
            ("ocid1.user.oc1..eligible", NODE_USER),
        ]
    }
    ctx._idd_identity_admin_users_by_domain_cache = {  # noqa: SLF001
        did: {"ocid1.user.oc1..identity_admin"}
    }
    ctx._idd_user_admin_users_by_domain_cache = {  # noqa: SLF001
        did: {"ocid1.user.oc1..user_admin"}
    }

    stats = Counter()
    _run_idd_role_emitters(
        session=None,
        ctx=ctx,
        raw_role_name="User Manager",
        role_nid="iddrole::demo::user-manager",
        role_name="DemoDomain/User Manager",
        app_id="IDCSAppId",
        app_name="DemoDomain/IDCS Application",
        did=did,
        role_scope={"scope_mode": "all_users_or_default"},
        groups_by_domain={},
        idd_admin_groups_by_domain={},
        user_admin_groups_by_domain={},
        stats=stats,
        stats_prefix="",
        debug=False,
    )

    assert len(ctx.edges) == 1
    assert ctx.edges[0]["edge_type"] == EDGE_IDD_USER_MANAGER
    assert ctx.edges[0]["destination_id"] == "ocid1.user.oc1..eligible"


def test_default_allow_rules_include_expected_identity_edge():
    edge_labels = {rule.edge_label for rule in DEFAULT_ALLOW_EDGE_RULES}
    assert "OCI_CREATE_USER_API_KEY" in edge_labels


def test_policy_statement_fixtures_use_obfuscated_ocids():
    scenario_root = Path("tests/integration/opengraph_golden_iam/scenarios")
    assert scenario_root.exists()
    # Treat long OCID suffixes as likely real tenant/resource identifiers.
    real_like_ocid = re.compile(r"ocid1\.[a-z0-9._-]+\.oc1\.\.[a-z0-9]{16,}", re.IGNORECASE)
    offenders = []
    for statement_path in scenario_root.glob("**/statement.txt"):
        text = statement_path.read_text(encoding="utf-8")
        if real_like_ocid.search(text):
            offenders.append(str(statement_path))
    assert offenders == []
