# management_agent_install_key_graph_builder.py
"""Additive OpenGraph builder: Management-Agent install key -> dynamic group.

A management-agent install key is a portable BEARER credential. Whoever holds a
*usable* key can register a NEW management agent -- from ANY host, on- or off-OCI --
as a principal created in the KEY'S compartment (Oracle: "if the unlimited install key
is compromised, an attacker can install rogue agents in your tenancy"). If a dynamic
group there matches ``resource.type='managementagent'``, that rogue agent joins the DG
and inherits its IAM policy grants.

This mirrors the existing ``INSTANCE_CAN_JOIN_DG`` edge (a launchable instance joining a
matching DG). It is fully ADDITIVE: a new node type + new edge kind emitted by a
standalone build step, with dynamic-group matching done via the engine's hypothetical
matcher for the ``managementagent`` type -- no change to any golden base builder or to
the shared ``DYNAMIC_GROUP_RESOURCE_TYPES`` set.
"""
from datetime import datetime, timezone

from ocinferno.modules.opengraph.utilities.helpers import (
    build_edge_properties as _build_edge_properties,
    EDGE_CATEGORY_GROUP_MEMBERSHIP,
)
from ocinferno.modules.opengraph.utilities.helpers.context import _dlog
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    EDGE_TYPE_OCI_INSTALL_KEY_CAN_JOIN_DG as EDGE_INSTALL_KEY_CAN_JOIN_DG,
    NODE_TYPE_OCI_DYNAMIC_GROUP as DYNAMIC_GROUP_NODE,
    NODE_TYPE_OCI_MANAGEMENT_AGENT_INSTALL_KEY as INSTALL_KEY_NODE,
)
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import emit_edge as _emit_edge_shared
from ocinferno.modules.opengraph.utilities.helpers.matching_rules_engine import (
    DynamicGroupPermissionLocationMatcher,
)

# The OCI dynamic-group resource.type token for a management agent.
_MANAGEMENT_AGENT_RESOURCE_TYPES = {"managementagent"}


def _truthy(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y", "t"}


def _key_is_usable(key: dict) -> bool:
    """A key is exploitable when ACTIVE, not expired, and has install slots left.

    Fail-open on unparseable fields (an unknown value must not silently drop a
    potentially-usable key from the attacker's perspective)."""
    state = str(key.get("lifecycle_state") or "").strip().upper()
    if state and state != "ACTIVE":
        return False

    raw_exp = str(key.get("time_expires") or "").strip()
    if raw_exp:
        try:
            exp = datetime.fromisoformat(raw_exp.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= datetime.now(timezone.utc):
                return False
        except Exception:
            pass  # unparseable expiry -> treat as usable

    if _truthy(key.get("is_unlimited")):
        return True
    try:
        allowed = int(float(key.get("allowed_key_install_count") or 0))
        current = int(float(key.get("current_key_install_count") or 0))
        if allowed and current >= allowed:
            return False
    except Exception:
        pass
    return True


def _dg_inventory(ctx):
    """[(dg_id, matching_rule, compartment_id), ...] from the materialized DG inventory
    (identity-domain + classic dynamic groups already loaded onto ctx)."""
    out = []
    for dg in (getattr(ctx, "idd_dynamic_groups", None) or []):
        dg_id = str(dg.get("ocid") or "").strip()
        if dg_id:
            out.append((
                dg_id,
                str(dg.get("matching_rule") or "").strip(),
                str(dg.get("compartment_ocid") or dg.get("compartment_id") or "").strip(),
            ))
    for dg in (getattr(ctx, "classic_dynamic_groups", None) or []):
        dg_id = str(dg.get("id") or "").strip()
        if dg_id:
            out.append((
                dg_id,
                str(dg.get("matching_rule") or "").strip(),
                str(dg.get("compartment_id") or dg.get("compartment_ocid") or "").strip(),
            ))
    return out


def build_management_agent_install_key_dg_edges_offline(*, session, ctx, debug: bool = False, auto_commit=False) -> dict:
    """Emit ``OCIManagementAgentInstallKey --INSTALL_KEY_CAN_JOIN_DG--> OCIDynamicGroup``
    for every usable install key whose compartment has a DG matching a management agent."""
    totals = {
        "install_keys_total": 0,
        "install_keys_usable": 0,
        "install_key_nodes_written": 0,
        "dynamic_groups_considered": 0,
        "edges_written": 0,
    }

    keys = session.get_resource_fields("management_agent_install_keys") or []
    totals["install_keys_total"] = len(keys)
    dgs = _dg_inventory(ctx)
    totals["dynamic_groups_considered"] = len(dgs)

    if not keys or not dgs:
        if auto_commit:
            ctx.commit()
        _dlog(debug, "install_key_dg: nothing to do", **totals)
        return totals

    for key in keys:
        if not isinstance(key, dict):
            continue
        key_id = str(key.get("id") or "").strip()
        if not key_id or not _key_is_usable(key):
            continue
        totals["install_keys_usable"] += 1
        key_comp = str(key.get("compartment_id") or "").strip()

        matched_dgs = []
        for dg_id, rule, _dg_comp in dgs:
            if not rule:
                continue
            try:
                if DynamicGroupPermissionLocationMatcher._rule_matches_hypothetical_resource(
                    rule_text=rule,
                    location=key_comp,
                    candidate_resource_types=_MANAGEMENT_AGENT_RESOURCE_TYPES,
                ):
                    matched_dgs.append(dg_id)
            except Exception as e:
                _dlog(debug, "install_key_dg: rule eval failed", dynamic_group_id=dg_id, err=f"{type(e).__name__}: {e}")

        if not matched_dgs:
            continue

        if ctx.write_specific_resource_node(
            dict(key), INSTALL_KEY_NODE, commit=False, table_name="management_agent_install_keys"
        ):
            totals["install_key_nodes_written"] += 1

        for dg_id in sorted(set(matched_dgs)):
            wrote = _emit_edge_shared(
                ctx,
                src_id=key_id,
                src_type=INSTALL_KEY_NODE,
                dst_id=dg_id,
                dst_type=DYNAMIC_GROUP_NODE,
                edge_type=EDGE_INSTALL_KEY_CAN_JOIN_DG,
                edge_properties=_build_edge_properties(
                    edge_category=EDGE_CATEGORY_GROUP_MEMBERSHIP,
                    edge_inner_properties={
                        "attack": "management_agent_install_key_registration",
                        "evaluated_resource_type": "managementagent",
                        "evaluated_location": key_comp,
                        "is_unlimited": _truthy(key.get("is_unlimited")),
                        "time_expires": str(key.get("time_expires") or ""),
                        "created_by_principal_id": str(key.get("created_by_principal_id") or ""),
                        "note": (
                            "Holder of this install key can register a rogue management agent "
                            "(from any host, on- or off-OCI) into this compartment; the agent "
                            "matches this dynamic group and inherits its IAM policy grants."
                        ),
                    },
                ),
                commit=False,
                on_conflict="update",
                dedupe=True,
            )
            if wrote:
                totals["edges_written"] += 1

    if auto_commit:
        ctx.commit()
    _dlog(debug, "install_key_dg: done", **totals)
    return totals
