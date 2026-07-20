"""The multi-permission bundle matcher (ALLOW_RULE_DEFS `bundle.requires_all`): an edge
fires only when a principal holds EVERY requirement (each = all permissions on at least
one of its resource tokens) at the same location. Pure core, no graph plumbing."""
from __future__ import annotations

from ocinferno.modules.opengraph.utilities.allowlist_bundle_graph_builder import (
    bundle_rule_matches,
    _requirement_satisfied,
    _load_bundle_rules,
)


def _rule():
    # create-instance-shaped bundle: INSTANCE_CREATE (instances) AND VNIC_ATTACH+VNIC_CREATE
    # (vnics) AND SUBNET_READ (subnets), all at the same location.
    return {
        "requires_all": [
            {"permissions_all": {"INSTANCE_CREATE"}, "resource_tokens": {"instances"}},
            {"permissions_all": {"VNIC_CREATE", "VNIC_ATTACH"}, "resource_tokens": {"vnics"}},
            {"permissions_all": {"SUBNET_READ"}, "resource_tokens": {"subnets"}},
        ]
    }


def test_all_requirements_met_matches():
    perms_by_token = {
        "instances": {"INSTANCE_CREATE"},
        "vnics": {"VNIC_CREATE", "VNIC_ATTACH"},
        "subnets": {"SUBNET_READ", "SUBNET_ATTACH"},
    }
    assert bundle_rule_matches(_rule(), perms_by_token) is True


def test_missing_one_requirement_does_not_match():
    perms_by_token = {
        "instances": {"INSTANCE_CREATE"},
        "vnics": {"VNIC_CREATE"},  # missing VNIC_ATTACH -> requirement unsatisfied
        "subnets": {"SUBNET_READ"},
    }
    assert bundle_rule_matches(_rule(), perms_by_token) is False


def test_requirement_satisfied_across_any_of_its_tokens():
    # permissions_all on ANY one of the requirement's resource_tokens satisfies it.
    req = {"permissions_all": {"SECRET_BUNDLE_READ"}, "resource_tokens": {"secret-bundles", "vaults"}}
    assert _requirement_satisfied(req, {"vaults": {"SECRET_BUNDLE_READ"}}) is True
    assert _requirement_satisfied(req, {"other": {"SECRET_BUNDLE_READ"}}) is False


def test_empty_rule_never_matches():
    assert bundle_rule_matches({"requires_all": []}, {"instances": {"INSTANCE_CREATE"}}) is False


def test_no_bundle_rules_defined_by_default():
    # Default ALLOW_RULE_DEFS ships no `bundle` rules -> the build step is a no-op
    # (graph unchanged). Users add bundle rules to enable multi-permission routes.
    assert _load_bundle_rules() == []
