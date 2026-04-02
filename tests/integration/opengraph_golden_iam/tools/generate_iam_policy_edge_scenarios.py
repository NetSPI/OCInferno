from __future__ import annotations

import copy
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from ocinferno.modules.opengraph.utilities.helpers.constants import DEFAULT_ALLOW_EDGE_RULES, PRINCIPAL_GROUPS

SCENARIO_ROOT = Path(__file__).resolve().parents[1] / "scenarios"
GOLDEN_ROOT = Path(__file__).resolve().parents[1] / "golden"

TENANCY = "ocid1.tenancy.oc1..goldtenant"
ROOT_COMP = "ocid1.compartment.oc1..root"
APP_COMP = "ocid1.compartment.oc1..app"
DEV_COMP = "ocid1.compartment.oc1..dev"

GROUP_ID = "ocid1.group.oc1..securityadmins"
GROUP_NAME = "SecurityAdmins"
DG_ID = "ocid1.dynamicgroup.oc1..webservers"
DG_NAME = "WebServers"

ALICE_ID = "ocid1.user.oc1..alice"
BOB_ID = "ocid1.user.oc1..bob"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(text or "").strip().lower()).strip("_") or "rule"


def _dump_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _compartment_rows() -> list[dict]:
    return [
        {
            "compartment_id": TENANCY,
            "parent_compartment_id": "",
            "name": "tenant",
            "display_name": "Tenant",
            "lifecycle_state": "ACTIVE",
        },
        {
            "compartment_id": ROOT_COMP,
            "parent_compartment_id": TENANCY,
            "name": "root-team",
            "display_name": "RootTeam",
            "lifecycle_state": "ACTIVE",
            "defined_tags": {"team": {"env": "shared"}},
        },
        {
            "compartment_id": APP_COMP,
            "parent_compartment_id": ROOT_COMP,
            "name": "app-team",
            "display_name": "AppTeam",
            "lifecycle_state": "ACTIVE",
            "defined_tags": {"team": {"env": "prod"}},
        },
        {
            "compartment_id": DEV_COMP,
            "parent_compartment_id": ROOT_COMP,
            "name": "dev-team",
            "display_name": "DevTeam",
            "lifecycle_state": "ACTIVE",
            "defined_tags": {"team": {"env": "dev"}},
        },
    ]


def _group_rows() -> list[dict]:
    return [
        {
            "id": GROUP_ID,
            "name": GROUP_NAME,
            "compartment_id": ROOT_COMP,
            "lifecycle_state": "ACTIVE",
        }
    ]


def _dynamic_group_rows() -> list[dict]:
    return [
        {
            "id": DG_ID,
            "name": DG_NAME,
            "matching_rule": "Any {resource.type = 'instance'}",
            "description": "Web server resource principals",
            "compartment_id": ROOT_COMP,
            "lifecycle_state": "ACTIVE",
        }
    ]


def _user_rows() -> list[dict]:
    return [
        {
            "id": ALICE_ID,
            "name": "alice",
            "email": "alice@example.com",
            "compartment_id": APP_COMP,
            "lifecycle_state": "ACTIVE",
        },
        {
            "id": BOB_ID,
            "name": "bob",
            "email": "bob@example.com",
            "compartment_id": DEV_COMP,
            "lifecycle_state": "ACTIVE",
        },
    ]


def _instance_rows() -> list[dict]:
    return [
        {
            "id": "ocid1.instance.oc1..insta",
            "display_name": "app-a",
            "compartment_id": APP_COMP,
            "lifecycle_state": "RUNNING",
        },
        {
            "id": "ocid1.instance.oc1..instb",
            "display_name": "dev-b",
            "compartment_id": DEV_COMP,
            "lifecycle_state": "RUNNING",
        },
    ]


def _policy_row(*, policy_id: str, policy_name: str, compartment_id: str) -> dict:
    return {
        "id": policy_id,
        "name": policy_name,
        "compartment_id": compartment_id,
        "lifecycle_state": "ACTIVE",
    }


def _subject_group() -> dict:
    return {"type": "group", "values": [{"ocid": GROUP_ID, "name": GROUP_NAME}]}


def _subject_dynamic_group() -> dict:
    return {"type": "dynamic-group", "values": [{"ocid": DG_ID, "name": DG_NAME}]}


def _subject_any_user() -> dict:
    return {"type": "any-user", "values": []}


def _subject_text(subject_type: str) -> str:
    if subject_type == "group":
        return f"group {GROUP_NAME}"
    if subject_type == "dynamic-group":
        return f"dynamic-group {DG_NAME}"
    if subject_type == "any-user":
        return "any-user"
    return "group SecurityAdmins"


def _subject_parsed(subject_type: str) -> dict:
    if subject_type == "group":
        return _subject_group()
    if subject_type == "dynamic-group":
        return _subject_dynamic_group()
    if subject_type == "any-user":
        return _subject_any_user()
    return _subject_group()


def _sorted_tokens(rule) -> list[str]:
    tokens = sorted({str(t) for t in (rule.match_resource_tokens or ()) if str(t)})
    if tokens:
        return tokens
    dst = str(rule.destination_token_to_make or "").strip()
    return [dst] if dst else ["all-resources"]


def _resource_text(tokens: list[str]) -> str:
    if len(tokens) == 1:
        return tokens[0]
    return "{" + ", ".join(tokens) + "}"


def _action_phrase_for_statement(rule) -> str:
    min_verbs = sorted({str(v) for v in (rule.min_verbs or ()) if str(v)})
    any_verbs = sorted({str(v) for v in (rule.any_verbs or ()) if str(v)})
    min_perms = sorted({str(p) for p in (rule.min_permissions or ()) if str(p)})
    any_perms = sorted({str(p) for p in (rule.any_permissions or ()) if str(p)})

    if min_verbs:
        return min_verbs[0]
    if any_verbs:
        return any_verbs[0]
    perms = min_perms or any_perms[:1]
    if perms:
        return "{" + ", ".join(perms) + "}"
    return "manage"


def _actions_for_parsed_statement(rule) -> dict:
    min_verbs = sorted({str(v) for v in (rule.min_verbs or ()) if str(v)})
    any_verbs = sorted({str(v) for v in (rule.any_verbs or ()) if str(v)})
    min_perms = sorted({str(p) for p in (rule.min_permissions or ()) if str(p)})
    any_perms = sorted({str(p) for p in (rule.any_permissions or ()) if str(p)})

    if min_verbs:
        return {"type": "verbs", "values": min_verbs}
    if any_verbs:
        # Pick one deterministic verb that satisfies the rule.
        return {"type": "verbs", "values": [any_verbs[0]]}

    perms = list(min_perms)
    if not perms and any_perms:
        perms = [any_perms[0]]
    if perms:
        return {"type": "permissions", "values": perms}
    return {"type": "verbs", "values": ["manage"]}


def _allow_statement(
    *,
    subject: dict,
    actions: dict,
    resources: list[str],
    resources_type: str,
    location_type: str,
    location_values: list[str],
    conditions: dict | None = None,
) -> dict:
    return {
        "kind": "allow",
        "subject": copy.deepcopy(subject),
        "actions": copy.deepcopy(actions),
        "resources": {"type": str(resources_type), "values": list(resources)},
        "location": {"type": location_type, "values": list(location_values)},
        "conditions": copy.deepcopy(conditions or {}),
    }


def _clause(var: str, op: str, rhs: str) -> dict:
    return {
        "lhs": {"type": "attribute", "value": var},
        "op": op,
        "rhs": {"type": "string", "value": rhs},
    }


@dataclass(slots=True)
class ConditionalSpec:
    name: str
    subject_type: str
    text_suffix: str
    conditions: dict


CONDITIONAL_SPECS = [
    ConditionalSpec(
        name="target.compartment.id",
        subject_type="group",
        text_suffix=f"where target.compartment.id = '{APP_COMP}'",
        conditions={"mode": "all", "clauses": [_clause("target.compartment.id", "eq", APP_COMP)]},
    ),
    ConditionalSpec(
        name="request.user.id",
        subject_type="any-user",
        text_suffix=f"where request.user.id = '{ALICE_ID}'",
        conditions={"mode": "all", "clauses": [_clause("request.user.id", "eq", ALICE_ID)]},
    ),
    ConditionalSpec(
        name="request.utc-timestamp",
        subject_type="group",
        text_suffix="where request.utc-timestamp before '2099-01-01T00:00:00Z'",
        conditions={"mode": "all", "clauses": [_clause("request.utc-timestamp", "before", "2099-01-01T00:00:00Z")]},
    ),
    ConditionalSpec(
        name="target.resource.compartment.tag",
        subject_type="group",
        text_suffix="where target.resource.compartment.tag.team.env = 'prod'",
        conditions={"mode": "all", "clauses": [_clause("target.resource.compartment.tag.team.env", "eq", "prod")]},
    ),
]


def _rule_allows_subject(rule, subject_type: str) -> bool:
    key = str(getattr(rule, "principal_group_key", "") or "")
    allowed = PRINCIPAL_GROUPS.get(key, set(PRINCIPAL_GROUPS.get("principals-all", set())))
    return subject_type in set(allowed or ())


def _seed_tables_for_policy(
    *,
    policy_compartment_id: str,
    policy_id: str,
    policy_name: str,
    include_group_subject: bool,
    include_dynamic_group_subject: bool,
    rule_resource_tokens: list[str],
    force_users: bool = False,
) -> dict:
    tokens = {str(t) for t in (rule_resource_tokens or ())}
    out = {
        "resource_compartments": _compartment_rows(),
        "identity_policies": [
            _policy_row(
                policy_id=policy_id,
                policy_name=policy_name,
                compartment_id=policy_compartment_id,
            )
        ],
    }

    need_groups = include_group_subject or ("groups" in tokens)
    need_dynamic_groups = include_dynamic_group_subject or ("dynamic-groups" in tokens)
    need_users = force_users or ("users" in tokens)
    need_instances = "instances" in tokens

    if need_groups:
        out["identity_groups"] = _group_rows()
    if need_dynamic_groups:
        out["identity_dynamic_groups"] = _dynamic_group_rows()
    if need_users:
        out["identity_users"] = _user_rows()
    if need_instances:
        out["compute_instances"] = _instance_rows()
    return out


def _fixture(
    *,
    workspace_id: int,
    module_args: list[str],
    seed_tables: dict,
    parsed_policy_statement: dict | None = None,
    description: str,
) -> dict:
    parser_stubs = {}
    if parsed_policy_statement is not None:
        parser_stubs["policy_statements"] = [copy.deepcopy(parsed_policy_statement)]

    return {
        "description": description,
        "workspace": {
            "workspace_id": workspace_id,
            "workspace_name": "opengraph-golden",
            "tenancy_ocid": TENANCY,
            "compartment_ocid": ROOT_COMP,
        },
        "module_args": list(module_args),
        "inputs": {
            "seed_tables": copy.deepcopy(seed_tables),
            "parser_stubs": parser_stubs,
        },
    }


def _write_scenario(*, rel_dir: str, statement: str, fixture: dict) -> None:
    out_dir = SCENARIO_ROOT / rel_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "statement.txt").write_text(statement.strip() + "\n", encoding="utf-8")
    _dump_json(out_dir / "fixture.json", fixture)


def _location_name(location_id: str) -> str:
    if location_id == APP_COMP:
        return "AppTeam"
    if location_id == ROOT_COMP:
        return "RootTeam"
    return "AppTeam"


def _statement_text_for_rule(*, rule, subject_type: str, location_id: str, condition_suffix: str = "") -> str:
    tokens = _sorted_tokens(rule)
    resource_phrase = _resource_text(tokens)
    action_phrase = _action_phrase_for_statement(rule)
    loc_name = _location_name(location_id)
    text = (
        f"Allow {_subject_text(subject_type)} to {action_phrase} "
        f"{resource_phrase} in compartment {loc_name}"
    )
    if condition_suffix:
        text += " " + condition_suffix.strip()
    return text


def _parsed_statement_for_rule(
    *,
    rule,
    subject_type: str,
    location_id: str,
    conditions: dict | None = None,
) -> dict:
    tokens = _sorted_tokens(rule)
    resources_type = "all-resources" if tokens == ["all-resources"] else "specific"
    resources_values = [] if resources_type == "all-resources" else tokens
    return _allow_statement(
        subject=_subject_parsed(subject_type),
        actions=_actions_for_parsed_statement(rule),
        resources=resources_values,
        resources_type=resources_type,
        location_type="compartment_id",
        location_values=[location_id],
        conditions=conditions,
    )


def main() -> None:
    if SCENARIO_ROOT.exists():
        shutil.rmtree(SCENARIO_ROOT)
    SCENARIO_ROOT.mkdir(parents=True, exist_ok=True)

    if GOLDEN_ROOT.exists():
        shutil.rmtree(GOLDEN_ROOT)
    GOLDEN_ROOT.mkdir(parents=True, exist_ok=True)

    workspace = 10000
    generated = 0

    # ------------------------------------------------------------------
    # Base group case (human-readable non-policy membership statement)
    # ------------------------------------------------------------------
    workspace += 1
    _write_scenario(
        rel_dir="base_group_cases/idd_user_in_group",
        statement="Identity domain user alice is a member of group BlueTeam",
        fixture=_fixture(
            workspace_id=workspace,
            module_args=["--reset", "--groups"],
            seed_tables={
                "resource_compartments": _compartment_rows(),
                "identity_domains": [
                    {
                        "id": "ocid1.domain.oc1..golddomain",
                        "display_name": "GoldenDomain",
                        "compartment_id": ROOT_COMP,
                    }
                ],
                "identity_domain_users": [
                    {
                        "id": "scim-user-alice",
                        "ocid": ALICE_ID,
                        "user_name": "alice",
                        "display_name": "alice",
                        "domain_ocid": "ocid1.domain.oc1..golddomain",
                        "compartment_ocid": APP_COMP,
                        "tenancy_ocid": TENANCY,
                        "groups": json.dumps(
                            [
                                {
                                    "ocid": "ocid1.group.oc1..blue",
                                    "display_name": "BlueTeam",
                                    "membership_ocid": "ocid1.groupmembership.oc1..blue1",
                                }
                            ]
                        ),
                    }
                ],
                "identity_domain_groups": [
                    {
                        "id": "scim-group-blue",
                        "ocid": "ocid1.group.oc1..blue",
                        "display_name": "BlueTeam",
                        "domain_ocid": "ocid1.domain.oc1..golddomain",
                        "compartment_ocid": APP_COMP,
                        "tenancy_ocid": TENANCY,
                        "users": "[]",
                    }
                ],
            },
            parsed_policy_statement=None,
            description="Identity Domain baseline user-to-group membership emission.",
        ),
    )
    generated += 1

    # ------------------------------------------------------------------
    # Base dynamic-group principal case
    # ------------------------------------------------------------------
    workspace += 1
    dg_rule = DEFAULT_ALLOW_EDGE_RULES[1]  # instances + manage
    dg_statement = "Allow dynamic-group WebServers to manage instances in compartment AppTeam"
    _write_scenario(
        rel_dir="base_dg_cases/dynamic_group_manage_instances",
        statement=dg_statement,
        fixture=_fixture(
            workspace_id=workspace,
            module_args=["--reset"],
            seed_tables=_seed_tables_for_policy(
                policy_compartment_id=APP_COMP,
                policy_id="ocid1.policy.oc1..base_dg_manage_instances",
                policy_name="BaseDynamicGroupPolicy",
                include_group_subject=False,
                include_dynamic_group_subject=True,
                rule_resource_tokens=_sorted_tokens(dg_rule),
            ),
            parsed_policy_statement=_parsed_statement_for_rule(
                rule=dg_rule,
                subject_type="dynamic-group",
                location_id=APP_COMP,
                conditions={},
            ),
            description="Direct dynamic-group principal to instances edge behavior.",
        ),
    )
    generated += 1

    # ------------------------------------------------------------------
    # Full edge matrix: base direct + inherited for every default allow rule.
    # ------------------------------------------------------------------
    for idx, rule in enumerate(DEFAULT_ALLOW_EDGE_RULES):
        edge_slug = _slug(rule.edge_label)
        rule_slug = f"rule_{idx:02d}_{edge_slug}"

        base_subject_type = "group"
        if not _rule_allows_subject(rule, base_subject_type):
            base_subject_type = "any-user"

        # Direct
        workspace += 1
        direct_statement = _statement_text_for_rule(
            rule=rule,
            subject_type=base_subject_type,
            location_id=APP_COMP,
        )
        _write_scenario(
            rel_dir=f"base_policy_matrix_cases/direct/{rule_slug}",
            statement=direct_statement,
            fixture=_fixture(
                workspace_id=workspace,
                module_args=["--reset"],
                seed_tables=_seed_tables_for_policy(
                    policy_compartment_id=APP_COMP,
                    policy_id=f"ocid1.policy.oc1..base_direct_{idx:02d}_{edge_slug}",
                    policy_name=f"BaseDirect_{idx:02d}_{rule.edge_label}",
                    include_group_subject=(base_subject_type == "group"),
                    include_dynamic_group_subject=(base_subject_type == "dynamic-group"),
                    rule_resource_tokens=_sorted_tokens(rule),
                    force_users=(base_subject_type == "any-user"),
                ),
                parsed_policy_statement=_parsed_statement_for_rule(
                    rule=rule,
                    subject_type=base_subject_type,
                    location_id=APP_COMP,
                    conditions={},
                ),
                description=f"Base direct rule coverage for {rule.edge_label} (rule {idx:02d}).",
            ),
        )
        generated += 1

        # Inherited
        workspace += 1
        inherited_statement = _statement_text_for_rule(
            rule=rule,
            subject_type=base_subject_type,
            location_id=ROOT_COMP,
        )
        _write_scenario(
            rel_dir=f"base_policy_matrix_cases/inherited/{rule_slug}",
            statement=inherited_statement,
            fixture=_fixture(
                workspace_id=workspace,
                module_args=["--reset", "--expand-inherited"],
                seed_tables=_seed_tables_for_policy(
                    policy_compartment_id=ROOT_COMP,
                    policy_id=f"ocid1.policy.oc1..base_inherited_{idx:02d}_{edge_slug}",
                    policy_name=f"BaseInherited_{idx:02d}_{rule.edge_label}",
                    include_group_subject=(base_subject_type == "group"),
                    include_dynamic_group_subject=(base_subject_type == "dynamic-group"),
                    rule_resource_tokens=_sorted_tokens(rule),
                    force_users=(base_subject_type == "any-user"),
                ),
                parsed_policy_statement=_parsed_statement_for_rule(
                    rule=rule,
                    subject_type=base_subject_type,
                    location_id=ROOT_COMP,
                    conditions={},
                ),
                description=f"Base inherited rule coverage for {rule.edge_label} (rule {idx:02d}).",
            ),
        )
        generated += 1

        # ------------------------------------------------------------------
        # Conditional variants for each conditional type, when subject type is compatible.
        # ------------------------------------------------------------------
        for cond in CONDITIONAL_SPECS:
            if not _rule_allows_subject(rule, cond.subject_type):
                continue

            # Direct conditional
            workspace += 1
            direct_cond_statement = _statement_text_for_rule(
                rule=rule,
                subject_type=cond.subject_type,
                location_id=APP_COMP,
                condition_suffix=cond.text_suffix,
            )
            _write_scenario(
                rel_dir=f"conditionals/{cond.name}/direct/{rule_slug}",
                statement=direct_cond_statement,
                fixture=_fixture(
                    workspace_id=workspace,
                    module_args=["--reset", "--cond-eval"],
                    seed_tables=_seed_tables_for_policy(
                        policy_compartment_id=APP_COMP,
                        policy_id=f"ocid1.policy.oc1..cond_direct_{cond.name}_{idx:02d}_{edge_slug}",
                        policy_name=f"CondDirect_{cond.name}_{idx:02d}_{rule.edge_label}",
                        include_group_subject=(cond.subject_type == "group"),
                        include_dynamic_group_subject=(cond.subject_type == "dynamic-group"),
                        rule_resource_tokens=_sorted_tokens(rule),
                        force_users=(cond.subject_type == "any-user" or cond.name == "request.user.id"),
                    ),
                    parsed_policy_statement=_parsed_statement_for_rule(
                        rule=rule,
                        subject_type=cond.subject_type,
                        location_id=APP_COMP,
                        conditions=cond.conditions,
                    ),
                    description=f"Direct conditional {cond.name} for {rule.edge_label} (rule {idx:02d}).",
                ),
            )
            generated += 1

            # Inherited conditional
            workspace += 1
            inherited_cond_statement = _statement_text_for_rule(
                rule=rule,
                subject_type=cond.subject_type,
                location_id=ROOT_COMP,
                condition_suffix=cond.text_suffix,
            )
            _write_scenario(
                rel_dir=f"conditionals/{cond.name}/inherited/{rule_slug}",
                statement=inherited_cond_statement,
                fixture=_fixture(
                    workspace_id=workspace,
                    module_args=["--reset", "--cond-eval", "--expand-inherited"],
                    seed_tables=_seed_tables_for_policy(
                        policy_compartment_id=ROOT_COMP,
                        policy_id=f"ocid1.policy.oc1..cond_inherited_{cond.name}_{idx:02d}_{edge_slug}",
                        policy_name=f"CondInherited_{cond.name}_{idx:02d}_{rule.edge_label}",
                        include_group_subject=(cond.subject_type == "group"),
                        include_dynamic_group_subject=(cond.subject_type == "dynamic-group"),
                        rule_resource_tokens=_sorted_tokens(rule),
                        force_users=(cond.subject_type == "any-user" or cond.name == "request.user.id"),
                    ),
                    parsed_policy_statement=_parsed_statement_for_rule(
                        rule=rule,
                        subject_type=cond.subject_type,
                        location_id=ROOT_COMP,
                        conditions=cond.conditions,
                    ),
                    description=f"Inherited conditional {cond.name} for {rule.edge_label} (rule {idx:02d}).",
                ),
            )
            generated += 1

    # ------------------------------------------------------------------
    # Mixed conditional examples (still statement-first)
    # ------------------------------------------------------------------
    workspace += 1
    mixed_rule = DEFAULT_ALLOW_EDGE_RULES[2]  # manage users
    nested_stmt = (
        f"Allow any-user to manage users in compartment RootTeam where any {{ "
        f"request.user.id = '{ALICE_ID}', "
        f"all {{ target.compartment.id = '{APP_COMP}', request.utc-timestamp before '2099-01-01T00:00:00Z' }} }}"
    )
    nested_cond = {
        "type": "group",
        "mode": "any",
        "items": [
            {"type": "clause", "node": _clause("request.user.id", "eq", ALICE_ID)},
            {
                "type": "group",
                "mode": "all",
                "items": [
                    {"type": "clause", "node": _clause("target.compartment.id", "eq", APP_COMP)},
                    {"type": "clause", "node": _clause("request.utc-timestamp", "before", "2099-01-01T00:00:00Z")},
                ],
            },
        ],
    }
    _write_scenario(
        rel_dir="mixed_conditionals/nested_any_all/rule_02_oci_manage_users",
        statement=nested_stmt,
        fixture=_fixture(
            workspace_id=workspace,
            module_args=["--reset", "--cond-eval", "--expand-inherited"],
            seed_tables=_seed_tables_for_policy(
                policy_compartment_id=ROOT_COMP,
                policy_id="ocid1.policy.oc1..mixed_nested_any_all",
                policy_name="MixedNestedAnyAllPolicy",
                include_group_subject=False,
                include_dynamic_group_subject=False,
                rule_resource_tokens=_sorted_tokens(mixed_rule),
                force_users=True,
            ),
            parsed_policy_statement=_parsed_statement_for_rule(
                rule=mixed_rule,
                subject_type="any-user",
                location_id=ROOT_COMP,
                conditions=nested_cond,
            ),
            description="Nested any/all conditional semantics with compatible variables.",
        ),
    )
    generated += 1

    workspace += 1
    multi_stmt = (
        f"Allow any-user to manage users in compartment RootTeam "
        f"where request.user.id = '{ALICE_ID}' and target.resource.compartment.tag.team.env = 'prod'"
    )
    _write_scenario(
        rel_dir="mixed_conditionals/multi_filter_cases/rule_02_oci_manage_users",
        statement=multi_stmt,
        fixture=_fixture(
            workspace_id=workspace,
            module_args=["--reset", "--cond-eval", "--expand-inherited"],
            seed_tables=_seed_tables_for_policy(
                policy_compartment_id=ROOT_COMP,
                policy_id="ocid1.policy.oc1..mixed_multi_filter",
                policy_name="MixedMultiFilterPolicy",
                include_group_subject=False,
                include_dynamic_group_subject=False,
                rule_resource_tokens=_sorted_tokens(mixed_rule),
                force_users=True,
            ),
            parsed_policy_statement=_parsed_statement_for_rule(
                rule=mixed_rule,
                subject_type="any-user",
                location_id=ROOT_COMP,
                conditions={
                    "mode": "all",
                    "clauses": [
                        _clause("request.user.id", "eq", ALICE_ID),
                        _clause("target.resource.compartment.tag.team.env", "eq", "prod"),
                    ],
                },
            ),
            description="Multiple compatible conditional filters combined in one statement.",
        ),
    )
    generated += 1

    print(f"generated {generated} statement-driven scenarios under {SCENARIO_ROOT}")
    print("golden directory was reset; regenerate via OCINFERNO_REGEN_GOLDEN=1 pytest tests/integration/opengraph_golden_iam -q")


if __name__ == "__main__":
    main()
