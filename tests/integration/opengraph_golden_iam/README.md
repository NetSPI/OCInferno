# OpenGraph IAM Golden Scenario Framework

This directory contains the primary statement-first golden test system for OpenGraph.

## Layout

- `scenarios/<case>/statement.txt`: primary human-readable scenario input
- `scenarios/<case>/fixture.json`: secondary supporting environment (seed rows, parser stubs, module args)
- `golden/<case>.json`: checked-in normalized OpenGraph export
- `framework.py`: scenario loader, runner, canonicalizer, golden diff logic
- `test_opengraph_golden_scenarios.py`: pytest discovery + execution

## Scenario format

Each scenario is a folder with:

1. `statement.txt` (required)
2. `fixture.json` (required)

Example `statement.txt`:

```text
Allow group SecurityAdmins to manage users in compartment AppTeam
```

Example `fixture.json`:

```json
{
  "description": "Direct policy scope baseline.",
  "workspace": {
    "workspace_id": 9801,
    "workspace_name": "opengraph-golden",
    "tenancy_ocid": "ocid1.tenancy.oc1..goldtenant",
    "compartment_ocid": "ocid1.compartment.oc1..root"
  },
  "module_args": ["--reset"],
  "inputs": {
    "seed_tables": {
      "resource_compartments": [],
      "identity_groups": [],
      "identity_policies": []
    },
    "parser_stubs": {
      "policy_statements": [
        {
          "kind": "allow",
          "subject": { "type": "group", "values": [] },
          "actions": { "type": "verbs", "values": ["manage"] },
          "resources": { "type": "specific", "values": ["users"] },
          "location": { "type": "compartment_id", "values": ["ocid1.compartment.oc1..app"] },
          "conditions": {}
        }
      ]
    }
  }
}
```

Notes:

- `statement.txt` is the primary visible input and should remain easy to read.
- `fixture.json` should stay minimal and only contain test-support data.
- If `identity_policies[*].statements` is omitted, the framework injects lines from `statement.txt`.

## Folder organization

Scenarios are grouped for readability:

- `base_group_cases/`
- `base_dg_cases/`
- `base_policy_matrix_cases/direct/`
- `base_policy_matrix_cases/inherited/`
- `conditionals/<conditional_name>/direct/`
- `conditionals/<conditional_name>/inherited/`
- `mixed_conditionals/nested_any_all/`
- `mixed_conditionals/multi_filter_cases/`

`base_policy_matrix_cases/*` and `conditionals/*` are generated from
`DEFAULT_ALLOW_EDGE_RULES`, so every default edge rule has:

- base direct + inherited scenarios
- conditional direct + inherited scenarios per conditional type when subject-compatible

Current generated matrix size:

- 27 base direct edge cases
- 27 base inherited edge cases
- 27 direct + 27 inherited cases per conditional type
- 274 total statement-driven scenarios (including base group/dynamic-group and mixed conditional examples)

## Golden behavior

- Actual output is normalized before compare (stable key/order handling + sorted nodes/edges).
- Goldens are pretty-printed JSON and checked in.
- Unified diff is shown on mismatch.

## Regenerating goldens

```bash
OCINFERNO_REGEN_GOLDEN=1 pytest tests/integration/opengraph_golden_iam -q
```

## Regenerating matrix scenarios

```bash
PYTHONPATH=. python tests/integration/opengraph_golden_iam/tools/generate_iam_policy_edge_scenarios.py
```

This script rewrites:

- `scenarios/`
- `golden/` (emptied so tests can regenerate fresh JSON)
