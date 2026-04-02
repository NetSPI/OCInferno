# Test Suite Guide

This repository keeps OpenGraph validation statement-first.

## Primary OpenGraph Golden Suite

- `tests/integration/opengraph_golden_iam/scenarios/`: human-readable `statement.txt` inputs
- `tests/integration/opengraph_golden_iam/golden/`: checked-in JSON expected outputs
- `tests/integration/opengraph_golden_iam/framework.py`: runner + normalization + compare logic
- `tests/integration/opengraph_golden_iam/tools/generate_iam_policy_edge_scenarios.py`: matrix generator

Additional focused OpenGraph integration suites:

- `tests/integration/opengraph_basic_group_membership/`
- `tests/integration/opengraph_dynamic_group_membership/`

## Enumeration Unit Tests

- `tests/enum_modules/` contains one unit test file per `enum_*` module.
- Naming is 1:1 for quick ownership lookup (for example `test_enum_comp.py`, `test_enum_identity.py`).
- Each module test validates:
  - all module CLI flags can be parsed
  - module `run_module(...)` executes with offline stubs (no OCI/network calls)

## Scenario Organization

- `base_group_cases/`
- `base_dg_cases/`
- `base_policy_matrix_cases/direct/`
- `base_policy_matrix_cases/inherited/`
- `conditionals/<conditional_type>/direct/`
- `conditionals/<conditional_type>/inherited/`
- `mixed_conditionals/`

## Useful Commands

```bash
# Regenerate matrix scenarios (rewrites scenarios + clears goldens)
PYTHONPATH=. python tests/integration/opengraph_golden_iam/tools/generate_iam_policy_edge_scenarios.py

# Rebuild checked-in goldens from current engine behavior
OCINFERNO_REGEN_GOLDEN=1 pytest tests/integration/opengraph_golden_iam -q

# Verify checked-in goldens match implementation
pytest tests/integration/opengraph_golden_iam -q
```
