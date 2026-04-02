# Contributing to OCInferno

Thanks for contributing.

This document covers the practical workflow for local development, testing, and pull requests.

## Contribution Types

- Privilege escalation route submissions (OpenGraph edges/pathing).
- Lateral movement route submissions (OpenGraph edges/pathing).
- Bug reports and regressions.
- Feature requests.
- New/updated enum module behavior.
- New/updated config audit checks.
- Test and fixture maintenance.
- Documentation and wiki improvements.

## Ground Rules

- Keep changes focused and easy to review.
- Prefer small PRs over large multi-area refactors.
- Update docs (`README.md` and `wiki/`) when behavior or flags change.
- Add or update tests for behavioral changes.

## Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install .[dev]
```

## Run Tests

Run unit tests (same scope as CI):

```bash
python -m pytest -q -ra tests/unit
```

If you are working on integration behavior, run only the relevant integration tests for your change.

## Python Versions

CI runs unit tests on:

- 3.10
- 3.11
- 3.12

Please avoid introducing version-specific behavior unless guarded and tested.

## Coding Notes

- Keep CLI output stable and readable.
- Avoid adding deprecated aliases unless explicitly requested.
- Preserve existing user-facing command behavior unless the change is intentional and documented.

## Pull Request Checklist

- [ ] Unit tests pass locally.
- [ ] New behavior is covered by tests.
- [ ] Docs updated where needed (`README.md`, `wiki/`).
- [ ] No unrelated formatting or broad refactors mixed into the PR.
- [ ] Changelog/roadmap notes added when relevant.

## Submitting Privilege Escalation or Lateral Movement Routes

Use this process when proposing or implementing new OpenGraph route logic.

1. If this warrants a vulnerable disclosure to OCI themselves, follow these [guidelines](https://www.oracle.com/corporate/security-practices/assurance/vulnerability/reporting/).
2. Open an issue first with a clear route proposal.
3. Include the route category: `privilege-escalation` or `lateral-movement`.
4. Include source and destination node types (what can reach what).
5. Include minimum required permissions/actions and OCI scope requirements.
6. Include a minimal reproducible policy example using obfuscated values.
7. Include why the route is valid and what guardrails prevent false positives.
8. Implement the route in code, favoring existing helpers/rule tables where possible.
9. Add or update tests that prove positive and negative cases.
10. Update OpenGraph golden scenarios/outputs when behavior changes.
11. In the PR, link the issue and summarize the exact edge(s) added/changed.

For OpenGraph route changes, include these artifacts in the PR:

- Updated scenario fixtures/statements under `tests/integration/opengraph_golden_iam/scenarios/` when applicable.
- Updated goldens under `tests/integration/opengraph_golden_iam/golden/` when applicable.
- Unit tests for rule/exclusion behavior under `tests/unit/`.

Recommended validation commands:

```bash
pytest -q tests/unit
pytest -q tests/integration/opengraph_golden_iam
pytest -q tests/integration/opengraph_basic_group_membership
pytest -q tests/integration/opengraph_dynamic_group_membership
```

## Reporting Bugs

When filing issues, include:

- Command used
- Expected behavior
- Actual behavior
- Full error output
- Python version
- OS details

## Submitting Issues

Use issues for all non-trivial submissions before opening a large PR.

- Bug report: include repro steps, expected vs actual, and logs/errors.
- Route correctness report: identify false-positive or false-negative edge behavior and include policy examples.
- Feature request: describe user outcome, not just implementation details.
- Refactor proposal: include risk, expected benefit, and impacted modules.

If you can, include:

- Scope of impact (`enum_all`, specific enum module, OpenGraph, config audit, exports).
- Whether behavior is breaking, additive, or a bug fix.
- Suggested acceptance criteria.

## Other Submission Types

For non-route contributions, use the same quality bar:

- Docs: update `README.md` and `wiki/` pages tied to the behavior.
- Tests only: explain what behavior is now protected and why it matters.
- Enum/config-audit changes: include sample command usage and expected output deltas.
- Performance work: include before/after measurements and test coverage.

## License

By contributing, you agree your contributions are licensed under the project BSD-3-Clause license.
