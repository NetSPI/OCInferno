"""DEFAULT_RESOURCE_FAMILIES data integrity: instance-agent-command-execution-family
and instance-agent-command-family must resolve to distinct members. If they
aliased to the same members, a policy scoped to the execution-family token would
get FAMILY_INCLUDES wired to the wrong, less-sensitive resource type (command
definitions, not their per-instance execution/status records)."""
from __future__ import annotations

from ocinferno.modules.opengraph.utilities.helpers.constants import (
    DEFAULT_RESOURCE_FAMILIES,
)


def test_execution_family_resolves_to_executions_not_commands():
    assert set(DEFAULT_RESOURCE_FAMILIES["instance-agent-command-execution-family"]) == {
        "instance-agent-command-executions"
    }


def test_command_family_and_execution_family_are_distinct():
    command_members = set(DEFAULT_RESOURCE_FAMILIES["instance-agent-command-family"])
    execution_members = set(DEFAULT_RESOURCE_FAMILIES["instance-agent-command-execution-family"])
    assert command_members.isdisjoint(execution_members)
