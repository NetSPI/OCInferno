"""_resource_type_alias_closure/_eval_pred must treat resource-type synonyms as
equivalent regardless of which spelling appears on which side. Oracle Functions
rows (resource_type="fnfunction", from resource_scope_map.json's dg_type) must
satisfy a real dynamic-group matching rule written as `resource.type = 'fnfunc'`
(the actual OCI syntax, per constants.py's DYNAMIC_GROUP_RESOURCE_TYPES) -- a raw
string compare would never match synonyms."""
from __future__ import annotations

import pytest

from ocinferno.modules.opengraph.utilities.helpers.matching_rules_engine import (
    OP_EQ,
    OP_NEQ,
    VAR_RESOURCE_TYPE,
    Pred,
    _eval_pred,
    _resource_type_alias_closure,
)


def test_alias_closure_symmetric_from_any_member():
    from_key = _resource_type_alias_closure("fn-function")
    from_value = _resource_type_alias_closure("fnfunction")
    assert from_key == from_value == {"fn-function", "fnfunction", "fnfunc", "fnfnc"}


def test_alias_closure_unrelated_type_has_no_functions_aliases():
    assert _resource_type_alias_closure("computecontainerinstance") == {"computecontainerinstance"}


def test_alias_closure_empty_input():
    assert _resource_type_alias_closure("") == set()
    assert _resource_type_alias_closure(None) == set()


@pytest.mark.parametrize(
    "op, rhs, expected",
    [
        pytest.param(OP_EQ, "fnfunc", True, id="matches-across-synonyms"),
        pytest.param(OP_EQ, ["instance", "fnfunc"], True, id="matches-list-rhs-across-synonyms"),
        pytest.param(OP_NEQ, "fnfunc", False, id="neq-respects-synonyms"),
        pytest.param(OP_EQ, "instance", False, id="no-match-for-unrelated-type"),
    ],
)
def test_eval_pred_resource_type(op, rhs, expected):
    row = {"resource_type": "fnfunction"}
    pred = Pred(var=VAR_RESOURCE_TYPE, op=op, rhs=rhs, tag=None)
    assert _eval_pred(pred=pred, row=row) is expected
