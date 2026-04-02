import unittest

from ocinferno.modules.opengraph.utilities.helpers.iam_conditionals import (
    BoolTri,
    EvalContext,
    StatementConditionalsEngine,
)


class _Session:
    def __init__(self, tables):
        self._tables = tables

    def get_resource_fields(self, table_name, where_conditions=None, columns=None):
        rows = list(self._tables.get(table_name, []))
        if not where_conditions:
            return rows
        out = []
        for r in rows:
            ok = True
            for k, v in where_conditions.items():
                if r.get(k) != v:
                    ok = False
                    break
            if ok:
                out.append(r)
        return out


class _Ctx:
    pass


class TestIamConditionalsRequestOperation(unittest.TestCase):
    def setUp(self):
        self.engine = StatementConditionalsEngine(ctx=_Ctx(), session=_Session({}), debug=False)

    def test_request_operation_scopes_permissions_by_service(self):
        ctx = EvalContext(
            subjects=[],
            verbs_l=set(),
            perms={"DESKTOP_WORKREQUEST_INSPECT"},
            resource_tokens_l={"desktop-pool"},
            location_ids=set(),
        )
        delta = self.engine._h_request_operation(
            var="request.operation",
            op="eq",
            rhs_val="ListWorkRequests",
            rhs_type="",
            ctx=ctx,
        )
        self.assertEqual(delta.tri, BoolTri.TRUE)
        self.assertEqual(delta.trimmed_permissions, {"DESKTOP_WORKREQUEST_INSPECT"})

    def test_request_operation_incompatible_service_scope_is_false(self):
        ctx = EvalContext(
            subjects=[],
            verbs_l=set(),
            perms={"INSTANCE_INSPECT"},
            resource_tokens_l={"instances"},
            location_ids=set(),
        )
        delta = self.engine._h_request_operation(
            var="request.operation",
            op="eq",
            rhs_val="ListWorkRequests",
            rhs_type="",
            ctx=ctx,
        )
        self.assertEqual(delta.tri, BoolTri.FALSE)
        self.assertIn("not compatible with statement resource scope", delta.reason)


class TestIamConditionalsOrmHandlers(unittest.TestCase):
    def setUp(self):
        tables = {
            "resource_manager_jobs": [
                {"id": "job1", "compartment_id": "c1", "operation": "PLAN"},
            ],
            "resource_manager_stacks": [
                {"id": "stack1", "compartment_id": "c1", "display_name": "s1"},
            ],
        }
        self.engine = StatementConditionalsEngine(ctx=_Ctx(), session=_Session(tables), debug=False)

    def test_target_job_operation_accepts_orm_jobs_alias_token(self):
        ctx = EvalContext(
            subjects=[],
            verbs_l=set(),
            perms=set(),
            resource_tokens_l={"orm_jobs"},
            location_ids={"c1"},
        )
        delta = self.engine._h_target_job_operation(op="eq", rhs_val="PLAN", ctx=ctx)
        self.assertEqual(delta.tri, BoolTri.TRUE)
        self.assertIn("job1", set(delta.matched_resource_node_ids or set()))

    def test_target_stack_id_accepts_orm_stacks_alias_token(self):
        ctx = EvalContext(
            subjects=[],
            verbs_l=set(),
            perms=set(),
            resource_tokens_l={"orm_stacks"},
            location_ids={"c1"},
        )
        delta = self.engine._h_target_stack_id(op="eq", rhs_val="stack1", ctx=ctx)
        self.assertEqual(delta.tri, BoolTri.TRUE)
        self.assertIn("stack1", set(delta.matched_resource_node_ids or set()))


class TestIamConditionalsSupportedVariables(unittest.TestCase):
    def setUp(self):
        self.engine = StatementConditionalsEngine(ctx=_Ctx(), session=_Session({}), debug=False)

    def test_supported_but_unimplemented_var_is_classified_correctly(self):
        clause = {
            "lhs": {"type": "attribute", "value": "target.image.id"},
            "op": "eq",
            "rhs": {"type": "string", "value": "ocid1.image.oc1..example"},
        }
        ctx = EvalContext(
            subjects=[],
            verbs_l=set(),
            perms=set(),
            resource_tokens_l={"images"},
            location_ids={"c1"},
        )
        _delta, _sup, _uns, reasons = self.engine._eval_clause_delta(clause=clause, ctx=ctx)
        joined = " | ".join(reasons)
        self.assertIn("known-but-unimplemented var: target.image.id", joined)


class TestIamConditionalsLoggingHandlers(unittest.TestCase):
    def test_target_loggroup_id_uses_logging_scope_tokens(self):
        tables = {
            "logging_log_groups": [
                {"id": "lg1", "compartment_id": "c1", "display_name": "g1"},
            ],
        }
        engine = StatementConditionalsEngine(ctx=_Ctx(), session=_Session(tables), debug=False)
        ctx = EvalContext(
            subjects=[],
            verbs_l=set(),
            perms=set(),
            resource_tokens_l={"log-groups"},
            location_ids={"c1"},
        )
        delta = engine._h_target_loggroup_id(op="eq", rhs_val="lg1", ctx=ctx)
        self.assertEqual(delta.tri, BoolTri.TRUE)
        self.assertIn("lg1", set(delta.matched_resource_node_ids or set()))


class TestIamConditionalsTargetCompartmentId(unittest.TestCase):
    def setUp(self):
        self.engine = StatementConditionalsEngine(ctx=_Ctx(), session=_Session({}), debug=False)

    def test_target_compartment_id_eq_includes_descendants(self):
        ctx = EvalContext(
            subjects=[],
            verbs_l=set(),
            perms=set(),
            resource_tokens_l={"users"},
            location_ids={"root", "app", "dev", "other"},
            children_by_compartment_id={
                "root": {"app", "other"},
                "app": {"dev"},
                "dev": set(),
                "other": set(),
            },
        )
        delta = self.engine._h_target_compartment_id(op="eq", rhs_val="app", ctx=ctx)
        self.assertEqual(delta.tri, BoolTri.TRUE)
        self.assertEqual(set(delta.allowed_location_ids or set()), {"app", "dev"})

    def test_target_compartment_id_neq_keeps_descendants(self):
        ctx = EvalContext(
            subjects=[],
            verbs_l=set(),
            perms=set(),
            resource_tokens_l={"users"},
            location_ids={"app", "dev", "other"},
            children_by_compartment_id={
                "app": {"dev"},
                "dev": set(),
                "other": set(),
            },
        )
        delta = self.engine._h_target_compartment_id(op="neq", rhs_val="app", ctx=ctx)
        self.assertEqual(delta.tri, BoolTri.TRUE)
        self.assertEqual(set(delta.allowed_location_ids or set()), {"dev", "other"})


if __name__ == "__main__":
    unittest.main()
