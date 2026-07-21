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


class TestIamConditionalsTargetResourceCompartmentTag(unittest.TestCase):
    """_compartment_tag_poststep must propagate an unresolved upstream delta (e.g.
    _match_resources_across_tables returning unresolved=True for empty
    ctx.location_ids) instead of collapsing it to a hard FALSE -- an AND-combinator
    needs "cannot determine" here, not "definitely no match", or it silently
    prunes an edge that should have surfaced as unresolved."""

    def setUp(self):
        self.engine = StatementConditionalsEngine(ctx=_Ctx(), session=_Session({}), debug=False)

    def test_empty_location_ids_propagates_unresolved_not_hard_false(self):
        ctx = EvalContext(
            subjects=[],
            verbs_l=set(),
            perms=set(),
            resource_tokens_l=set(),
            location_ids=set(),
        )
        delta = self.engine._h_target_resource_compartment_tag(
            var="target.resource.compartment.tag.team.env",
            op="eq",
            rhs_val="prod",
            ctx=ctx,
        )
        self.assertEqual(delta.tri, BoolTri.UNKNOWN)
        self.assertTrue(delta.unresolved)

    def test_no_matching_compartments_is_still_a_resolved_false(self):
        """A genuinely-resolved 'nothing matched' (non-empty location_ids, tag just
        doesn't match anything) must remain a hard FALSE, not get reclassified as
        unresolved -- only a truly unresolved upstream delta should propagate."""
        session = _Session(
            {
                "resource_compartments": [
                    {
                        "id": "ocid1.compartment.oc1..devcomp",
                        "defined_tags": '{"team": {"env": "dev"}}',
                    }
                ],
            }
        )
        engine = StatementConditionalsEngine(ctx=_Ctx(), session=session, debug=False)
        ctx = EvalContext(
            subjects=[],
            verbs_l=set(),
            perms=set(),
            resource_tokens_l=set(),
            location_ids={"ocid1.compartment.oc1..devcomp"},
            children_by_compartment_id={"ocid1.compartment.oc1..devcomp": set()},
        )
        delta = engine._h_target_resource_compartment_tag(
            var="target.resource.compartment.tag.team.env",
            op="eq",
            rhs_val="prod",
            ctx=ctx,
        )
        self.assertEqual(delta.tri, BoolTri.FALSE)
        self.assertFalse(delta.unresolved)


class TestIamConditionalsTargetColumnAdditions(unittest.TestCase):
    """New target.* handlers added from the OCI conditional-variable gap survey:
    target.bucket.name, target.cluster.id, target.nodepool.id,
    target.virtualnodepool.id, target.display-name (network firewall), target.run.id
    (data flow)."""

    def _ctx(self, *, tokens, locs):
        return EvalContext(
            subjects=[],
            verbs_l={"manage"},
            perms=set(),
            resource_tokens_l=set(tokens),
            location_ids=set(locs),
        )

    def test_target_bucket_name_matches(self):
        session = _Session(
            {
                "object_storage_buckets": [
                    {"id": "ocid1.bucket.oc1..b1", "name": "prod-bucket", "compartment_id": "ocid1.compartment.oc1..app"},
                    {"id": "ocid1.bucket.oc1..b2", "name": "dev-bucket", "compartment_id": "ocid1.compartment.oc1..app"},
                ]
            }
        )
        engine = StatementConditionalsEngine(ctx=_Ctx(), session=session, debug=False)
        ctx = self._ctx(tokens={"buckets"}, locs={"ocid1.compartment.oc1..app"})
        delta = engine._handlers["target.bucket.name"](
            var="target.bucket.name", op="eq", rhs_val="prod-bucket", rhs_type="string", ctx=ctx, st=None
        )
        self.assertEqual(delta.tri, BoolTri.TRUE)
        self.assertEqual(delta.matched_resource_node_ids, {"ocid1.bucket.oc1..b1"})

    def test_target_bucket_name_no_match_is_false(self):
        session = _Session({"object_storage_buckets": [{"id": "ocid1.bucket.oc1..b1", "name": "prod-bucket", "compartment_id": "ocid1.compartment.oc1..app"}]})
        engine = StatementConditionalsEngine(ctx=_Ctx(), session=session, debug=False)
        ctx = self._ctx(tokens={"buckets"}, locs={"ocid1.compartment.oc1..app"})
        delta = engine._handlers["target.bucket.name"](
            var="target.bucket.name", op="eq", rhs_val="no-such-bucket", rhs_type="string", ctx=ctx, st=None
        )
        self.assertEqual(delta.tri, BoolTri.FALSE)

    def test_target_bucket_name_not_applicable_to_other_resource_type(self):
        session = _Session({"object_storage_buckets": [{"id": "ocid1.bucket.oc1..b1", "name": "prod-bucket", "compartment_id": "ocid1.compartment.oc1..app"}]})
        engine = StatementConditionalsEngine(ctx=_Ctx(), session=session, debug=False)
        ctx = self._ctx(tokens={"instances"}, locs={"ocid1.compartment.oc1..app"})
        delta = engine._handlers["target.bucket.name"](
            var="target.bucket.name", op="eq", rhs_val="prod-bucket", rhs_type="string", ctx=ctx, st=None
        )
        self.assertEqual(delta.tri, BoolTri.FALSE)
        self.assertIn("resource-token mismatch", delta.reason)

    def test_target_cluster_id_matches_and_family_scoped_statement_still_applies(self):
        session = _Session({"containerengine_clusters": [{"id": "ocid1.cluster.oc1..c1", "name": "prod", "compartment_id": "ocid1.compartment.oc1..app"}]})
        engine = StatementConditionalsEngine(ctx=_Ctx(), session=session, debug=False)
        for tokens in ({"clusters"}, {"cluster-family"}):
            ctx = self._ctx(tokens=tokens, locs={"ocid1.compartment.oc1..app"})
            delta = engine._handlers["target.cluster.id"](
                var="target.cluster.id", op="eq", rhs_val="ocid1.cluster.oc1..c1", rhs_type="string", ctx=ctx, st=None
            )
            self.assertEqual(delta.tri, BoolTri.TRUE, f"failed for tokens={tokens}")
            self.assertEqual(delta.matched_resource_node_ids, {"ocid1.cluster.oc1..c1"})

    def test_target_nodepool_id_matches(self):
        session = _Session({"containerengine_node_pools": [{"id": "ocid1.nodepool.oc1..np1", "name": "pool1", "compartment_id": "ocid1.compartment.oc1..app"}]})
        engine = StatementConditionalsEngine(ctx=_Ctx(), session=session, debug=False)
        ctx = self._ctx(tokens={"cluster-node-pools"}, locs={"ocid1.compartment.oc1..app"})
        delta = engine._handlers["target.nodepool.id"](
            var="target.nodepool.id", op="eq", rhs_val="ocid1.nodepool.oc1..np1", rhs_type="string", ctx=ctx, st=None
        )
        self.assertEqual(delta.tri, BoolTri.TRUE)
        self.assertEqual(delta.matched_resource_node_ids, {"ocid1.nodepool.oc1..np1"})

    def test_target_virtualnodepool_id_matches(self):
        session = _Session({"containerengine_virtual_node_pools": [{"id": "ocid1.virtualnodepool.oc1..vnp1", "display_name": "vpool1", "compartment_id": "ocid1.compartment.oc1..app"}]})
        engine = StatementConditionalsEngine(ctx=_Ctx(), session=session, debug=False)
        ctx = self._ctx(tokens={"cluster-virtualnode-pools"}, locs={"ocid1.compartment.oc1..app"})
        delta = engine._handlers["target.virtualnodepool.id"](
            var="target.virtualnodepool.id", op="eq", rhs_val="ocid1.virtualnodepool.oc1..vnp1", rhs_type="string", ctx=ctx, st=None
        )
        self.assertEqual(delta.tri, BoolTri.TRUE)
        self.assertEqual(delta.matched_resource_node_ids, {"ocid1.virtualnodepool.oc1..vnp1"})

    def test_target_display_name_matches_network_firewall_policy(self):
        session = _Session({"network_firewall_policies": [{"id": "ocid1.networkfirewallpolicy.oc1..fw1", "display_name": "MyFirewallPolicy", "compartment_id": "ocid1.compartment.oc1..app"}]})
        engine = StatementConditionalsEngine(ctx=_Ctx(), session=session, debug=False)
        ctx = self._ctx(tokens={"firewallpolicies"}, locs={"ocid1.compartment.oc1..app"})
        delta = engine._handlers["target.display-name"](
            var="target.display-name", op="eq", rhs_val="MyFirewallPolicy", rhs_type="string", ctx=ctx, st=None
        )
        self.assertEqual(delta.tri, BoolTri.TRUE)
        self.assertEqual(delta.matched_resource_node_ids, {"ocid1.networkfirewallpolicy.oc1..fw1"})

    def test_target_run_id_matches_dataflow_run(self):
        session = _Session({"dataflow_runs": [{"id": "ocid1.dataflowrun.oc1..r1", "display_name": "nightly-etl", "compartment_id": "ocid1.compartment.oc1..app"}]})
        engine = StatementConditionalsEngine(ctx=_Ctx(), session=session, debug=False)
        ctx = self._ctx(tokens={"dataflow-run"}, locs={"ocid1.compartment.oc1..app"})
        delta = engine._handlers["target.run.id"](
            var="target.run.id", op="eq", rhs_val="ocid1.dataflowrun.oc1..r1", rhs_type="string", ctx=ctx, st=None
        )
        self.assertEqual(delta.tri, BoolTri.TRUE)
        self.assertEqual(delta.matched_resource_node_ids, {"ocid1.dataflowrun.oc1..r1"})


if __name__ == "__main__":
    unittest.main()
