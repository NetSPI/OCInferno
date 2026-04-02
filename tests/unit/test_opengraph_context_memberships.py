from __future__ import annotations

from ocinferno.modules.opengraph.utilities.helpers.context import OfflineIamContext


class _FakeSession:
    workspace_id = 1

    def __init__(self):
        self._tables = {
            "identity_user_group_memberships": [
                {"id": "classic-m1", "user_id": "ocid1.user.oc1..u1", "group_id": "ocid1.group.oc1..g1"},
            ],
            "identity_domain_user_group_memberships": [
                {"id": "idd-m1", "user_id": "ocid1.user.oc1..u2", "group_id": "ocid1.group.oc1..g2"},
            ],
        }

    def get_resource_fields(self, table_name, where_conditions=None, columns=None):
        return list(self._tables.get(table_name, []))


def test_context_loads_classic_and_idd_membership_tables():
    ctx = OfflineIamContext(session=_FakeSession(), lazy=True)
    ctx.load_for_steps({"groups"})

    membership_ids = {str(r.get("id")) for r in ctx.memberships}
    assert membership_ids == {"classic-m1", "idd-m1"}
