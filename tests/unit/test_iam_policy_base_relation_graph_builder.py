"""Tests for ocinferno/modules/opengraph/utilities/iam_policy_base_relation_graph_builder.py's
subject-filtering and location-token-resolution helpers.

``_filter_known_subjects`` must restore service-kind subjects when include_all=True.
Otherwise service subjects ("Allow service <name> to ...") are dropped
unconditionally with no escape hatch, making the caller's
`skip_service_subject_edges = (s.subj_type_l == "service" and not s.include_all)`
flag check downstream dead in practice -- the candidate subject list would already
be emptied by the time it runs, regardless of --include-all.

``_location_tokens``'s `compartment_name` branch must drop an unresolvable name
instead of using the raw literal name string as a pseudo location-id. Otherwise
two unrelated policies in different parts of the tenancy that both reference an
unresolvable, identically-named compartment (e.g. "ProdEnv") would collapse onto
the same graph node (`instances@ProdEnv`), merging distinct attack-path scopes --
matching the sibling `compartment` (structured-id) branch, which already
correctly drops unresolved entries instead of guessing.
"""
from __future__ import annotations

import pytest

from ocinferno.modules.opengraph.utilities.iam_policy_base_relation_graph_builder import (
    _filter_known_subjects,
    _location_tokens,
)


class _SubjectCtx:
    idd_user_ocids = set()
    classic_user_ocids = set()
    idd_group_ocids = set()
    classic_group_ocids = set()
    idd_dynamic_group_ocids = set()
    classic_dynamic_group_ocids = set()


@pytest.mark.parametrize(
    "subjects, include_all, expected_kept",
    [
        pytest.param(
            [{"id": "objectstorage-us-phoenix-1", "kind": "service", "node_type": "OCIPrincipal"}],
            False, False,
            id="service-subject-dropped-by-default",
        ),
        pytest.param(
            [{"id": "objectstorage-us-phoenix-1", "kind": "service", "node_type": "OCIPrincipal"}],
            True, True,
            id="service-subject-restored-with-include-all",
        ),
        pytest.param(
            [{"id": "ANY_USER@loc", "kind": "any-user", "node_type": "OCIAnyUser"}],
            False, True,
            id="any-user-subject-kept-without-include-all",
        ),
        pytest.param(
            [{"id": "ANY_USER@loc", "kind": "any-user", "node_type": "OCIAnyUser"}],
            True, True,
            id="any-user-subject-kept-with-include-all",
        ),
        pytest.param(
            [{"id": "ocid1.user.oc1..unknown", "kind": "user", "node_type": "OCIUser"}],
            True, False,
            id="unknown-user-still-dropped-even-with-include-all",
        ),
    ],
)
def test_filter_known_subjects(subjects, include_all, expected_kept):
    result = _filter_known_subjects(_SubjectCtx(), subjects, include_all=include_all)
    assert result == (subjects if expected_kept else [])


class _LocationCtx:
    def __init__(self, *, names_by_id=None, descendants=None):
        self.compartment_names_l_by_id = names_by_id or {}
        self._descendants = descendants or {}

    def descendants_including_self(self, cid):
        return self._descendants.get(cid, (cid,))


def test_unresolvable_compartment_name_drops_entry_not_raw_name():
    st = {"location": {"type": "compartment_name", "values": ["NoSuchCompartment"]}}
    ctx = _LocationCtx(names_by_id={"root": {"other-compartment"}}, descendants={"root": ("root",)})

    result = _location_tokens(ctx, st, "root", "ocid1.tenancy.oc1..tenant", False)

    assert result == []


def test_resolvable_compartment_name_returns_real_ocid():
    st = {"location": {"type": "compartment_name", "values": ["ProdEnv"]}}
    ctx = _LocationCtx(
        names_by_id={"ocid1.compartment.oc1..prod": {"prodenv"}},
        descendants={"root": ("root", "ocid1.compartment.oc1..prod")},
    )

    result = _location_tokens(ctx, st, "root", "ocid1.tenancy.oc1..tenant", False)

    assert result == [("ocid1.compartment.oc1..prod", False)]
