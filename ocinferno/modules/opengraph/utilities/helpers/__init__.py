"""
OpenGraph helper facade.

Module split:
- core_helpers.py: generic value/JSON/string normalization + edge/node property helpers.
- graph_utils.py: OpenGraph state helpers, scope-node helpers, RESOURCE_SCOPE_MAP table/spec helpers.

This file re-exports the stable helper surface used by OpenGraph builders.
"""

from ocinferno.modules.opengraph.utilities.helpers.core_helpers import (  # noqa: F401
    EDGE_CATEGORY_GROUP_MEMBERSHIP,
    EDGE_CATEGORY_PERMISSION,
    EDGE_CATEGORY_RESOURCE,
    as_json_text,
    build_edge_properties,
    dlog,
    edge_row_with_flattened_properties,
    flatten_edge_properties,
    infer_edge_category,
    is_empty_value,
    json_list,
    json_load,
    l,
    merge_edge_properties,
    merge_list,
    merge_statement_entries,
    merge_value,
    node_properties_from_row,
    normalize_edge_properties,
    ocid_type,
    parse_defined_tag_var,
    s,
    scope_token_loc,
    short_hash,
    short_text,
    statement_policy_ids,
    statement_stable_key,
    statement_texts,
    synthetic_principal_id,
)
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import (  # noqa: F401
    build_table_token_indexes,
    canonical_resource_row_from_spec,
    ensure_edge,
    ensure_new_compute_instance_candidate_node,
    ensure_new_rpst_resource_candidate_node,
    ensure_node,
    ensure_principal_node,
    ensure_scope_node,
    ensure_scoped_node,
    family_keys_l,
    family_map,
    family_members_l,
    get_og_state,
    is_family,
    iter_scope_specs,
    row_get,
    scope_node_type,
    select_scope_specs,
    table_specs_for_token,
)
