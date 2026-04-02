# context.py
from __future__ import annotations

import hashlib
import json

from ocinferno.modules.opengraph.utilities.helpers.core_helpers import (
    dlog as _dlog,
    json_load as _json_load,
    l as _l,
    merge_edge_properties as _merge_edge_properties,
    merge_value as _merge_value,
    node_properties_from_row as _node_properties_from_row_shared,
    s as _s,
)
from ocinferno.modules.opengraph.utilities.helpers.graph_utils import (
    canonical_resource_row_from_spec as _canonical_resource_row_from_spec,
    select_scope_specs as _select_scope_specs,
    table_specs_for_token as _table_specs_for_token,
)
from ocinferno.modules.opengraph.utilities.helpers.constants import (
    NODE_TYPE_OCI_DYNAMIC_GROUP,
    NODE_TYPE_OCI_GENERIC_RESOURCE,
    NODE_TYPE_OCI_USER,
    RESOURCE_SCOPE_MAP,
)


def _base_name(display_name):
    """
    Normalize principal display to "base name" for matching:
      - "Domain/Scott" -> "Scott"
      - "Scott" -> "Scott"
    """
    if not isinstance(display_name, str):
        return ""
    s = display_name.strip()
    if not s:
        return ""
    if "/" in s:
        return s.split("/", 1)[1].strip()
    return s


# --------------------------------------------------------------------------------------
# OfflineIamContext
# --------------------------------------------------------------------------------------
class OfflineIamContext:
    """
    One-time-loaded + normalized view of IAM-ish data used by offline builders.

    Simplified model:
      - We load both IDD and classic tables.
      - We write nodes as we see them (builders can create both).
      - IAM statements can optionally infer/attach identity domains to classic principals.

    Domain-cast behavior (CLI: --domain-cast):
      - Stored on `default_domain_arg`.
      - We do NOT mint a synthetic domain for the cast value until the very end of __init__.
        (So any "natural" domain discovery from identity_domains happens first.)
    """

    def __init__(
        self,
        session=None,
        workspace_id=None,
        debug=False,
        default_domain=None,
        lazy=False,
        iam_config=None,
    ):
        self.session = session
        self.workspace_id = workspace_id if workspace_id is not None else getattr(session, "workspace_id", None)
        self.debug = bool(debug)
        self._lazy_mode = bool(lazy)
        self._loaded_steps = set()
        self._tables_loaded = set()

        self.iam_config = {
            # defaults (can be overridden by CLI before calling IAM builder)
            "expand_inheritance": False,
            "conditional_evaluation": False,
            "include_all": False,
            "parse_define_subs": True,
            "infer_domain": False,
            "drop_time_based_no_effective_permissions": False,
            "drop_all_no_effective_permissions": False,
        }
        if isinstance(iam_config, dict):
            for key, value in iam_config.items():
                if key in self.iam_config:
                    self.iam_config[key] = value

        self.iam_stats_last = {}
        self.iam_stats_total = {}

        # Domain hint (CLI --infer-domain [DOMAIN]) used as inference hint.
        self.default_domain_arg = default_domain or None  # may be None; finalized at end
        self.default_domain_ocid = ""
        self.domain_cast_ocid = ""

        # principal tables
        self.idd_users = []
        self.idd_groups = []
        self.idd_dynamic_groups = []
        self.domains = []

        self.classic_users = []
        self.classic_groups = []
        self.classic_dynamic_groups = []
        self.memberships = []

        # group/dynamic-group membership caches (resolved by helpers)
        self.group_member_mapping_cache: dict[str, set[str]] = {}            # group_id -> [user_id,...]
        self.dynamic_group_member_mapping_cache: dict[str, dict[str, dict]] = {}  # dg_id -> {member_id: row}

        # compartments
        self.compartments = []

        # sets / indexes
        self.idd_user_ocids = set()
        self.idd_group_ocids = set()
        self.idd_dynamic_group_ocids = set()

        self.classic_user_ocids = set()
        self.classic_group_ocids = set()
        self.classic_dynamic_group_ocids = set()

        self.domain_name_by_ocid = {}
        self.domain_ocid_by_name_l = {}
        self.synthetic_domain_ctr = 0

        self.compartment_name_by_id = {}
        self.compartment_names_l_by_id = {}

        # principal resolution indexes
        self.idd_group_by_domain_and_name = {}
        self.idd_dg_by_domain_and_name = {}
        self.classic_group_by_name = {}
        self.classic_dg_by_name = {}

        # compartment graph + tenant inference
        self.parent_by_compartment_id = {}
        self.all_parents_by_compartment_id = {}
        self.children_by_compartment_id = {}
        self.descendants_cache = {}
        self.tenant_by_compartment_id = {}

        # micro caches
        self._node_cache = {}  # (node_id,node_type) -> row dict
        self._edge_cache = {}  # (src,edge_type,dst) -> row dict

        self.stats = {}
        if not self._lazy_mode:
            self.load_for_steps({"all"})

    # -------------------------------------------------------------------------
    # OpenGraph dedupe/merge state (shared across builders)
    # -------------------------------------------------------------------------
    def refresh_opengraph_state(self, *, force=False):
        """
        Load latest OpenGraph node IDs and edge keys from DB into ctx.og_state.

        State shape:
        self.og_state = {
            "existing_nodes_set": set(node_id),
            "existing_edges_set": set((src, edge, dst)),
            "existing_node_types": {node_id: node_type},
        }
        """
        st = getattr(self, "og_state", None)
        if not isinstance(st, dict) or force:
            st = {}
        st.setdefault("existing_nodes_set", set())
        st.setdefault("existing_edges_set", set())
        st.setdefault("existing_node_types", {})

        if force or not st["existing_nodes_set"] and not st["existing_edges_set"]:
            st["existing_nodes_set"].clear()
            st["existing_edges_set"].clear()
            st["existing_node_types"].clear()
        elif st["existing_nodes_set"] and st["existing_edges_set"] and (
            st["existing_node_types"] or not st["existing_nodes_set"]
        ):
            # Already hydrated for this run.
            self.og_state = st
            return st

        session = getattr(self, "session", None)
        if not session:
            self.og_state = st
            return st

        nodes = session.get_resource_fields("opengraph_nodes", columns=["node_id", "node_type"]) or []
        edges = session.get_resource_fields(
            "opengraph_edges",
            columns=["source_id", "edge_type", "destination_id"],
        ) or []

        en = st["existing_nodes_set"]
        es = st["existing_edges_set"]
        nt = st["existing_node_types"]

        for r in nodes:
            if isinstance(r, dict):
                nid = r.get("node_id")
                if nid:
                    en.add(nid)
                    ntype = r.get("node_type")
                    if isinstance(ntype, str) and ntype:
                        nt[nid] = ntype

        for r in edges:
            if not isinstance(r, dict):
                continue
            k = (r.get("source_id"), r.get("edge_type"), r.get("destination_id"))
            if k[0] and k[1] and k[2]:
                es.add(k)

        self.og_state = st
        return st


    # -------------------------------------------------------------------------
    # IAM stats helpers
    # -------------------------------------------------------------------------
    def record_iam_stats(self, stats):
        """
        Save last-run IAM stats and optionally accumulate numeric counters.
        """
        if not isinstance(stats, dict):
            return False

        self.iam_stats_last = dict(stats)

        total = self.iam_stats_total if isinstance(getattr(self, "iam_stats_total", None), dict) else {}
        for k, v in stats.items():
            if isinstance(v, int):
                total[k] = int(total.get(k, 0)) + v
        self.iam_stats_total = total
        return True

    # -------------------------------------------------------------------------
    # DB helpers
    # -------------------------------------------------------------------------
    def commit(self):
        try:
            if hasattr(self.session, "commit"):
                self.session.commit()
        except Exception:
            pass

    def _og_existing_nodes_set(self):
        st = getattr(self, "og_state", None)
        if not isinstance(st, dict):
            return None
        s = st.get("existing_nodes_set")
        return s if isinstance(s, set) else None

    def _og_existing_node_types(self):
        st = getattr(self, "og_state", None)
        if not isinstance(st, dict):
            return None
        m = st.get("existing_node_types")
        return m if isinstance(m, dict) else None

    def _og_existing_edges_set(self):
        st = getattr(self, "og_state", None)
        if not isinstance(st, dict):
            return None
        s = st.get("existing_edges_set")
        return s if isinstance(s, set) else None

    # -------------------------------------------------------------------------
    # Loads + dedupe
    # -------------------------------------------------------------------------
    def _load_tables(self, table_names=None):
        s = self.session

        def _rows(name):
            return [x for x in (s.get_resource_fields(name) or []) if isinstance(x, dict)]

        wanted = set(table_names or [])
        load_all = not wanted

        def _load_into(table, attr):
            if table in self._tables_loaded:
                return
            if not load_all and table not in wanted:
                return
            setattr(self, attr, _rows(table))
            self._tables_loaded.add(table)

        def _load_memberships() -> None:
            classic_table = "identity_user_group_memberships"
            idd_table = "identity_domain_user_group_memberships"
            if classic_table in self._tables_loaded and idd_table in self._tables_loaded:
                return

            want_classic = load_all or classic_table in wanted
            want_idd = load_all or idd_table in wanted
            if not (want_classic or want_idd):
                return

            merged = []
            if want_classic:
                merged.extend(_rows(classic_table))
                self._tables_loaded.add(classic_table)
            if want_idd:
                merged.extend(_rows(idd_table))
                self._tables_loaded.add(idd_table)
            self.memberships = merged

        _load_into("identity_domain_users", "idd_users")
        _load_into("identity_domain_groups", "idd_groups")
        _load_into("identity_domain_dynamic_groups", "idd_dynamic_groups")
        _load_into("identity_domains", "domains")
        _load_into("identity_users", "classic_users")
        _load_into("identity_groups", "classic_groups")
        _load_into("identity_dynamic_groups", "classic_dynamic_groups")
        _load_memberships()
        _load_into("resource_compartments", "compartments")

        self.idd_user_ocids = {u.get("ocid") for u in self.idd_users if isinstance(u.get("ocid"), str) and u.get("ocid")}
        self.idd_group_ocids = {g.get("ocid") for g in self.idd_groups if isinstance(g.get("ocid"), str) and g.get("ocid")}
        self.idd_dynamic_group_ocids = {
            g.get("ocid") for g in self.idd_dynamic_groups if isinstance(g.get("ocid"), str) and g.get("ocid")
        }

    def _finalize_loaded_state(self):
        self._build_domain_map()

        # Always ensure Default exists logically
        self.default_domain_ocid = self.get_or_create_domain_ocid("Default")

        self._dedupe_classic_vs_idd()
        self._build_principal_indexes()
        self._build_compartment_graph_all()
        self._build_compartment_name_index()

        if not (isinstance(self.default_domain_arg, str) and self.default_domain_arg.strip()):
            self.default_domain_arg = "Default"
        self.domain_cast_ocid = self.get_or_create_domain_ocid(self.default_domain_arg)

        self.stats = {
            "default_domain_ocid": self.default_domain_ocid,
            "domain_cast_arg": self.default_domain_arg,
            "domain_cast_ocid": self.domain_cast_ocid,
            "idd_users": len(self.idd_users),
            "idd_groups": len(self.idd_groups),
            "idd_dynamic_groups": len(self.idd_dynamic_groups),
            "classic_users": len(self.classic_users),
            "classic_groups": len(self.classic_groups),
            "classic_dynamic_groups": len(self.classic_dynamic_groups),
            "memberships": len(self.memberships),
            "compartments": len(self.compartments),
        }

    def load_for_steps(self, steps=None):
        """
        Lazy-loader entrypoint used by OpenGraph pipeline.
        """
        step_set = {str(s) for s in (steps or set()) if s}
        if "all" in step_set:
            self._load_tables()
            self._finalize_loaded_state()
            self._loaded_steps |= {"all"}
            return

        tables = set()
        if step_set & {"groups", "iam", "identity_domains", "resource_scope", "iam_derived"}:
            tables |= {
                "identity_domain_users",
                "identity_domain_groups",
                "identity_users",
                "identity_groups",
                "identity_user_group_memberships",
                "identity_domain_user_group_memberships",
            }
        if step_set & {"dynamic_groups", "iam", "resource_scope", "iam_derived", "identity_domains"}:
            tables |= {
                "identity_domain_dynamic_groups",
                "identity_dynamic_groups",
            }
        if step_set & {"identity_domains", "iam"}:
            tables |= {"identity_domains"}
        if step_set & {"iam", "resource_scope", "iam_derived", "groups", "dynamic_groups", "identity_domains"}:
            tables |= {"resource_compartments"}

        if not tables:
            # Safe default for unknown combinations.
            self._load_tables()
        else:
            self._load_tables(table_names=tables)
        self._finalize_loaded_state()
        self._loaded_steps |= step_set

    def _dedupe_classic_vs_idd(self):
        # classic uses "id", idd uses "ocid"
        #
        # IMPORTANT:
        #   We dedupe only principal seed tables here (classic users/groups/dynamic groups).
        #   We intentionally DO NOT prune/alter self.memberships. Membership rows remain
        #   available for group-membership graph Phase B, where endpoint mode is resolved
        #   against the queued principal cache.
        self.classic_users = [
            u for u in self.classic_users
            if isinstance(u.get("id"), str) and u.get("id") and u.get("id") not in self.idd_user_ocids
        ]
        self.classic_groups = [
            g for g in self.classic_groups
            if isinstance(g.get("id"), str) and g.get("id") and g.get("id") not in self.idd_group_ocids
        ]
        self.classic_dynamic_groups = [
            g for g in self.classic_dynamic_groups
            if isinstance(g.get("id"), str) and g.get("id") and g.get("id") not in self.idd_dynamic_group_ocids
        ]

        self.classic_user_ocids = {u.get("id") for u in self.classic_users if isinstance(u.get("id"), str) and u.get("id")}
        self.classic_group_ocids = {g.get("id") for g in self.classic_groups if isinstance(g.get("id"), str) and g.get("id")}
        self.classic_dynamic_group_ocids = {
            g.get("id") for g in self.classic_dynamic_groups if isinstance(g.get("id"), str) and g.get("id")
        }

    # -------------------------------------------------------------------------
    # Domain map + synthetic domains
    # -------------------------------------------------------------------------
    def _build_domain_map(self):
        self.domain_name_by_ocid = {}
        self.domain_ocid_by_name_l = {}

        for d in self.domains:
            did = d.get("id")
            if not (isinstance(did, str) and did):
                continue
            name = d.get("display_name") or d.get("name") or "Default"
            if not isinstance(name, str) or not name:
                name = "Default"
            self.domain_name_by_ocid[did] = name
            self.domain_ocid_by_name_l[name.lower()] = did

    def _synthetic_domain_ocid(self, name_or_seed):
        h = hashlib.sha1(str(name_or_seed).encode("utf-8")).hexdigest()[:12]
        return f"synthetic:domain:{h}"

    def get_or_create_domain_ocid(self, domain_arg):
        """
        Accept:
          - None/"" => ""
          - ocid1.* => return it
          - name => lookup; if missing, mint synthetic ocid and remember it
        """
        if not (isinstance(domain_arg, str) and domain_arg.strip()):
            return ""
        v = domain_arg.strip()
        if v.startswith("ocid1."):
            self.domain_name_by_ocid.setdefault(v, v)
            return v

        key = v.lower()
        oc = self.domain_ocid_by_name_l.get(key)
        if oc:
            return oc

        syn_ocid = self._synthetic_domain_ocid(v)
        self.domain_ocid_by_name_l[key] = syn_ocid
        self.domain_name_by_ocid[syn_ocid] = v
        _dlog(self.debug, "domain: minted synthetic domain ocid", name=v, ocid=syn_ocid)
        return syn_ocid

    def get_or_create_domain_simple_name(self, dom_ocid):
        """
        If we only have an OCID (maybe synthetic) but no friendly name, mint one.
        """
        existing = self.domain_name_by_ocid.get(dom_ocid)
        if isinstance(existing, str) and existing:
            return existing
        self.synthetic_domain_ctr += 1
        syn = f"SYNDOMAIN_{self.synthetic_domain_ctr}"
        self.domain_name_by_ocid[dom_ocid] = syn
        self.domain_ocid_by_name_l[syn.lower()] = dom_ocid
        _dlog(self.debug, "domain: minted synthetic simple name", domain_ocid=dom_ocid, simple=syn)
        return syn

    # -------------------------------------------------------------------------
    # Compartment names
    # -------------------------------------------------------------------------
    def _build_compartment_name_index(self):
        self.compartment_name_by_id.clear()
        self.compartment_names_l_by_id.clear()

        for r in self.compartments or []:
            cid = r.get("compartment_id")
            if not isinstance(cid, str) or not cid:
                continue

            nm = r.get("name")
            dn = r.get("display_name")
            display = dn if isinstance(dn, str) and dn else nm
            if isinstance(display, str) and display:
                self.compartment_name_by_id[cid] = display

            names = set()
            if isinstance(nm, str) and nm:
                names.add(nm.lower())
            if isinstance(dn, str) and dn:
                names.add(dn.lower())
            if names:
                self.compartment_names_l_by_id[cid] = names

    def resolve_compartment_id_by_name_near_policy(self, *, policy_compartment_id, target_name):
        tgt = (target_name or "").lower()
        if not tgt:
            return ""
        start = policy_compartment_id
        if not start:
            return ""

        candidates = [start]
        candidates.extend(self.all_parents_by_compartment_id.get(start, []) or [])
        for cid in candidates:
            names = self.compartment_names_l_by_id.get(cid)
            if names and tgt in names:
                return cid
        return ""

    # -------------------------------------------------------------------------
    # Principal resolution indexes
    # -------------------------------------------------------------------------
    def _build_principal_indexes(self):
        self.idd_group_by_domain_and_name.clear()
        self.idd_dg_by_domain_and_name.clear()
        self.classic_group_by_name.clear()
        self.classic_dg_by_name.clear()

        for g in self.idd_groups:
            dom = g.get("domain_ocid")
            ocid = g.get("ocid")
            if not (isinstance(dom, str) and dom and isinstance(ocid, str) and ocid):
                continue
            name = (g.get("display_name") or g.get("name") or "").lower()
            if name:
                self.idd_group_by_domain_and_name[(dom, name)] = ocid

        for g in self.idd_dynamic_groups:
            dom = g.get("domain_ocid")
            ocid = g.get("ocid")
            if not (isinstance(dom, str) and dom and isinstance(ocid, str) and ocid):
                continue
            name = (g.get("display_name") or g.get("name") or "").lower()
            if name:
                self.idd_dg_by_domain_and_name[(dom, name)] = ocid

        for g in self.classic_groups:
            ocid = g.get("id")
            if not (isinstance(ocid, str) and ocid):
                continue
            name = (g.get("name") or "").lower()
            if name:
                self.classic_group_by_name[name] = ocid

        for g in self.classic_dynamic_groups:
            ocid = g.get("id")
            if not (isinstance(ocid, str) and ocid):
                continue
            name = (g.get("name") or "").lower()
            if name:
                self.classic_dg_by_name[name] = ocid

    # -------------------------------------------------------------------------
    # Compartment graph + tenant mapping
    # -------------------------------------------------------------------------
    def _synthetic_tenant_for_component_root(self, root):
        h = hashlib.sha1(str(root).encode("utf-8")).hexdigest()[:12]
        return f"synthetic:tenancy:{h}"

    def _discover_compartments_and_tenant_hints(self):
        discovered = set()
        tenant_hint = {}

        comp_fields = ["compartment_ocid", "compartment_id"]
        tenancy_fields = ["tenancy_ocid", "tenant_id", "tenancy_id"]

        tables = [
            "identity_domain_users",
            "identity_domain_groups",
            "identity_domain_dynamic_groups",
            "identity_domain_app_roles",
            "identity_domain_grants",
        ]

        for table in tables:
            try:
                rows = self.session.get_resource_fields(table, columns=comp_fields + tenancy_fields) or []
            except Exception:
                continue

            for r in rows:
                if not isinstance(r, dict):
                    continue

                cid = ""
                for cf in comp_fields:
                    v = r.get(cf)
                    if isinstance(v, str) and v:
                        cid = v
                        break
                if not cid:
                    continue
                discovered.add(cid)

                ten = ""
                for tf in tenancy_fields:
                    v = r.get(tf)
                    if isinstance(v, str) and v:
                        ten = v
                        break
                if ten and cid not in tenant_hint and ten.startswith("ocid1.tenancy."):
                    tenant_hint[cid] = ten

        return discovered, tenant_hint

    def _build_compartment_parents(self, *, discovered_compartment_ids=None, tenant_hint_by_compartment_id=None, max_hops=64):
        hints = tenant_hint_by_compartment_id or {}
        sentinel = "UNKNOWN_TENANT_VALUE"

        def _is_tenancy(x):
            return isinstance(x, str) and x.startswith("ocid1.tenancy.")

        def _is_syn_ten(x):
            return isinstance(x, str) and x.startswith("synthetic:tenancy:")

        def _is_tenant_token(x):
            return _is_tenancy(x) or _is_syn_ten(x)

        self.parent_by_compartment_id.clear()
        rows = self.session.get_resource_fields("resource_compartments") or []
        for r in rows:
            if not isinstance(r, dict):
                continue
            cid = r.get("compartment_id")
            pid = r.get("parent_compartment_id")
            if not isinstance(cid, str) or not cid:
                continue
            if _is_tenancy(cid):
                self.parent_by_compartment_id.setdefault(cid, "")
                continue
            if isinstance(pid, str) and pid and pid != cid:
                self.parent_by_compartment_id[cid] = pid
            else:
                self.parent_by_compartment_id.setdefault(cid, "")

        for cid in discovered_compartment_ids or set():
            if isinstance(cid, str) and cid:
                self.parent_by_compartment_id.setdefault(cid, "")

        self.all_parents_by_compartment_id.clear()
        for cid in list(self.parent_by_compartment_id.keys()):
            chain = []
            cur = cid
            seen = {cid}
            for _ in range(max_hops):
                parent = self.parent_by_compartment_id.get(cur) or ""
                if not parent or parent in seen:
                    break
                chain.append(parent)
                seen.add(parent)
                cur = parent

            if not chain or not _is_tenant_token(chain[-1]):
                if not chain or chain[-1] != sentinel:
                    chain.append(sentinel)
            self.all_parents_by_compartment_id[cid] = chain

        self.tenant_by_compartment_id.clear()
        for cid in list(self.parent_by_compartment_id.keys()):
            if _is_tenancy(cid):
                self.tenant_by_compartment_id[cid] = cid
                self.all_parents_by_compartment_id[cid] = []
                continue

            chain = list(self.all_parents_by_compartment_id.get(cid) or [])
            tenant = ""

            for p in chain:
                if _is_tenancy(p):
                    tenant = p
                    break

            if not tenant:
                probe = [cid] + (chain[:-1] if chain and chain[-1] == sentinel else chain)
                for x in probe:
                    ten = hints.get(x)
                    if _is_tenancy(ten):
                        tenant = ten
                        break

            if tenant:
                self.tenant_by_compartment_id[cid] = tenant
                if chain and chain[-1] == sentinel:
                    chain[-1] = tenant
                self.all_parents_by_compartment_id[cid] = chain

        for cid in list(self.parent_by_compartment_id.keys()):
            if _is_tenancy(cid):
                continue
            ten = self.tenant_by_compartment_id.get(cid)
            if _is_tenant_token(ten):
                continue

            chain = list(self.all_parents_by_compartment_id.get(cid) or [])
            seed = cid
            if chain:
                if chain[-1] == sentinel and len(chain) >= 2:
                    seed = chain[-2]
                elif chain[-1] != sentinel:
                    seed = chain[-1]
            syn = self._synthetic_tenant_for_component_root(seed)
            self.tenant_by_compartment_id[cid] = syn

            if chain and chain[-1] == sentinel:
                chain[-1] = syn
            elif not chain or chain[-1] != syn:
                chain.append(syn)
            self.all_parents_by_compartment_id[cid] = chain

    def _build_compartment_children_and_descendants(self):
        self.children_by_compartment_id.clear()
        for child, parent in (self.parent_by_compartment_id or {}).items():
            self.children_by_compartment_id.setdefault(child, set())
            if parent and parent != child:
                self.children_by_compartment_id.setdefault(parent, set()).add(child)
        self.descendants_cache.clear()

    def _build_compartment_graph_all(self):
        discovered_ids, tenant_hints = self._discover_compartments_and_tenant_hints()
        self._build_compartment_parents(discovered_compartment_ids=discovered_ids, tenant_hint_by_compartment_id=tenant_hints)
        self._build_compartment_children_and_descendants()

    def tenant_for_compartment(self, cid):
        if not isinstance(cid, str) or not cid:
            return None
        if cid.startswith("ocid1.tenancy."):
            self.tenant_by_compartment_id.setdefault(cid, cid)
            self.parent_by_compartment_id.setdefault(cid, "")
            self.all_parents_by_compartment_id.setdefault(cid, [])
            self.children_by_compartment_id.setdefault(cid, set())
            return cid
        return self.tenant_by_compartment_id.get(cid)

    def descendants_including_self(self, cid):
        """
        Downward expansion: [cid, child1, grandchild, ...]
        Caches results.
        """
        if not isinstance(cid, str) or not cid:
            return ()
        cached = self.descendants_cache.get(cid)
        if isinstance(cached, (list, tuple)):
            return tuple(cached)

        out = []
        stack = [cid]
        seen = set()

        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            out.append(cur)
            kids = self.children_by_compartment_id.get(cur) or set()
            for k in kids:
                if k not in seen:
                    stack.append(k)

        self.descendants_cache[cid] = tuple(out)
        return tuple(out)

    # -------------------------------------------------------------------------
    # Node / edge writers
    # -------------------------------------------------------------------------
    def write_principal_node(self, principal, principal_type, identity_domain=True, commit=True, node_properties=None):
        """
        If identity_domain=True: expects principal["ocid"].
        If identity_domain=False: expects principal["id"].
        """

        if not isinstance(principal, dict):
            return ""

        node_id = principal.get("ocid") if identity_domain else principal.get("id")
        if not node_id:
            return ""

        if identity_domain:
            if principal_type == NODE_TYPE_OCI_USER:
                # Prefer login/user handle for IDD users to avoid collisions when
                # human display names are duplicated across multiple user objects.
                display_name = (
                    principal.get("user_name")
                    or principal.get("name")
                    or principal.get("display_name")
                    or principal.get("display")
                    or node_id
                )
            else:
                display_name = principal.get("name") or principal.get("display_name") or principal.get("display") or node_id
        else:
            display_name = principal.get("name") or principal.get("display_name") or principal.get("display") or node_id

        comp_id = principal.get("compartment_id") or principal.get("compartment_ocid")
        tenant_id = principal.get("tenant_id") or principal.get("tenancy_ocid")

        if node_properties is None:
            if identity_domain:
                props = {
                    "scim_id": principal.get("id"),
                    "domain_ocid": principal.get("domain_ocid") or principal.get("identity_domain_ocid"),
                    "in_identity_domain": True,
                }
                if principal_type == NODE_TYPE_OCI_DYNAMIC_GROUP:
                    props["matching_rule"] = principal.get("matching_rule")
            else:
                props = {
                    "lifecycle_state": principal.get("lifecycle_state"),
                    "in_identity_domain": False,
                }
                if principal_type == NODE_TYPE_OCI_DYNAMIC_GROUP:
                    props["matching_rule"] = principal.get("matching_rule")
                elif principal_type == NODE_TYPE_OCI_USER:
                    props["email"] = principal.get("email")
        else:
            props = dict(node_properties) if isinstance(node_properties, dict) else {}

        # Only prefix IDD names if we actually know the domain ocid on the record
        if identity_domain and isinstance(props, dict):
            dom_ocid = props.get("domain_ocid")
            if isinstance(dom_ocid, str) and dom_ocid:
                domain_simple = self.get_or_create_domain_simple_name(dom_ocid)
                if isinstance(display_name, str) and display_name:
                    display_name = f"{domain_simple}/{_base_name(display_name) or display_name}"

        props["name"] = display_name
        comp = comp_id if isinstance(comp_id, str) and comp_id else (props.get("compartment_id") or props.get("compartment_ocid"))
        if isinstance(comp, str) and comp:
            props["compartment_id"] = comp
        ten = tenant_id if isinstance(tenant_id, str) and tenant_id else (props.get("tenant_id") or props.get("tenancy_ocid"))
        if isinstance(ten, str) and ten:
            props["tenant_id"] = ten

        self.upsert_node(
            node_id=node_id,
            node_type=principal_type,
            node_properties=props,
            commit=commit,
        )
        return node_id

    def write_specific_resource_node(
        self,
        raw_row,
        node_type,
        *,
        commit=True,
        node_properties=None,
        table_name=None,
        resource_token=None,
    ):
        """
        Upsert a concrete resource node from a raw DB row.

        This method performs key extraction/normalization internally (id, display,
        compartment, tenant). Callers can pass raw rows directly; table/token hints
        improve normalization for tables with non-standard id/compartment columns.
        """
        if not isinstance(raw_row, dict):
            return ""

        row = dict(raw_row)
        table = _s(table_name or "")
        token = _l(resource_token or "")

        # If caller provides table/token context, normalize row keys from scope spec
        # so we can consistently resolve id/display/compartment columns.
        if table:
            specs = []
            if token:
                specs = list(
                    _table_specs_for_token(RESOURCE_SCOPE_MAP, token, table)
                    or _select_scope_specs(RESOURCE_SCOPE_MAP, token)
                )
            else:
                specs = [
                    spec
                    for (_k, spec) in (RESOURCE_SCOPE_MAP or {}).items()
                    if isinstance(spec, dict) and _s(spec.get("table")) == table
                ]
            for spec in specs:
                normalized = _canonical_resource_row_from_spec(row, spec)
                if normalized:
                    row = normalized
                    break

        node_id = _s(row.get("id") or row.get("ocid") or row.get("resource_id") or "")
        if not node_id:
            return ""

        display = _s(
            row.get("display_name")
            or row.get("name")
            or row.get("display")
            or row.get("resource_name")
            or node_id
        )
        comp_id = _s(
            row.get("compartment_id")
            or row.get("compartment_ocid")
            or row.get("target_compartment_id")
            or ""
        )
        tenant_id = _s(
            row.get("tenant_id")
            or row.get("tenancy_ocid")
            or row.get("tenancy_id")
            or ""
        )
        if not tenant_id and comp_id:
            tenant_id = _s(self.tenant_for_compartment(comp_id) or "")

        if node_properties is None:
            props = dict(row)
        else:
            props = dict(row)
            if isinstance(node_properties, dict):
                props.update(node_properties)

        props["name"] = display
        if comp_id:
            props["compartment_id"] = comp_id
        if tenant_id:
            props["tenant_id"] = tenant_id

        self.upsert_node(
            node_id=node_id,
            node_type=node_type or NODE_TYPE_OCI_GENERIC_RESOURCE,
            node_properties=props,
            commit=commit,
        )
        return node_id

    def upsert_node(
        self,
        *,
        node_id,
        node_type,
        display_name=None,
        compartment_id=None,
        tenant_id=None,
        node_properties=None,
        commit=True
    ):

        if not node_id or not node_type:
            return node_id

        key = (node_id, node_type)
        existing = self._node_cache.get(key)
        existing_nodes = self._og_existing_nodes_set()

        if existing is None:
            existing = {}
            should_lookup = True
            # Fast path: when OG state is hydrated and node_id is known absent,
            # skip the per-key existence read.
            if isinstance(existing_nodes, set) and node_id not in existing_nodes:
                should_lookup = False
            if should_lookup:
                try:
                    rows = self.session.get_resource_fields(
                        "opengraph_nodes",
                        where_conditions={"node_id": node_id, "node_type": node_type},
                    ) or []
                    if len(rows) == 1 and isinstance(rows[0], dict):
                        existing = rows[0]
                except Exception:
                    existing = {}
            self._node_cache[key] = existing

        existing_found = bool(existing.get("node_id")) if isinstance(existing, dict) else False

        old_props = _node_properties_from_row_shared(existing)

        # Build incoming node_properties first; top-level args are optional overrides.
        new_props = dict(node_properties) if isinstance(node_properties, dict) else {}

        name = display_name if isinstance(display_name, str) and display_name else ""
        if not name:
            alt_name = new_props.get("name") or new_props.get("display_name")
            name = alt_name if isinstance(alt_name, str) else ""

        comp = compartment_id if isinstance(compartment_id, str) and compartment_id else ""
        if not comp:
            alt_comp = new_props.get("compartment_id") or new_props.get("compartment_ocid")
            comp = alt_comp if isinstance(alt_comp, str) else ""

        ten = tenant_id if isinstance(tenant_id, str) and tenant_id else ""
        if not ten:
            alt_ten = new_props.get("tenant_id") or new_props.get("tenancy_ocid")
            ten = alt_ten if isinstance(alt_ten, str) else ""
        if not ten and comp:
            ten = self.tenant_for_compartment(comp) or ""

        if name:
            new_props["name"] = name
        if comp:
            new_props["compartment_id"] = comp
        if ten:
            new_props["tenant_id"] = ten

        final_props = _merge_value(old_props or {}, new_props or {})
        final_props_obj = final_props if final_props else None
        # If any run supplies IDD evidence, keep the node marked as IDD.
        # merge_value preserves old non-empty scalars, so this explicit OR
        # prevents stale false values from blocking true upgrades.
        if isinstance(final_props_obj, dict):
            old_idd = bool((old_props or {}).get("in_identity_domain")) if isinstance(old_props, dict) else False
            new_idd = bool((new_props or {}).get("in_identity_domain")) if isinstance(new_props, dict) else False
            if old_idd or new_idd:
                final_props_obj["in_identity_domain"] = True

        final_props_json = json.dumps(final_props_obj, sort_keys=False) if final_props_obj else None

        if existing_found and old_props == (final_props_obj or {}):
            return node_id

        row = {
            "node_type": node_type,
            "node_id": node_id,
            "node_properties": final_props_json,
        }
        self.session.set_node_fields(row, commit=commit, on_conflict="update")
        self._node_cache[key] = dict(row)
        if isinstance(existing_nodes, set):
            existing_nodes.add(node_id)
        existing_node_types = self._og_existing_node_types()
        if isinstance(existing_node_types, dict):
            existing_node_types[node_id] = node_type
        return node_id

    def write_edge(
        self,
        source_id,
        source_type,
        destination_id,
        destination_type,
        edge_type,
        *,
        edge_properties=None,
        commit=True,
        on_conflict="update",
    ):
        if not source_id or not destination_id or not edge_type:
            return False
        if source_id == destination_id:
            return False

        key = (source_id, edge_type, destination_id)
        existing = self._edge_cache.get(key)
        existing_edges = self._og_existing_edges_set()
        if existing is None:
            existing = {}
            should_lookup = True
            # Fast path: when OG state is hydrated and this edge is known absent,
            # avoid per-edge existence reads.
            if isinstance(existing_edges, set) and key not in existing_edges:
                should_lookup = False
            if should_lookup:
                try:
                    rows = self.session.get_resource_fields(
                        "opengraph_edges",
                        where_conditions={"source_id": source_id, "edge_type": edge_type, "destination_id": destination_id},
                    ) or []
                    if len(rows) == 1 and isinstance(rows[0], dict):
                        existing = rows[0]
                except Exception:
                    existing = {}
            self._edge_cache[key] = existing

        existing_props = _json_load(existing.get("edge_properties"), dict) if isinstance(existing, dict) else {}
        incoming_props = edge_properties if isinstance(edge_properties, dict) else {}
        final_props = _merge_edge_properties(existing_props or {}, incoming_props or {}, edge_type=edge_type)
        final_props_json = json.dumps(final_props, sort_keys=False) if final_props else None

        row = {
            "source_id": source_id,
            "edge_type": edge_type,
            "destination_id": destination_id,
            "edge_properties": final_props_json,
        }

        same = True
        for k, v in row.items():
            if (existing.get(k) if isinstance(existing, dict) else None) != v:
                same = False
                break
        if same:
            return True

        self.session.set_edge_fields(row, commit=commit, on_conflict=on_conflict)
        self._edge_cache[key] = dict(row)
        if isinstance(existing_edges, set):
            existing_edges.add(key)
        return True
