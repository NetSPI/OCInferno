from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


class DataController:
    _SERVICE_TABLE_INDEXES = {
        "opengraph_nodes": [
            ("ix_opengraph_nodes_workspace_node", ("workspace_id", "node_id")),
            ("ix_opengraph_nodes_workspace_type", ("workspace_id", "node_type")),
        ],
        "opengraph_edges": [
            ("ix_opengraph_edges_workspace_src", ("workspace_id", "source_id")),
            ("ix_opengraph_edges_workspace_dst", ("workspace_id", "destination_id")),
            ("ix_opengraph_edges_workspace_type", ("workspace_id", "edge_type")),
        ],
        "identity_user_group_memberships": [
            ("ix_ugm_workspace_user", ("workspace_id", "user_id")),
            ("ix_ugm_workspace_group", ("workspace_id", "group_id")),
        ],
        "identity_domain_grants": [
            ("ix_idd_grants_workspace_grantee", ("workspace_id", "grantee_id")),
            ("ix_idd_grants_workspace_domain", ("workspace_id", "domain_ocid")),
        ],
        "identity_policies": [
            ("ix_identity_policies_workspace_compartment", ("workspace_id", "compartment_id")),
        ],
        "resource_compartments": [
            ("ix_resource_compartments_workspace_compartment", ("workspace_id", "compartment_id")),
            ("ix_resource_compartments_workspace_parent", ("workspace_id", "parent_compartment_id")),
        ],
        "compute_instances": [
            ("ix_compute_instances_workspace_compartment", ("workspace_id", "compartment_id")),
        ],
        "identity_dynamic_groups": [
            ("ix_identity_dynamic_groups_workspace_compartment", ("workspace_id", "compartment_id")),
        ],
        "identity_domain_dynamic_groups": [
            ("ix_identity_domain_dynamic_groups_workspace_compartment", ("workspace_id", "compartment_ocid")),
        ],
    }
    """
    DataController: two SQLite DBs
      - metadata_db: workspace_index, sessions, user_permissions
      - service_db:  service_info tables (YAML-defined) + opengraph nodes/edges, etc.

    Key upgrades vs your original:
      - single _get_conn_cursor (you had duplicates)
      - transaction() context manager (BEGIN/COMMIT/ROLLBACK)
      - save_dict_row(commit=...) so callers can avoid per-row commits
      - save_dict_rows_bulk() for executemany() (major speed-up)
      - PRAGMA tuning for write-heavy pipelines
      - close() + context manager support

    NEW (minimal changes):
      - ensure_user_permissions_row()
      - smarter upsert_user_permissions_merge() that de-dupes list content
        for your existing JSON shapes.
    """

    _repo_root = Path(__file__).resolve().parents[1]
    metadata_db = str(_repo_root / "databases" / "organization_metadata.db")
    service_db = str(_repo_root / "databases" / "service_info.db")

    def __init__(self):
        os.makedirs(str(Path(self.service_db).parent), exist_ok=True)

        # Metadata DB connection
        self.conn = sqlite3.connect(self.metadata_db)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self._apply_pragmas(self.conn)
        self._initialize_metadata_schema()

        # Service DB connection
        self.service_conn = sqlite3.connect(self.service_db)
        self.service_conn.row_factory = sqlite3.Row
        self.service_cursor = self.service_conn.cursor()
        self._apply_pragmas(self.service_conn)

    # -------------------------------------------------------------------------
    # Lifecycle / pragmas
    # -------------------------------------------------------------------------

    def close(self) -> None:
        try:
            self.cursor.close()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass
        try:
            self.service_cursor.close()
        except Exception:
            pass
        try:
            self.service_conn.close()
        except Exception:
            pass

    def commit(self, db: Optional[str] = None) -> None:
        """Commit pending writes.

        - db=None: commit both metadata and service DBs
        - db='metadata': commit metadata DB only
        - db='service': commit service DB only
        """
        target = (db or "").strip().lower()
        if target in ("", "metadata"):
            self.conn.commit()
        if target in ("", "service"):
            self.service_conn.commit()

    def rollback(self, db: Optional[str] = None) -> None:
        """Rollback pending writes (same db selector behavior as commit())."""
        target = (db or "").strip().lower()
        if target in ("", "metadata"):
            self.conn.rollback()
        if target in ("", "service"):
            self.service_conn.rollback()

    def __enter__(self) -> "DataController":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _apply_pragmas(self, conn: sqlite3.Connection) -> None:
        cur = conn.cursor()
        try:
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA temp_store=MEMORY;")
            cur.execute("PRAGMA cache_size=-20000;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.execute("PRAGMA busy_timeout=5000;")
        finally:
            cur.close()

    @contextmanager
    def transaction(self, db: str):
        conn, cursor = self._get_conn_cursor(db)
        try:
            cursor.execute("BEGIN")
            yield
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # -------------------------------------------------------------------------
    # Metadata schema
    # -------------------------------------------------------------------------

    def _initialize_metadata_schema(self) -> None:
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_permissions (
                workspace_id INTEGER,
                credname TEXT,

                -- JSON blobs (stored as TEXT)
                permissions_json TEXT,
                apis_success_json TEXT,
                apis_failed_json TEXT,

                updated_at TEXT,
                PRIMARY KEY (workspace_id, credname)
            )
            """
        )
        self.conn.commit()

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS workspace_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                configs TEXT
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                workspace_id INTEGER,
                credname TEXT,
                credtype TEXT,
                default_compartment_id TEXT,
                session_creds TEXT,
                PRIMARY KEY (workspace_id, credname)
            )
            """
        )
        self.conn.commit()

    def ensure_user_permissions_row(self, workspace_id: int, credname: str) -> None:
        """
        Ensure row exists so merge/upsert always has a base.
        Does not overwrite existing blobs.
        """
        existing = self.fetch_user_permissions(workspace_id, credname)
        if existing:
            return
        payload = {
            "workspace_id": workspace_id,
            "credname": credname,
            "permissions_json": "{}",
            "apis_success_json": "{}",
            "apis_failed_json": "{}",
            "updated_at": datetime.utcnow().isoformat(),
        }
        self.save_dict_row(
            db="metadata",
            table_name="user_permissions",
            row=payload,
            on_conflict="ignore",
            conflict_cols=["workspace_id", "credname"],
            commit=True,
        )

    # ---- small internal helpers ----

    def _safe_json_obj(self, s: Any) -> Dict[str, Any]:
        if isinstance(s, dict):
            return s
        if not isinstance(s, str) or not s.strip():
            return {}
        try:
            v = json.loads(s)
            return v if isinstance(v, dict) else {}
        except Exception:
            return {}

    def _json_list_dedupe_extend(self, dst_list: list, src_list: list) -> list:
        """
        Dedupe while preserving order.
        Supports scalars and dicts.
        """
        if not isinstance(dst_list, list):
            dst_list = []
        if not isinstance(src_list, list) or not src_list:
            return dst_list

        seen = set()
        out = []

        def keyify(x: Any) -> str:
            if isinstance(x, dict):
                # stable representation
                return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            return str(x)

        for x in dst_list:
            k = keyify(x)
            if k not in seen:
                seen.add(k)
                out.append(x)

        for x in src_list:
            k = keyify(x)
            if k not in seen:
                seen.add(k)
                out.append(x)

        return out

    def _merge_permissions_blob(self, base: Dict[str, Any], delta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Expected shape:
          {
            "PERM_NAME": {
              "resources": [..],
              "evidence": [ {service,op,ts}, ...]
            },
            ...
          }
        """
        out = dict(base or {})
        for perm, info in (delta or {}).items():
            if perm not in out or not isinstance(out.get(perm), dict):
                out[perm] = {"resources": [], "evidence": []}

            cur = out[perm] if isinstance(out[perm], dict) else {"resources": [], "evidence": []}
            inc = info if isinstance(info, dict) else {}

            cur_resources = cur.get("resources", [])
            cur_evidence = cur.get("evidence", [])

            inc_resources = inc.get("resources", []) or []
            inc_evidence = inc.get("evidence", []) or []

            # de-dupe within these lists
            cur["resources"] = self._json_list_dedupe_extend(cur_resources, inc_resources)
            cur["evidence"] = self._json_list_dedupe_extend(cur_evidence, inc_evidence)

            out[perm] = cur
        return out

    def _merge_api_events_blob(self, base: Dict[str, Any], delta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Expected shape:
          { "identity": [ {op,resource,ts,(err)}, ...], "core":[...], ... }
        """
        out = dict(base or {})
        for svc, events in (delta or {}).items():
            if svc not in out or not isinstance(out.get(svc), list):
                out[svc] = []
            out[svc] = self._json_list_dedupe_extend(out[svc], events or [])
            # cap per-service so DB doesn't grow forever
            if len(out[svc]) > 5000:
                out[svc] = out[svc][-5000:]
        return out

    def upsert_user_permissions_merge(
        self,
        workspace_id: int,
        credname: str,
        *,
        permissions_delta: Optional[Dict[str, Any]] = None,
        apis_success_delta: Optional[Dict[str, Any]] = None,
        apis_failed_delta: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Merge JSON blobs in user_permissions for (workspace_id, credname).

        NEW behavior (minimal but important):
          - For permissions_json: de-dupe resources/evidence lists per permission.
          - For api event blobs: de-dupe event dicts, cap size.

        This avoids endless duplication when your modules retry / re-enumerate.
        """
        now = datetime.utcnow().isoformat()

        self.ensure_user_permissions_row(workspace_id, credname)
        row = self.fetch_user_permissions(workspace_id, credname) or {}

        perms = self._safe_json_obj(row.get("permissions_json"))
        ok = self._safe_json_obj(row.get("apis_success_json"))
        bad = self._safe_json_obj(row.get("apis_failed_json"))

        if permissions_delta:
            perms = self._merge_permissions_blob(perms, permissions_delta)

        if apis_success_delta:
            ok = self._merge_api_events_blob(ok, apis_success_delta)

        if apis_failed_delta:
            bad = self._merge_api_events_blob(bad, apis_failed_delta)

        payload = {
            "workspace_id": workspace_id,
            "credname": credname,
            "permissions_json": json.dumps(perms, separators=(",", ":"), ensure_ascii=False),
            "apis_success_json": json.dumps(ok, separators=(",", ":"), ensure_ascii=False),
            "apis_failed_json": json.dumps(bad, separators=(",", ":"), ensure_ascii=False),
            "updated_at": now,
        }
        return self.save_dict_row(
            db="metadata",
            table_name="user_permissions",
            row=payload,
            on_conflict="update",
            conflict_cols=["workspace_id", "credname"],
            commit=True,
        )

    def fetch_user_permissions(self, workspace_id: int, credname: str) -> Optional[Dict[str, Any]]:
        try:
            self.cursor.execute(
                "SELECT * FROM user_permissions WHERE workspace_id = ? AND credname = ?",
                (workspace_id, credname),
            )
            r = self.cursor.fetchone()
            return dict(r) if r else None
        except Exception as e:
            print(f"[X] fetch_user_permissions failed: {e}")
            return None

    # -------------------------------------------------------------------------
    # Generic helpers
    # -------------------------------------------------------------------------

    def _get_conn_cursor(self, db: str) -> Tuple[sqlite3.Connection, sqlite3.Cursor]:
        if db not in ("metadata", "service"):
            raise ValueError("db must be 'metadata' or 'service'")
        return (self.conn, self.cursor) if db == "metadata" else (self.service_conn, self.service_cursor)

    def _table_columns(self, db: str, table_name: str) -> List[str]:
        _, cursor = self._get_conn_cursor(db)
        cursor.execute(f'PRAGMA table_info("{table_name}")')
        return [r["name"] for r in cursor.fetchall()]

    def _pk_columns(self, db: str, table_name: str) -> List[str]:
        _, cursor = self._get_conn_cursor(db)
        cursor.execute(f'PRAGMA table_info("{table_name}")')
        rows = cursor.fetchall()
        return [r["name"] for r in sorted(rows, key=lambda x: x["pk"]) if r["pk"] > 0]

    def _serialize_for_sql(self, value: Any, encode_bools_as_int: bool = True) -> Any:
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            return json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
        if isinstance(value, (set, tuple)):
            return json.dumps(list(value), separators=(",", ":"), ensure_ascii=False, sort_keys=True)
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, bool):
            return 1 if encode_bools_as_int else ("true" if value else "false")
        return str(value)

    # -------------------------------------------------------------------------
    # Path-based SQLite readers (shared by export helpers)
    # -------------------------------------------------------------------------

    @staticmethod
    def list_sqlite_tables_by_path(db_path: str) -> List[str]:
        db_file = Path(str(db_path or "")).expanduser().resolve()
        if not db_file.exists():
            return []
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            rows = cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            return [str(r[0]) for r in rows if r and r[0]]
        finally:
            try:
                cur.close()
            except Exception:
                pass
            conn.close()

    @staticmethod
    def list_sqlite_table_columns_by_path(db_path: str, table_name: str) -> List[str]:
        db_file = Path(str(db_path or "")).expanduser().resolve()
        if not db_file.exists():
            return []
        table = str(table_name or "").strip()
        if not table:
            return []
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            pragma = cur.execute(f'PRAGMA table_info("{table}")').fetchall()
            return [str(p[1]) for p in pragma if len(p) > 1 and p[1]]
        finally:
            try:
                cur.close()
            except Exception:
                pass
            conn.close()

    @staticmethod
    def fetch_sqlite_rows_by_path(db_path: str, table_name: str) -> List[Dict[str, Any]]:
        db_file = Path(str(db_path or "")).expanduser().resolve()
        if not db_file.exists():
            return []
        table = str(table_name or "").strip()
        if not table:
            return []
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            return [dict(r) for r in cur.execute(f'SELECT * FROM "{table}"').fetchall()]
        finally:
            try:
                cur.close()
            except Exception:
                pass
            conn.close()

    @classmethod
    def collect_sqlite_table_refs_by_paths(cls, db_paths: List[str]) -> List[Dict[str, Any]]:
        refs: List[Dict[str, Any]] = []
        for db_path in db_paths or []:
            db_file = Path(str(db_path or "")).expanduser().resolve()
            if not db_file.exists():
                continue
            db_name = db_file.stem
            table_names = cls.list_sqlite_tables_by_path(str(db_file))
            for table_name in table_names:
                refs.append(
                    {
                        "db_name": db_name,
                        "db_path": str(db_file),
                        "table_name": table_name,
                        "columns": cls.list_sqlite_table_columns_by_path(str(db_file), table_name),
                    }
                )
        return refs

    @staticmethod
    def _sql_output_cell(value: Any) -> Any:
        if value is None:
            return ""
        if isinstance(value, (int, float, str)):
            return value
        if isinstance(value, (bytes, bytearray)):
            return value.hex()
        return str(value)

    def run_sql_query(self, db: str, query: str, *, max_rows: int = 200) -> Dict[str, Any]:
        conn, cursor = self._get_conn_cursor(db)
        sql = str(query or "").strip()
        if not sql:
            raise ValueError("query is required")

        cursor.execute(sql)

        # SELECT-style query
        if cursor.description is not None:
            columns = [str(col[0]) for col in (cursor.description or [])]
            rows: List[Dict[str, Any]] = []
            total = 0
            truncated = False

            while True:
                chunk = cursor.fetchmany(1000)
                if not chunk:
                    break
                for row in chunk:
                    total += 1
                    row_dict = {c: self._sql_output_cell(row[c]) for c in columns}
                    if len(rows) < max_rows:
                        rows.append(row_dict)
                    else:
                        truncated = True
                        break
                if truncated:
                    break

            return {
                "query_type": "select",
                "db": db,
                "columns": columns,
                "rows": rows,
                "row_count": total,
                "truncated": truncated,
                "max_rows": max_rows,
            }

        # Write query
        conn.commit()
        affected = cursor.rowcount if isinstance(cursor.rowcount, int) and cursor.rowcount >= 0 else 0
        return {
            "query_type": "write",
            "db": db,
            "affected_rows": affected,
        }

    def plan_service_wipe(self, workspace_id: int, *, all_workspaces: bool = False) -> Dict[str, Any]:
        cursor = self.service_cursor
        target_ws = int(workspace_id)

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        table_rows = cursor.fetchall() or []
        table_names = [str(r[0]) for r in table_rows if isinstance(r, (tuple, list, sqlite3.Row)) and r]
        if not table_names:
            return {
                "db_path": self.service_db,
                "scope_label": ("all workspaces" if all_workspaces else f"workspace_id={target_ws}"),
                "plans": [],
                "candidate_tables": [],
                "non_workspace_tables": [],
                "tables_with_rows": [],
                "total_rows": 0,
            }

        plans: List[Dict[str, Any]] = []
        total_rows = 0
        for table_name in table_names:
            cursor.execute(f'PRAGMA table_info("{table_name}")')
            columns = [str(c[1]) for c in (cursor.fetchall() or []) if isinstance(c, (tuple, list, sqlite3.Row)) and len(c) > 1]
            has_workspace_id = "workspace_id" in columns

            if not has_workspace_id:
                plans.append(
                    {
                        "table_name": table_name,
                        "has_workspace_id": False,
                        "row_count": 0,
                    }
                )
                continue

            if all_workspaces:
                cursor.execute(f'SELECT COUNT(1) FROM "{table_name}"')
            else:
                cursor.execute(f'SELECT COUNT(1) FROM "{table_name}" WHERE "workspace_id" = ?', (target_ws,))

            row = cursor.fetchone()
            count = int(row[0]) if isinstance(row, (tuple, list, sqlite3.Row)) and row else 0
            count = max(count, 0)
            total_rows += count
            plans.append(
                {
                    "table_name": table_name,
                    "has_workspace_id": True,
                    "row_count": count,
                }
            )

        candidate_tables = [p for p in plans if p["has_workspace_id"]]
        non_workspace_tables = [p["table_name"] for p in plans if not p["has_workspace_id"]]
        tables_with_rows = [p for p in candidate_tables if int(p.get("row_count", 0)) > 0]

        return {
            "db_path": self.service_db,
            "scope_label": ("all workspaces" if all_workspaces else f"workspace_id={target_ws}"),
            "plans": plans,
            "candidate_tables": candidate_tables,
            "non_workspace_tables": non_workspace_tables,
            "tables_with_rows": tables_with_rows,
            "total_rows": total_rows,
        }

    def wipe_service_rows(
        self,
        workspace_id: int,
        *,
        all_workspaces: bool = False,
        planned_tables_with_rows: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        target_ws = int(workspace_id)
        tables_with_rows = list(planned_tables_with_rows or [])
        if not tables_with_rows:
            plan = self.plan_service_wipe(target_ws, all_workspaces=all_workspaces)
            tables_with_rows = list(plan.get("tables_with_rows") or [])

        deleted_total = 0
        deleted_tables = 0
        for entry in tables_with_rows:
            table_name = str(entry.get("table_name") or "").strip()
            if not table_name:
                continue
            if all_workspaces:
                self.service_cursor.execute(f'DELETE FROM "{table_name}"')
            else:
                self.service_cursor.execute(f'DELETE FROM "{table_name}" WHERE "workspace_id" = ?', (target_ws,))
            deleted_tables += 1
            deleted_total += int(entry.get("row_count") or 0)

        self.service_conn.commit()
        return {
            "deleted_rows": deleted_total,
            "deleted_tables": deleted_tables,
        }

    # -------------------------------------------------------------------------
    # Upsert: fill Unknowns
    # -------------------------------------------------------------------------

    def upsert_fill_unknowns(
        self,
        db: str,
        table_name: str,
        new_data: Dict[str, Union[str, int, float, None]],
        override: bool = False,
        unknown_sentinel: str = "Unknown",
        treat_empty_as_unknown: bool = True,
    ) -> Tuple[str, List[str]]:
        conn, cursor = self._get_conn_cursor(db)
        pk_cols = self._pk_columns(db, table_name)

        if not pk_cols or any(pk not in new_data for pk in pk_cols):
            cols = [f'"{c}"' for c in new_data.keys()]
            placeholders = ",".join(["?"] * len(new_data))
            sql = f'INSERT INTO "{table_name}" ({",".join(cols)}) VALUES ({placeholders})'
            cursor.execute(sql, list(new_data.values()))
            conn.commit()
            return ("inserted", list(new_data.keys()))

        where = {k: new_data[k] for k in pk_cols}
        where_clause = " AND ".join([f'"{k}" = ?' for k in where])
        sel_sql = f'SELECT * FROM "{table_name}" WHERE {where_clause}'
        cursor.execute(sel_sql, list(where.values()))
        row = cursor.fetchone()

        if row is None:
            cols = [f'"{c}"' for c in new_data.keys()]
            placeholders = ",".join(["?"] * len(new_data))
            sql = f'INSERT INTO "{table_name}" ({",".join(cols)}) VALUES ({placeholders})'
            cursor.execute(sql, list(new_data.values()))
            conn.commit()
            return ("inserted", list(new_data.keys()))

        row_dict = dict(row)

        def is_unknown(val: Any) -> bool:
            if val is None:
                return treat_empty_as_unknown
            if isinstance(val, str):
                if treat_empty_as_unknown and val == "":
                    return True
                return val.lower() == unknown_sentinel.lower()
            return False

        updates: Dict[str, Any] = {}
        for col, new_val in new_data.items():
            if col in pk_cols:
                continue
            if col not in row_dict:
                continue
            if override:
                updates[col] = new_val
            else:
                if is_unknown(row_dict[col]):
                    updates[col] = new_val

        if not updates:
            return ("noop", [])

        set_clause = ", ".join([f'"{c}" = ?' for c in updates.keys()])
        upd_sql = f'UPDATE "{table_name}" SET {set_clause} WHERE {where_clause}'
        params = list(updates.values()) + list(where.values())
        cursor.execute(upd_sql, params)
        conn.commit()
        return ("updated", list(updates.keys()))

    # -------------------------------------------------------------------------
    # Fetch / Delete / Update (generic)
    # -------------------------------------------------------------------------

    def fetch_column_from_table(
        self,
        db: str,
        table_name: str,
        columns: Optional[Union[str, List[str]]] = None,
        where: Optional[Dict[str, Union[str, int, float]]] = None,
        as_dict: bool = False,
    ) -> List[Union[Tuple[Any, ...], Dict[str, Any], Any]]:
        _, cursor = self._get_conn_cursor(db)
        single_column = False

        if columns is None or columns == "*":
            col_str = "*"
        else:
            if isinstance(columns, str):
                columns = [columns]
                single_column = True
            else:
                single_column = len(columns) == 1
            col_str = ", ".join([f'"{col}"' for col in columns])

        query = f'SELECT {col_str} FROM "{table_name}"'
        params: List[Any] = []

        if where:
            where_clause = " AND ".join([f'"{k}" = ?' for k in where])
            query += f" WHERE {where_clause}"
            params.extend(where.values())

        try:
            cursor.execute(query, params)
            rows = cursor.fetchall()

            if as_dict:
                col_names = [desc[0] for desc in cursor.description]
                return [dict(zip(col_names, row)) for row in rows]

            if single_column and col_str != "*":
                return [row[0] for row in rows]

            return [tuple(row) for row in rows]

        except Exception as e:
            print(f"[X] Failed to fetch from '{table_name}' in '{db}': {e}")
            return []

    def save_value_to_table_column(
        self,
        db: str,
        table_name: str,
        target_column: str,
        value: Union[str, int, float],
        where: Dict[str, Union[str, int]],
    ) -> bool:
        conn, cursor = self._get_conn_cursor(db)

        try:
            where_clause = " AND ".join([f'"{key}" = ?' for key in where.keys()])
            query = f'UPDATE "{table_name}" SET "{target_column}" = ? WHERE {where_clause}'
            params = [value] + list(where.values())

            cursor.execute(query, params)
            conn.commit()

            if cursor.rowcount == 0:
                print(f"[!] No rows updated in '{table_name}' (check WHERE match).")
            return True

        except Exception as e:
            print(f"[X] Failed to update '{table_name}.{target_column}': {e}")
            return False

    # -------------------------------------------------------------------------
    # Workspace/session methods (metadata DB)
    # -------------------------------------------------------------------------

    def insert_workspace(self, name: str, starting_config_data_json_blob: str) -> Optional[int]:
        try:
            self.cursor.execute(
                "INSERT INTO workspace_index (name, configs) VALUES (?, ?)",
                (name, starting_config_data_json_blob),
            )
            self.conn.commit()
            return self.cursor.lastrowid
        except Exception as e:
            print("[X] Failed to insert workspace:", e)
            return None

    def fetch_all_workspace_names(self) -> List[str]:
        try:
            self.cursor.execute("SELECT name FROM workspace_index")
            return [row["name"] for row in self.cursor.fetchall()]
        except Exception as e:
            print("[X] Failed to fetch workspace names:", e)
            return []

    def get_workspaces(self) -> List[Tuple[int, str]]:
        try:
            self.cursor.execute("SELECT id, name FROM workspace_index")
            return [(row["id"], row["name"]) for row in self.cursor.fetchall()]
        except Exception as e:
            print("[X] Failed to get workspaces:", e)
            return []

    def insert_creds(self, workspace_id: int, credname: str, credtype: str, session_creds: str) -> Optional[int]:
        try:
            columns = ["workspace_id", "credname", "credtype", "session_creds"]
            values = [workspace_id, credname, credtype, session_creds]
            placeholders = ["?"] * len(values)
            query = f"INSERT OR REPLACE INTO sessions ({','.join(columns)}) VALUES ({','.join(placeholders)})"
            self.cursor.execute(query, values)
            self.conn.commit()
            return self.cursor.lastrowid
        except Exception as e:
            print("[X] Failed in insert_creds:", e)
            return None

    def list_creds(self, workspace_id: int) -> Optional[List[Tuple[str, str]]]:
        try:
            self.cursor.execute(
                "SELECT credname, credtype FROM sessions WHERE workspace_id = ?",
                (workspace_id,),
            )
            return [(row["credname"], row["credtype"]) for row in self.cursor.fetchall()]
        except Exception as e:
            print(f"[X] Failed in list_creds: {e}")
            return None

    def fetch_cred(self, workspace_id: int, credname: str) -> Optional[Dict[str, Any]]:
        try:
            self.cursor.execute(
                "SELECT credname, credtype, session_creds FROM sessions WHERE workspace_id = ? AND credname = ?",
                (workspace_id, credname),
            )
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            print("[X] Failed in fetch_cred:", e)
            return None

    # -------------------------------------------------------------------------
    # Service table logic
    # -------------------------------------------------------------------------

    @staticmethod
    def _resolve_database_info_yaml_path() -> str:
        # Load only packaged resource path (works for both installed wheel and repo source).
        try:
            candidate = resources.files("ocinferno.mappings").joinpath("database_info.yaml")
            if candidate.is_file():
                return str(candidate)
        except Exception as exc:
            raise FileNotFoundError(
                "Required resource 'mappings/database_info.yaml' is missing. "
                "Reinstall/upgrade OCInferno in a clean environment."
            ) from exc
        raise FileNotFoundError(
            "Required resource 'mappings/database_info.yaml' is missing. "
            "Reinstall/upgrade OCInferno in a clean environment."
        )

    def create_service_tables_from_yaml(self, yaml_path: str | None = None) -> bool:
        try:
            import yaml

            if not yaml_path:
                yaml_path = self._resolve_database_info_yaml_path()

            with open(yaml_path, "r", encoding="utf-8") as file:
                yaml_data = yaml.safe_load(file)

            for db in yaml_data.get("databases", []):
                for table in db.get("tables", []):
                    table_name = table["table_name"]
                    columns = list(table["columns"]) + ["workspace_id"]
                    primary_keys = list(table["primary_keys"]) + ["workspace_id"]
                    self._create_service_table(table_name, columns, primary_keys)

            return True
        except Exception as e:
            print("[X] Failed to create service tables from YAML:", e)
            return False

    def _create_service_table(self, table_name: str, columns: List[str], primary_keys: List[str]) -> None:
        try:
            col_defs = ", ".join([f'"{col}" TEXT' for col in columns])
            pk_defs = ", ".join([f'"{pk}"' for pk in primary_keys])
            create_stmt = f'''
            CREATE TABLE IF NOT EXISTS "{table_name}" (
                {col_defs},
                PRIMARY KEY ({pk_defs})
            );
            '''
            self.service_cursor.execute(create_stmt)

            # Schema drift fix: add newly-defined columns to existing tables.
            self.service_cursor.execute(f'PRAGMA table_info("{table_name}")')
            existing_cols = set()
            for r in (self.service_cursor.fetchall() or []):
                if isinstance(r, sqlite3.Row):
                    existing_cols.add(str(r["name"]))
                elif isinstance(r, (list, tuple)) and len(r) >= 2:
                    existing_cols.add(str(r[1]))
            for col in columns:
                if col not in existing_cols:
                    self.service_cursor.execute(f'ALTER TABLE "{table_name}" ADD COLUMN "{col}" TEXT')

            # Ensure full edge identity uniqueness for existing DBs, even if legacy PK is narrower.
            if table_name == "opengraph_edges":
                self.service_cursor.execute(
                    'CREATE UNIQUE INDEX IF NOT EXISTS "ux_opengraph_edges_identity" '
                    'ON "opengraph_edges" ("source_id", "edge_type", "destination_id", "workspace_id")'
                )

            for index_name, index_cols in (self._SERVICE_TABLE_INDEXES.get(table_name) or []):
                if not index_cols:
                    continue
                cols_sql = ", ".join(f'"{c}"' for c in index_cols)
                self.service_cursor.execute(
                    f'CREATE INDEX IF NOT EXISTS "{index_name}" ON "{table_name}" ({cols_sql})'
                )

            self.service_conn.commit()
        except Exception as e:
            print(f"[X] Failed to create table '{table_name}': {e}")

    # -------------------------------------------------------------------------
    # SAVE SERVICE DATA: save_dict_row + bulk
    # -------------------------------------------------------------------------

    def save_dict_row(
        self,
        db: str,
        table_name: str,
        row: Dict[str, Any],
        on_conflict: str = "replace",
        encode_bools_as_int: bool = True,
        conflict_cols: Optional[List[str]] = None,
        commit: bool = True,
    ) -> bool:
        conn, cursor = self._get_conn_cursor(db)
        cols_in_table = set(self._table_columns(db, table_name))
        if not cols_in_table:
            print(f"[X] Table '{table_name}' not found.")
            return False

        filtered = {k: self._serialize_for_sql(v, encode_bools_as_int) for k, v in row.items() if k in cols_in_table}
        if not filtered:
            print(f"[X] No valid columns to insert for '{table_name}'.")
            return False

        columns = list(filtered.keys())
        placeholders = ",".join(["?"] * len(columns))
        col_list = ",".join([f'"{c}"' for c in columns])
        values = [filtered[c] for c in columns]

        try:
            if on_conflict == "ignore":
                sql = f'INSERT OR IGNORE INTO "{table_name}" ({col_list}) VALUES ({placeholders})'
                cursor.execute(sql, values)

            elif on_conflict == "replace":
                sql = f'INSERT OR REPLACE INTO "{table_name}" ({col_list}) VALUES ({placeholders})'
                cursor.execute(sql, values)

            elif on_conflict in ("update", "update_nulls"):
                pk_cols = conflict_cols or self._pk_columns(db, table_name)

                if not pk_cols:
                    # No PK => can't do ON CONFLICT target
                    sql = f'INSERT OR REPLACE INTO "{table_name}" ({col_list}) VALUES ({placeholders})'
                    cursor.execute(sql, values)
                else:
                    non_pk = [c for c in columns if c not in pk_cols]
                    conflict_cols_sql = ",".join([f'"{c}"' for c in pk_cols])

                    if non_pk:
                        if on_conflict == "update":
                            # Overwrite with incoming values, but only if something is different
                            set_clause = ", ".join([f'"{c}"=excluded."{c}"' for c in non_pk])

                            # Only perform UPDATE if any non-PK differs (NULL-safe)
                            where_clause = " OR ".join(
                                [f'excluded."{c}" IS NOT "{table_name}"."{c}"' for c in non_pk]
                            )

                            sql = (
                                f'INSERT INTO "{table_name}" ({col_list}) VALUES ({placeholders}) '
                                f'ON CONFLICT({conflict_cols_sql}) DO UPDATE SET {set_clause} '
                                f'WHERE {where_clause}'
                            )
                        else:
                            # update_nulls: fill NULLs only (existing non-NULL values win)
                            set_clause = ", ".join(
                                [f'"{c}"=COALESCE("{table_name}"."{c}", excluded."{c}")' for c in non_pk]
                            )
                            sql = (
                                f'INSERT INTO "{table_name}" ({col_list}) VALUES ({placeholders}) '
                                f'ON CONFLICT({conflict_cols_sql}) DO UPDATE SET {set_clause}'
                            )

                        cursor.execute(sql, values)
                    else:
                        sql = (
                            f'INSERT INTO "{table_name}" ({col_list}) VALUES ({placeholders}) '
                            f'ON CONFLICT({conflict_cols_sql}) DO NOTHING'
                        )
                        cursor.execute(sql, values)

            else:
                print(f"[X] Unknown on_conflict mode '{on_conflict}'.")
                return False

            if commit:
                conn.commit()
            return True

        except Exception as e:
            print(f"[X] Failed to save dict row into '{table_name}': {e}")
            try:
                conn.rollback()
            except Exception:
                pass
            return False

    def save_dict_rows_bulk(
        self,
        db: str,
        table_name: str,
        rows: List[Dict[str, Any]],
        on_conflict: str = "update",
        encode_bools_as_int: bool = True,
        conflict_cols: Optional[List[str]] = None,
    ) -> int:
        if not rows:
            return 0

        conn, cursor = self._get_conn_cursor(db)
        cols_in_table = set(self._table_columns(db, table_name))
        if not cols_in_table:
            print(f"[X] Table '{table_name}' not found.")
            return 0

        columns = [c for c in rows[0].keys() if c in cols_in_table]
        if not columns:
            print(f"[X] No valid columns to insert for '{table_name}'.")
            return 0

        col_list = ",".join([f'"{c}"' for c in columns])
        placeholders = ",".join(["?"] * len(columns))

        values_list: List[List[Any]] = []
        for r in rows:
            filtered = {k: self._serialize_for_sql(v, encode_bools_as_int) for k, v in r.items() if k in columns}
            values_list.append([filtered.get(c) for c in columns])

        pk_cols = conflict_cols or self._pk_columns(db, table_name)

        if on_conflict in ("update", "update_nulls") and pk_cols:
            non_pk = [c for c in columns if c not in pk_cols]
            conflict_cols_sql = ",".join([f'"{c}"' for c in pk_cols])

            if non_pk:
                if on_conflict == "update":
                    set_clause = ", ".join([f'"{c}"=excluded."{c}"' for c in non_pk])
                    where_clause = " OR ".join([f'excluded."{c}" IS NOT "{table_name}"."{c}"' for c in non_pk])

                    sql = (
                        f'INSERT INTO "{table_name}" ({col_list}) VALUES ({placeholders}) '
                        f'ON CONFLICT({conflict_cols_sql}) DO UPDATE SET {set_clause} '
                        f'WHERE {where_clause}'
                    )
                else:
                    set_clause = ", ".join([f'"{c}"=COALESCE("{table_name}"."{c}", excluded."{c}")' for c in non_pk])
                    sql = (
                        f'INSERT INTO "{table_name}" ({col_list}) VALUES ({placeholders}) '
                        f'ON CONFLICT({conflict_cols_sql}) DO UPDATE SET {set_clause}'
                    )
            else:
                sql = (
                    f'INSERT INTO "{table_name}" ({col_list}) VALUES ({placeholders}) '
                    f'ON CONFLICT({conflict_cols_sql}) DO NOTHING'
                )
        else:
            sql = f'INSERT OR REPLACE INTO "{table_name}" ({col_list}) VALUES ({placeholders})'

        try:
            cursor.executemany(sql, values_list)
            if not conn.in_transaction:
                conn.commit()
            return len(rows)
        except Exception as e:
            print(f"[X] Bulk save failed into '{table_name}': {e}")
            try:
                conn.rollback()
            except Exception:
                pass
            return 0

    # -------------------------------------------------------------------------
    # Delete dict row
    # -------------------------------------------------------------------------

    def delete_dict_row(
        self,
        db: str,
        table_name: str,
        where: Dict[str, Any],
        encode_bools_as_int: bool = True,
        require_where: bool = True,
        commit: bool = True,
    ) -> bool:
        conn, cursor = self._get_conn_cursor(db)

        cols_in_table = set(self._table_columns(db, table_name))
        if not cols_in_table:
            print(f"[X] Table '{table_name}' not found.")
            return False

        if not isinstance(where, dict):
            print("[X] WHERE clause must be a dict.")
            return False

        filtered = {k: self._serialize_for_sql(v, encode_bools_as_int) for k, v in where.items() if k in cols_in_table}

        if not filtered:
            if require_where:
                print(f"[X] Refusing to delete from '{table_name}' without a valid WHERE clause.")
                return False
            try:
                cursor.execute(f'DELETE FROM "{table_name}"')
                if commit:
                    conn.commit()
                return True
            except Exception as e:
                print(f"[X] Failed to delete all rows from '{table_name}': {e}")
                return False

        where_clause = " AND ".join([f'"{k}" = ?' for k in filtered.keys()])
        values = list(filtered.values())

        sql = f'DELETE FROM "{table_name}" WHERE {where_clause}'
        try:
            cursor.execute(sql, values)
            if commit:
                conn.commit()
            return True
        except Exception as e:
            print(f"[X] Failed to delete dict row from '{table_name}': {e}")
            try:
                conn.rollback()
            except Exception:
                pass
            return False
