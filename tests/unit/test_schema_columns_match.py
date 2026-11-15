"""CI guard against schema drift: every OciListResource subclass's COLUMNS must be a subset
of its database_info.json schema table's columns.

Why this matters: the save path (session.save_resources -> db.save_dict_rows_bulk) filters each
row to the DB table's columns. A field a helper extracts/declares in COLUMNS but that is NOT a
column in database_info.json is SILENTLY DROPPED at save -- the operator sees it in the printed
table, but exports, config_audit, and OpenGraph never see it. Several real data-loss bugs of this
exact shape were found and fixed (DNS resolvers saved with no id/name, DataScience runs dropping
time_accepted, DataFlow dropping `operation`, FileStorage dropping region, ...). This test catches
the whole class so new drift fails CI instead of silently losing data.

Not covered (future enhancement): fields injected via row.setdefault(...) rather than declared in
COLUMNS. Those need AST analysis; COLUMNS subset-of-schema is the high-value invariant.
"""
import importlib
import json
import pathlib

_REPO = pathlib.Path(__file__).resolve().parents[2]
_PKG = _REPO / "ocinferno"


def _schema_columns():
    data = json.loads((_PKG / "mappings" / "database_info.json").read_text(encoding="utf-8"))
    return {t["table_name"]: set(t["columns"]) for t in data["tables"]}


def _import_all_helper_modules():
    failures = {}
    for p in (_PKG / "modules").rglob("*.py"):
        if p.name.startswith("_") or "/utilities/" not in p.as_posix():
            continue
        dotted = p.relative_to(_REPO).with_suffix("").as_posix().replace("/", ".")
        try:
            importlib.import_module(dotted)
        except Exception as e:  # pragma: no cover - import issues surfaced, not asserted
            failures[dotted] = f"{type(e).__name__}: {e}"
    return failures


def _resource_classes():
    from ocinferno.core.resource import OciListResource

    def _subs(cls):
        for s in cls.__subclasses__():
            yield s
            yield from _subs(s)

    return _subs(OciListResource)


def test_resource_columns_are_in_schema():
    import_failures = _import_all_helper_modules()
    schema = _schema_columns()

    offenders = []
    checked = 0
    seen = set()
    for cls in _resource_classes():
        # Only production resource classes; test modules define their own mock subclasses
        # with fake table names that aren't in the schema.
        if not getattr(cls, "__module__", "").startswith("ocinferno."):
            continue
        table = getattr(cls, "TABLE_NAME", None)
        columns = getattr(cls, "COLUMNS", None)
        if not table or not columns or table in seen:
            continue
        seen.add(table)
        checked += 1
        table_cols = schema.get(table)
        if table_cols is None:
            offenders.append(f"{cls.__name__}: TABLE_NAME '{table}' has no database_info.json table")
            continue
        missing = [c for c in columns if c not in table_cols]
        if missing:
            offenders.append(
                f"{cls.__name__} (table '{table}'): COLUMNS {missing} are not schema columns "
                f"-> silently dropped at save"
            )

    assert checked > 100, f"only {checked} resource classes discovered (import problem?): {import_failures}"
    assert not offenders, "COLUMNS/schema drift (data silently dropped at save):\n  " + "\n  ".join(offenders)
