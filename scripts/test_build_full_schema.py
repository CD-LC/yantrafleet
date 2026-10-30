"""The one-shot rebuild file must track the migrations and only wipe what they own."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import build_full_schema as b  # noqa: E402


def test_includes_every_migration_except_superseded_0006_in_order():
    names = [p.name for p in b.migrations()]
    assert "0006_harden.sql" not in names
    assert names == sorted(names)
    assert names[0].startswith("0001") and names[-1].startswith("0019")
    sql = b.build()
    assert all(f"-- ---- {n}" in sql for n in names)


def test_wipe_is_limited_to_objects_the_migrations_define():
    tables, funcs, triggers, _ = b.parse_objects(b.migrations())
    assert {"robots", "alerts", "commands", "user_roles", "workspaces", "ingest_keys"} <= set(tables)
    assert "yf_has_role" in funcs and triggers == ["yf_on_auth_user_created"]
    assert not {"users", "schema_migrations", "objects"} & set(tables)   # never auth/storage names
    sql = b.build()
    import re
    low = sql.lower()
    assert "drop schema" not in low
    assert not re.search(r"^\s*truncate\b", low, re.M)             # a statement, not a privilege name
    wipe = sql[sql.index("begin;"):sql.index("-- ---- 0001_init.sql")]   # code only, not the header prose
    assert "auth." not in wipe.replace("drop trigger if exists yf_on_auth_user_created on auth.users;", "")
    assert sql.index("begin;") < sql.index("$wipe$") < sql.rindex("commit;")


def test_ends_locked_down_not_demo_open():
    sql = b.build()
    # 0007 (RBAC) must come after 0001 (which creates demo_all) so the transaction ends locked.
    assert sql.index("-- ---- 0001_init.sql") < sql.index("-- ---- 0007_rbac.sql")
    assert "notify pgrst, 'reload schema'" in sql
