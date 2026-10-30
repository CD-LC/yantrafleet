"""The scanner must fire on real secret shapes and stay quiet on the
publishable key, placeholders and waived lines. Fixtures are assembled at
runtime so this file never contains a literal secret."""
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from secret_scan import scan_line  # noqa: E402


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _jwt(role: str) -> str:
    return ".".join([_b64({"alg": "HS256", "typ": "JWT"}),
                     _b64({"iss": "supabase", "role": role}), "x" * 20])


def test_service_role_jwt_is_flagged_but_anon_jwt_is_not():
    assert "Supabase service_role JWT" in scan_line(f"KEY={_jwt('service_role')}")
    assert scan_line(f"KEY={_jwt('anon')}") == []


def test_new_style_keys():
    assert scan_line("k=sb_secret_" + "a1B2c3D4" * 4)
    assert scan_line("k=sb_publishable_7rqvPRggmPDRKNL8Jurcqg_Hf531puf") == []


def test_common_token_shapes():
    assert scan_line("-----BEGIN " + "RSA PRIVATE KEY-----")
    assert scan_line("aws=AKIA" + "ABCDEFGHIJKLMNOP")
    assert scan_line("t=ghp_" + "a" * 36)
    assert scan_line("k=sk-ant-" + "a1b2c3" * 6)
    assert scan_line("k=AIza" + "A" * 35)


def test_database_url_password_vs_placeholder():
    assert scan_line("postgresql://postgres:" + "Hunter2hunter2" + "@db.example.supabase.co:5432/postgres")
    assert scan_line("postgresql://postgres:<password>@db.x.supabase.co/postgres") == []
    assert scan_line("postgres://user:${DB_PASSWORD}@host/db") == []


def test_allow_marker_waives_a_line():
    assert scan_line("k=sb_secret_" + "a1B2c3D4" * 4 + "  # secret-scan: allow") == []
