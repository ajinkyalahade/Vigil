from fastapi.testclient import TestClient

from security_check.app import create_app
from security_check.config import Settings


def test_health_ok(tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(Settings(db_path=tmp_path / "test.db"))
    client = TestClient(app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_scanners_list(tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(Settings(db_path=tmp_path / "test.db"))
    client = TestClient(app)
    resp = client.get("/api/scanners")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert any(s["id"] == "macos.hardening" for s in data)
