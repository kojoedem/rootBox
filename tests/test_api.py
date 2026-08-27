import os
import pytest
from fastapi.testclient import TestClient

@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_vault.db")
    test_vault = str(tmp_path / "test_storage")

    monkeypatch.setenv("DATABASE_PATH", test_db)
    monkeypatch.setenv("VAULT_DIR", test_vault)

    # Re-import main to trigger lifespan/setup with new env vars
    from app.main import app
    from app.database import init_db
    from app.vault import ensure_vault_exists

    init_db()
    ensure_vault_exists()

    with TestClient(app) as c:
        yield c

def test_homepage_empty(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Quarantine Vault Repository" in response.text
    assert "No malware samples uploaded yet" in response.text

def test_upload_and_download_flow(client):
    file_payload = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    files = {
        "file": ("eicar.com", file_payload, "application/octet-stream")
    }
    data = {
        "threat_type": "Test Sample / EICAR",
        "file_format": "DOS Executable",
        "description": "Standard EICAR test string for verification",
        "analysis_notes": "Safe signature testing file."
    }

    # Post upload
    response = client.post("/upload", files=files, data=data, follow_redirects=True)
    assert response.status_code == 200
    assert "eicar.com" in response.text
    assert "Test Sample / EICAR" in response.text

    # Check detail page
    detail_response = client.get("/sample/1")
    assert detail_response.status_code == 200
    assert "Technical Properties" in detail_response.text
    assert "Standard EICAR test string" in detail_response.text

    # Check secure download
    download_response = client.get("/download/1")
    assert download_response.status_code == 200
    assert download_response.content == file_payload
    assert download_response.headers["content-type"] == "application/octet-stream"
    assert download_response.headers["x-content-type-options"] == "nosniff"
    assert 'attachment; filename="eicar.com.bin"' in download_response.headers["content-disposition"]

def test_duplicate_upload_prevention(client):
    file_payload = b"duplicate test content"
    files = {"file": ("test.bin", file_payload, "application/octet-stream")}
    data = {"threat_type": "Trojan", "file_format": "ELF"}

    res1 = client.post("/upload", files=files, data=data, follow_redirects=True)
    assert res1.status_code == 200

    # Duplicate upload attempt
    files2 = {"file": ("test_dup.bin", file_payload, "application/octet-stream")}
    res2 = client.post("/upload", files=files2, data=data)
    assert res2.status_code == 200
    assert "Sample with matching SHA-256 hash already exists" in res2.text
