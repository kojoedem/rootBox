import os
import pytest
import tempfile
from app.vault import store_in_vault, read_from_vault, compute_hashes_and_size, XOR_KEY

def test_vault_storage_and_containment(tmp_path, monkeypatch):
    test_vault_dir = tmp_path / "vault_test"
    monkeypatch.setenv("VAULT_DIR", str(test_vault_dir))

    sample_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    sha256, md5, size = compute_hashes_and_size(sample_content)

    vault_filename, stored_sha, stored_md5, stored_size = store_in_vault(sample_content)

    assert stored_sha == sha256
    assert stored_md5 == md5
    assert stored_size == len(sample_content)

    filepath = test_vault_dir / vault_filename
    assert filepath.exists()

    # Check that file on disk is obfuscated (not raw sample bytes)
    disk_data = filepath.read_bytes()
    assert disk_data != sample_content
    assert bytes([b ^ XOR_KEY for b in disk_data]) == sample_content

    # Check permissions (0600 -> stat permissions mask 0o777 should be 0o600)
    mode = filepath.stat().st_mode & 0o777
    assert mode == 0o600

    # Check retrieval deobfuscation
    retrieved = read_from_vault(vault_filename)
    assert retrieved == sample_content

def test_directory_traversal_prevention(tmp_path, monkeypatch):
    test_vault_dir = tmp_path / "vault_test"
    monkeypatch.setenv("VAULT_DIR", str(test_vault_dir))

    sample_content = b"test payload"
    vault_filename, _, _, _ = store_in_vault(sample_content)

    # Attempt path traversal
    retrieved = read_from_vault(f"../../{vault_filename}")
    assert retrieved == sample_content
