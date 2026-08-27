import os
import hashlib
import uuid

def get_vault_dir():
    return os.environ.get("VAULT_DIR", os.path.abspath("storage"))

XOR_KEY = 0x5A  # Simple byte XOR obfuscation key to ensure files stored on disk are inert/disarmed binaries

def ensure_vault_exists():
    os.makedirs(get_vault_dir(), mode=0o700, exist_ok=True)

def compute_hashes_and_size(data: bytes):
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    size = len(data)
    return sha256, md5, size

def obfuscate_data(data: bytes) -> bytes:
    """XOR obfuscates binary data so it cannot be directly executed as an active binary on the server disk."""
    return bytes([b ^ XOR_KEY for b in data])

def deobfuscate_data(data: bytes) -> bytes:
    """Reverses XOR obfuscation when retrieving raw file for authorized downloading."""
    return bytes([b ^ XOR_KEY for b in data])

def store_in_vault(data: bytes) -> tuple[str, str, str, int]:
    """
    Computes hashes and stores the obfuscated payload in the isolated storage directory.
    Returns: (vault_filename, sha256, md5, size)
    """
    ensure_vault_exists()
    sha256, md5, size = compute_hashes_and_size(data)

    # Generate unique quarantined filename with .quarantine extension
    vault_filename = f"{sha256}.quarantine"
    filepath = os.path.join(get_vault_dir(), vault_filename)

    # Obfuscate before writing
    obfuscated = obfuscate_data(data)

    with open(filepath, "wb") as f:
        f.write(obfuscated)

    # Restrict permissions to owner read/write only (0600)
    os.chmod(filepath, 0o600)

    return vault_filename, sha256, md5, size

def read_from_vault(vault_filename: str) -> bytes:
    """
    Reads the quarantined file from vault directory, deobfuscates it, and returns raw bytes.
    Prevents directory traversal vulnerabilities.
    """
    ensure_vault_exists()

    # Prevent directory traversal
    safe_filename = os.path.basename(vault_filename)
    filepath = os.path.join(get_vault_dir(), safe_filename)

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Sample file {vault_filename} not found in vault.")

    with open(filepath, "rb") as f:
        obfuscated = f.read()

    return deobfuscate_data(obfuscated)
