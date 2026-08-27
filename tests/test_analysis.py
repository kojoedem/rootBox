import pytest
from app.analysis import calculate_shannon_entropy, detect_magic_file_type, extract_strings, generate_hex_dump, generate_yara_rule, analyze_binary

def test_shannon_entropy():
    # Low entropy (all zeros)
    assert calculate_shannon_entropy(b"\x00" * 100) == 0.0

    # High entropy (random bytes)
    random_bytes = bytes(range(256))
    assert calculate_shannon_entropy(random_bytes) == 8.0

def test_detect_magic_file_type():
    assert detect_magic_file_type(b"MZ\x90\x00") == "Windows Portable Executable (PE/EXE/DLL)"
    assert detect_magic_file_type(b"\x7fELF\x02") == "Linux ELF Executable"
    assert detect_magic_file_type(b"%PDF-1.7") == "PDF Document"
    assert detect_magic_file_type(b"PK\x03\x04") == "ZIP Archive / Compressed Document"
    assert detect_magic_file_type(b"CAFEBABE") == "Java Class File / Mach-O Binary"

def test_extract_strings():
    data = b"Hello\x00\x00World_Test_String_1234\x00\x01\x02"
    strings = extract_strings(data, min_len=4)
    assert "Hello" in strings
    assert "World_Test_String_1234" in strings

def test_generate_yara_rule():
    rule = generate_yara_rule("test_sample.exe", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "Trojan", ["http://malicious.domain/c2"])
    assert "rule rootBox_test_sample_exe" in rule
    assert "http://malicious.domain/c2" in rule
    assert "sha256 = \"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\"" in rule

def test_analyze_binary():
    payload = b"MZ\x90\x00Test_Binary_Payload_String"
    results = analyze_binary(payload, "test.exe", "fakehash", "Trojan")
    assert results["magic_type"] == "Windows Portable Executable (PE/EXE/DLL)"
    assert "entropy" in results
    assert "hex_dump" in results
    assert "yara_rule" in results
