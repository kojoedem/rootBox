import math
import re
from typing import Dict, Any, List

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculates Shannon Entropy of a binary payload (range 0.0 to 8.0).
    Higher entropy (> 7.0) typically indicates packed, obfuscated, or encrypted payloads.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return round(entropy, 3)

def detect_magic_file_type(data: bytes) -> str:
    """
    Identifies common file signatures / magic bytes.
    """
    if not data:
        return "Empty File"

    if data.startswith(b"MZ"):
        return "Windows Portable Executable (PE/EXE/DLL)"
    elif data.startswith(b"\x7fELF"):
        return "Linux ELF Executable"
    elif data.startswith(b"%PDF"):
        return "PDF Document"
    elif data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return "ZIP Archive / Compressed Document"
    elif data.startswith(b"\x1f\x8b"):
        return "GZIP Compressed File"
    elif data.startswith(b"Rar!\x1a\x07"):
        return "RAR Archive"
    elif data.startswith(b"CAFEBABE") or data.startswith(b"\xca\xfe\xba\xbe"):
        return "Java Class File / Mach-O Binary"
    elif data.startswith(b"<!DOCTYPE") or data.startswith(b"<html") or data.startswith(b"<?xml"):
        return "HTML / XML Document"
    elif data.startswith(b"#!/"):
        return "Shell / Script Executable"
    elif b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data:
        return "EICAR Standard Antivirus Test Pattern"
    else:
        return "Raw Binary Data / Unknown Magic"

def extract_strings(data: bytes, min_len: int = 4, max_count: int = 40) -> List[str]:
    """
    Extracts printable ASCII and Unicode strings from binary payload for IoC inspection.
    """
    # ASCII strings
    ascii_re = re.compile(f"[\x20-\x7E]{{{min_len},}}".encode("ascii"))
    strings = [s.decode("ascii", errors="ignore") for s in ascii_re.findall(data)]

    # Deduplicate while preserving order
    seen = set()
    unique_strings = []
    for s in strings:
        cleaned = s.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_strings.append(cleaned)
            if len(unique_strings) >= max_count:
                break

    return unique_strings

def assess_harm_level(data: bytes, entropy: float, magic_type: str, extracted_strings: List[str]) -> tuple[int, str]:
    """
    Background heuristic analysis assessing whether the payload is harmful, suspicious, or low risk.
    Returns: (threat_score: int [0-100], threat_level: str)
    """
    score = 0

    # 1. Check EICAR standard test pattern
    if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data:
        return 95, "Harmful / High Risk (Test Threat Pattern)"

    # 2. Check Magic Byte Executable Signatures
    if "Executable" in magic_type or "PE/EXE/DLL" in magic_type or "ELF" in magic_type:
        score += 35

    # 3. High Entropy Check (Packing / Encryption / Obfuscation)
    if entropy > 7.2:
        score += 35
    elif entropy > 6.0:
        score += 15

    # 4. IoC String Inspection (Dangerous system calls, shell scripts, C2 patterns, ransomware terms)
    high_risk_patterns = [
        r"powershell", r"cmd\.exe", r"wscript", r"cscript", r"regadd", r"vssadmin",
        r"bitcoin", r"ransom", r"decrypt", r"wallet", r"socket", r"connect",
        r"downloadstring", r"exec", r"system\(", r"eval\(", r"chmod \+x"
    ]

    suspicious_string_hits = 0
    all_text = " ".join(extracted_strings).lower()
    for pat in high_risk_patterns:
        if re.search(pat, all_text):
            suspicious_string_hits += 1

    if suspicious_string_hits >= 3:
        score += 35
    elif suspicious_string_hits >= 1:
        score += 20

    # Cap score at 100
    final_score = min(score, 100)

    if final_score >= 60:
        level = "Harmful / High Risk"
    elif final_score >= 30:
        level = "Suspicious / Moderate Risk"
    else:
        level = "Low Risk / Likely Benign"

    return final_score, level

def generate_hex_dump(data: bytes, max_bytes: int = 256) -> str:
    """
    Generates formatted hex dump preview (address, hex bytes, ascii representation).
    """
    chunk = data[:max_bytes]
    lines = []
    for i in range(0, len(chunk), 16):
        sub_chunk = chunk[i:i+16]
        hex_bytes = " ".join(f"{b:02x}" for b in sub_chunk)
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in sub_chunk)
        lines.append(f"{i:08x}  {hex_bytes:<48}  |{ascii_chars}|")
    return "\n".join(lines)

def generate_yara_rule(sample_name: str, sha256: str, threat_type: str, extracted_strings: List[str]) -> str:
    """
    Generates a functional YARA rule for threat detection based on sample hashes and extracted IoC strings.
    """
    safe_rule_name = re.sub(r"[^a-zA-Z0-9_]", "_", sample_name.replace(" ", "_"))
    if not safe_rule_name or safe_rule_name[0].isdigit():
        safe_rule_name = f"Sample_{safe_rule_name}"

    string_rules = []
    for idx, s in enumerate(extracted_strings[:5]):
        escaped_str = s.replace('\\', '\\\\').replace('"', '\\"')
        string_rules.append(f'        $str{idx + 1} = "{escaped_str}" ascii wide')

    strings_block = "\n".join(string_rules) if string_rules else '        $hash_id = "' + sha256[:16] + '"'
    condition = "any of ($str*)" if string_rules else "any of them"

    yara_code = f"""rule rootBox_{safe_rule_name} {{
    meta:
        description = "Automated YARA rule generated by rootBox Malware Vault"
        author = "rootBox Security Analyst Lab"
        threat_type = "{threat_type}"
        sha256 = "{sha256}"
        date = "2025-01-01"

    strings:
{strings_block}

    condition:
        {condition}
}}"""
    return yara_code

def analyze_binary(data: bytes, original_filename: str, sha256: str, threat_type: str) -> Dict[str, Any]:
    """
    Runs full static analysis pipeline on raw binary data.
    """
    entropy = calculate_shannon_entropy(data)
    magic_type = detect_magic_file_type(data)
    strings = extract_strings(data)
    hex_dump = generate_hex_dump(data)
    yara_rule = generate_yara_rule(original_filename, sha256, threat_type, strings)
    threat_score, threat_level = assess_harm_level(data, entropy, magic_type, strings)

    # Entropy interpretation
    if entropy > 7.2:
        entropy_level = "High (Likely Packed / Encrypted / Compressed)"
        entropy_color = "red"
    elif entropy > 5.5:
        entropy_level = "Moderate (Standard Code / Mixed Binary Data)"
        entropy_color = "yellow"
    else:
        entropy_level = "Low (Plaintext / Sparse / Uncompressed Data)"
        entropy_color = "green"

    return {
        "entropy": entropy,
        "entropy_level": entropy_level,
        "entropy_color": entropy_color,
        "magic_type": magic_type,
        "extracted_strings": strings,
        "hex_dump": hex_dump,
        "yara_rule": yara_rule,
        "threat_score": threat_score,
        "threat_level": threat_level
    }
