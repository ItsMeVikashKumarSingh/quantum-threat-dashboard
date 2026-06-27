import re
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

# Regex patterns for scanning code/text files
ALGO_PATTERNS = {
    "MD5": re.compile(r"\bmd5\b", re.IGNORECASE),
    "SHA-1": re.compile(r"\bsha-?1\b", re.IGNORECASE),
    "DES": re.compile(r"\bdes\b", re.IGNORECASE),
    "3DES": re.compile(r"\b(3des|triple-?des)\b", re.IGNORECASE),
    "RC4": re.compile(r"\brc4\b", re.IGNORECASE),
    "RSA-1024": re.compile(r"\brsa[-_]?1024\b", re.IGNORECASE),
    "RSA-2048": re.compile(r"\brsa[-_]?2048\b", re.IGNORECASE),
    "RSA-4096": re.compile(r"\brsa[-_]?4096\b", re.IGNORECASE),
    "AES-128": re.compile(r"\baes[-_]?128\b", re.IGNORECASE),
    "AES-256": re.compile(r"\baes[-_]?256\b", re.IGNORECASE),
}

def analyze_raw_text(text: str, filename: str) -> list:
    """Scan raw text/config content for references to legacy cryptographic algorithms."""
    results = []
    for algo_name, pattern in ALGO_PATTERNS.items():
        if pattern.search(text):
            # Classify
            if algo_name in ["MD5", "SHA-1", "DES", "3DES", "RC4", "RSA-1024"]:
                threat = "High"
            elif algo_name in ["RSA-2048", "RSA-4096", "AES-128", "AES-256"]:
                threat = "Medium"
            else:
                threat = "Low"
            
            results.append({
                "name": f"{filename} ({algo_name} reference)",
                "asset_type": "Configuration File",
                "detected_algorithm": algo_name,
                "key_size": 1024 if "1024" in algo_name else (2048 if "2048" in algo_name else None),
                "threat_level": threat
            })
    return results

def analyze_crypto_file(file_bytes: bytes, filename: str) -> list:
    """Attempt to parse bytes as X.509 certificate or PEM key. Fallback to text scanning."""
    # 1. Try parsing as X509 Certificate
    try:
        cert = x509.load_pem_x509_certificate(file_bytes)
        pub_key = cert.public_key()
        return [extract_key_info(pub_key, f"Certificate: {filename}")]
    except Exception:
        pass
        
    # 2. Try parsing as Private Key
    try:
        priv_key = serialization.load_pem_private_key(file_bytes, password=None)
        pub_key = priv_key.public_key()
        return [extract_key_info(pub_key, f"Private Key: {filename}")]
    except Exception:
        pass
        
    # 3. Try parsing as Public Key
    try:
        pub_key = serialization.load_pem_public_key(file_bytes)
        return [extract_key_info(pub_key, f"Public Key: {filename}")]
    except Exception:
        pass
        
    # 4. Fallback to text scanning
    try:
        text = file_bytes.decode("utf-8", errors="ignore")
        return analyze_raw_text(text, filename)
    except Exception:
        return []

def extract_key_info(pub_key, name: str) -> dict:
    """Extract key type, size, and threat level from a cryptography public key object."""
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_size = pub_key.key_size
        algo = f"RSA-{key_size}"
        if key_size < 2048:
            threat = "High"
        else:
            threat = "Medium" # Classically secure but vulnerable to Shor
        return {
            "name": name,
            "asset_type": "Cryptographic Key",
            "detected_algorithm": algo,
            "key_size": key_size,
            "threat_level": threat
        }
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        curve_name = pub_key.curve.name
        algo = f"ECDSA-{curve_name}"
        # ECDSA is classically secure, but highly vulnerable to Shor
        return {
            "name": name,
            "asset_type": "Cryptographic Key",
            "detected_algorithm": algo,
            "key_size": pub_key.key_size,
            "threat_level": "Medium"
        }
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_size = pub_key.key_size
        algo = f"DSA-{key_size}"
        return {
            "name": name,
            "asset_type": "Cryptographic Key",
            "detected_algorithm": algo,
            "key_size": key_size,
            "threat_level": "High"
        }
    else:
        return {
            "name": name,
            "asset_type": "Cryptographic Key",
            "detected_algorithm": "Unknown Classical",
            "key_size": None,
            "threat_level": "High"
        }
