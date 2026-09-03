"""
Generates independent reference test vectors for our AES-256-GCM, PBKDF2,
and HKDF-SHA256 implementations, using Python's `cryptography` library
(OpenSSL-backed) as a completely separate implementation from the
Node/WebCrypto and @noble/* code under test in this package.

This is deliberately NOT hand-transcribed from memory of published NIST/RFC
vectors -- an independently *computed* cross-implementation vector is more
trustworthy than a hex string typed from recollection, and serves the same
purpose: proving our envelope code composes the primitives correctly.

Run: python3 generate_vectors.py > vectors.json
"""
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def h(b: bytes) -> str:
    return b.hex()


vectors = {"aes256gcm": [], "pbkdf2_sha256": [], "hkdf_sha256": []}

# --- AES-256-GCM: fixed key/iv/plaintext/aad cases, deterministic (no RNG) ---
aes_cases = [
    {"key": b"\x00" * 32, "iv": b"\x00" * 12, "plaintext": b"", "aad": b""},
    {"key": b"\x00" * 32, "iv": b"\x00" * 12, "plaintext": b"\x00" * 16, "aad": b""},
    {"key": bytes(range(32)), "iv": bytes(range(12)), "plaintext": b"The quick brown fox jumps over the lazy dog", "aad": b""},
    {"key": bytes(range(32)), "iv": bytes(range(100, 112)), "plaintext": b"PhantomVault production crypto core", "aad": b"header-v1"},
    {"key": os.urandom(32), "iv": os.urandom(12), "plaintext": os.urandom(256), "aad": b""},
]
for c in aes_cases:
    aes = AESGCM(c["key"])
    ct_and_tag = aes.encrypt(c["iv"], c["plaintext"], c["aad"] or None)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    vectors["aes256gcm"].append({
        "key": h(c["key"]), "iv": h(c["iv"]), "plaintext": h(c["plaintext"]),
        "aad": h(c["aad"]), "ciphertext": h(ciphertext), "tag": h(tag),
        "ciphertext_with_tag": h(ct_and_tag),
    })

# --- PBKDF2-HMAC-SHA256: fixed password/salt/iterations (kept low for fast CI; the
#     application itself uses 600k, see packages/crypto-core/src/primitives.ts) ---
pbkdf2_cases = [
    {"password": b"correct horse battery staple", "salt": b"\x00" * 16, "iterations": 1000, "length": 32},
    {"password": b"", "salt": b"salt", "iterations": 1, "length": 32},
    {"password": b"PhantomVault!", "salt": bytes(range(16)), "iterations": 10000, "length": 32},
]
for c in pbkdf2_cases:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=c["length"], salt=c["salt"], iterations=c["iterations"])
    derived = kdf.derive(c["password"])
    vectors["pbkdf2_sha256"].append({
        "password": c["password"].decode("latin1"), "salt": h(c["salt"]),
        "iterations": c["iterations"], "length": c["length"], "derived": h(derived),
    })

# --- HKDF-SHA256 ---
hkdf_cases = [
    {"ikm": b"\x0b" * 22, "salt": bytes(range(13)), "info": bytes(range(240, 250)), "length": 42},
    {"ikm": os.urandom(32), "salt": os.urandom(16), "info": b"phantomvault-sealed-box-v1", "length": 32},
]
for c in hkdf_cases:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=c["length"], salt=c["salt"], info=c["info"])
    derived = hkdf.derive(c["ikm"])
    vectors["hkdf_sha256"].append({
        "ikm": h(c["ikm"]), "salt": h(c["salt"]), "info": h(c["info"]),
        "length": c["length"], "okm": h(derived),
    })

print(json.dumps(vectors, indent=2))
