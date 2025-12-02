# app/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64
import base64 as _b64
import time
from pathlib import Path
from typing import Dict

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes

import pyotp

# -------------------------
# Configuration / paths
# -------------------------
# For local Windows testing we use a project-relative ./data folder.
# In Docker, this should be mounted to the container's /data volume.
DATA_DIR = Path("./data")
SEED_FILE = DATA_DIR / "seed.txt"
PRIVATE_KEY_PATH = Path("student_private.pem")

# TOTP parameters (must match the assignment)
TOTP_PERIOD = 30
TOTP_DIGITS = 6

app = FastAPI(title="GPP PKI-2FA Microservice")


# -------------------------
# Request models
# -------------------------
class DecryptRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str


# -------------------------
# Cryptography helpers
# -------------------------
def decrypt_seed_bytes(encrypted_seed_b64: str, private_key_path: Path) -> str:
    """
    Decrypt base64-encoded ciphertext using RSA/OAEP with SHA-256.
    Returns a lowercase 64-char hex string on success, raises ValueError on failure.
    """
    # Validate input presence
    if not encrypted_seed_b64 or not isinstance(encrypted_seed_b64, str):
        raise ValueError("Missing or invalid encrypted_seed")

    # Load private key
    if not private_key_path.exists():
        raise ValueError("Private key file not found")

    key_data = private_key_path.read_bytes()
    try:
        private_key = load_pem_private_key(key_data, password=None)
    except Exception as exc:
        raise ValueError(f"Failed to load private key: {exc}")

    # Base64 decode ciphertext
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except Exception as exc:
        raise ValueError(f"Base64 decode error: {exc}")

    # Decrypt with OAEP(SHA-256, MGF1(SHA-256))
    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as exc:
        raise ValueError(f"Decryption failed: {exc}")

    # Decode and validate hex string
    try:
        seed_str = plaintext_bytes.decode("utf-8").strip()
    except Exception as exc:
        raise ValueError(f"Failed to decode plaintext: {exc}")

    if len(seed_str) != 64 or not all(c in "0123456789abcdefABCDEF" for c in seed_str):
        raise ValueError("Decrypted seed is not a 64-character hex string")

    return seed_str.lower()


def save_seed(seed_hex: str) -> None:
    """
    Save hex seed to disk at SEED_FILE (create DATA_DIR if necessary).
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SEED_FILE.write_text(seed_hex, encoding="utf-8")
    # best-effort permission set; on Windows this is mostly a no-op
    try:
        import os
        os.chmod(SEED_FILE, 0o600)
    except Exception:
        pass


# -------------------------
# TOTP helpers
# -------------------------
def hex_seed_to_base32(hex_seed: str) -> str:
    """
    Convert 64-char hex seed to base32 string accepted by pyotp.
    """
    b = bytes.fromhex(hex_seed)
    b32 = _b64.b32encode(b).decode("utf-8")
    return b32


def generate_totp_from_hex(hex_seed: str) -> str:
    """
    Generate TOTP (6-digit) for the current time from hex seed.
    """
    b32 = hex_seed_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=TOTP_DIGITS, interval=TOTP_PERIOD)
    return totp.now()


def get_totp_valid_for_seconds() -> int:
    """
    Return remaining seconds in the current TOTP step (1..TOTP_PERIOD).
    """
    epoch = int(time.time())
    elapsed = epoch % TOTP_PERIOD
    remaining = TOTP_PERIOD - elapsed
    # If remaining == TOTP_PERIOD then next tick just happened; we want 30..1 range.
    return remaining


# -------------------------
# API endpoints
# -------------------------
@app.post("/decrypt-seed")
def decrypt_seed_endpoint(req: DecryptRequest) -> Dict[str, str]:
    """
    POST /decrypt-seed
    Body: {"encrypted_seed": "BASE64..."}
    On success: {"status": "ok"} (and seed saved to disk)
    On failure: HTTP 500 with {"error": "Decryption failed"}
    """
    try:
        seed_hex = decrypt_seed_bytes(req.encrypted_seed, PRIVATE_KEY_PATH)
    except Exception:
        # Do not leak internal errors to the client
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

    try:
        save_seed(seed_hex)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Failed to save seed"})

    return {"status": "ok"}


@app.get("/generate-2fa")
def generate_2fa():
    """
    GET /generate-2fa
    Returns: {"code": "123456", "valid_for": 30}
    """
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    hex_seed = SEED_FILE.read_text().strip()
    try:
        code = generate_totp_from_hex(hex_seed)
        valid_for = get_totp_valid_for_seconds()
        return {"code": code, "valid_for": valid_for}
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Failed to generate code"})


@app.post("/verify-2fa")
def verify_2fa(req: VerifyRequest):
    """
    POST /verify-2fa
    Body: {"code": "123456"}
    Returns: {"valid": true} or {"valid": false}
    """
    if not req.code:
        raise HTTPException(status_code=400, detail={"error": "Missing code"})
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    hex_seed = SEED_FILE.read_text().strip()
    try:
        b32 = hex_seed_to_base32(hex_seed)
        totp = pyotp.TOTP(b32, digits=TOTP_DIGITS, interval=TOTP_PERIOD)
        valid = totp.verify(req.code, valid_window=1)  # ±1 period tolerance
        return {"valid": bool(valid)}
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Verification failed"})
