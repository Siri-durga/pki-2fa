#!/usr/bin/env python3

import time
from pathlib import Path
import base64 as _b64
import pyotp
from datetime import datetime, timezone

SEED_FILE = Path("/data/seed.txt")
LOG_FILE = Path("/cron/last_code.txt")

TOTP_PERIOD = 30
TOTP_DIGITS = 6


def hex_seed_to_base32(hex_seed: str) -> str:
    """
    Convert 64-char hex seed to base32 for pyotp.
    """
    b = bytes.fromhex(hex_seed)
    return _b64.b32encode(b).decode("utf-8")


def generate_totp(hex_seed: str) -> str:
    """
    Generate 6-digit TOTP code.
    """
    b32 = hex_seed_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=TOTP_DIGITS, interval=TOTP_PERIOD)
    return totp.now()


def log(message: str):
    """
    Append message to cron log file.
    """
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")


def main():
    if not SEED_FILE.exists():
        log("[ERROR] Seed file missing at /data/seed.txt")
        return

    try:
        hex_seed = SEED_FILE.read_text().strip()
        code = generate_totp(hex_seed)

        # Timestamp in UTC
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        log(f"{timestamp} - 2FA Code: {code}")

    except Exception as e:
        log(f"[ERROR] {e}")


if __name__ == "__main__":
    main()
