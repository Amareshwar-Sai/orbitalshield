"""
OrbitalShield - Auth & Integrity Module
Handles tokens, nonces, HMAC checksums, and message signing.
"""
from typing import Tuple, Optional

import hashlib
import hmac
import time
import uuid
import json
from config.settings import SECRET_KEY, TOKEN_VALIDITY_SECONDS, NONCE_EXPIRY_SECONDS

# In-memory nonce store: {nonce: timestamp}
_used_nonces = {}


def generate_token(source_id: str) -> dict:
    """Generate a time-limited auth token for a source node."""
    issued_at = time.time()
    expires_at = issued_at + TOKEN_VALIDITY_SECONDS
    payload = f"{source_id}:{issued_at}:{expires_at}"
    signature = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return {
        "source_id": source_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "signature": signature,
    }


def validate_token(token: dict) -> Tuple[bool, str]:
    """Validate a token. Returns (valid: bool, reason: str)."""
    try:
        source_id = token["source_id"]
        issued_at = token["issued_at"]
        expires_at = token["expires_at"]
        signature = token["signature"]
    except KeyError as e:
        return False, f"Missing token field: {e}"

    if time.time() > expires_at:
        return False, "Token expired"

    expected_payload = f"{source_id}:{issued_at}:{expires_at}"
    expected_sig = hmac.new(SECRET_KEY.encode(), expected_payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_sig):
        return False, "Token signature invalid"

    return True, "OK"


def generate_nonce() -> str:
    """Generate a unique nonce."""
    return str(uuid.uuid4())


def validate_nonce(nonce: str) -> Tuple[bool, str]:
    """Check nonce hasn't been used before (replay protection)."""
    _cleanup_nonces()
    if nonce in _used_nonces:
        return False, "Replay detected: nonce already used"
    _used_nonces[nonce] = time.time()
    return True, "OK"


def _cleanup_nonces():
    """Expire old nonces."""
    now = time.time()
    expired = [n for n, t in _used_nonces.items() if now - t > NONCE_EXPIRY_SECONDS]
    for n in expired:
        del _used_nonces[n]


def compute_checksum(data: dict) -> str:
    """Compute SHA-256 checksum of a dict payload."""
    payload = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def verify_checksum(data: dict, checksum: str) -> bool:
    """Verify integrity of a received message."""
    return compute_checksum(data) == checksum


def sign_message(message: dict) -> dict:
    """Add nonce + checksum to a message dict."""
    message = dict(message)
    message["nonce"] = generate_nonce()
    # Checksum over everything except the checksum field itself
    message["checksum"] = compute_checksum({k: v for k, v in message.items() if k != "checksum"})
    return message


def verify_message(message: dict) -> Tuple[bool, str]:
    """Full message integrity + replay check."""
    nonce = message.get("nonce")
    checksum = message.get("checksum")

    if not nonce:
        return False, "Missing nonce"
    if not checksum:
        return False, "Missing checksum"

    # Replay check
    valid, reason = validate_nonce(nonce)
    if not valid:
        return False, reason

    # Integrity check
    payload = {k: v for k, v in message.items() if k != "checksum"}
    if not verify_checksum(payload, checksum):
        return False, "Checksum mismatch - message tampered"

    return True, "OK"
