"""
Report Encryption Module
---------------------------
Encrypts generated PDF reports before they touch disk, and decrypts them
only in memory at download time. Uses Fernet (AES-128-CBC + HMAC-SHA256,
authenticated encryption) from the `cryptography` library rather than
hand-rolled crypto.

Threat model and what this does/doesn't protect against:
  - DOES protect against: casual/lazy disk exposure — a misconfigured
    backup snapshot, a log aggregator that slurps disk contents, anyone
    who can browse the filesystem but doesn't also have the env var, a
    `cat` of the raw file showing readable PDF content.
  - DOES NOT protect against: an attacker who compromises the running
    server process itself, since the key is loaded into that process's
    environment and used automatically with no human in the loop (there's
    no login step where a person enters a password). This is the correct
    tradeoff for a public, no-login tool — full key isolation would
    require per-visitor secrets, which doesn't fit this app's design.

Key source: the REPORT_ENCRYPTION_KEY environment variable, expected to be
a Fernet-format key (44 url-safe-base64 characters). If unset, a key is
auto-generated at process startup as a fallback so the app still runs —
but that fallback key only lives in process memory and is lost on every
restart, which means any report encrypted with it cannot be decrypted
after a restart (the report would already have been auto-deleted by the
30-minute retention sweep well before most restarts anyway, but this is
documented so it's not a surprise). For a real deployment, set
REPORT_ENCRYPTION_KEY explicitly in Render's environment variables so the
key is stable across restarts within its lifetime — generate one with:
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""
from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken

_ENV_VAR_NAME = "REPORT_ENCRYPTION_KEY"


def _load_or_generate_key() -> bytes:
    env_key = os.environ.get(_ENV_VAR_NAME)
    if env_key:
        return env_key.encode("utf-8")
    # Fallback: generate an ephemeral key for this process only. Logged as
    # a warning (not the key itself) so an operator notices and sets a
    # stable key in their environment instead of relying on this fallback.
    print(
        f"[report_encryption] WARNING: {_ENV_VAR_NAME} is not set. Using an "
        f"auto-generated key that only persists for this process's lifetime. "
        f"Set {_ENV_VAR_NAME} in your environment for stable encryption across restarts."
    )
    return Fernet.generate_key()


_KEY = _load_or_generate_key()
_fernet = Fernet(_KEY)


def encrypt_bytes(plaintext: bytes) -> bytes:
    return _fernet.encrypt(plaintext)


def decrypt_bytes(ciphertext: bytes) -> bytes:
    """Raises cryptography.fernet.InvalidToken if the key doesn't match
    (e.g. the server restarted and lost a fallback-generated key) or the
    data was tampered with/corrupted."""
    return _fernet.decrypt(ciphertext)


__all__ = ["encrypt_bytes", "decrypt_bytes", "InvalidToken"]
