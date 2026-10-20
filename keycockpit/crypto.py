"""Small helpers around Ed25519 (via the `cryptography` package)."""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64e(data: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    """Inverse of b64e. Raises ValueError on anything that is not valid base64."""
    if not isinstance(text, str):
        raise ValueError("expected a base64 string")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(obj: Any) -> bytes:
    """Deterministic JSON bytes, so signer and verifier hash identical input."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_b64(key: Ed25519PrivateKey) -> str:
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return b64e(raw)


def private_key_from_b64(text: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b64d(text))


def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64e(raw)


def sign(key: Ed25519PrivateKey, data: bytes) -> str:
    return b64e(key.sign(data))


def verify(public_b64: str, data: bytes, signature_b64: str) -> bool:
    """True only if the signature is valid. Malformed input counts as invalid."""
    try:
        Ed25519PublicKey.from_public_bytes(b64d(public_b64)).verify(
            b64d(signature_b64), data
        )
        return True
    except (InvalidSignature, ValueError):
        return False
