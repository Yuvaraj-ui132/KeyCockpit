"""The backend's key authority: issues signed key certificates and revocation lists.

A key certificate is just a JSON payload plus an Ed25519 signature made with the
issuer's private key. The car only needs the issuer's PUBLIC key, so it can
verify certificates with no internet connection.
"""

from __future__ import annotations

import os
import time
from typing import Callable, Optional

from . import crypto

# Which commands each role may run. The list is copied into the signed
# certificate, so the car does not have to ask the backend what a key may do.
ROLE_PERMISSIONS = {
    "owner": ("lock", "unlock", "open_trunk", "open_glovebox", "start", "stop"),
    "guest": ("lock", "unlock", "open_trunk", "start", "stop"),
    "valet": ("lock", "unlock", "start", "stop"),
}

# Short lifetimes limit the damage of a stolen phone while a car is offline and
# cannot receive a revocation yet.
MAX_VALID_MINUTES = {
    "owner": 30 * 24 * 60,
    "guest": 7 * 24 * 60,
    "valet": 12 * 60,
}


def sign_payload(private_key, payload: dict) -> dict:
    return {"payload": payload, "sig": crypto.sign(private_key, crypto.canonical(payload))}


def verify_signed(issuer_public_key: str, signed) -> Optional[dict]:
    """Return the payload if `signed` carries a valid issuer signature, else None."""
    try:
        payload = signed["payload"]
        signature = signed["sig"]
    except (KeyError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    if not crypto.verify(issuer_public_key, crypto.canonical(payload), signature):
        return None
    return payload


class KeyIssuer:
    def __init__(self, private_key, clock: Callable[[], float] = time.time):
        self._key = private_key
        self._clock = clock

    @property
    def public_key(self) -> str:
        return crypto.public_key_b64(self._key)

    def issue(
        self,
        vehicle_id: str,
        holder: str,
        role: str,
        phone_public_key: str,
        valid_minutes: float,
    ) -> dict:
        """Create a signed certificate that binds a phone's public key to a vehicle."""
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"unknown role: {role}")
        if (
            isinstance(valid_minutes, bool)
            or not isinstance(valid_minutes, (int, float))
            or valid_minutes <= 0
        ):
            raise ValueError("valid_minutes must be a positive number")
        cap = MAX_VALID_MINUTES[role]
        if valid_minutes > cap:
            raise ValueError(f"{role} keys can be valid for at most {cap} minutes")
        if len(crypto.b64d(phone_public_key)) != 32:
            raise ValueError("phone_public_key must be a 32-byte Ed25519 public key")

        now = int(self._clock())
        payload = {
            "v": 1,
            "key_id": os.urandom(8).hex(),
            "vehicle_id": vehicle_id,
            "holder": holder,
            "role": role,
            "perms": list(ROLE_PERMISSIONS[role]),
            "phone_pub": phone_public_key,
            "not_before": now,
            "not_after": now + int(valid_minutes * 60),
        }
        return sign_payload(self._key, payload)

    def revocation_list(self, vehicle_id: str, revoked_key_ids) -> dict:
        """Signed list of revoked keys for one vehicle.

        `version` only ever grows (keys are never un-revoked), so a car can
        refuse an older list that an attacker replays to bring a key back.
        """
        ids = sorted(revoked_key_ids)
        payload = {
            "v": 1,
            "vehicle_id": vehicle_id,
            "version": len(ids),
            "revoked": ids,
            "issued_at": int(self._clock()),
        }
        return sign_payload(self._key, payload)
