"""Bytes that the phone signs and the car re-builds to verify."""

from __future__ import annotations

from . import crypto

PROTOCOL_VERSION = 1


def unlock_message(
    vehicle_id: str, challenge_id: str, nonce: str, key_id: str, command: str
) -> bytes:
    """What the phone signs for one command.

    The vehicle, the one-time challenge, the key and the command are all inside
    the signed bytes. A captured signature therefore cannot be reused later
    (fresh nonce), on another car (vehicle_id) or for another action (command).
    """
    return crypto.canonical(
        {
            "v": PROTOCOL_VERSION,
            "vehicle_id": vehicle_id,
            "challenge_id": challenge_id,
            "nonce": nonce,
            "key_id": key_id,
            "command": command,
        }
    )
