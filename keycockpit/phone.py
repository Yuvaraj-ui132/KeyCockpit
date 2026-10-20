"""A simulated phone holding a private key and a key certificate.

On a real phone the private key lives in secure hardware (Android Keystore /
Secure Element) and never leaves it. Here it is just an object in memory.
"""

from __future__ import annotations

from typing import Optional

from . import crypto, protocol
from .car import Car


class Phone:
    def __init__(self, holder: str, private_key=None):
        self.holder = holder
        self._key = private_key or crypto.generate_private_key()
        self.certificate: Optional[dict] = None
        self.session: Optional[str] = None  # returned by the car when the engine starts
        self.last_message: Optional[dict] = None  # what went over the air (an eavesdropper sees it)

    @property
    def public_key(self) -> str:
        return crypto.public_key_b64(self._key)

    def sign(self, vehicle_id: str, challenge: dict, key_id: str, command: str) -> str:
        message = protocol.unlock_message(
            vehicle_id, challenge["challenge_id"], challenge["nonce"], key_id, command
        )
        return crypto.sign(self._key, message)

    def press(self, car: Car, command: str, link_delay_s: float = 0.0) -> dict:
        """Run the whole handshake with a car: challenge, sign, send, read the answer.

        `link_delay_s` is how long the reply takes to arrive. Normal short-range
        radio is a few milliseconds; a relay attacker adds much more.
        """
        if self.certificate is None:
            raise RuntimeError("this phone has no key certificate yet")
        challenge = car.new_challenge()
        key_id = self.certificate["payload"]["key_id"]
        signature = self.sign(car.vehicle_id, challenge, key_id, command)
        self.last_message = {
            "certificate": self.certificate,
            "challenge_id": challenge["challenge_id"],
            "command": command,
            "signature": signature,
        }
        with car.link_delay(link_delay_s):
            result = car.handle(self.certificate, challenge["challenge_id"], command, signature)
        if result.get("ok") and result.get("session"):
            self.session = result["session"]
        return result
