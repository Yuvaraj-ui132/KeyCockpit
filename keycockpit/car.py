"""A simulated vehicle ECU ("the car").

The car works fully OFFLINE. It knows only:
  * the issuer's public key (to check key certificates and revocation lists),
  * the last revocation list it received,
  * its own clock.

It never calls the backend to decide whether to open. That is the point: a car
in an underground car park has no internet.
"""

from __future__ import annotations

import contextlib
import hmac
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Optional

from . import crypto, issuer, protocol

COMMANDS = ("lock", "unlock", "open_trunk", "open_glovebox", "start", "stop")


class SimClock:
    """Real time plus a controllable offset, so tests and demos can fake delay.

    `delayed(s)` adds `s` seconds only while a message is "in flight" (used to
    simulate radio latency and relay attackers). `advance(s)` moves time on for
    good (used to test certificate expiry).
    """

    def __init__(self, start: Optional[float] = None):
        self._start = start
        self._offset = 0.0

    def __call__(self) -> float:
        base = time.time() if self._start is None else self._start
        return base + self._offset

    def advance(self, seconds: float) -> None:
        self._offset += seconds

    @contextmanager
    def delayed(self, seconds: float):
        self._offset += seconds
        try:
            yield
        finally:
            self._offset -= seconds


@dataclass
class CarState:
    locked: bool = True
    trunk_open: bool = False
    glovebox_open: bool = False
    engine_on: bool = False
    holder: Optional[str] = None
    role: Optional[str] = None
    key_id: Optional[str] = None


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def clean_projection(data) -> dict:
    """Keep only the fields the cockpit knows, as short plain strings/ints.

    Whatever a phone sends is untrusted. The dashboard also renders it with
    textContent, so markup in these strings is never interpreted.
    """
    out: dict = {}
    if not isinstance(data, dict):
        return out

    def text(value, limit):
        return value[:limit] if isinstance(value, str) else ""

    nav = data.get("nav")
    if isinstance(nav, dict):
        out["nav"] = {
            "destination": text(nav.get("destination"), 80),
            "eta_min": nav["eta_min"] if _is_int(nav.get("eta_min")) else None,
        }
    media = data.get("media")
    if isinstance(media, dict):
        out["media"] = {
            "title": text(media.get("title"), 80),
            "artist": text(media.get("artist"), 80),
        }
    call = data.get("call")
    if isinstance(call, dict):
        out["call"] = {"name": text(call.get("name"), 40)}
    return out


class Car:
    def __init__(
        self,
        vehicle_id: str,
        issuer_public_key: str,
        clock: Callable[[], float] = time.time,
        max_response_s: float = 0.15,
        challenge_ttl_s: float = 10.0,
        max_open_challenges: int = 16,
        clock_skew_s: float = 60.0,
    ):
        self.vehicle_id = vehicle_id
        self._issuer_pub = issuer_public_key
        self._clock = clock
        self.max_response_s = max_response_s
        self._challenge_ttl_s = challenge_ttl_s
        self._max_open = max_open_challenges
        self._skew = clock_skew_s
        self._challenges: dict[str, tuple[str, float]] = {}
        self._revoked: set[str] = set()
        self.revocation_version = 0
        self._session: Optional[str] = None
        self.state = CarState()
        self.projection: dict = {}

    # -- radio link helper -------------------------------------------------

    def link_delay(self, seconds: float):
        """Context manager: messages delivered inside it arrive `seconds` late."""
        delayed = getattr(self._clock, "delayed", None)
        if delayed is None or not seconds:
            return contextlib.nullcontext()
        return delayed(seconds)

    # -- challenge/response ------------------------------------------------

    def new_challenge(self) -> dict:
        now = self._clock()
        for cid in [c for c, (_, t) in self._challenges.items() if now - t > self._challenge_ttl_s]:
            del self._challenges[cid]
        while len(self._challenges) >= self._max_open:
            del self._challenges[next(iter(self._challenges))]  # drop the oldest
        challenge_id, nonce = os.urandom(8).hex(), os.urandom(16).hex()
        self._challenges[challenge_id] = (nonce, now)
        return {"challenge_id": challenge_id, "nonce": nonce}

    def handle(self, certificate, challenge_id, command, signature) -> dict:
        """Check a command from a phone. Every check runs before anything moves."""
        if not (
            isinstance(challenge_id, str)
            and isinstance(command, str)
            and isinstance(signature, str)
        ):
            return self._deny("bad_request")
        if command not in COMMANDS:
            return self._deny("unknown_command")

        # 1. Each challenge works once: it is removed here, pass or fail.
        entry = self._challenges.pop(challenge_id, None)
        if entry is None:
            return self._deny("unknown_challenge")  # replayed, expired or invented
        nonce, issued_at = entry
        now = self._clock()

        # 2. Distance bounding by timing: a relayed answer is slow.
        if now - issued_at > self.max_response_s:
            return self._deny("too_slow")

        # 3. The certificate must be signed by the backend (checked offline).
        cert = issuer.verify_signed(self._issuer_pub, certificate)
        if cert is None:
            return self._deny("bad_certificate")
        try:
            key_id = cert["key_id"]
            holder = cert["holder"]
            role = cert["role"]
            phone_pub = cert["phone_pub"]
            perms = cert["perms"]
            who = {"key_id": key_id, "holder": holder}  # verified, so safe to log
            if cert["vehicle_id"] != self.vehicle_id:
                return self._deny("wrong_vehicle", who)
            if now < cert["not_before"] - self._skew:
                return self._deny("not_yet_valid", who)
            if now >= cert["not_after"]:
                return self._deny("expired", who)
        except (KeyError, TypeError):
            return self._deny("bad_certificate")

        # 4. Not on the revocation list this car currently knows.
        if key_id in self._revoked:
            return self._deny("revoked", who)

        # 5. Proof of possession: only the phone's private key can sign this.
        message = protocol.unlock_message(self.vehicle_id, challenge_id, nonce, key_id, command)
        if not crypto.verify(phone_pub, message, signature):
            return self._deny("bad_signature", who)

        # 6. The key's role must allow this command.
        if command not in perms:
            return self._deny("not_permitted", who)

        # 7. While the engine runs, only the key that started it may command.
        if self.state.engine_on and key_id != self.state.key_id:
            return self._deny("in_use", who)

        return self._apply(command, key_id, holder, role)

    # -- state machine -----------------------------------------------------

    def _apply(self, command: str, key_id: str, holder: str, role: str) -> dict:
        s = self.state
        session = None
        who = {"key_id": key_id, "holder": holder}
        if command == "lock":
            if s.engine_on:
                return self._deny("engine_running", who)
            self.state = CarState()
            self._session = None
            self.projection = {}
        elif command == "unlock":
            s.locked = False
            s.holder, s.role, s.key_id = holder, role, key_id
        elif command in ("open_trunk", "open_glovebox"):
            if s.locked:
                return self._deny("car_locked", who)
            if command == "open_trunk":
                s.trunk_open = True
            else:
                s.glovebox_open = True
        elif command == "start":
            if s.locked:
                return self._deny("car_locked", who)
            if not s.engine_on:
                s.engine_on = True
                s.holder, s.role, s.key_id = holder, role, key_id
                self._session = os.urandom(16).hex()
            session = self._session
        elif command == "stop":
            s.engine_on = False
            self._session = None
            self.projection = {}
        result = {"ok": True, "reason": None, "command": command,
                  "key_id": key_id, "holder": holder, "role": role}
        if session:
            result["session"] = session  # given only to the phone that started the engine
        return result

    @staticmethod
    def _deny(reason: str, who: Optional[dict] = None) -> dict:
        """A refusal. `who` is only passed once the certificate has been verified."""
        return {"ok": False, "reason": reason, **(who or {})}

    # -- revocation --------------------------------------------------------

    def update_revocations(self, signed_list) -> bool:
        """Accept a newer issuer-signed revocation list. Older or forged ones are ignored."""
        payload = issuer.verify_signed(self._issuer_pub, signed_list)
        if payload is None or payload.get("vehicle_id") != self.vehicle_id:
            return False
        version, revoked = payload.get("version"), payload.get("revoked")
        if not _is_int(version) or not isinstance(revoked, list):
            return False
        if version <= self.revocation_version:
            return False  # stale list (a replayed old one cannot un-revoke a key)
        self._revoked = {k for k in revoked if isinstance(k, str)}
        self.revocation_version = version
        # If the revoked key is the one currently in the car and nobody is
        # driving, lock up. A running engine is left alone (never cut a moving car).
        if self.state.key_id in self._revoked and not self.state.engine_on:
            self.state = CarState()
            self.projection = {}
        return True

    # -- cockpit -----------------------------------------------------------

    def set_projection(self, session_token, data) -> bool:
        """The phone shows nav/media/call on the cockpit, only during its own session."""
        if (
            not self._session
            or not isinstance(session_token, str)
            or not hmac.compare_digest(session_token, self._session)
        ):
            return False
        self.projection = clean_projection(data)
        return True

    def snapshot(self) -> dict:
        s = self.state
        return {
            "locked": s.locked,
            "trunk_open": s.trunk_open,
            "glovebox_open": s.glovebox_open,
            "engine_on": s.engine_on,
            "holder": s.holder,
            "role": s.role,
            "revocation_version": self.revocation_version,
        }
