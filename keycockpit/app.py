"""HTTP API (Starlette) for the key backend, the simulated car and the cockpit.

Three groups of endpoints:
  /api/vehicles/...        owner side (needs the owner token) + the car's "radio" side
  /api/vehicles/{id}/cockpit   read-only state for the dashboard
  /api/demo/...            only when seed_demo=True: virtual phones + attack lab
"""

from __future__ import annotations

import os
import secrets
import time
from pathlib import Path
from typing import Optional

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from . import crypto, issuer
from .car import COMMANDS, Car, SimClock
from .phone import Phone
from .store import Store

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
DEMO_OWNER_TOKEN = "demo-owner-token"  # demo vehicle only; never used outside seed_demo
DEFAULT_PROFILE = {"seat_position": 50, "cabin_temp_c": 22, "music_preset": "Radio", "theme": "day"}

# Simulated radio latencies (seconds). See the README for why these are software values.
NORMAL_LINK_DELAY_S = 0.005
RELAY_EXTRA_DELAY_S = 0.250


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message


# ---------------------------------------------------------------------------
# Service object
# ---------------------------------------------------------------------------

class KeyCockpit:
    def __init__(self, db_path: str = ":memory:", clock=None, max_response_s: Optional[float] = None):
        self.clock = clock or SimClock()
        self.store = Store(db_path)
        if max_response_s is None:
            max_response_s = float(os.environ.get("KEYCOCKPIT_MAX_RESPONSE_MS", "150")) / 1000
        self.max_response_s = max_response_s

        stored = self.store.get_meta("issuer_key")
        if stored:
            private_key = crypto.private_key_from_b64(stored)
        else:
            private_key = crypto.generate_private_key()
            self.store.set_meta("issuer_key", crypto.private_key_to_b64(private_key))
        self.issuer = issuer.KeyIssuer(private_key, clock=self.clock)

        self.cars: dict[str, Car] = {}
        self.online: dict[str, bool] = {}
        self.phones: dict[str, Phone] = {}   # demo only
        self.demo_vehicle: Optional[str] = None
        self.captured: Optional[dict] = None  # last message an "eavesdropper" saw (demo)
        for row in self.store.list_vehicles():
            self._make_car(row["id"])

    def _make_car(self, vehicle_id: str) -> Car:
        car = Car(vehicle_id, self.issuer.public_key, clock=self.clock,
                  max_response_s=self.max_response_s)
        self.cars[vehicle_id] = car
        self.online[vehicle_id] = True
        self.push_revocations(vehicle_id)
        return car

    def register_vehicle(self, name: str, token: Optional[str] = None) -> tuple[str, str]:
        vehicle_id = "veh_" + os.urandom(4).hex()
        token = token or secrets.token_urlsafe(32)
        self.store.add_vehicle(vehicle_id, name, token)
        self._make_car(vehicle_id)
        return vehicle_id, token

    def push_revocations(self, vehicle_id: str) -> bool:
        """Deliver the latest signed revocation list, but only if the car is online."""
        if not self.online.get(vehicle_id):
            return False
        signed = self.issuer.revocation_list(vehicle_id, self.store.revoked_ids(vehicle_id))
        self.cars[vehicle_id].update_revocations(signed)
        return True

    def issue_key(self, vehicle_id: str, holder: str, role: str, phone_public_key: str,
                  valid_minutes: float) -> dict:
        certificate = self.issuer.issue(vehicle_id, holder, role, phone_public_key, valid_minutes)
        self.store.add_key(certificate)
        return certificate

    def run_command(self, vehicle_id: str, certificate, challenge_id, command, signature) -> dict:
        """One command from a phone, with an audit entry for every outcome."""
        result = self.cars[vehicle_id].handle(certificate, challenge_id, command, signature)
        # Wall-clock time for display. The simulated clock can be shifted by a fake
        # radio delay at this moment, so it is not used for the log.
        self.store.log(vehicle_id, result["ok"], result["reason"], command=command,
                       key_id=result.get("key_id"), holder=result.get("holder"))
        return result

    def cockpit(self, vehicle_id: str) -> dict:
        car = self.cars[vehicle_id]
        snap = car.snapshot()
        profile = None
        if snap["holder"] and not snap["locked"]:
            profile = self.store.get_profile(vehicle_id, snap["holder"]) or DEFAULT_PROFILE
        return {
            "vehicle": {"id": vehicle_id, "name": self.store.get_vehicle(vehicle_id)["name"]},
            "online": self.online[vehicle_id],
            "car": snap,
            "profile": profile,
            "projection": car.projection if snap["engine_on"] else {},
            "events": self.store.recent_audit(vehicle_id, 12),
        }

    # -- demo ----------------------------------------------------------------

    def seed_demo(self) -> None:
        vehicle_id, _ = self.register_vehicle("Demo SUV", token=DEMO_OWNER_TOKEN)
        self.demo_vehicle = vehicle_id
        roster = [
            ("Alice", "owner", 24 * 60, {"seat_position": 35, "cabin_temp_c": 21,
                                          "music_preset": "Indie Playlist", "theme": "night"}),
            ("Bob", "guest", 3 * 60, {"seat_position": 62, "cabin_temp_c": 24,
                                       "music_preset": "Bollywood Hits", "theme": "day"}),
            ("Valet", "valet", 60, {"seat_position": 50, "cabin_temp_c": 22,
                                     "music_preset": "Off", "theme": "day"}),
        ]
        for holder, role, minutes, profile in roster:
            phone = Phone(holder)
            phone.certificate = self.issue_key(vehicle_id, holder, role, phone.public_key, minutes)
            self.phones[holder.lower()] = phone
            self.store.set_profile(vehicle_id, holder, profile)


def kc_of(request: Request) -> KeyCockpit:
    return request.app.state.kc


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

async def read_json(request: Request) -> dict:
    try:
        data = await request.json()
    except Exception:
        raise ApiError(400, "body must be valid JSON")
    if not isinstance(data, dict):
        raise ApiError(400, "body must be a JSON object")
    return data


def bearer(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else ""


def vehicle_or_404(request: Request) -> str:
    vehicle_id = request.path_params["vehicle_id"]
    if kc_of(request).store.get_vehicle(vehicle_id) is None:
        raise ApiError(404, "unknown vehicle")
    return vehicle_id


def owner_vehicle(request: Request) -> str:
    vehicle_id = vehicle_or_404(request)
    if not kc_of(request).store.check_owner(vehicle_id, bearer(request)):
        raise ApiError(401, "owner token required (Authorization: Bearer <token>)")
    return vehicle_id


def need_str(data: dict, field: str, max_len: int = 64) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip() or len(value) > max_len:
        raise ApiError(400, f"'{field}' must be a non-empty string up to {max_len} characters")
    return value.strip()


def need_int(data: dict, field: str, lo: int, hi: int) -> int:
    value = data.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise ApiError(400, f"'{field}' must be an integer from {lo} to {hi}")
    return value


# ---------------------------------------------------------------------------
# Owner endpoints
# ---------------------------------------------------------------------------

async def create_vehicle(request: Request):
    data = await read_json(request)
    vehicle_id, token = kc_of(request).register_vehicle(need_str(data, "name", 60))
    return JSONResponse({"vehicle_id": vehicle_id, "owner_token": token,
                         "issuer_public_key": kc_of(request).issuer.public_key}, status_code=201)


async def issue_key(request: Request):
    vehicle_id = owner_vehicle(request)
    data = await read_json(request)
    holder = need_str(data, "holder", 40)
    role = data.get("role")
    try:
        certificate = kc_of(request).issue_key(
            vehicle_id, holder, role, data.get("phone_public_key"), data.get("valid_minutes"))
    except (ValueError, TypeError) as exc:
        raise ApiError(400, str(exc))
    return JSONResponse({"key_id": certificate["payload"]["key_id"], "certificate": certificate},
                        status_code=201)


async def list_keys(request: Request):
    vehicle_id = owner_vehicle(request)
    kc, now = kc_of(request), int(kc_of(request).clock())
    keys = []
    for row in kc.store.list_keys(vehicle_id):
        status = "revoked" if row["revoked_at"] else ("expired" if row["not_after"] <= now else "active")
        keys.append({"key_id": row["key_id"], "holder": row["holder"], "role": row["role"],
                     "expires_at": row["not_after"], "status": status})
    return JSONResponse({"keys": keys})


async def revoke_key(request: Request):
    vehicle_id = owner_vehicle(request)
    kc, key_id = kc_of(request), request.path_params["key_id"]
    if kc.store.get_key(vehicle_id, key_id) is None:
        raise ApiError(404, "unknown key")
    newly_revoked = kc.store.revoke_key(vehicle_id, key_id, int(kc.clock()))
    car_updated = kc.push_revocations(vehicle_id)
    return JSONResponse({"revoked": True, "already_revoked": not newly_revoked,
                         "car_updated": car_updated,
                         "note": None if car_updated else
                         "car is offline: it keeps accepting this key until it syncs or the key expires"})


async def set_connectivity(request: Request):
    vehicle_id = owner_vehicle(request)
    data = await read_json(request)
    if not isinstance(data.get("online"), bool):
        raise ApiError(400, "'online' must be true or false")
    kc = kc_of(request)
    kc.online[vehicle_id] = data["online"]
    synced = kc.push_revocations(vehicle_id)  # coming back online = pull the latest list
    return JSONResponse({"online": data["online"], "synced": synced,
                         "revocation_version": kc.cars[vehicle_id].revocation_version})


async def set_profile(request: Request):
    vehicle_id = owner_vehicle(request)
    holder = request.path_params["holder"]
    data = await read_json(request)
    if data.get("theme") not in ("day", "night"):
        raise ApiError(400, "'theme' must be 'day' or 'night'")
    profile = {
        "seat_position": need_int(data, "seat_position", 0, 100),
        "cabin_temp_c": need_int(data, "cabin_temp_c", 16, 30),
        "music_preset": need_str(data, "music_preset", 40),
        "theme": data["theme"],
    }
    kc_of(request).store.set_profile(vehicle_id, holder, profile)
    return JSONResponse(profile)


async def get_audit(request: Request):
    vehicle_id = owner_vehicle(request)
    return JSONResponse({"events": kc_of(request).store.recent_audit(vehicle_id, 100)})


# ---------------------------------------------------------------------------
# Car "radio" endpoints (what a phone talks to; BLE/NFC/UWB in a real car)
# ---------------------------------------------------------------------------

async def car_challenge(request: Request):
    vehicle_id = vehicle_or_404(request)
    return JSONResponse(kc_of(request).cars[vehicle_id].new_challenge())


async def car_command(request: Request):
    vehicle_id = vehicle_or_404(request)
    data = await read_json(request)
    result = kc_of(request).run_command(
        vehicle_id, data.get("certificate"), data.get("challenge_id"),
        data.get("command"), data.get("signature"))
    return JSONResponse(result, status_code=200 if result["ok"] else 403)


async def cockpit_state(request: Request):
    vehicle_id = vehicle_or_404(request)
    return JSONResponse(kc_of(request).cockpit(vehicle_id))


async def cockpit_project(request: Request):
    """Phone -> cockpit: navigation, media and call info (CarPlay / Android Auto idea)."""
    vehicle_id = vehicle_or_404(request)
    data = await read_json(request)
    if not kc_of(request).cars[vehicle_id].set_projection(bearer(request), data):
        raise ApiError(403, "no active driving session for this token")
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# Demo endpoints
# ---------------------------------------------------------------------------

def demo_vehicle(request: Request) -> str:
    kc = kc_of(request)
    if not kc.demo_vehicle:
        raise ApiError(404, "demo mode is off")
    return kc.demo_vehicle


def demo_phone(request: Request) -> Phone:
    phone = kc_of(request).phones.get(request.path_params["name"].lower())
    if phone is None:
        raise ApiError(404, "unknown demo phone")
    return phone


async def demo_info(request: Request):
    kc, vehicle_id = kc_of(request), demo_vehicle(request)
    phones = []
    for phone in kc.phones.values():
        payload = phone.certificate["payload"]
        phones.append({"name": phone.holder, "role": payload["role"], "key_id": payload["key_id"],
                       "expires_at": payload["not_after"]})
    return JSONResponse({"vehicle_id": vehicle_id, "owner_token": DEMO_OWNER_TOKEN,
                         "commands": list(COMMANDS), "phones": phones})


async def demo_press(request: Request):
    """A virtual phone runs the real challenge/response with the simulated car."""
    kc, vehicle_id, phone = kc_of(request), demo_vehicle(request), demo_phone(request)
    command = (await read_json(request)).get("command")
    if command not in COMMANDS:
        raise ApiError(400, f"'command' must be one of {', '.join(COMMANDS)}")
    car = kc.cars[vehicle_id]
    challenge = car.new_challenge()
    key_id = phone.certificate["payload"]["key_id"]
    signature = phone.sign(vehicle_id, challenge, key_id, command)
    with car.link_delay(NORMAL_LINK_DELAY_S):
        result = kc.run_command(vehicle_id, phone.certificate, challenge["challenge_id"],
                                command, signature)
    if result["ok"]:
        kc.captured = {"vehicle_id": vehicle_id, "certificate": phone.certificate,
                       "challenge_id": challenge["challenge_id"], "command": command,
                       "signature": signature}
        if result.get("session"):
            phone.session = result["session"]
    result.pop("session", None)
    return JSONResponse(result)


async def demo_project(request: Request):
    kc, vehicle_id, phone = kc_of(request), demo_vehicle(request), demo_phone(request)
    data = await read_json(request)
    if not phone.session or not kc.cars[vehicle_id].set_projection(phone.session, data):
        raise ApiError(403, f"{phone.holder}'s phone has no active driving session")
    return JSONResponse({"ok": True})


async def demo_attack(request: Request):
    """Attack lab: each attack is a real attempt against the car's real checks."""
    kc, vehicle_id = kc_of(request), demo_vehicle(request)
    kind, car = request.path_params["kind"], kc.cars[vehicle_id]

    if kind == "replay":
        cap = kc.captured
        if cap is None:
            raise ApiError(409, "nothing captured yet: press a button on a phone first")
        result = kc.run_command(vehicle_id, cap["certificate"], cap["challenge_id"],
                                cap["command"], cap["signature"])
        what = f"replayed a captured '{cap['command']}' message"

    elif kind == "relay":
        victim = kc.phones["alice"]
        challenge = car.new_challenge()
        key_id = victim.certificate["payload"]["key_id"]
        signature = victim.sign(vehicle_id, challenge, key_id, "unlock")
        with car.link_delay(NORMAL_LINK_DELAY_S + RELAY_EXTRA_DELAY_S):
            result = kc.run_command(vehicle_id, victim.certificate, challenge["challenge_id"],
                                    "unlock", signature)
        what = "relayed the car's challenge to Alice's real phone far away (valid answer, arrives late)"

    elif kind in ("forged_cert", "stolen_cert"):
        thief = Phone("Thief")
        challenge = car.new_challenge()
        if kind == "forged_cert":
            fake_authority = issuer.KeyIssuer(crypto.generate_private_key(), clock=kc.clock)
            cert = fake_authority.issue(vehicle_id, "Thief", "owner", thief.public_key, 60)
            what = "made up a certificate signed by their own fake authority"
        else:
            cert = kc.phones["bob"].certificate
            what = "copied Bob's certificate (public) but only has their own private key"
        signature = thief.sign(vehicle_id, challenge, cert["payload"]["key_id"], "unlock")
        with car.link_delay(NORMAL_LINK_DELAY_S):
            result = kc.run_command(vehicle_id, cert, challenge["challenge_id"], "unlock", signature)
    else:
        raise ApiError(404, "unknown attack")

    result.pop("session", None)
    return JSONResponse({"attack": kind, "what": what, "blocked": not result["ok"],
                         "reason": result["reason"]})


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

async def index(request: Request):
    return FileResponse(STATIC_DIR / "index.html")


async def on_api_error(request: Request, exc: ApiError):
    return JSONResponse({"error": exc.message}, status_code=exc.status)


async def on_http_exception(request: Request, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


def create_app(db_path: str = ":memory:", seed_demo: bool = False, clock=None,
               max_response_s: Optional[float] = None) -> Starlette:
    routes = [
        Route("/", index),
        Route("/api/vehicles", create_vehicle, methods=["POST"]),
        Route("/api/vehicles/{vehicle_id}/keys", issue_key, methods=["POST"]),
        Route("/api/vehicles/{vehicle_id}/keys", list_keys, methods=["GET"]),
        Route("/api/vehicles/{vehicle_id}/keys/{key_id}", revoke_key, methods=["DELETE"]),
        Route("/api/vehicles/{vehicle_id}/car/connectivity", set_connectivity, methods=["POST"]),
        Route("/api/vehicles/{vehicle_id}/car/challenge", car_challenge, methods=["POST"]),
        Route("/api/vehicles/{vehicle_id}/car/command", car_command, methods=["POST"]),
        Route("/api/vehicles/{vehicle_id}/cockpit", cockpit_state, methods=["GET"]),
        Route("/api/vehicles/{vehicle_id}/cockpit/projection", cockpit_project, methods=["POST"]),
        Route("/api/vehicles/{vehicle_id}/profiles/{holder}", set_profile, methods=["PUT"]),
        Route("/api/vehicles/{vehicle_id}/audit", get_audit, methods=["GET"]),
        Route("/api/demo", demo_info, methods=["GET"]),
        Route("/api/demo/phones/{name}/press", demo_press, methods=["POST"]),
        Route("/api/demo/phones/{name}/project", demo_project, methods=["POST"]),
        Route("/api/demo/attacks/{kind}", demo_attack, methods=["POST"]),
    ]
    app = Starlette(routes=routes, exception_handlers={
        ApiError: on_api_error, HTTPException: on_http_exception})
    app.state.kc = KeyCockpit(db_path, clock=clock, max_response_s=max_response_s)
    if seed_demo:
        app.state.kc.seed_demo()
    return app


def main() -> None:
    """`python -m keycockpit` starts the demo server on http://127.0.0.1:8000"""
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    app = create_app(db_path=os.environ.get("KEYCOCKPIT_DB", ":memory:"), seed_demo=True)
    print(f"KeyCockpit demo -> http://127.0.0.1:{port}   (Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
