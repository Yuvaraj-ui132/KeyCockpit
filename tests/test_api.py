"""End-to-end API tests. Requests go straight to the ASGI app, so no network is needed."""

import asyncio
import json
import unittest

from keycockpit import crypto
from keycockpit.app import create_app
from keycockpit.car import SimClock
from keycockpit.phone import Phone

T0 = 1_700_000_000.0


class Client:
    """Tiny ASGI test client (the real one needs httpx, which is not required here)."""

    def __init__(self, app):
        self.app = app

    def request(self, method, path, body=None, token=None, raw=None):
        payload = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
        headers = [(b"host", b"test")]
        if payload:
            headers.append((b"content-type", b"application/json"))
        if token:
            headers.append((b"authorization", f"Bearer {token}".encode()))
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
                 "query_string": b"", "headers": headers, "client": ("test", 1),
                 "server": ("test", 80)}
        out = {"status": None, "body": b""}
        request_received = False
        response_complete = asyncio.Event()

        async def receive():
            nonlocal request_received
            if not request_received:
                request_received = True
                return {"type": "http.request", "body": payload, "more_body": False}
            await response_complete.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.start":
                out["status"] = message["status"]
            elif message["type"] == "http.response.body":
                out["body"] += message.get("body", b"")
                if not message.get("more_body", False):
                    response_complete.set()

        asyncio.run(self.app(scope, receive, send))
        try:
            data = json.loads(out["body"])
        except ValueError:
            data = out["body"]
        return out["status"], data


class ApiBase(unittest.TestCase):
    def setUp(self):
        self.clock = SimClock(start=T0)
        self.app = create_app(clock=self.clock)
        self.addCleanup(self.app.state.kc.store.db.close)
        self.c = Client(self.app)
        status, data = self.c.request("POST", "/api/vehicles", {"name": "Test car"})
        self.assertEqual(status, 201)
        self.vid, self.token = data["vehicle_id"], data["owner_token"]
        self.base = f"/api/vehicles/{self.vid}"

    def enroll(self, holder, role="guest", minutes=60):
        phone = Phone(holder)
        status, data = self.c.request("POST", f"{self.base}/keys", {
            "holder": holder, "role": role, "phone_public_key": phone.public_key,
            "valid_minutes": minutes}, token=self.token)
        self.assertEqual(status, 201, data)
        phone.certificate = data["certificate"]
        return phone

    def press(self, phone, command, delay=0.0):
        """What a real phone app would do: two HTTP calls to the car's radio endpoints."""
        _, challenge = self.c.request("POST", f"{self.base}/car/challenge")
        key_id = phone.certificate["payload"]["key_id"]
        signature = phone.sign(self.vid, challenge, key_id, command)
        car = self.app.state.kc.cars[self.vid]
        with car.link_delay(delay):
            return self.c.request("POST", f"{self.base}/car/command", {
                "certificate": phone.certificate, "challenge_id": challenge["challenge_id"],
                "command": command, "signature": signature})

    def cockpit(self):
        return self.c.request("GET", f"{self.base}/cockpit")[1]


class TestOwnerAuth(ApiBase):
    def test_owner_endpoints_need_the_token(self):
        phone = Phone("X")
        body = {"holder": "X", "role": "guest", "phone_public_key": phone.public_key, "valid_minutes": 5}
        self.assertEqual(self.c.request("POST", f"{self.base}/keys", body)[0], 401)
        self.assertEqual(self.c.request("POST", f"{self.base}/keys", body, token="wrong")[0], 401)
        self.assertEqual(self.c.request("GET", f"{self.base}/keys")[0], 401)
        self.assertEqual(self.c.request("GET", f"{self.base}/audit")[0], 401)
        self.assertEqual(self.c.request("DELETE", f"{self.base}/keys/abc")[0], 401)
        self.assertEqual(self.c.request("POST", f"{self.base}/car/connectivity", {"online": False})[0], 401)
        self.assertEqual(self.c.request("PUT", f"{self.base}/profiles/X", {})[0], 401)

    def test_another_vehicles_token_does_not_work(self):
        _, other = self.c.request("POST", "/api/vehicles", {"name": "Other"})
        status, _ = self.c.request("GET", f"{self.base}/keys", token=other["owner_token"])
        self.assertEqual(status, 401)

    def test_unknown_vehicle(self):
        self.assertEqual(self.c.request("GET", "/api/vehicles/nope/cockpit")[0], 404)
        self.assertEqual(self.c.request("POST", "/api/vehicles/nope/car/challenge")[0], 404)

    def test_bad_bodies(self):
        self.assertEqual(self.c.request("POST", "/api/vehicles", raw=b"not json")[0], 400)
        self.assertEqual(self.c.request("POST", "/api/vehicles", raw=b"[1,2]")[0], 400)
        self.assertEqual(self.c.request("POST", "/api/vehicles", {"name": ""})[0], 400)
        self.assertEqual(self.c.request("POST", f"{self.base}/car/command", raw=b"{")[0], 400)

    def test_issue_validates_input(self):
        phone = Phone("X")
        for body in [
            {"holder": "X", "role": "admin", "phone_public_key": phone.public_key, "valid_minutes": 5},
            {"holder": "X", "role": "guest", "phone_public_key": "AAAA", "valid_minutes": 5},
            {"holder": "X", "role": "valet", "phone_public_key": phone.public_key, "valid_minutes": 99999},
            {"holder": "", "role": "guest", "phone_public_key": phone.public_key, "valid_minutes": 5},
            {"holder": "X", "role": "guest", "phone_public_key": phone.public_key},
        ]:
            self.assertEqual(self.c.request("POST", f"{self.base}/keys", body, token=self.token)[0], 400, body)


class TestKeyLifecycle(ApiBase):
    def test_issue_use_list_revoke(self):
        bob = self.enroll("Bob")
        self.assertEqual(self.press(bob, "unlock")[0], 200)
        _, listing = self.c.request("GET", f"{self.base}/keys", token=self.token)
        self.assertEqual([k["status"] for k in listing["keys"]], ["active"])

        key_id = bob.certificate["payload"]["key_id"]
        status, data = self.c.request("DELETE", f"{self.base}/keys/{key_id}", token=self.token)
        self.assertEqual((status, data["car_updated"]), (200, True))
        status, data = self.press(bob, "unlock")
        self.assertEqual((status, data["reason"]), (403, "revoked"))
        _, listing = self.c.request("GET", f"{self.base}/keys", token=self.token)
        self.assertEqual(listing["keys"][0]["status"], "revoked")

    def test_revoking_unknown_key_is_404(self):
        self.assertEqual(self.c.request("DELETE", f"{self.base}/keys/nope", token=self.token)[0], 404)

    def test_offline_car_keeps_trusting_until_it_syncs(self):
        bob = self.enroll("Bob")
        self.c.request("POST", f"{self.base}/car/connectivity", {"online": False}, token=self.token)
        key_id = bob.certificate["payload"]["key_id"]
        _, data = self.c.request("DELETE", f"{self.base}/keys/{key_id}", token=self.token)
        self.assertFalse(data["car_updated"])
        self.assertEqual(self.press(bob, "unlock")[0], 200)       # the honest limitation
        _, data = self.c.request("POST", f"{self.base}/car/connectivity", {"online": True}, token=self.token)
        self.assertTrue(data["synced"])
        self.assertEqual(self.press(bob, "unlock")[1]["reason"], "revoked")

    def test_short_lived_keys_limit_the_offline_window(self):
        bob = self.enroll("Bob", minutes=30)
        self.c.request("POST", f"{self.base}/car/connectivity", {"online": False}, token=self.token)
        self.clock.advance(31 * 60)
        self.assertEqual(self.press(bob, "unlock")[1]["reason"], "expired")
        _, listing = self.c.request("GET", f"{self.base}/keys", token=self.token)
        self.assertEqual(listing["keys"][0]["status"], "expired")

    def test_double_revoke_is_harmless(self):
        bob = self.enroll("Bob")
        key_id = bob.certificate["payload"]["key_id"]
        self.c.request("DELETE", f"{self.base}/keys/{key_id}", token=self.token)
        _, data = self.c.request("DELETE", f"{self.base}/keys/{key_id}", token=self.token)
        self.assertTrue(data["already_revoked"])

    def test_issuer_key_and_revocations_survive_a_restart(self):
        import os, tempfile
        path = os.path.join(tempfile.mkdtemp(), "kc.db")
        app1 = create_app(db_path=path, clock=self.clock)
        self.addCleanup(app1.state.kc.store.db.close)
        c1 = Client(app1)
        _, v = c1.request("POST", "/api/vehicles", {"name": "Persist"})
        base = f"/api/vehicles/{v['vehicle_id']}"
        phone = Phone("Bob")
        _, k = c1.request("POST", f"{base}/keys", {"holder": "Bob", "role": "guest",
                          "phone_public_key": phone.public_key, "valid_minutes": 60}, token=v["owner_token"])
        phone.certificate = k["certificate"]
        c1.request("DELETE", f"{base}/keys/{k['key_id']}", token=v["owner_token"])

        app2 = create_app(db_path=path, clock=self.clock)   # "restart"
        self.addCleanup(app2.state.kc.store.db.close)
        car = app2.state.kc.cars[v["vehicle_id"]]
        self.assertEqual(car.revocation_version, 1)
        self.assertEqual(phone.press(car, "unlock")["reason"], "revoked")
        self.assertEqual(app2.state.kc.issuer.public_key, app1.state.kc.issuer.public_key)


class TestAttacksOverHttp(ApiBase):
    def test_replay_over_http(self):
        bob = self.enroll("Bob")
        _, challenge = self.c.request("POST", f"{self.base}/car/challenge")
        sig = bob.sign(self.vid, challenge, bob.certificate["payload"]["key_id"], "unlock")
        body = {"certificate": bob.certificate, "challenge_id": challenge["challenge_id"],
                "command": "unlock", "signature": sig}
        self.assertEqual(self.c.request("POST", f"{self.base}/car/command", body)[0], 200)
        status, data = self.c.request("POST", f"{self.base}/car/command", body)
        self.assertEqual((status, data["reason"]), (403, "unknown_challenge"))

    def test_relay_over_http(self):
        bob = self.enroll("Bob")
        status, data = self.press(bob, "unlock", delay=0.5)
        self.assertEqual((status, data["reason"]), (403, "too_slow"))

    def test_denials_are_audited_with_the_verified_holder(self):
        valet = self.enroll("Valet", role="valet")
        self.press(valet, "unlock")
        self.press(valet, "open_trunk")
        _, audit = self.c.request("GET", f"{self.base}/audit", token=self.token)
        newest = audit["events"][0]
        self.assertEqual((newest["ok"], newest["reason"], newest["holder"], newest["command"]),
                         (False, "not_permitted", "Valet", "open_trunk"))

    def test_audit_does_not_trust_names_inside_unverified_certificates(self):
        thief = Phone("Thief")
        fake_cert = {"payload": {"holder": "Alice", "key_id": "x"}, "sig": "AAAA"}
        _, challenge = self.c.request("POST", f"{self.base}/car/challenge")
        self.c.request("POST", f"{self.base}/car/command", {
            "certificate": fake_cert, "challenge_id": challenge["challenge_id"],
            "command": "unlock", "signature": "AAAA"})
        _, audit = self.c.request("GET", f"{self.base}/audit", token=self.token)
        self.assertEqual(audit["events"][0]["reason"], "bad_certificate")
        self.assertIsNone(audit["events"][0]["holder"])


class TestCockpit(ApiBase):
    def test_profile_loads_for_whoever_unlocked(self):
        alice, bob = self.enroll("Alice", "owner"), self.enroll("Bob")
        for who, seat in (("Alice", 30), ("Bob", 70)):
            status, _ = self.c.request("PUT", f"{self.base}/profiles/{who}", {
                "seat_position": seat, "cabin_temp_c": 22, "music_preset": f"{who} mix", "theme": "night"},
                token=self.token)
            self.assertEqual(status, 200)
        self.assertIsNone(self.cockpit()["profile"])               # locked: nothing shown
        self.press(alice, "unlock")
        self.assertEqual(self.cockpit()["profile"]["seat_position"], 30)
        self.press(alice, "lock")
        self.press(bob, "unlock")
        self.assertEqual(self.cockpit()["profile"]["music_preset"], "Bob mix")

    def test_unknown_holder_gets_the_default_profile(self):
        self.press(self.enroll("Eve"), "unlock")
        self.assertEqual(self.cockpit()["profile"]["music_preset"], "Radio")

    def test_profile_validation(self):
        for body in [{"seat_position": 500, "cabin_temp_c": 22, "music_preset": "x", "theme": "day"},
                     {"seat_position": 5, "cabin_temp_c": 22, "music_preset": "x", "theme": "neon"},
                     {"seat_position": 5, "cabin_temp_c": True, "music_preset": "x", "theme": "day"},
                     {"seat_position": 5, "cabin_temp_c": 22, "music_preset": "", "theme": "day"}]:
            self.assertEqual(self.c.request("PUT", f"{self.base}/profiles/X", body, token=self.token)[0], 400, body)

    def test_phone_projection_needs_the_engine_session(self):
        alice = self.enroll("Alice", "owner")
        self.press(alice, "unlock")
        nav = {"nav": {"destination": "Fort", "eta_min": 9}}
        self.assertEqual(self.c.request("POST", f"{self.base}/cockpit/projection", nav, token="guess")[0], 403)
        _, started = self.press(alice, "start")
        status, _ = self.c.request("POST", f"{self.base}/cockpit/projection", nav, token=started["session"])
        self.assertEqual(status, 200)
        self.assertEqual(self.cockpit()["projection"]["nav"]["destination"], "Fort")
        self.press(alice, "stop")
        self.assertEqual(self.cockpit()["projection"], {})
        self.assertEqual(self.c.request("POST", f"{self.base}/cockpit/projection", nav, token=started["session"])[0], 403)

    def test_cockpit_never_leaks_the_session_token(self):
        alice = self.enroll("Alice", "owner")
        self.press(alice, "unlock")
        _, started = self.press(alice, "start")
        self.assertNotIn(started["session"], json.dumps(self.cockpit()))


class TestDemoMode(unittest.TestCase):
    def setUp(self):
        app = create_app(seed_demo=True)
        self.addCleanup(app.state.kc.store.db.close)
        self.c = Client(app)

    def test_demo_flow_and_attack_lab(self):
        status, info = self.c.request("GET", "/api/demo")
        self.assertEqual(status, 200)
        self.assertEqual([p["name"] for p in info["phones"]], ["Alice", "Bob", "Valet"])
        press = lambda who, cmd: self.c.request("POST", f"/api/demo/phones/{who}/press", {"command": cmd})
        self.assertEqual(press("alice", "unlock")[1]["ok"], True)
        self.assertEqual(press("valet", "open_trunk")[1]["reason"], "not_permitted")
        self.assertEqual(press("alice", "start")[1]["ok"], True)
        self.assertNotIn("session", press("alice", "start")[1])
        status, _ = self.c.request("POST", "/api/demo/phones/alice/project", {"nav": {"destination": "Home"}})
        self.assertEqual(status, 200)
        self.assertEqual(self.c.request("POST", "/api/demo/phones/bob/project", {"nav": {}})[0], 403)
        for kind in ("replay", "relay", "forged_cert", "stolen_cert"):
            status, data = self.c.request("POST", f"/api/demo/attacks/{kind}")
            self.assertEqual((status, data["blocked"]), (200, True), kind)
        self.assertEqual(self.c.request("POST", "/api/demo/attacks/nope")[0], 404)

    def test_replay_needs_something_captured(self):
        self.assertEqual(self.c.request("POST", "/api/demo/attacks/replay")[0], 409)

    def test_demo_endpoints_are_off_by_default(self):
        app = create_app()
        self.addCleanup(app.state.kc.store.db.close)
        plain = Client(app)
        self.assertEqual(plain.request("GET", "/api/demo")[0], 404)
        self.assertEqual(plain.request("POST", "/api/demo/attacks/relay")[0], 404)

    def test_dashboard_is_served(self):
        status, body = self.c.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"KeyCockpit", body)


if __name__ == "__main__":
    unittest.main()
