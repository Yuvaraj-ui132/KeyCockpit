"""Security tests for the car, written as attacks against it."""

import copy
import unittest

from keycockpit import crypto, issuer
from keycockpit.car import Car, SimClock
from keycockpit.phone import Phone

T0 = 1_700_000_000.0


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = SimClock(start=T0)
        self.authority = issuer.KeyIssuer(crypto.generate_private_key(), clock=self.clock)
        self.car = Car("veh_1", self.authority.public_key, clock=self.clock)
        self.alice = self.new_phone("Alice", "owner", 60)
        self.bob = self.new_phone("Bob", "guest", 60)
        self.valet = self.new_phone("Valet", "valet", 60)

    def new_phone(self, name, role, minutes, vehicle="veh_1", authority=None):
        phone = Phone(name)
        phone.certificate = (authority or self.authority).issue(
            vehicle, name, role, phone.public_key, minutes)
        return phone

    def key_id(self, phone):
        return phone.certificate["payload"]["key_id"]

    def revocation_list(self, *phones, vehicle="veh_1", authority=None):
        return (authority or self.authority).revocation_list(
            vehicle, [self.key_id(p) for p in phones])


class TestNormalUse(Base):
    def test_full_drive_cycle(self):
        self.assertTrue(self.alice.press(self.car, "unlock")["ok"])
        self.assertFalse(self.car.snapshot()["locked"])
        self.assertTrue(self.alice.press(self.car, "open_trunk")["ok"])
        result = self.alice.press(self.car, "start")
        self.assertTrue(result["ok"] and result["session"])
        self.assertTrue(self.car.snapshot()["engine_on"])
        self.assertTrue(self.alice.press(self.car, "stop")["ok"])
        self.assertTrue(self.alice.press(self.car, "lock")["ok"])
        self.assertTrue(self.car.snapshot()["locked"])

    def test_normal_radio_delay_is_accepted(self):
        self.assertTrue(self.alice.press(self.car, "unlock", link_delay_s=0.005)["ok"])

    def test_works_with_no_backend_at_all(self):
        # The car object only ever received the issuer's public key. Nothing else
        # is reachable from it, so a successful unlock proves offline verification.
        self.assertTrue(self.alice.press(self.car, "unlock")["ok"])


class TestReplayAndBinding(Base):
    def capture(self, command="unlock"):
        challenge = self.car.new_challenge()
        key_id = self.key_id(self.alice)
        signature = self.alice.sign("veh_1", challenge, key_id, command)
        return challenge, signature

    def test_replaying_a_captured_message_is_refused(self):
        challenge, sig = self.capture()
        cert = self.alice.certificate
        first = self.car.handle(cert, challenge["challenge_id"], "unlock", sig)
        again = self.car.handle(cert, challenge["challenge_id"], "unlock", sig)
        self.assertTrue(first["ok"])
        self.assertEqual(again["reason"], "unknown_challenge")

    def test_signature_cannot_be_reused_for_another_command(self):
        challenge, sig = self.capture("unlock")
        result = self.car.handle(self.alice.certificate, challenge["challenge_id"], "start", sig)
        self.assertEqual(result["reason"], "bad_signature")
        self.assertTrue(self.car.snapshot()["locked"])

    def test_signature_cannot_be_moved_to_another_challenge(self):
        _, sig = self.capture()
        other = self.car.new_challenge()
        result = self.car.handle(self.alice.certificate, other["challenge_id"], "unlock", sig)
        self.assertEqual(result["reason"], "bad_signature")

    def test_a_failed_attempt_still_burns_the_challenge(self):
        challenge, good_sig = self.capture()
        self.car.handle(self.alice.certificate, challenge["challenge_id"], "unlock", "AAAA")
        retry = self.car.handle(self.alice.certificate, challenge["challenge_id"], "unlock", good_sig)
        self.assertEqual(retry["reason"], "unknown_challenge")

    def test_invented_challenge_is_refused(self):
        result = self.car.handle(self.alice.certificate, "deadbeef", "unlock", "AAAA")
        self.assertEqual(result["reason"], "unknown_challenge")

    def test_open_challenges_are_capped(self):
        first = self.car.new_challenge()
        for _ in range(40):
            self.car.new_challenge()
        self.assertLessEqual(len(self.car._challenges), 16)
        sig = self.alice.sign("veh_1", first, self.key_id(self.alice), "unlock")
        result = self.car.handle(self.alice.certificate, first["challenge_id"], "unlock", sig)
        self.assertEqual(result["reason"], "unknown_challenge")


class TestRelayAttack(Base):
    def test_valid_but_late_answer_is_refused(self):
        # Alice's real phone gives a perfectly valid answer, but the relay made it slow.
        result = self.alice.press(self.car, "unlock", link_delay_s=0.4)
        self.assertEqual(result["reason"], "too_slow")
        self.assertTrue(self.car.snapshot()["locked"])

    def test_same_phone_close_by_is_fine(self):
        self.assertTrue(self.alice.press(self.car, "unlock", link_delay_s=0.01)["ok"])


class TestCertificates(Base):
    def attempt(self, certificate, signer, command="unlock", key_id=None):
        challenge = self.car.new_challenge()
        key_id = key_id or certificate["payload"]["key_id"]
        sig = signer.sign("veh_1", challenge, key_id, command)
        return self.car.handle(certificate, challenge["challenge_id"], command, sig)

    def test_certificate_from_a_fake_authority(self):
        fake = issuer.KeyIssuer(crypto.generate_private_key(), clock=self.clock)
        thief = self.new_phone("Thief", "owner", 60, authority=fake)
        self.assertEqual(self.attempt(thief.certificate, thief)["reason"], "bad_certificate")

    def test_tampering_with_a_certificate_breaks_its_signature(self):
        forged = copy.deepcopy(self.valet.certificate)
        forged["payload"]["role"] = "owner"
        forged["payload"]["perms"] = list(issuer.ROLE_PERMISSIONS["owner"])
        result = self.attempt(forged, self.valet, command="open_glovebox")
        self.assertEqual(result["reason"], "bad_certificate")

    def test_extending_expiry_is_detected(self):
        forged = copy.deepcopy(self.bob.certificate)
        forged["payload"]["not_after"] += 10 ** 7
        self.assertEqual(self.attempt(forged, self.bob)["reason"], "bad_certificate")

    def test_stolen_certificate_without_the_private_key(self):
        thief = Phone("Thief")
        result = self.attempt(self.alice.certificate, thief)
        self.assertEqual(result["reason"], "bad_signature")

    def test_certificate_for_another_vehicle(self):
        other = self.new_phone("Alice", "owner", 60, vehicle="veh_2")
        self.assertEqual(self.attempt(other.certificate, other)["reason"], "wrong_vehicle")

    def test_garbage_certificates(self):
        for junk in (None, "x", 5, {}, {"payload": 1, "sig": "x"}, {"payload": {}, "sig": 3}):
            challenge = self.car.new_challenge()
            result = self.car.handle(junk, challenge["challenge_id"], "unlock", "AAAA")
            self.assertEqual(result["reason"], "bad_certificate", junk)

    def test_expired_key(self):
        self.clock.advance(61 * 60)
        self.assertEqual(self.alice.press(self.car, "unlock")["reason"], "expired")

    def test_key_not_yet_valid(self):
        future = SimClock(start=T0 + 3600)
        later = issuer.KeyIssuer(self.authority._key, clock=future)
        phone = Phone("Early")
        phone.certificate = later.issue("veh_1", "Early", "owner", phone.public_key, 60)
        self.assertEqual(phone.press(self.car, "unlock")["reason"], "not_yet_valid")

    def test_small_clock_difference_is_tolerated(self):
        ahead = SimClock(start=T0 + 30)
        late = issuer.KeyIssuer(self.authority._key, clock=ahead)
        phone = Phone("Skew")
        phone.certificate = late.issue("veh_1", "Skew", "owner", phone.public_key, 60)
        self.assertTrue(phone.press(self.car, "unlock")["ok"])


class TestRevocation(Base):
    def test_revoked_key_is_refused(self):
        self.assertTrue(self.car.update_revocations(self.revocation_list(self.bob)))
        self.assertEqual(self.bob.press(self.car, "unlock")["reason"], "revoked")
        self.assertTrue(self.alice.press(self.car, "unlock")["ok"])

    def test_old_list_cannot_bring_a_key_back(self):
        old = self.revocation_list(self.bob)
        new = self.revocation_list(self.bob, self.valet)
        self.assertTrue(self.car.update_revocations(old))
        self.assertTrue(self.car.update_revocations(new))
        self.assertFalse(self.car.update_revocations(old))      # replayed stale list
        self.assertEqual(self.valet.press(self.car, "unlock")["reason"], "revoked")

    def test_forged_or_foreign_lists_are_ignored(self):
        fake = issuer.KeyIssuer(crypto.generate_private_key(), clock=self.clock)
        self.assertFalse(self.car.update_revocations(self.revocation_list(self.bob, authority=fake)))
        self.assertFalse(self.car.update_revocations(self.revocation_list(self.bob, vehicle="veh_2")))
        self.assertFalse(self.car.update_revocations({"payload": {}, "sig": "x"}))
        self.assertTrue(self.bob.press(self.car, "unlock")["ok"])

    def test_revoking_the_key_in_the_car_locks_it_when_parked(self):
        self.bob.press(self.car, "unlock")
        self.car.update_revocations(self.revocation_list(self.bob))
        self.assertTrue(self.car.snapshot()["locked"])
        self.assertIsNone(self.car.snapshot()["holder"])

    def test_a_moving_car_is_not_shut_off(self):
        self.bob.press(self.car, "unlock")
        self.bob.press(self.car, "start")
        self.car.update_revocations(self.revocation_list(self.bob))
        self.assertTrue(self.car.snapshot()["engine_on"])
        self.assertEqual(self.bob.press(self.car, "stop")["reason"], "revoked")  # no new commands


class TestPermissionsAndState(Base):
    def test_valet_cannot_open_trunk_or_glovebox(self):
        self.valet.press(self.car, "unlock")
        self.assertEqual(self.valet.press(self.car, "open_trunk")["reason"], "not_permitted")
        self.assertEqual(self.valet.press(self.car, "open_glovebox")["reason"], "not_permitted")
        self.assertFalse(self.car.snapshot()["trunk_open"])

    def test_guest_can_use_trunk_but_not_glovebox(self):
        self.bob.press(self.car, "unlock")
        self.assertTrue(self.bob.press(self.car, "open_trunk")["ok"])
        self.assertEqual(self.bob.press(self.car, "open_glovebox")["reason"], "not_permitted")

    def test_locked_car_does_not_open_anything(self):
        self.assertEqual(self.alice.press(self.car, "open_trunk")["reason"], "car_locked")
        self.assertEqual(self.alice.press(self.car, "start")["reason"], "car_locked")

    def test_only_the_driver_can_command_while_the_engine_runs(self):
        self.bob.press(self.car, "unlock")
        self.bob.press(self.car, "start")
        self.assertEqual(self.alice.press(self.car, "unlock")["reason"], "in_use")
        self.assertEqual(self.car.snapshot()["holder"], "Bob")

    def test_cannot_lock_a_running_car(self):
        self.alice.press(self.car, "unlock")
        self.alice.press(self.car, "start")
        self.assertEqual(self.alice.press(self.car, "lock")["reason"], "engine_running")

    def test_lock_resets_everything(self):
        self.alice.press(self.car, "unlock")
        self.alice.press(self.car, "open_trunk")
        self.alice.press(self.car, "lock")
        snap = self.car.snapshot()
        self.assertTrue(snap["locked"])
        self.assertFalse(snap["trunk_open"])
        self.assertIsNone(snap["holder"])

    def test_malformed_requests(self):
        challenge = self.car.new_challenge()
        cert = self.alice.certificate
        self.assertEqual(self.car.handle(cert, None, "unlock", "x")["reason"], "bad_request")
        self.assertEqual(self.car.handle(cert, challenge["challenge_id"], ["unlock"], "x")["reason"], "bad_request")
        self.assertEqual(self.car.handle(cert, challenge["challenge_id"], "self_destruct", "x")["reason"], "unknown_command")
        self.assertEqual(self.car.handle(cert, challenge["challenge_id"], "unlock", 5)["reason"], "bad_request")


class TestProjection(Base):
    def drive(self):
        self.alice.press(self.car, "unlock")
        return self.alice.press(self.car, "start")["session"]

    def test_projection_needs_the_session_token(self):
        session = self.drive()
        data = {"nav": {"destination": "Home", "eta_min": 5}}
        self.assertFalse(self.car.set_projection("wrong", data))
        self.assertFalse(self.car.set_projection(None, data))
        self.assertTrue(self.car.set_projection(session, data))
        self.assertEqual(self.car.projection["nav"]["destination"], "Home")

    def test_no_projection_before_the_engine_starts(self):
        self.alice.press(self.car, "unlock")
        self.assertFalse(self.car.set_projection("anything", {"nav": {}}))

    def test_projection_is_cleared_and_token_dies_when_the_engine_stops(self):
        session = self.drive()
        self.car.set_projection(session, {"media": {"title": "x", "artist": "y"}})
        self.alice.press(self.car, "stop")
        self.assertEqual(self.car.projection, {})
        self.assertFalse(self.car.set_projection(session, {"media": {"title": "late"}}))

    def test_projection_content_is_sanitised(self):
        session = self.drive()
        self.car.set_projection(session, {
            "nav": {"destination": "A" * 500, "eta_min": "soon"},
            "evil": "<script>", "call": {"name": 7}})
        self.assertEqual(len(self.car.projection["nav"]["destination"]), 80)
        self.assertIsNone(self.car.projection["nav"]["eta_min"])
        self.assertNotIn("evil", self.car.projection)
        self.assertEqual(self.car.projection["call"]["name"], "")


class TestIssuer(Base):
    def test_validity_is_capped_per_role(self):
        phone = Phone("X")
        with self.assertRaises(ValueError):
            self.authority.issue("veh_1", "X", "valet", phone.public_key, 13 * 60)
        self.authority.issue("veh_1", "X", "valet", phone.public_key, 12 * 60)

    def test_rejects_bad_input(self):
        phone = Phone("X")
        for role, key, minutes in [("admin", phone.public_key, 5), ("guest", phone.public_key, 0),
                                   ("guest", phone.public_key, -3), ("guest", phone.public_key, True),
                                   ("guest", phone.public_key, "5"), ("guest", "AAAA", 5),
                                   ("guest", None, 5)]:
            with self.assertRaises(ValueError, msg=(role, key, minutes)):
                self.authority.issue("veh_1", "X", role, key, minutes)


if __name__ == "__main__":
    unittest.main()
