"""Terminal walkthrough of the whole system, no server needed.

    python demo.py

Every line below is the real car logic making a real decision.
"""

import copy

from keycockpit import crypto, issuer
from keycockpit.car import Car, SimClock
from keycockpit.phone import Phone

clock = SimClock()
authority = issuer.KeyIssuer(crypto.generate_private_key(), clock=clock)
car = Car("veh_demo", authority.public_key, clock=clock)  # the car only gets the PUBLIC key


def phone(name, role, minutes):
    p = Phone(name)
    p.certificate = authority.issue("veh_demo", name, role, p.public_key, minutes)
    return p


def show(who, command, result, note=""):
    verdict = "ALLOWED" if result["ok"] else f"DENIED  ({result['reason']})"
    print(f"  {who:<8} {command:<14} {verdict}  {note}")


def scene(title):
    print(f"\n== {title}")


alice, bob, valet = phone("Alice", "owner", 24 * 60), phone("Bob", "guest", 180), phone("Valet", "valet", 60)

scene("1. Normal use: the owner's phone")
for cmd in ("unlock", "open_trunk", "start", "stop", "lock"):
    show("Alice", cmd, alice.press(car, cmd))

scene("2. Roles: the valet key cannot open the trunk or glovebox")
show("Valet", "unlock", valet.press(car, "unlock"))
show("Valet", "open_trunk", valet.press(car, "open_trunk"))
show("Valet", "open_glovebox", valet.press(car, "open_glovebox"))
show("Valet", "start", valet.press(car, "start"))
show("Valet", "stop", valet.press(car, "stop"))
show("Valet", "lock", valet.press(car, "lock"))

scene("3. Replay attack: an eavesdropper re-sends a captured unlock message")
challenge = car.new_challenge()
sig = alice.sign("veh_demo", challenge, alice.certificate["payload"]["key_id"], "unlock")
captured = (alice.certificate, challenge["challenge_id"], "unlock", sig)
show("Alice", "unlock", car.handle(*captured), "(the genuine message)")
show("Attacker", "unlock", car.handle(*captured), "(same bytes, sent again)")
show("Alice", "lock", alice.press(car, "lock"))

scene("4. Relay attack: Alice's phone is far away; the answer is valid but slow")
show("Alice", "unlock", alice.press(car, "unlock", link_delay_s=0.005), "(phone next to the car)")
show("Alice", "lock", alice.press(car, "lock"))
show("Relay", "unlock", alice.press(car, "unlock", link_delay_s=0.250), "(+250 ms through the relay)")

scene("5. Forged and stolen certificates")
fake_authority = issuer.KeyIssuer(crypto.generate_private_key(), clock=clock)
thief = Phone("Thief")
thief.certificate = fake_authority.issue("veh_demo", "Thief", "owner", thief.public_key, 60)
show("Thief", "unlock", thief.press(car, "unlock"), "(certificate signed by their own authority)")
tampered = copy.deepcopy(valet.certificate)
tampered["payload"]["perms"] = list(issuer.ROLE_PERMISSIONS["owner"])
valet_with_edit = Phone("Valet")
valet_with_edit._key, valet_with_edit.certificate = valet._key, tampered
show("Valet", "unlock", valet_with_edit.press(car, "unlock"), "(edited own permissions)")
stolen = Phone("Thief")
stolen.certificate = bob.certificate
show("Thief", "unlock", stolen.press(car, "unlock"), "(Bob's certificate, wrong private key)")

scene("6. Revocation: Bob's phone is lost")
show("Bob", "unlock", bob.press(car, "unlock"), "(before revoking)")
show("Bob", "lock", bob.press(car, "lock"))
bob_id = bob.certificate["payload"]["key_id"]
print("  owner revokes Bob's key; the car is online and gets the signed list")
car.update_revocations(authority.revocation_list("veh_demo", [bob_id]))
show("Bob", "unlock", bob.press(car, "unlock"))

scene("7. Expiry: valet key is valid for 1 hour, then it simply stops working")
clock.advance(61 * 60)
show("Valet", "unlock", valet.press(car, "unlock"), "(61 minutes later)")
show("Alice", "unlock", alice.press(car, "unlock"), "(owner key lasts longer)")
print()
