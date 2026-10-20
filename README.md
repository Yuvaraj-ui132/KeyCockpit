# KeyCockpit

A small **phone-as-a-key + digital cockpit** simulator in Python.

Your phone holds a signed digital key. A simulated car checks it **offline**, unlocks, and
loads the driver's profile onto a cockpit screen, where the phone can also show navigation,
music and call info (the idea behind CarPlay / Android Auto). An attack lab tries to break in
and shows why each attempt fails.

![dashboard](docs/dashboard.png)

## What is real and what is simulated

| Real | Simulated |
|---|---|
| Ed25519 signatures (`cryptography` package) | The radio link (BLE / NFC / UWB), done as function calls and HTTP |
| Signed key certificates, checked by the car with only the issuer's **public** key | The vehicle itself: a state machine in `car.py` |
| One-time challenge/response, replay protection | Phone secure hardware: the private key is just a Python object |
| Revocation lists with version numbers | Distance: approximated with a response-time limit (see Limits) |
| Roles with permissions, short-lived keys, audit log | |

Real cars follow the Car Connectivity Consortium **Digital Key** standard and use NFC/UWB.
This project does not implement that standard. It shows the ideas behind it.

## Run it

Python 3.10+ (tested on 3.13).

```bash
pip install -r requirements.txt

python -m keycockpit        # dashboard at http://127.0.0.1:8000
python demo.py              # same story in the terminal, no server
python -m unittest discover -s tests -t .   # 62 tests
```

In the dashboard: press **Unlock** on Alice's phone, then **Start**, then **Cast to car**.
Try Valet's **Glovebox** (denied), then the four buttons in the **Attack lab**. Take the car
**offline**, revoke Bob's key, and see that the car still trusts it until it syncs.

## How it works

```
 Owner (token) ──► Backend ─── issues signed certificate ───► Phone
                      │                                         │
                      │ signed revocation list                  │ challenge → signed answer
                      ▼                                         ▼
                    Car  ◄──────────── (simulated radio) ───────┘
                     │
                     ▼
              Cockpit dashboard (profile, phone projection)
```

1. The owner registers a phone's **public key**; the backend returns a **certificate**: holder,
   role, permissions, vehicle, validity window, all signed with the issuer's private key.
2. To act, the phone asks the car for a **challenge** (random, single use), signs
   `vehicle + challenge + nonce + key id + command`, and sends it with the certificate.
3. The car checks, in order: challenge exists (and is consumed) → answer arrived fast enough →
   certificate signature → vehicle → validity window → not revoked → phone's signature →
   role allows the command → nobody else is driving. Only then does it move.
4. The car never calls the backend to decide. It only needs the issuer's public key.

### Roles

| Role | Can do | Max key lifetime |
|---|---|---|
| owner | everything | 30 days |
| guest | lock, unlock, trunk, start, stop | 7 days |
| valet | lock, unlock, start, stop (no trunk, no glovebox) | 12 hours |

## Threat model

Each row is a test in `tests/` and a button in the attack lab.

| Attack | What the attacker has | Why it fails | Car answer |
|---|---|---|---|
| Replay | A recorded valid unlock message | The challenge was already used; every message needs a fresh one | `unknown_challenge` |
| Reuse a signature for another command | A signed `unlock` | The command is inside the signed bytes | `bad_signature` |
| Relay | A way to forward the car's challenge to the real phone far away | The answer is valid but late; the car enforces a time limit | `too_slow` |
| Forged certificate | Their own "authority" | Certificate not signed by the issuer the car trusts | `bad_certificate` |
| Edited certificate | A valet key, edited to say "owner" | Any change breaks the issuer's signature | `bad_certificate` |
| Stolen certificate | A copy of Bob's certificate (it is not secret) | Cannot sign the challenge without Bob's private key | `bad_signature` |
| Key for another car | A real certificate for a different vehicle | Vehicle id is checked | `wrong_vehicle` |
| Lost phone | The phone | Owner revokes; the car gets a newer signed list | `revoked` |
| Un-revoking | An old revocation list | Lists carry a version; older ones are ignored | list rejected |
| Expired key | An old guest key | Validity window is inside the certificate | `expired` |
| Hijack a running car | A guest key while the owner drives | Only the key that started the engine may command | `in_use` |
| Hijack the cockpit | A guess at the projection token | Needs the session token the car gave to the driving phone | HTTP 403 |
| Give yourself more rights | Calls to the owner API | Issuing, revoking and profiles need the owner token | HTTP 401 |

Also covered: malformed or wrong-typed input, and failed attempts still consuming their
challenge (so an attacker cannot keep guessing against one challenge).

## API

Owner calls need `Authorization: Bearer <owner_token>` (returned when the vehicle is created).

| Method and path | Who | Purpose |
|---|---|---|
| `POST /api/vehicles` | anyone | Create a vehicle; returns `vehicle_id` and `owner_token` |
| `POST /api/vehicles/{id}/keys` | owner | Issue a key: `holder`, `role`, `phone_public_key`, `valid_minutes` |
| `GET /api/vehicles/{id}/keys` | owner | List keys with status (active / expired / revoked) |
| `DELETE /api/vehicles/{id}/keys/{key_id}` | owner | Revoke; pushes the signed list if the car is online |
| `POST /api/vehicles/{id}/car/connectivity` | owner | `{"online": false}` simulates a car with no signal |
| `PUT /api/vehicles/{id}/profiles/{holder}` | owner | Seat, cabin temperature, music preset, theme |
| `GET /api/vehicles/{id}/audit` | owner | Every allow/deny decision |
| `POST /api/vehicles/{id}/car/challenge` | phone | Get a one-time challenge |
| `POST /api/vehicles/{id}/car/command` | phone | `certificate`, `challenge_id`, `command`, `signature` |
| `POST /api/vehicles/{id}/cockpit/projection` | phone | Navigation / media / call data (needs the engine session token) |
| `GET /api/vehicles/{id}/cockpit` | dashboard | Car state, active profile, projection, recent events |

`/api/demo/...` (virtual phones and the attack lab) exists only when started with demo data.

## Limits (read before using for anything real)

- **Relay defence is simplified.** A software time limit on a simulated link teaches the idea.
  Real systems measure signal time-of-flight with UWB, because Bluetooth timing and signal
  strength are not reliable enough for distance. The default limit is 150 ms
  (`KEYCOCKPIT_MAX_RESPONSE_MS`), sized for HTTP on one machine.
- **Revocation needs connectivity.** An offline car keeps trusting a revoked key until it syncs
  or the key expires. That is why keys are short-lived. A car that is already driving is not
  shut off when its key is revoked.
- **Simple owner auth.** One bearer token per vehicle. No accounts, no HTTPS, no rate limiting,
  no request size limits. Do not expose it to the internet.
- **Keys at rest.** The issuer private key sits in SQLite. A real system uses an HSM or cloud KMS.
  A real phone keeps its private key in the Android Keystore or a secure element.
- **No pairing ceremony.** A real car verifies that the person adding a key is physically there.
- **Demo mode shortcut.** The dashboard's virtual phones keep their keys on the server so the
  page can act as three phones. The demo owner token is a public constant: demo only.
- Single process, in-memory car state, SQLite. Fine for a demo, not for scale.

## Project layout

```
keycockpit/
  crypto.py     Ed25519 helpers, canonical JSON
  protocol.py   the exact bytes a phone signs
  issuer.py     certificates, roles, revocation lists
  car.py        the simulated ECU: every security check lives here
  phone.py      simulated phone: signs challenges
  store.py      SQLite: vehicles, keys, audit log, profiles
  app.py        Starlette API + demo endpoints
static/index.html   cockpit dashboard (plain HTML/JS, no build step)
demo.py             terminal walkthrough
tests/              62 tests, including attacks against the car
```

## Ideas to extend

- An **Android (Kotlin) key app** that stores the private key in the Android Keystore and talks
  to the car over real BLE.
- A **car on a microcontroller**, with `car.py`'s checks rewritten in C.
- Share a key by link with a one-time claim code, and a per-key usage count.

## License

MIT
