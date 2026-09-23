# BULL Hardware Authority

Physical Human Approval Token

## Implementation status

This is an unfinished hardware bring-up, not a production authenticator.
The current Pico SDK target is **bull_hardware_diagnostic**. It exposes only
vendor-defined HID status, reads button levels, and probes the ATECC wake
response. Diagnostic revision 1 probes address 0x60; revision 2 first probes
0x60, 0x35, 0x36 and 0x10, then remaining non-reserved I2C addresses, and reports
the bus line levels. It cannot sign or approve anything. It has no
keyboard, mass-storage interface, CDC console, REPL, or private key.

The portable button state machine and Python canonical codec/signature verifier
have software tests. The host verifier is now wired into the existing ApprovalGate with durable
request consumption and per-key counters. Signed approval and denial, replay,
expiry, binding changes and audit failure have software conformance tests. The
diagnostic firmware cannot produce a signed assertion and cannot satisfy the gate.
The existing OpenSSH security-key provider retains its presence/verification checks.

Still required: identify and validate the actual secure-element part/configuration,
implement its driver and self-test, perform physical provisioning/enrollment,
implement authenticated host requests and bounded signing-protocol HID framing,
and verify the physical buttons, signed assertions and hardware failure matrix. Do not present software test keys as hardware keys.

Bring-up evidence (2026-09-23): the board currently reports `BULL-DIAG-3`,
`approval_available=false`, no valid ATECC wake response, zero successful
four-byte reads, and no pending diagnostic request. SDA and SCL read high at
boot. This does not identify a chip or validate wiring, power, address or timing.
The physical click test was cancelled; two-/three-click gestures are not yet
verified on the board. Original firmware backups and raw diagnostic logs remain
private. The operator confirmed that only the KB2040 is present; no secure-element
breakout is connected. No secure element has been provisioned or enrolled.

The alternate Trust&GO and TrustFLEX defaults are documented in Microchip's
[ATECC608A Trust Development Board guide](https://ww1.microchip.com/downloads/en/DeviceDoc/ATECC608A-Trust-Development-Board-Users-Guide-DS50002922A.pdf).

## Wiring

Disconnect power while wiring. Confirm the breakout's supply and logic voltages
before reconnecting it. Do not connect 5 V logic to the RP2040.

| KB2040 | Connection |
| --- | --- |
| 3V | 3.3 V-compatible secure-element supply |
| GND | Secure-element ground and button common ground |
| SDA / GPIO12 | Secure-element SDA |
| SCL / GPIO13 | Secure-element SCL |
| D4 / GPIO4 | Normally-open YES button to GND |
| D5 / GPIO5 | Normally-open NO button to GND |
| GPIO17 | Onboard NeoPixel |

The GPIO mapping is taken from the
[Pico SDK KB2040 board definition](https://github.com/raspberrypi/pico-sdk/blob/2.2.0/src/boards/include/boards/adafruit_kb2040.h)
and [Adafruit pinout](https://learn.adafruit.com/adafruit-kb2040/pinouts).
Buttons use internal pull-ups: LOW means pressed. Check that opposite contacts
on a four-leg tactile button are used; same-side legs may already be connected.

## Intended architecture and trust boundary

BULL constructs an exact request through its existing ApprovalGate. The host
displays the operation and waits without clickable or keyboard YES/NO controls.
Only physical buttons may request a signature from the controller. A validated
secure element generates and retains a non-exportable P-256 signing key.
The host verifies the assertion, atomically consumes the request and advances
the device counter, delivers required audit records, and rechecks policy,
domain, executable/resource and argv before the exact effect.

The RP2040 does not establish authenticated firmware or hardened secure boot.
A secure element protects key extraction; it does not prove that controller
firmware honestly enforced a button press. This prototype is not FIDO2-certified,
tamper-proof, equivalent to a commercial security key, or resistant to invasive
physical attacks. A compromised host can also misrepresent the human-readable
operation: without a trusted display, the token cannot verify what the user saw.

## Canonical protocol draft

All integers use big-endian encoding, without padding. Packets are bounded by
512 bytes. Request: the 11 bytes `BULL-AUTH-1`, type byte 1, eight 32-byte fields
(request ID, session digest, complete action digest, operation digest, resource
digest, parameter digest, policy digest, fresh host nonce), creation and expiry
as unsigned 64-bit seconds. Lifetime is at most 30 seconds. SHA-256 of all request
bytes is the request digest. The complete action digest must include BULL's
existing full binding, including executable identity and argv where applicable.

Assertion: the same protocol bytes, decision byte (0 DENY, 1 APPROVE), five
32-byte fields (enrolled device identity, request ID, request digest, session
digest, host nonce), unsigned 32-bit monotonic counter, and 64-byte P-256 r||s
signature. ECDSA-SHA256 signs every assertion byte before the signature field.
Request authentication and signing-protocol HID framing are not yet implemented
in firmware. The diagnostic HID commands are a separate, non-authorizing protocol.
The host derives the fresh nonce from the random 256-bit request ID, complete
canonical request and credential identity with a domain-separated SHA-256 hash.

The host must reject wrong signatures, disabled/unknown keys, session/digest/
nonce mismatches, stale counters and expired requests. Skipped counters are valid
because failed deliveries can consume hardware counter values. Replay safety
also requires a durable transaction consuming the request and advancing its
counter. ApprovalGate performs both in the same SQLite transaction before audit
delivery and before any effect. Signed DENY is terminal and audited separately.
Counters follow the public-key fingerprint across enrollment aliases.

## Physical presence

The operator changed the requested UX to **two BOOT clicks for YES and three
BOOT clicks for NO**. Diagnostic revision 3 implements this through
`boot_clicks.c`, with 30 ms debounce on each edge and 600 ms quiet time after
the second release before YES. A third click during that window yields NO.
A single click followed by a pause, a press held for 1.5 seconds, the 30-second
request timeout, disconnect, suspend, reset or malformed command cancels.
The button must first be released after a request arrives; idle clicks never
carry into another request. This is a diagnostic UX only. The supplied hardware acceptance specification
requires separate YES/NO buttons and a deliberate YES hold; BOOT clicks have
not been accepted as a replacement for that production ceremony.

The host can start a harmless diagnostic request with:

```sh
python tools/hardware_diagnostic.py --test-clicks
```

This sends a fresh 32-byte diagnostic challenge. Yellow means that one test is
pending, green briefly indicates the diagnostic YES, and red indicates NO or
cancellation. The device subsequently returns to flashing red because secure
approval remains unavailable. The diagnostic response is **not signed**, cannot
satisfy ApprovalGate, and must never be used to execute protected operations.
HID commands are status, arm diagnostic request, and cancellation only; there
is no host command for generating a click or setting the decision. Reset clears
the state without producing a signed denial. BOOT sampling runs from SRAM with
interrupts disabled briefly; core 1 and flash-reading DMA are not used.

The earlier, separate two-external-button state machine requires both buttons to be released for 30 ms after
each new request. It then requires YES for 30 ms debounce plus 750 ms continuous
hold. A short tap or idle press grants nothing. NO stable for 30 ms denies.
Simultaneous raw presses, expiry and disconnect clear the request. A second
request cannot replace the first. Reset clears all volatile state. A decision
may be emitted only once; signing and delivery must complete before returning
to idle, and any secure-element/counter/signing failure must clear and fail closed.

## Provisioning and enrollment requirements

First read exact part identity, revision, configuration bytes and lock status.
Save those bytes and validate the intended slot against the part's documentation.
Test key generation, public-key readout, signature verification, RNG and counter
on a disposable chip. Never blindly lock a zone or regenerate an existing key.
The current diagnostic firmware contains no such write commands.

Final enrollment must record device ID, chip serial, public key, algorithm,
protocol, role `human_approval`, enabled flag and last accepted counter in private
owner-only storage. USB VID/PID and a reported chip serial are discovery hints,
not cryptographic identity. Enrollment must be separate from approval and must
not enroll a new key based solely on a host-controlled USB response.

## Host integration

Install `.[hardware]` to enable the custom P-256 verifier. Run `bull hardware
status` for read-only status, optionally selecting a USB serial. USB identifiers
are discovery hints only. `bull hardware test-buttons` starts one harmless,
unsigned diagnostic; it cannot grant authority.

After physically verifying a secure-element-generated public key and recording
the part, serial, configuration and firmware fingerprints, `bull hardware
enrollment-record --help` creates an owner-only **disabled** record. It does not
provision hardware, generate a key, enable the credential, or change policy.
Never label a software-generated key as hardware. Test keys exist only in tests.
An operator must verify provisioning and deliberately include the enabled record
under a credential ID in the signed `human_approval.credentials` policy. Custom
hardware uses a 30-second lifetime. Signed provisioning metadata records operator
inspection; it is not manufacturer attestation or proof of RP2040 firmware trust.

`bull approval hardware-request REQUEST_ID --credential ID --output request.bin`
exports only a pending, unexpired request for an enabled credential. The host
prints the operation; it provides no software approval button. The production
signing firmware/transport is still required to produce a response.

A device response is the complete binary Assertion, supplied in the existing
`ApprovalProof(request_id, credential_id, signature=response_bytes)`. The normal
ProductionDispatcher broker route calls ApprovalGate, verifies the binding and
signature, atomically consumes the request and counter, delivers the audit, then
rechecks policy and domain before effect. Invalid, absent, diagnostic or disabled
proofs fail closed. After audit failure, consumption stays terminal; no automatic
retry can reuse that proof. Existing deployment policies must be regenerated
with the new integrity manifest before using the updated trusted runtime.

The bundled firmware is **diagnostic-only**. There is no production USB signing
transport or secure-element driver to activate yet; software conformance tests
must not be presented as a physically completed integration.

## Build and test

Use Pico SDK 2.2.0 with its pinned TinyUSB submodule, ARM bare-metal GCC/newlib,
and picotool 2.2.0. Set `PICO_SDK_PATH` and put the compiler on PATH, then:

```sh
cmake -S firmware -B build/hardware -Dpicotool_DIR=/path/to/picotool/lib/cmake/picotool
cmake --build build/hardware -j4
python -m pytest -q tests/test_hardware_authority.py tests/test_human_approval.py
cc -std=c11 -Wall -Wextra -Werror -I firmware/src firmware/src/state_machine.c firmware/tests/state_machine_test.c -o /tmp/bull-buttons
/tmp/bull-buttons
cc -std=c11 -Wall -Wextra -Werror -I firmware/src firmware/src/boot_clicks.c firmware/tests/boot_clicks_test.c -o /tmp/bull-boot-clicks
/tmp/bull-boot-clicks
```

The diagnostic UF2 is explicitly not the final demo firmware. It uses development
VID/PID cafe:4010 and must obtain an assigned USB identity before distribution.
Use the physical BOOT/RESET gesture to recover it; it exposes no reboot command.

## Presentation and future work

Only after hardware verification may a demo claim a non-exportable secure-element
key binds physical approval to the exact pending request. Demonstrate signed
APPROVE, signed DENY, and rejection of a replayed approval. Record physical
decisions separately from policy denials. LED color is never cryptographic proof.

Future work: RP2350 secure boot and OTP trust, debug locking, a trusted OLED that
renders information derived from the exact signed bytes, PCB/enclosure design,
and separately scoped certified FIDO2/CTAP2 work. None is a present security claim.
