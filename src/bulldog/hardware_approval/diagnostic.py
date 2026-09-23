#!/usr/bin/env python3
"""Read the KB2040 diagnostic HID; never constructs approval proofs."""
import ctypes as C
import json
import argparse
import secrets
import time


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-clicks", action="store_true", help="Arm one harmless 30-second BOOT click test")
    parser.add_argument("--serial", help="USB discovery hint only; never an enrolled identity")
    args = parser.parse_args(argv)
    lib = C.CDLL("libhidapi-libusb.so.0")
    lib.hid_open.argtypes = [C.c_ushort, C.c_ushort, C.c_wchar_p]
    lib.hid_open.restype = C.c_void_p
    lib.hid_write.argtypes = [C.c_void_p, C.c_void_p, C.c_size_t]
    lib.hid_read_timeout.argtypes = [C.c_void_p, C.c_void_p, C.c_size_t, C.c_int]
    lib.hid_close.argtypes = [C.c_void_p]
    lib.hid_error.argtypes = [C.c_void_p]
    lib.hid_error.restype = C.c_wchar_p
    lib.hid_init()
    handle = lib.hid_open(0xcafe, 0x4010, args.serial)
    if not handle:
        raise SystemExit("Diagnostic KB2040 unavailable or USB permission denied")
    try:
        def send(payload):
            command = C.create_string_buffer(b'\0' + payload, 65)
            if lib.hid_write(handle, command, 65) != 65:
                raise SystemExit("HID request failed: " + str(lib.hid_error(handle)))

        def receive_status(timeout_ms):
            output = C.create_string_buffer(64)
            count = lib.hid_read_timeout(handle, output, 64, timeout_ms)
            if count == 0:
                return None
            if count != 64 or output.raw[:11] not in (b'BULL-DIAG-1', b'BULL-DIAG-2', b'BULL-DIAG-3'):
                raise SystemExit("Missing or malformed diagnostic status")
            if output.raw[11] != 0:
                raise SystemExit("Unexpected authority flag in diagnostic firmware")
            return output.raw

        # CANCEL emits a status reply. A previous invocation can close before
        # reading it, leaving a stale report on the interrupt endpoint. Drain a
        # bounded queue before sending any command; never reuse its decisions.
        for _ in range(8):
            if receive_status(100) is None:
                break
        else:
            raise SystemExit("Diagnostic receive queue did not settle")

        def read_status():
            send(b'\1' + bytes(63))
            data = receive_status(2000)
            if data is None:
                raise SystemExit("Missing diagnostic status")
            return data

        data = read_status()
        if args.test_clicks:
            if data[:11] != b'BULL-DIAG-3':
                raise SystemExit("BOOT click firmware revision 3 required")
            if data[23]:
                raise SystemExit("A diagnostic request is already pending")
            nonce = secrets.token_bytes(32)
            send(b'\2' + nonce + bytes(31))
            print("DIAGNOSTIC ONLY — no BULL action can execute.\n"
                  "Waiting: click BOOT twice for YES or three times for NO.\n"
                  "Keep clicks under 600 ms apart; release between clicks.", flush=True)
            deadline = time.monotonic() + 32
            try:
                while time.monotonic() < deadline:
                    data = read_status()
                    if data[32:] != nonce:
                        raise SystemExit("Diagnostic challenge changed or device reset; cancelled")
                    if data[24]:
                        result = {1: "NO", 2: "YES", 3: "CANCELLED"}.get(data[24])
                        if result is None:
                            raise SystemExit("Invalid diagnostic result")
                        print(json.dumps({"diagnostic_decision": result, "approval_available": False,
                                          "challenge": nonce.hex()}), flush=True)
                        return
                    time.sleep(0.05)
                raise SystemExit("Diagnostic timed out")
            finally:
                send(b'\3' + bytes(63))
        expanded = data[:11] in (b'BULL-DIAG-2', b'BULL-DIAG-3')
        print(json.dumps({"firmware": data[:11].decode("ascii"), "approval_available": False,
                          "i2c_0x60_read": bool(data[12]), "wake_response": data[13:17].hex(),
                          "atecc_wake_valid": data[13:17] == bytes.fromhex('04113343'),
                          "probe_phase": "boot",
                          "successful_four_byte_reads": data[22] if expanded else None,
                          "detected_atecc_address": hex(data[19]) if data[19] else None,
                          "sda_high_before_probe": bool(data[20]) if expanded else None,
                          "scl_high_before_probe": bool(data[21]) if expanded else None,
                          "yes_pressed": bool(data[17]), "no_pressed": bool(data[18]),
                          "boot_pressed": bool(data[26]) if data[:11] == b'BULL-DIAG-3' else None,
                          "diagnostic_pending": bool(data[23]),
                          "diagnostic_click_count": data[25]}, indent=2))
    finally:
        lib.hid_close(handle)
        lib.hid_exit()


if __name__ == '__main__':
    main()
