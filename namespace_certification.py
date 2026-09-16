from pathlib import Path
import shutil

from bulldog.namespace_sandbox import (
    NamespaceSandbox,
)


BASE = Path(
    "/tmp/bull_namespace_backend_cert"
)

PROJECT = BASE / "project"

shutil.rmtree(
    BASE,
    ignore_errors=True,
)

PROJECT.mkdir(
    parents=True,
)

(PROJECT / "inside.txt").write_text(
    "inside-project\n",
    encoding="utf-8",
)


sandbox = NamespaceSandbox()


# =========================================================================
# WRITABLE WORKSPACE TEST
# =========================================================================

payload_path = PROJECT / "payload.py"

payload_path.write_text(
    """
from pathlib import Path
import socket

print("=" * 80)
print("INSIDE BULL NAMESPACE SANDBOX")
print("=" * 80)

assert (
    Path("/workspace/inside.txt").read_text()
    == "inside-project\\n"
)

print("PROJECT_READ=PASS")


Path(
    "/workspace/created.txt"
).write_text(
    "created-inside\\n"
)

assert (
    Path("/workspace/created.txt").read_text()
    == "created-inside\\n"
)

print("PROJECT_WRITE=PASS")


Path(
    "/tmp/private.txt"
).write_text(
    "private-temp\\n"
)

assert (
    Path("/tmp/private.txt").read_text()
    == "private-temp\\n"
)

print("PRIVATE_TMP=PASS")


assert not Path(
    "/content"
).exists()

print("HOST_CONTENT_HIDDEN=PASS")


assert not Path(
    "/root"
).exists()

print("HOST_ROOT_HIDDEN=PASS")


assert not Path(
    "/etc/shadow"
).exists()

print("HOST_SHADOW_HIDDEN=PASS")


status = Path(
    "/proc/self/status"
).read_text()

nnp = None

for line in status.splitlines():

    if line.startswith(
        "NoNewPrivs:"
    ):
        nnp = line.split(
            ":",
            1,
        )[1].strip()

print(
    "NO_NEW_PRIVS="
    + str(nnp)
)

assert nnp == "1"


sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM,
)

sock.settimeout(1)

try:

    sock.connect(
        ("1.1.1.1", 53)
    )

except OSError:

    print(
        "NETWORK_BLOCK=PASS"
    )

else:

    raise AssertionError(
        "network unexpectedly succeeded"
    )

finally:

    sock.close()


print(
    "SANDBOX_PAYLOAD=PASS"
)
""",
    encoding="utf-8",
)


result = sandbox.run(
    [
        "/usr/bin/python3",
        "/workspace/payload.py",
    ],
    project_root=PROJECT,
    writable=True,
    timeout=20,
)


print(result.stdout)

if result.stderr:
    print("STDERR:")
    print(result.stderr)


print(
    "RETURN_CODE:",
    result.returncode,
)


if result.returncode != 0:
    raise SystemExit(
        result.returncode
    )


required = (
    "PROJECT_READ=PASS",
    "PROJECT_WRITE=PASS",
    "PRIVATE_TMP=PASS",
    "HOST_CONTENT_HIDDEN=PASS",
    "HOST_ROOT_HIDDEN=PASS",
    "HOST_SHADOW_HIDDEN=PASS",
    "NO_NEW_PRIVS=1",
    "NETWORK_BLOCK=PASS",
    "SANDBOX_PAYLOAD=PASS",
)


for marker in required:

    assert marker in result.stdout, marker


assert (
    PROJECT / "created.txt"
).read_text() == "created-inside\n"

print(
    "PROJECT_BIND_PERSISTENCE=PASS"
)


# =========================================================================
# READ-ONLY WORKSPACE TEST
# =========================================================================

readonly_payload = PROJECT / "readonly_payload.py"

readonly_payload.write_text(
    """
from pathlib import Path

assert (
    Path("/workspace/inside.txt").read_text()
    == "inside-project\\n"
)

print(
    "READONLY_PROJECT_READ=PASS"
)

try:

    Path(
        "/workspace/forbidden.txt"
    ).write_text(
        "must fail"
    )

except OSError:

    print(
        "READONLY_PROJECT_WRITE_BLOCK=PASS"
    )

else:

    raise AssertionError(
        "read-only workspace allowed a write"
    )
""",
    encoding="utf-8",
)


readonly = sandbox.run(
    [
        "/usr/bin/python3",
        "/workspace/readonly_payload.py",
    ],
    project_root=PROJECT,
    writable=False,
    timeout=20,
)


print(readonly.stdout)

if readonly.stderr:
    print("STDERR:")
    print(readonly.stderr)


if readonly.returncode != 0:
    raise SystemExit(
        readonly.returncode
    )


assert (
    "READONLY_PROJECT_READ=PASS"
    in readonly.stdout
)

assert (
    "READONLY_PROJECT_WRITE_BLOCK=PASS"
    in readonly.stdout
)


print()
print("=" * 80)
print("BULL NAMESPACE SANDBOX CERTIFICATION: PASS")
print("=" * 80)
