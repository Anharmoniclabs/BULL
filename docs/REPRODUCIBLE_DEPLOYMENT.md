# Reproduce a BULL deployment with your own authority

Already using Codespaces? The [VM and physical-key checklist](CODESPACES_VM_AND_KEY_CHECKS.md)
provides the commands for the remaining real-environment tests.

BULL does not require the author's keys, Cloudflare account, hardware credential,
home directory, or private VM baseline. Every operator follows this workflow and
owns their deployment state. Supported enforcement/guest qualification currently
targets Linux x86-64 with the required namespaces, seccomp, Landlock, cgroup v2
and, for VM cases, usable KVM. Other systems must report their missing protections.

Reproducibility here means public inputs and a repeatable preparation/test
procedure with recorded identities. Fresh keys and sessions intentionally differ
between installations. **Bit-for-bit guest-image reproducibility has not been
demonstrated.** A source-test PASS, configured guest recipe or generated policy is
not a guest boot, physical approval, independent review, or universal certification.

## 1. Install the selected source candidate

Use a reviewed commit or release ref and record `git rev-parse HEAD`. Do not reset
an existing checkout with uncommitted work. From the selected BULL checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
```

Python 3.11 or newer and Bash are required. The host checks also use OpenSSH
`ssh-keygen`, libseccomp, util-linux and the existing strict sandbox prerequisites.
The VM runner additionally needs QEMU/KVM, OpenSSL and e2fsprogs. Dependencies and
platform versions appear in the validation evidence; the pip test extra is a
version range, not a complete hermetic dependency lock.

## 2. Delegate host resources explicitly

On a machine you administer, run the checked-in helper:

```bash
sudo /usr/bin/python3 -I tools/host_setup.py \
  --user "$(id -un)" --grant-kvm --enter-shell
```

This grants membership in the existing KVM device group, creates a dedicated
`/sys/fs/cgroup/bull-UID` subtree, and opens an **unprivileged** Bash there with
refreshed groups. Run subsequent commands in that shell; `exit` returns to the
previous shell. The parent cgroup stays empty while the coordinator and workload
children can be populated. This follows Linux's [cgroup delegation rules](https://docs.kernel.org/admin-guide/cgroup-v2.html#delegation).

If parent controllers are disabled, the helper stops. An administrator can review
and explicitly add `--enable-parent-controllers`; it does not remount restricted
provider filesystems or substitute fake cgroup files. Omit `--grant-kvm` for host
validation on a system without KVM; guest checks stay BLOCKED. Existing service
managers may supply their own delegated subtree instead.

Host setup reports `PROVISIONED_NOT_TESTED`. The deployment checker performs
actual child placement and reads back its memory, process and CPU limits. This
does not claim a memory-pressure, process-exhaustion or CPU-throttling test.

## 3. Generate an installation's private authority

```bash
BULL_STATE="$HOME/.local/share/bull/deployment-01"
.venv/bin/python tools/deployment_setup.py init \
  --state "$BULL_STATE" --project-root "$PWD" \
  --cgroup-parent "$BULL_CGROUP_PARENT"
```

State must be outside the admitted project and Git. Directories are mode 0700;
private files are mode 0600 even under a permissive umask. The tool generates
independent integrity, policy and collector keys plus installation/session IDs.
It verifies the signed policy and runtime manifest. The default capability
ceiling is `fs.read.project, process.exec`. Repeat `--capability` to choose a
different explicit ceiling; credential/network/security capabilities require
an enrolled approval public key. This does not add unsupported operation brokers.

An existing state path is refused. The tool never silently rotates keys, resets
the ledger, changes its session, signs modified runtime files, or resets Git.
For an existing collector, provide `--existing-collector-key /PRIVATE/key` at
initialization; its exact private-file bytes are preserved. Otherwise the new
collector key is at `$BULL_STATE/secrets/collector.key`, ready to provision your
own collector. No endpoint is selected implicitly.

`show --state "$BULL_STATE"` prints configuration, paths and readiness without
key values. `environment --state "$BULL_STATE" --output "$BULL_STATE/environment.sh"`
writes a new private Bash environment file for operator integrations. Keep this
file and the entire deployment directory private.

## 4. Provision your collector

Deploy the supplied [Cloudflare Worker and D1 collector](../deploy/cloudflare-audit/README.md),
or a compatible collector behind your own trusted HTTPS endpoint. Each independent
installation needs its matching collector authority. For a new Worker, install the
new deployment's key over stdin, from your authenticated Cloudflare CLI:

```bash
cd deploy/cloudflare-audit
npx wrangler secret put BULL_ANCHOR_MASTER_KEY < "$BULL_STATE/secrets/collector.key"
cd ../..
.venv/bin/python tools/deployment_setup.py configure --state "$BULL_STATE" \
  --collector-url https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/v1/checkpoints
```

Replace the endpoint with the URL of **your deployed service**. No author's
service is contacted. `configure` preserves keys/session; changing an active
ledger's destination requires a new deployment. An authenticated acknowledgement
is tested separately and is not an independent durability review.

## 5. Enroll your hardware credential when using consequential operations

Create an OpenSSH security-key credential on the operator machine where the
authenticator is accessible. For example, for an authenticator supporting Ed25519:

```bash
install -d -m 700 "$HOME/.local/share/bull/credentials"
ssh-keygen -t ed25519-sk -O application=ssh:bull-approval -O verify-required \
  -f "$HOME/.local/share/bull/credentials/approval"
```

The command requires real device interaction. `ecdsa-sk` is also supported. Add
the following to a **new deployment's `init` command** to enroll the public key
and select the handle used by the harmless ceremony:

```bash
--approval-public-key "$HOME/.local/share/bull/credentials/approval.pub" \
--approval-key "$HOME/.local/share/bull/credentials/approval"
```

Those are each operator's credentials, never shared release secrets. Without
enrollment/access, physical approval stays BLOCKED; ordinary software SSH keys
are rejected. Browser access to a Codespace does not expose your USB authenticator
to its terminal. Supervised enrollment, manufacturer attestation and a trusted
display are distinct requirements; this workflow does not fabricate them.

## 6. Build guest inputs from public sources

The new public recipe needs no previous personal images or baseline directory:

```bash
BULL_GUEST="$HOME/.local/share/bull/guest-build-01"
.venv/bin/python microvm/guest/build_public.py prepare \
  --output "$BULL_GUEST" --fetch
```

`--fetch` downloads these immutable source commits and verifies clean checkouts:

| Component | Public source identity |
|---|---|
| Buildroot 2026.08 | `d5180309b1b66ef3b8eaccca70ad69be8e0729a1` |
| Linux 7.1.13 | SHA-256 `614d95fafdcb5cce2b6620e7edc6afbb606bffd4655405586815d84687841ad7` for `linux-7.1.13.tar.xz` |
| qboot | `8ca302e86d685fa05b16e2b208888243da319941`, recorded by QEMU v10.1.0 |

The kernel hash comes from [kernel.org's signed checksum listing](https://www.kernel.org/pub/linux/kernel/v7.x/sha256sums.asc).
The qboot revision comes from [QEMU's source record](https://github.com/qemu/qemu/tree/v10.1.0/roms/qboot).
Configs, the init script, mandatory feature checks and firmware build commands
are in Git. Buildroot enforces source-download hashes, including the custom kernel.
`prepare` runs real Kconfig resolution and checks required dependencies; it reports
`CONFIGURED_NOT_BUILT`. It does not claim that this newly public image was booted.

Build dependencies include a native C/C++ toolchain, make, Git, wget/curl, file,
patch, rsync, cpio, unzip, bzip2/xz, bc, flex, bison, Perl and development headers
specified by [Buildroot's manual](https://buildroot.org/downloads/manual/manual.html#requirement).
Qboot uses Meson/Ninja built from the same pinned Buildroot tree. Build as a normal
user; allow substantial disk space and compilation time. The default job count is 2.

Obtain fresh official ClamAV databases using [FreshClam](https://docs.clamav.net/manual/Usage/SignatureManagement.html)
on a supported operator host. Use a **new empty private database directory** so
`main.cvd`, `daily.cvd` and `bytecode.cvd` are full distributions. For example:

```bash
BULL_DB="$HOME/.local/share/bull/database-inputs-01"
install -d -m 700 "$BULL_DB"
printf 'DatabaseDirectory %s\nDatabaseOwner %s\nDatabaseMirror database.clamav.net\n' \
  "$BULL_DB" "$(id -un)" > "$BULL_DB/freshclam.conf"
freshclam --config-file="$BULL_DB/freshclam.conf"
.venv/bin/python microvm/guest/build_public.py databases \
  --output "$BULL_GUEST" --database-dir "$BULL_DB"
.venv/bin/python microvm/guest/build_public.py build --output "$BULL_GUEST" --jobs 2
```

An installed, supported `sigtool` must verify the real CVD signatures before and
after copying. Dummy databases or a caller-chosen hash alone cannot satisfy that
step. Database hashes are sealed into `build.json` before compilation. Official
database revisions change over time: preserve the exact verified inputs for a
repeat build. No updater is started in the guest.

Successful compilation verifies the resolved kernel features and input hashes,
then publishes canonical regular files and `assets.json`. Status is
`BUILT_NOT_BOOT_TESTED`. Buildroot's reproducibility option and a fixed source epoch
are enabled; two independently built images have not yet been compared byte-for-byte.

Register the build with your deployment:

```bash
.venv/bin/python tools/deployment_setup.py configure --state "$BULL_STATE" \
  --assets "$BULL_GUEST/assets.json"
```

The earlier private-baseline scripts and historical laptop results remain historical
evidence. They are not prerequisites or substitutes for qualifying this public recipe.

## 7. Run the same acceptance command for every installation

Obtain the pinned TLA+ jar once, verifying its digest:

```bash
curl --fail --location \
  https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar \
  --output "$HOME/bull-tla2tools-v1.7.4.jar"
printf '%s  %s\n' \
  936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88 \
  "$HOME/bull-tla2tools-v1.7.4.jar" | sha256sum --check --strict

.venv/bin/python tools/deployment_check.py \
  --deployment "$BULL_STATE" \
  --tla-jar "$HOME/bull-tla2tools-v1.7.4.jar" \
  --output "$HOME/bull-evidence-$(date -u +%Y%m%dT%H%M%SZ)"
```

Deployment mode verifies the private configuration and signed runtime before any
test, clears inherited `BULL_*` authority and uses only the selected installation.
Source/protocol test subprocesses receive no deployment credentials. Actual
production/collector checks receive the installation's selected authority.

The command tests source, finite models, real host protections, actual cgroup
placement, KVM readiness, conditional five-case guest execution, authenticated
external receipts and conditional interactive approval. Missing inputs stay
BLOCKED. Failure or blockage returns nonzero. Review `report.json` and its logs.
The report always retains `certified: false`; informed consent and independent
review cannot be granted by running the software itself.

CI tests two independently initialized installations, cross-key/policy/manifest
rejection, private permissions, stable authority on reruns, no ambient-authority
fallback, and the actual public Buildroot configuration step. CI does not relabel
synthetic SK tests as physical hardware or configuration checks as VM execution.
