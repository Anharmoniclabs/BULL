# Run the remaining checks from Codespaces

These commands run the actual five-case VM test on your Codespace. The preferred
path is to download a versioned guest release; the repository also retains a
source-build path for independent reproduction. The first
public guest build compiles a toolchain, Linux and ClamAV: allow several hours
and tens of GiB of free storage. Keep the Codespace running. The VM itself
requires 4 GiB of RAM in addition to the host. Check `df -h "$HOME"` and `free -h`
before starting. A completed build or a working KVM device is not a boot result.

## 0. Download a verified guest release

When a guest release has been published, download its five release files from
the GitHub release page into a private directory. Then verify every hash before
using an image:

```bash
cd /workspaces/BULL
mkdir -m 700 -p "$HOME/bull-guest-release"
cd "$HOME/bull-guest-release"
gh release download GUEST_RELEASE_TAG \
  --repo Anharmoniclabs/BULL \
  --pattern 'bzImage' --pattern 'rootfs.ext4' --pattern 'qboot.rom' \
  --pattern 'assets.json' --pattern 'build.json' --pattern 'SHA256SUMS' \
  --pattern 'RELEASE_SCOPE.txt'
sha256sum --check SHA256SUMS
python3 - <<'PY'
import json
from pathlib import Path
source = json.loads(Path('assets.json').read_text())
local = {name: {**entry, 'path': str(Path(entry['path']).with_name(Path(entry['path']).name))}
         for name, entry in source.items()}
# The release manifest records builder paths; this local manifest binds the same
# hashes to the files just downloaded into this directory.
local['kernel']['path'] = str(Path.cwd() / 'bzImage')
local['rootfs']['path'] = str(Path.cwd() / 'rootfs.ext4')
local['firmware']['path'] = str(Path.cwd() / 'qboot.rom')
Path('assets-local.json').write_text(json.dumps(local, indent=2) + '\n')
PY
```

The release scope must say `BUILT_NOT_BOOT_TESTED` until the five-case run below
passes. Do not use a release with a failed hash check or missing manifest.

## 1. Update and install the build and VM tools

Run from the existing BULL checkout. A conflicting checkout causes the
fast-forward pull to stop; it does not discard local work.

```bash
cd /workspaces/BULL
git pull --ff-only origin main
sudo apt-get update
sudo apt-get install -y build-essential binutils make bash patch gzip bzip2 \
  perl tar cpio unzip rsync file bc wget git curl xz-utils flex bison \
  libssl-dev libelf-dev pkg-config qemu-system-x86 e2fsprogs openssl \
  openssh-client clamav clamav-freshclam
.venv/bin/python -m pip install -e '.[test]'
df -h "$HOME"
free -h
```

Refresh the KVM group and enter a normal-user shell inside BULL's delegated
cgroup. Run subsequent commands in that new shell:

```bash
sudo /usr/bin/python3 -I tools/host_setup.py \
  --user "$(id -un)" --grant-kvm --enter-shell
```

If it explicitly reports that parent controllers are disabled, add
`--enable-parent-controllers` when repeating that administrator command.

## 2. Build the guest from public, pinned inputs

Use new build and database directories; existing directories are not overwritten.
No personal signing key or external audit account is needed for this VM fixture.

```bash
(
set -euo pipefail
umask 077
cd /workspaces/BULL
BULL_GUEST="$HOME/.local/share/bull/guest-build-01"
BULL_DB="$HOME/.local/share/bull/database-inputs-01"
.venv/bin/python microvm/guest/build_public.py prepare \
  --output "$BULL_GUEST" --fetch
mkdir -m 700 "$BULL_DB"
printf 'DatabaseDirectory %s\nDatabaseOwner %s\nDatabaseMirror database.clamav.net\n' \
  "$BULL_DB" "$(id -un)" > "$BULL_DB/freshclam.conf"
freshclam --config-file="$BULL_DB/freshclam.conf"
.venv/bin/python microvm/guest/build_public.py databases \
  --output "$BULL_GUEST" --database-dir "$BULL_DB"
.venv/bin/python microvm/guest/build_public.py build \
  --output "$BULL_GUEST" --jobs 2 2>&1 | tee "$BULL_GUEST/compile.log"
)
```

If compilation fails, retain the directory and inspect `compile.log`. After
fixing the reported prerequisite, repeat **only the `build` command**, with the
same `--output`. Do not repeat `prepare` over the existing directory. If the
official database service rate-limits a download, respect its stated retry time.
A dummy database cannot replace signature verification.

Successful compilation produces `guest-build-01/assets.json`. Its recorded
status `BUILT_NOT_BOOT_TESTED` is intentional: the next step must still run.

## 3. Boot the VM and run all five cases

This validates asset hashes, boots real QEMU/KVM, and collects each case's own
report. Test credentials and the local TLS audit collector are generated for
that run. The external production collector is a separate check.

```bash
(
set -euo pipefail
umask 077
cd /workspaces/BULL
PYTHONPATH=src .venv/bin/python - <<'PY'
import json, os, subprocess, sys, tempfile
from pathlib import Path
from tools.deployment_check import checked_assets, probe_kvm

readiness = probe_kvm()
print(json.dumps(readiness, indent=2), flush=True)
if readiness['status'] != 'PASS':
    raise SystemExit('KVM is not ready in this terminal; enter the delegated shell first.')
assets = checked_assets(Path.home() / 'bull-guest-release/assets-local.json')
# Short socket paths are required by the operating system.
root = Path(tempfile.mkdtemp(prefix='bull-kvm-', dir='/tmp'))
output = root / 'cases'
command = [sys.executable, 'microvm/integration.py', '--case', 'all', '--output', str(output)]
for name, item in assets.items():
    command += ['--' + name, item['path']]
print('Evidence directory:', root, flush=True)
result = subprocess.run(command, env=dict(os.environ, PYTHONPATH='src'), check=False)
summary = output / 'summary.json'
if summary.exists():
    print(summary.read_text())
print('Keep this evidence locally; it includes disposable private test state:', root)
raise SystemExit(result.returncode)
PY
)
```

The summary must show `PASS` for **allowed, denied, timeout, cancel and
missing-protection**. An error, missing summary, partial run or KVM-readiness
PASS alone does not satisfy that requirement. Reports retain the source commit
and asset hashes. Preserve the private evidence directory before your Codespace
is deleted. Share the summary and reviewed reports, not the entire directory:
it contains disposable signing/TLS keys.

## 4. Physical approval from a browser Codespace

A browser terminal cannot directly read a USB security key plugged into your
laptop. Use the [paired approval ceremony](HUMAN_APPROVAL.md): the Codespace
creates the exact request, the local computer signs it using its security key,
and the Codespace verifies the returned signature and rejects replay. The
private key stays on the local computer.

The resulting report checks the credential protocol. It cannot independently
prove manufacturer attestation, a trusted physical display, or whether the human
understood the action. Preserve those distinctions when publishing results.
