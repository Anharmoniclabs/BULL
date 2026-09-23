# Contributing to BULL

Use an issue to describe a bug or a small proposed change. For sensitive reports,
use [private vulnerability reporting](https://github.com/Anharmoniclabs/BULL/security/advisories/new)
instead of a public issue. Read the [security boundary](docs/SECURITY_CLAIMS.md).

## Local setup

Use Python 3.11+ in a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

The core package declares no third-party Python runtime dependencies. Test extras
install pytest and cryptography. Full Linux checks also need OpenSSL, OpenSSH,
util-linux, working user namespaces and local sockets. ClamAV plus authentic
signature databases, libseccomp, cgroup delegation and QEMU/KVM are deployment
prerequisites, not substitutes for source tests. See the
[deployment guide](docs/REPRODUCIBLE_DEPLOYMENT.md); do not disable protections to
make a restricted environment pass. Record unsupported checks as unavailable.

For packaging, install `setuptools>=77` and `wheel` in the virtual environment.
Build with `python -m pip wheel --no-deps --no-build-isolation . --wheel-dir /tmp/bull-wheels`.
For the website, run `python tools/build_site.py --output /tmp/bull-site`.
Output directories must be outside the checkout and should be new for each run.

## Pull requests

Keep changes focused. Explain the problem, resulting behavior and checks run.
For enforcement changes, include an allowed case and a denied case with observed
effects. Record source/image identities for deployment results. Fixtures, source
checks, live isolation, hardware approval and independent assessment are distinct.

Use a branch and a pull request; satisfy the repository's signature and required
check rules. Do not force-push shared branches, weaken gates, rotate deployment
keys, or publish private logs to resolve a test failure. The root LICENSE governs
original contributions; only contribute material you have the right to share.
Retain upstream notices when adding third-party material and update
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Be respectful and specific. Critique code and claims, not people. Harassment,
threats, discriminatory abuse and publication of personal information are not
welcome; maintainers may remove abusive content and restrict participation.

## Before requesting review

- Run checks appropriate to the change and report failures or missing prerequisites.
- Check `git diff --check` and review the staged files for secrets, generated state and VM images.
- Update documentation when behavior changes; keep historical results tied to their original source.
- Follow [distribution requirements](docs/DISTRIBUTION.md) before proposing binary assets.

No external collector account or physical key is required to read the code,
contribute documentation, or run the source tests supported by your host.
