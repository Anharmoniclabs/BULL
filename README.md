<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="site/assets/brand/bull-primary-dark.svg"><img src="site/assets/brand/bull-primary.svg" width="420" alt="BULL — Blocking Unauthorized Logic Loopholes"></picture></p>

# BULL

BULL is an experimental Linux security runtime for AI agents. It checks whether
an action has permission before running it, limits what the action can access,
and records the result. The goal is to keep people in control of the systems an
agent uses.

A model's request is input, not permission. The operator configures trusted
policies and approval credentials. BULL mediates operations that are explicitly
connected to its enforcement paths; it does not intercept every action on a host.

[Documentation](docs/README.md) · [Read the code](docs/CODE_READING_GUIDE.md) ·
[Security model](docs/PRODUCTION_SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Start here

| You want to… | Start with… |
|---|---|
| Understand the idea | [Five-minute presentation](docs/PRESENTATION.md) |
| Follow an action through the code | [Code reading guide](docs/CODE_READING_GUIDE.md) |
| Run source tests | The commands below and [contributor setup](CONTRIBUTING.md) |
| Configure a deployment | [Deployment guide](docs/REPRODUCIBLE_DEPLOYMENT.md) |
| Understand the current candidate | [Production assurance](docs/HUMAN_FIRST_PRODUCTION_ASSURANCE.md) |
| Review a security claim | [Claims and limits](docs/SECURITY_CLAIMS.md) |

Python 3.11+ and Git are required. These commands check source code; they do not
provision a secure deployment:

```sh
git clone https://github.com/Anharmoniclabs/BULL.git
cd BULL
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

Some tests need Linux namespaces, local sockets, OpenSSL or OpenSSH. Follow the
contributor guide for dependencies. A missing host feature is not a passing test.

## What has been observed

Results belong to the source and environment that produced them. This branch's
newest candidate evidence is an operator-supplied Codespaces transcript; its
private images and reports are not included here.

| Source | Observation | Boundary |
|---|---|---|
| `e6df4de` | Combined candidate reported 13 passing checks with separate agent and gateway users, nftables and systemd | Disposable Debian KVM candidate; dispatcher workload path and pinned image release remain separate checks |
| `ab53f56` | Retained record: 501 tests + 21 subtests and five real-KVM cases | Historical deployment snapshot; [record](site/data/validation/ab53f56.json) |
| Earlier governed-agent run | 40 actions in 11m 47s and two worker-exit recoveries | Host namespace sandbox; [separate evidence](docs/evidence/governed-agent-20260922/README.md) |

See [the candidate's exact scope](docs/HUMAN_FIRST_PRODUCTION_ASSURANCE.md) and
[the integration history](docs/INTEGRATION_QUALIFICATION_20260927.md). A source edit
does not inherit a fresh live-test result from an earlier commit.

## What still needs evidence

The combined candidate has not established the complete production dispatcher
workload path in a released, pinned networked image. Hardware approval has not
been demonstrated end to end. The KB2040 remains an unsigned diagnostic prototype;
see [hardware status](docs/HARDWARE_AUTHORITY.md).

BULL has no independent third-party security audit. Multi-day reliability,
host power-loss recovery and universal adapter coverage remain unverified. The
host administrator, kernel and hypervisor remain trusted. No test result here
establishes immunity to all prompt injection, kernel compromise or VM escape.

## Publication and citation

[**BULL II: Binding Authority to Execution — revised PDF**](site/assets/papers/bull-ii.pdf)
includes the validated `ab53f56` results (501 tests + 21 subtests, five KVM cases),
physical unsigned BOOT gestures, USB/session hardening, and remaining signing
gaps. [LaTeX and build instructions](docs/papers/bull-ii/README.md) ·
[Evidence/source companion](site/assets/papers/bull-ii-companion.zip) ·
[Artifact hashes](site/assets/papers/bull-ii-manifest.json).
The paper is published on [Zenodo](https://zenodo.org/records/22923455):
[**DOI: 10.5281/zenodo.22923455**](https://doi.org/10.5281/zenodo.22923455).
The deposited `bull-ii.pdf` matches the repository's revision 4 PDF.
The reproducible source/evidence companion is available from the GitHub links above.

**Citation:** Minier, Luis. (2026). *BULL : Blocking Unauthorized Logic Loopholes*.
Zenodo. https://doi.org/10.5281/zenodo.22923455

[Publication record and artifact identity](docs/PUBLICATION.md).

## License and contributions

BULL's original source is **GPL-2.0-or-later**; see [LICENSE](LICENSE).
Third-party tools, guest-image packages and referenced media retain their own
licenses; see [third-party notices](THIRD_PARTY_NOTICES.md) and the
[distribution checklist](docs/DISTRIBUTION.md). Source publication is distinct
from clearance to redistribute a bundled guest image.

Small, reviewable pull requests are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md).
Report sensitive vulnerabilities [privately](https://github.com/Anharmoniclabs/BULL/security/advisories/new);
see [SECURITY.md](SECURITY.md). Never include credentials or private deployment logs.

Hardware prototype and host verification: [BULL Hardware Authority](docs/HARDWARE_AUTHORITY.md).
The diagnostic token cannot authorize protected actions.
