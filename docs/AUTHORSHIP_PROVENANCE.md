# BULL Authorship and Provenance Record

This document records the currently supported authorship and provenance picture
for BULL — Blocking Unauthorized Logic Loopholes. It is deliberately
conservative: it records only facts supported by contemporaneous project/chat
history and repository evidence, and it does not claim that one person manually
wrote every line of the AI-assisted implementation.

It is an internal project provenance record, not a government copyright
registration, court finding, or independent legal opinion.

## Human-originated project direction

Recovered contemporaneous records show the following chronology.

### September 14, 2026 — original BULL problem definition

Luis Minier proposed building novel infrastructure against rogue or unwanted AI
agents using a small open-source coding/execution model and a defensive harness.

Later the same day, before the BULL implementation had matured, he defined the
project as an **AI firewall** for agents and used a **guard-dog / bulldog**
metaphor. The stated purpose was to defend the **local computer and filesystem**
from untrusted external text, files, or other agents becoming real machine
actions.

The enduring human-originated requirement was the separation of untrusted
information from permission to act: externally supplied or model-generated
content should not automatically become execution authority.

Minier then directed that the idea be instantiated as a Git project and
preserved for continued development. The BULL repository was created on
September 14, 2026.

### September 16, 2026 — execution authority and host controls

Subsequent human-directed requirements expanded the design beyond a policy-only
demo. Minier required or accepted concrete work on:

- host-controlled provenance and capability authority;
- parent/child privilege limits;
- credential and secret controls;
- controlled network egress;
- fail-closed audit behavior;
- malware scanning;
- immutable snapshot/hash binding;
- syscall/process hardening;
- external audit anchoring;
- sandboxing and human review;
- formal or machine-checkable verification where feasible.

These requirements were repeatedly tested and revised rather than treated as
documentation-only claims.

### September 17–18, 2026 — multi-agent containment and adversarial testing

Minier directed expansion toward multi-agent containment, including defensive
canary/honeytoken evidence and bounded delegated authority.

He also required adversarial testing of practical failure modes such as
credential access, host-file access, shell/process execution, unauthorized
egress, persistence, agent spawning, alternate paths, traversal, and
prompt/instruction-driven attempts to escape the intended authority boundary.

### September 19–20, 2026 — stronger isolation boundary

As the project evolved, Minier pushed BULL toward stronger OS and VM-backed
containment rather than treating policy labels alone as sufficient security.
That direction became the namespace/seccomp/Landlock and QEMU/KVM MicroVM work
present in the repository.

## Repository authorship evidence

An internal Git-history review performed on September 24, 2026 found one human
Git author identity across the inspected history:

`Anharmoniclabs <132678602+Anharmoniclabs@users.noreply.github.com>`

The same review found automated Dependabot and GitHub Actions attribution in
commit metadata, not an additional identified human source-code author.

This does not prove that every byte is original BULL authorship. Repository
provenance must also account for known third-party material and AI-assisted
implementation.

## Known third-party material

The current review identified the following explicit exceptions:

- `firmware/src/boot_button.c` states that its BOOTSEL sampling is adapted
  from Raspberry Pi `pico-examples/picoboard/button`; the Raspberry Pi
  copyright and BSD-3-Clause identifier are retained.
- `firmware/PICO_EXAMPLES_LICENSE.txt` preserves the corresponding
  BSD-3-Clause license text.
- `docs/papers/bull-ii/IEEEtran.cls` retains its original contributor
  copyrights and LPPL 1.3 notice.
- GNU GPL license files retain the Free Software Foundation copyright notice
  for the license text itself.
- External tools, packages, SDKs, model weights, generated images, and other
  dependencies retain their own licenses and copyrights.

See `THIRD_PARTY_NOTICES.md` for the maintained third-party inventory.

## AI-assisted development and human-in-the-loop authorship

BULL is accurately described as **human-directed and AI-assisted**.

Luis Minier does not claim to be a traditional software programmer who manually
typed the BULL codebase. AI systems were used as coding and implementation tools.

The finished project resulted from repeated human-in-the-loop work by Minier,
including:

- originating the BULL problem definition and project identity;
- specifying desired behavior and security boundaries in natural language;
- directing architectural changes and integrations;
- choosing which proposed implementations to keep, reject, or revise;
- designing and requesting experiments, adversarial tests, and validation runs;
- reviewing observed results and requiring corrections when results were
  insufficient;
- selecting, coordinating, and arranging the components that became the BULL
  system; and
- iterating until those components formed the resulting published project.

The recovered record therefore supports human origination and direction of the
project while accurately acknowledging that substantial source-code
implementation was AI-assisted.

This record does **not** claim that Luis Minier personally typed every
implementation line or that every machine-generated fragment is independently
copyrightable. The project copyright notice is intended to identify and preserve
the copyrightable human contributions and protectable human expression embodied
in the finished BULL project while accurately disclosing the role of AI-assisted
coding.

## Future provenance discipline

For future releases:

1. preserve third-party notices and per-file license headers;
2. review new Git authors and co-authors;
3. document newly bundled third-party source;
4. keep dependency/SBOM evidence for distributed binaries and guest images;
5. keep the human-in-the-loop and AI-assisted development record accurate; and
6. do not represent future multi-author code as solely owned by one person
   without re-checking contributor rights.
