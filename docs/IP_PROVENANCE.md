# BULL IP and provenance record

This document records the repository's current internal copyright and source-
provenance picture. It is an engineering provenance record, not a legal opinion,
patent filing, copyright registration, or independent audit.

## Original BULL material

Unless a file or section says otherwise, copyrightable human-authored portions
of original BULL source code, documentation, tests, diagrams, and project
materials are identified as:

> Copyright © 2026 Luis Minier

Original BULL software is published under GPL-2.0-or-later. The project-wide
notice is in [../COPYRIGHT](../COPYRIGHT).

Use of AI-assisted development tools does not change this record into a claim
over machine-generated material that is not copyrightable. The ownership notice
applies to copyrightable human authorship, including original expression and,
where applicable, human selection, coordination, arrangement, editing, and
modification.

## Internal chain-of-title review

An internal repository review performed on 2026-09-24 found:

- one human Git author identity across the inspected repository history:
  `Anharmoniclabs <132678602+Anharmoniclabs@users.noreply.github.com>`;
- automated Dependabot and GitHub Actions sign-off/co-author trailers in a
  dependency/integration commit;
- no additional human Git author identity identified by that history review;
- one clearly identified source-level third-party derivative in
  `firmware/src/boot_button.c`, documented below;
- external build/deployment dependencies referenced or pinned rather than
  silently vendored as BULL source, subject to the qualifications in
  [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

This review does not prove that no unidentified third-party fragment exists.
Future releases should continue source-provenance and license scanning.

## Known third-party and excluded material

### Raspberry Pi BOOTSEL sampling

`firmware/src/boot_button.c` states that its BOOTSEL sampling is adapted from
Raspberry Pi `pico-examples/picoboard/button`. The file retains:

- Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
- SPDX-License-Identifier: BSD-3-Clause

The complete notice is retained in `firmware/PICO_EXAMPLES_LICENSE.txt`.
Do not replace that upstream copyright or re-identify the file as wholly
original BULL code.

### IEEEtran

`docs/papers/bull-ii/IEEEtran.cls` is third-party IEEEtran material. Its header
identifies the original contributors and copyright holders and states that the
work is distributed under the LaTeX Project Public License (LPPL) version 1.3.
Its upstream notices must be retained.

### License texts

`LICENSE` and `docs/papers/bull-ii/LICENSE` contain the GNU General Public
License text and its Free Software Foundation copyright notice. The presence of
that notice does not make the Free Software Foundation the copyright owner of
BULL.

### External dependencies and generated environments

Python, Buildroot, qboot, Linux, QEMU, ClamAV, libseccomp, Pico SDK, TinyUSB,
toolchains, model weights, generated guest images, media dependencies, and other
external components retain their own licenses and copyrights. See
[../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) and
[DISTRIBUTION.md](DISTRIBUTION.md).

## Methods, systems, algorithms, and architecture

BULL documents and implements security techniques, execution-control flows,
policy mechanisms, isolation arrangements, audit mechanisms, and other technical
methods.

The copyright notice protects copyrightable expression in the implementation
and documentation. It does **not** claim that copyright grants exclusive rights
in an underlying idea, procedure, process, system, method of operation, concept,
principle, discovery, or algorithm.

Any potential patent rights in a technical invention are separate from copyright
and require a separate patent analysis and, if appropriate, a patent filing.
Nothing in this repository should be read as a patent grant, patent application,
or representation that any BULL method is patentable.

## Contributor provenance going forward

Contributors must submit only material they have the right to contribute and
must retain applicable upstream notices. A contribution accepted under the
project license does not silently erase the contributor's copyright.

Before changing licensing, offering exclusive rights, or representing that one
party owns all copyright in future multi-author versions, re-check the contributor
history and any applicable contributor agreements.

## Recommended release checks

Before a material release:

1. Review new Git author and co-author identities.
2. Search source for new copyright, SPDX, attribution, and upstream notices.
3. Update `THIRD_PARTY_NOTICES.md` for newly bundled third-party material.
4. Preserve per-file third-party license headers.
5. Produce an SBOM or equivalent dependency inventory for distributed binaries.
6. Keep generated images, model weights, firmware dependencies, and external
   packages tied to their actual upstream licenses.
7. Record AI-assisted material accurately if copyright registration is pursued.

The repository's copyright notice is a notice of rights; federal copyright
registration, trademark registration, and patent protection are separate legal
processes.
