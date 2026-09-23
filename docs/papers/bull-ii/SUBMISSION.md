# Zenodo submission — revision 4

Title: BULL II: Binding Authority to Execution

Author: Luis Minier (Anharmoniclabs)

Resource type: Publication / Technical report

Version: 4

License for original report/source: GPL-2.0-or-later, as supplied in the companion. Cited works retain their own rights.

Keywords: AI agent security; execution governance; capability security; QEMU/KVM; authenticated audit; physical approval; reproducibility.

## Description

BULL is an experimental execution-governance runtime for AI agents. This report explains how trusted host authority is bound to exact operations, admitted inputs, constrained execution and authenticated audit evidence. It documents the implementation, confidentiality/integrity/availability controls, information transport, build procedure, controlled recovery and the KB2040 physical-approval prototype.

The latest qualified runtime is ab53f563bcbcaf60820acb318b8212796ce502ff, with 501 passing tests and 21 subtests and five passing real-KVM cases. Historical benchmarks and the forty-action Qwen run retain their separate source identities. Physical BOOT gestures were observed, but hardware signing and protected credential release remain blocked. The report includes original technical drawings, source-derived tables and figures, independent references and a reproducible LaTeX/evidence companion. Results are author-operated; this is not an independent security audit.

## Files to upload

- bull-ii.pdf — report.
- bull-ii-companion.zip — LaTeX, build script, drawings and retained evidence.
- bull-ii-manifest.json — artifact and source hashes.

Use the actual submission date. Leave the DOI unassigned until Zenodo reserves or publishes one. Do not reuse the removed record's DOI. After publication, add the new record URL to the repository and website.

## Announcement draft

I have updated BULL II: Binding Authority to Execution, documenting how I built BULL to keep an AI agent's proposed actions tied to host-granted authority.

The report covers the execution path, information transport, authenticated audit records, controlled recovery and the KB2040 approval prototype. It includes the retained 501-test plus 21-subtest result, five real-KVM acceptance cases, and historical agent-run and benchmark evidence, with source identities and reproduction instructions.

The hardware work is documented at its measured stage: physical YES/NO gestures were observed; secure signing is still unfinished. Charts are generated from retained project data.

Paper and evidence: https://github.com/Anharmoniclabs/BULL#publication-and-citation

I welcome technical feedback on the implementation and evaluation methods.
