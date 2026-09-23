# Technical presentation Q&A

Start with the [five-minute presentation](PRESENTATION.md) and
[latest exact-candidate evidence](VALIDATION_20260923.md).

## Opening statement

BULL is an experimental execution firewall for operations routed through its
production integration. It separates model proposals from host-owned authority,
checks exact command and broker requests, constrains execution, and records
locally verifiable and remotely authenticated audit evidence. It is not a
system-wide interceptor or a certification of arbitrary AI behavior.

The meeting invitation is an opportunity for technical discussion. Do not imply
OpenSSF endorsement, sponsorship, certification or independent review from the
invitation alone; use the organizer's actual meeting/group name.

## Ten-minute presentation

1. **Problem (one minute):** an untrusted action proposal is not execution authority.
2. **Boundary (two minutes):** model proposal → production dispatcher → policy and
   exact argv/operation binding → protected execution or broker → audit receipt.
   Host/operator/key custody are trusted. Guest and host are distinct boundaries.
3. **Evidence (two minutes):** show the final candidate report, source digest,
   bounded models, actual cgroup behavior and five VM cases. Distinguish unit
   fixtures from real isolation. Show approval as synthetic protocol validation.
4. **Harmless demonstration (three minutes):** allowed workload, policy denial,
   and timeout/descendant cleanup in disposable local infrastructure. Show both
   return result and observed effect/cleanup; denial can be a returned result.
5. **Questions (two minutes):** ask reviewers about complete mediation, approval
   channel trust, audit recovery and independent evaluation methodology.

## Demonstration preparation

Use a fresh, private evidence output outside the repository and pinned verified
assets. Rehearse the documented local integration command from `microvm/README.md`
without external collector arguments. The integration runner creates disposable
local audit infrastructure by default. Never use production credentials in the
slides or deliberately corrupt a production collector to demonstrate denial.
Show allowed, denied and timeout reports from the same candidate. Keep the full
five-case acceptance run as supporting evidence. Record a short screen capture
before the meeting if the operator wants an offline backup; no recording has
been made by this audit. Keep private logs and machine paths out of the recording.

For a source-only demonstration, use the documented `tools/release_check.py`
command. Clearly label it source validation: it does not demonstrate a physical
key, a guest boot or external retention.

## Questions and precise answers

| Question | Answer |
|---|---|
| Does it stop every malicious AI action? | No. It enforces configured authority on mediated paths, within stated host/TCB assumptions. |
| Can it detect all prompt injection? | No. Model text and provenance signals do not replace capability enforcement. |
| Does every process need physical approval? | No. Exact host-authorized contained computation differs from consequential secret/network broker approval. |
| Have you tested a physical security key? | No. Synthetic SK protocol tests passed; compatible hardware and operator interaction remain required. |
| Does touch prove the person understood the operation? | No. No trusted action display or informed-consent proof is claimed. |
| Can child agents acquire broader rights? | Current registry tests verify capability/egress subset constraints under a trusted registry and integration. |
| Does a valid audit receipt guarantee permanent storage? | No. It authenticates a checkpoint bound to session, sequence and head. Retention/restore and collector compromise are separate questions. |
| Are the formal checks a proof of the implementation? | No. They explore finite state-machine abstractions. |
| Is the website green proof of firewall correctness? | No. Source, host, resource, VM, approval and audit gates are distinct. |
| What about issue #51? | Its harness mistook returned denial results for execution; new effect-aware tests cover grants and production argv binding. Development compatibility is explicitly weaker, and there is no separate executable allowlist. |
| Is main protected? | The inspected active ruleset requires PRs and five security/formal checks with no bypass actors. It does not require an independent approving reviewer. |
| Has all branch code been proven safe? | No. All fetched/local branch refs were inventoried; historical branch names/results are not current-candidate evidence. |
| What do you want from reviewers? | Critical feedback on mediation coverage, deployment assumptions, approval UX, audit recovery and independent validation. |

## Source of truth

- `SECURITY_CLAIMS.md`: implementation/test mapping and unsupported behaviors.
- `VALIDATION_20260923.md`: latest pinned evidence; older records remain historical.
- `BRANCH_AUDIT_20260922.md`: preserved branch inventory and historical caveats.
- PR #55: latest exact candidate status and reviewed public result summary.

Do not merge, release, or promote production merely to prepare this presentation.
Hardware and independent review gaps should remain visible. No presentation date,
slot duration or audience composition beyond the operator's report is assumed.
