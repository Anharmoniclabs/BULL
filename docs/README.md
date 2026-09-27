# Documentation

Start with the question you need answered. Historical reports describe their
own revisions; they are not a single cumulative certification of the current code.

## Understand and inspect

- [Code reading guide](CODE_READING_GUIDE.md): responsibilities, request paths and side effects.
- [Presentation](PRESENTATION.md): a short introduction to the research.
- [Production security](PRODUCTION_SECURITY.md): trust assumptions and enforcement design.
- [Security claims](SECURITY_CLAIMS.md): supported claims and limits.
- [Human-first production assurance](HUMAN_FIRST_PRODUCTION_ASSURANCE.md): current candidate and remaining checks.
- [Guest egress](SYSTEM_WIDE_EGRESS.md): gateway, network rules and their scope.

## Run and operate

- [Reproducible deployment](REPRODUCIBLE_DEPLOYMENT.md): host and service setup.
- [Codespaces deployment checks](CODESPACES_DEPLOYMENT_CHECKS.md): environment requirements.
- [Control console](CONTROL_CONSOLE.md): operator interface.
- [Governed agent run](GOVERNED_AGENT_RUN.md): bounded model workflow.
- [Human approval](HUMAN_APPROVAL.md) and [hardware authority](HARDWARE_AUTHORITY.md): approval configuration and limitations.
- [Adapter validation](ADAPTER_VALIDATION.md): supported execution paths.

## Read the evidence

- [September 27 integration history](INTEGRATION_QUALIFICATION_20260927.md): successive fixtures and revisions.
- [Historical deployment record](../site/data/validation/ab53f56.json): retained source-specific results.
- [Governed-agent evidence](evidence/governed-agent-20260922/README.md): earlier host sandbox run.
- [MicroVM reproduction](../microvm/README.md): image and guest setup.
- [Branch integration record](BRANCH_INTEGRATION.md): historical merge context.
- [Engineering site](https://anharmoniclabs.github.io/BULL/): architecture and historical benchmarks.
- [Publication record](PUBLICATION.md): paper identity and artifacts.
- [BULL II source](papers/bull-ii/README.md): paper build and companion material.

## Whole-repository readability pass

[Per-file review record](REPOSITORY_READABILITY.md) lists every tracked file,
what was changed or preserved, and the verification scope.

## Change the project

- [Contributing](../CONTRIBUTING.md): setup, tests and review expectations.
- [Distribution](DISTRIBUTION.md): licensing and redistribution requirements.
- [Security reporting](../SECURITY.md): private vulnerability disclosure.

Dated validation files and publication evidence remain historical records. When
a claim appears to conflict, compare its revision, fixture and evidence source
before treating it as a current result.
