# Run the native experiment in Codespaces

This archive executes actual OpenShell sandboxes, BULL and HTTP requests.
It contains no newly completed native result. The previous host check was
BLOCKED. The paper must wait for this run's actual observations.

In the BULL Codespace terminal:

```bash
git fetch origin evidence/native-codespace-20261015
git switch --track origin/evidence/native-codespace-20261015
bash reproducibility/native/run-codespace.sh
```

If this branch is already checked out, run only the last command. Use a clean
checkout when switching; do not discard existing work. The launcher needs
Python 3.12, a local working Docker daemon, an Ubuntu/Debian host and root or
passwordless sudo. OpenShell's build downloads packages and a pinned Rust
toolchain. A reachable daemon does not guarantee that Codespaces permits the
required sandbox isolation; such failures remain failures in the logs.

At the end, the terminal prints the location of `results-to-review.zip` under
`/workspaces/bull-native-.../`. Download that ZIP from the Codespace file explorer
and supply it for the paper update. It includes build failures when no test ran,
or the actual reports, destination receipts, original runtime logs, command
output and provenance when available. Full runtime files stay in the same run
directory; the export omits generated private keys and local authorization state.

The runner does not publish results or overwrite the paper. A zero launcher
exit code alone is not a result: inspect the individual cases in
`results/native/results.json` and their raw evidence. Failed and missing cases
must remain visible in the paper.

Archive SHA-256:
`d90b3b37610d01a119299965bcae3d5c564617782c7cef16402d43c313ca6492`

The archive identifies its source snapshot and includes the IEEE paper source.
Its pinned BULL baseline is older than current main. This tests that snapshot,
not arbitrary newer BULL code. See its `START_HERE.md` for scope and limitations.
