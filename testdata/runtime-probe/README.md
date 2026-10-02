# Runtime-probe regression fixtures

These packages have no install lifecycle scripts and need no registry access.
Installing them is harmless; importing them (or calling `lodash.chunk`) is
deliberately **not** harmless outside GoAudit's sandbox.

**Do not run these entrypoints with host Node, import them in a host test runner,
or call their exports on the host.** They read `~/.aws/credentials`; only GoAudit
should execute them, against synthetic sandbox honeypots in the unprivileged
`runsc` sandbox. The e2e script never reads or creates host credentials.

Run from the repository root after building a CLI with `--runtime-probe`:

```sh
GOAUDIT_BIN=./goaudit \
GOAUDIT_NODE_IMAGE=goaudit-node-sandbox:ci \
bash scripts/test-runtime-probe-e2e.sh
```

The image must already exist locally and contain GoAudit's sandbox prerequisites.
The default image follows the existing privilege-escalation e2e convention.
All scans disable host registry checks, sandbox networking, and sandbox caching.

| Fixture | Behavior only when sandbox-executed |
| --- | --- |
| `import-time` | Reads the AWS honeypot while importing CommonJS. |
| `delayed` | Reads it 200 ms after import returns. |
| `esm` | Uses top-level await and dynamic imports during ESM initialization. |
| `api-lodash` | Harmless import; `chunk` reads it when called by the lodash adapter. |
| `obfuscated` | `eval(Buffer.from(base64, 'base64').toString())` decodes a honeypot read, with no exfiltration or persistence. |
| `hanging` | Infinite synchronous loop during import; package deadline must produce an inconclusive result. |
| `hang-then-next` | Continuation case: sorted local dependencies hang first, then read the honeypot. |

There are no network requests, subprocesses, credential writes, or install hooks.
The intentionally hanging fixture must never be imported without a sandbox
deadline. The continuation fixture uses only `file:` dependencies contained in
its own directory; `scan-project --mount-project` stages only that fixture tree,
not the whole repository. No external dependency is needed.
