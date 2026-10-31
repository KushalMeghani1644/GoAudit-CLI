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
GOAUDIT_NODE_IMAGE=goaudit-e2e:ci \
bash scripts/test-runtime-probe-e2e.sh
```

Build the test-only fixture image on top of the prepared sandbox image first:

```sh
docker build -t goaudit-node-sandbox:ci -f docker/Dockerfile.node-sandbox .
docker build -t goaudit-e2e:ci -f docker/Dockerfile.e2e .
```

The test-only image packages fixtures as local tarballs without executing their
code or install hooks. Production sandbox images do not contain these fixtures.
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
deadline. Each test generates a temporary `package.json` pointing to fixture
tarballs already in the test image and runs `scan-project`. Only that manifest
is staged from the host; fixture source never enters a host project mount.
The continuation test names the hanging and following packages as two direct
dependencies so both receive independent probe deadlines. No external dependency
is needed.
