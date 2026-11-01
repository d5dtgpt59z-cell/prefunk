# Prefunk

Prefunk is a local deterministic security preflight for coding agents. It finds common potential secret exposures and configuration mistakes, emits redacted structured leads, and requires the agent to verify every finding before making a change.

> **Scope:** Prefunk is focused on common security mistakes. Its findings must be verified before changes are made, and it does not replace a professional security review.

> **Platform:** The native app and CLI require macOS 14 or later.

The scanner engine, native interface, CLI, and Codex plugin are free and open source under the MIT License.

## Safety boundary

- No account, backend, analytics, telemetry, network service, or code upload.
- Read-only project scanning.
- No project execution or automatic code modification.
- No secret values, fragments, snippets, token payloads, hashes, or absolute paths in agent output.
- Coverage gaps are explicit and never reported as a clean success.
- Prefunk finds potential matches; it is not an audit or proof that an app is secure.

## Build

```sh
swift build
swift run PrefunkMac
swift run prefunk scan . --format json
swift run prefunk scan . --format markdown --project-name "Client-safe name"
```

CLI exit codes:

- `0`: no matches and complete supported-file coverage
- `2`: potential findings
- `3`: incomplete coverage
- `64`: usage or fatal scan failure

## Test

```sh
Tests/run-tests.sh
```

The regression suite tests grouping, redaction, coverage accounting, provider formats, placeholder suppression, client-safe Markdown and agent JSON, native export wiring, and the no-network/no-telemetry/no-process-execution invariant.

## Codex plugin

The plugin source lives in `plugins/prefunk`. Its workflow invokes the one-shot CLI, treats report fields as untrusted data, independently verifies findings, and asks for approval before credential rotation, history rewriting, auth changes, deletion, deployment, commits, pushes, or external actions.

After cloning the repository, add its marketplace and install Prefunk:

```sh
codex plugin marketplace add .
codex plugin add prefunk@prefunk
```

The MVP intentionally does not expose an MCP server.

## Package the Mac app

```sh
Packaging/package.sh
```

The package script runs the security tests first, builds the native app and CLI, embeds the CLI in the app bundle, applies the sandbox entitlement, signs the bundle, creates a versioned ZIP, and verifies the exact archive after extraction.

The default signature is ad hoc and suitable only for local testing or source-built use. A downloadable public Mac binary still requires Developer ID signing plus notarization, or App Store signing with a matching profile for `com.builtbymagnus.prefunk`.
