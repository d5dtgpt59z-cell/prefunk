# Prefunk

Prefunk is a local deterministic security preflight for coding agents. It finds common potential secret exposures and configuration mistakes, emits redacted structured leads, and requires the agent to verify every finding before making a change.

> **Preview:** Prefunk is an early preview focused on common security mistakes. Its findings should be verified by your coding agent before changes are made, and it does not replace a professional security review.

The scanner engine and Codex plugin are open source under the MIT License. The $1.99 Mac App Store edition is the signed, sandboxed convenience product with a native interface, guided exports, and automatic updates.

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

The regression suite tests grouping, redaction, coverage accounting, provider formats, placeholder suppression, agent JSON, and the no-network/no-telemetry/no-process-execution invariant.

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

The package script runs the security tests first, builds the native app and CLI, embeds the CLI in the app bundle, applies the sandbox entitlement, signs the bundle, and creates `outputs/Prefunk-macOS.zip`.

The default signature is ad hoc for local testing. App Store distribution requires a matching profile for `com.builtbymagnus.prefunk` and Apple distribution signing.
