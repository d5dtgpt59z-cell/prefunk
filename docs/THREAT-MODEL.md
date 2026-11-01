# Prefunk threat model

## Assets

Prefunk protects project source, credentials, private paths, scan findings, and the integrity of the instructions supplied to a coding agent.

## Trust boundaries

- Project files, directory names, filenames, and report labels are untrusted.
- Prefunk rules and static prompt templates are trusted release content.
- Prefunk does not trust a coding agent to interpret a match as proof.
- Downstream agents have their own privacy and network behavior outside Prefunk’s control.
- Development-only binary overrides are untrusted and disabled unless explicitly enabled.

## Defended threats

- Secret disclosure through reports, JSON, clipboard prompts, filenames, hashes, or decoded JWTs.
- Prompt injection through project-controlled names or report fields.
- Symlink traversal outside the selected root.
- Silent partial scans caused by unsupported, oversized, unreadable, undecodable, excluded, traversal-failed, or work-limited content.
- Resource exhaustion through excessive file count or bytes.
- Automation bias and destructive agent remediation.
- Plugin binary substitution through ordinary `PATH` resolution.

## Controls

- Read-only scanning with no network, telemetry, project execution, plugins, archives, or automatic edits.
- Secret-free output schema containing only rule metadata and sanitized relative locations.
- Bounded file size, aggregate bytes, candidate count, and local JWT parsing.
- Explicit coverage status and non-success exit code for incomplete scans.
- Static agent contract requiring independent verification and approval for destructive or external actions.
- Signed App Store distribution target; the plugin prefers its known app-bundled CLI.

## Residual risks

Regex rules can miss transformed credentials and can produce false positives. Static scanning cannot validate runtime authorization, provider state, dependency vulnerabilities, or application behavior. A downstream coding agent may transmit files according to its own provider policy. Users must rotate genuinely exposed credentials and review repository history separately.
