# Prefunk agent report schema 1.0

Top-level fields:

- `schemaVersion`
- `engineVersion`
- `rulesVersion`
- `projectLabel` — sanitized label only, never an absolute path
- `generatedAt`
- `status` — `no_matches`, `potential_findings`, or `incomplete`
- `coverage`
- `findings`

Coverage includes inspected, unsupported, static-asset, generated-artifact, archive, database, symbolic-link, oversized, unreadable, undecodable, excluded-root and traversal-error counts, plus relative artifact paths, work-limit state, and completeness.

Each finding contains a rule ID, potential impact, confidence, title, explanation, remediation class, the literal redaction marker, and relative line locations. It never contains matched content, snippets, hashes, decoded token payloads, or absolute paths.

Exit status is authoritative for automation. Incomplete coverage takes precedence over findings.
