# Changelog

## 1.1.0 — release candidate

- Expanded Swift, Xcode, web, infrastructure, and common native source coverage.
- Separated static assets, generated artifacts, archives, databases, symbolic links, and routine build exclusions from unsupported source formats.
- Added known-file coverage rates, confidence, explicit gaps, and adaptive human-readable reports.
- Added client-safe project names across Markdown, agent JSON, prompts, macOS exports, and export filenames.
- Added Markdown CLI output and `--project-name`.
- Added archive artifact paths to agent JSON without exposing absolute paths or matched values.
- Reduced false positives for placeholder credentials and WebRTC ICE password syntax.
- Added exact packaged-app verification for archive hygiene, signatures, sandbox entitlements, and the bundled CLI.

Prefunk remains a deterministic preflight. This release does not establish that a scanned project is secure, compliant, or certified.
