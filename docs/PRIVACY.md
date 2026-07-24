# Privacy

Prefunk itself processes selected project files locally. It has no account system, backend, analytics, telemetry, advertising SDK, network client, upload path, or hosted report storage.

The native app receives read-only access only to folders selected through macOS. Report destinations are selected separately through the save panel. The CLI reads the explicit project root and writes to standard output unless the user opts into an output file.

Prefunk output excludes matched values, secret fragments, source snippets, decoded JWT payloads, raw fingerprints, and absolute paths. Credential-shaped project and file names are redacted.

Using a Prefunk report with Codex or another coding agent is a separate processing step governed by that product’s configuration and privacy terms. Prefunk does not invoke an agent automatically.
