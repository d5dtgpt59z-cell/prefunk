# Security policy

Prefunk is a narrow deterministic preflight, not a comprehensive security audit. Reports contain potential matches that must be independently verified.

Use GitHub private vulnerability reporting when it is available for this repository. If that option is unavailable, open a minimal public issue asking the maintainer for a private reporting channel; include no vulnerability details or sensitive project information in that issue. Never include real credentials, private source, environment files, absolute paths, or an unredacted Prefunk project in a public report.

The project accepts security reports for secret leakage, path escape, unreported coverage gaps, unsafe agent instructions, resource exhaustion, signing/update issues, and false-negative or false-positive rule behavior.

Until a signed binary release is published, the supported public surface is the current default branch. Revoked credentials and repository-history cleanup remain the reporter’s responsibility; Prefunk never performs those actions.
