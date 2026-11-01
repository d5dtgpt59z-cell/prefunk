# Release process

Prefunk has two distinct public surfaces:

1. The source repository, CLI source, native app source, and Codex plugin.
2. A downloadable prebuilt Mac app.

The source release can ship after the repository checks and clean-checkout reproduction pass. A downloadable Mac app must additionally pass Apple distribution signing and notarization. An ad hoc signed ZIP is a local test artifact, not a public binary.

## Source release gate

From a clean checkout:

```sh
Tests/run-tests.sh
swift build -c release
git diff --check
```

Then confirm:

- `README.md`, `SECURITY.md`, privacy, limitations, changelog, plugin metadata, app metadata, and scanner versions agree.
- Real-project scans preserve relative paths, redact sensitive names, and distinguish routine exclusions from genuine gaps.
- No hosted-product files, generated reports, credentials, build output, or unrelated workspace files are included.
- GitHub private vulnerability reporting is enabled, or another reviewed private reporting channel is documented before announcing the release.

## Local package gate

```sh
Packaging/package.sh
```

This produces and verifies `outputs/Prefunk-<version>-macOS.zip`. With the default ad hoc signature, the result is for local verification only.

## Downloadable public Mac binary gate

Build with a Developer ID Application identity, submit for notarization, staple the ticket, rebuild the final ZIP if required, and verify the exact downloadable archive:

```sh
SIGNING_IDENTITY="Developer ID Application: ..." Packaging/package.sh
REQUIRE_PUBLIC_SIGNATURE=1 Packaging/verify-package.sh outputs/Prefunk-<version>-macOS.zip
```

Do not call the binary public-ready until the second command passes on the exact artifact intended for upload.

## Publication boundary

Creating a commit, tag, GitHub release, upload, App Store submission, public announcement, or tester outreach is a separate action and requires explicit authorization.
