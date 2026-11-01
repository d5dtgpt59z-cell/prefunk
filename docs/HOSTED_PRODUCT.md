# Prefunk hosted product

## What exists today

Prefunk 1.1 is a deterministic local security preflight for coding agents. The Swift core scans supported text files for ten classes of potential secret exposure and configuration mistakes, including OpenAI/GitHub/AWS credentials, private keys, client-bundled secrets, wildcard CORS, open Firebase rules, Supabase service-role material, and hardcoded passwords.

The product has:

- a native macOS interface and one-shot CLI
- grouped, severity-ranked findings with redacted evidence
- explicit coverage accounting for unsupported, oversized, unreadable, and excluded content
- Markdown, JSON, and guarded agent-prompt exports
- placeholder suppression and confidence reduction for tests, samples, docs, and ambiguous rules
- regression tests enforcing read-only operation and the no-network/no-telemetry/no-process-execution boundary
- a Codex plugin that requires independent verification and approval before consequential actions

It currently has no accounts, backend, network service, analytics, cloud storage, or public-URL scanner. The local scanner is intentionally more capable on source code than a public website check can be.

## Lean hosted edition

The hosted MVP is a complementary product, not a server port of the local engine. It makes one passive request to a public page and checks visible security posture such as HTTPS use, HSTS, CSP, MIME-sniffing protection, referrer policy, permissions policy, cookie flags, and advertised framework metadata.

It adds accounts, a same-origin JSON backend API, scan intake, private saved reports, a dashboard, and a findings-to-outreach summary. It stores no source code and performs no authentication, crawling, form submission, fuzzing, exploit verification, port scanning, or vulnerability claims.

## Privacy and security pass

- Block local, private, reserved, credential-bearing, and custom-port targets to reduce SSRF risk.
- Resolve and validate every target before the request; do not follow redirects in the MVP.
- Pin the outbound request to a validated public IP to reduce DNS-rebinding risk.
- Cap response size and connection/runtime duration.
- Use a named secure HttpOnly SameSite session cookie and rotate the session ID at login.
- Require CSRF tokens on every state-changing request.
- Hash passwords with PHP's current default password algorithm.
- Use parameterized SQL and escape all rendered untrusted values.
- Keep reports owner-only; never expose sequential database IDs in URLs.
- Rate-limit registration, login, and scans. Keep the free daily limit configurable.
- Return plain findings without raw response bodies, cookie values, secret material, or exploit instructions.
- Minimize retained data and publish a deletion/contact path before launch.
- Add email verification and password reset before promoting beyond a small invite cohort.

## Outreach flow

1. Pick a public app whose owner can be identified and whose site permits normal public access.
2. Run the passive Prefunk check—never claim authorization for deeper testing.
3. Verify the result manually. Remove weak or generic findings.
4. Lead with one concrete observation and its practical consequence.
5. State the boundary: one passive public request, no login or exploit attempts.
6. Offer the complete free report; do not attach a wall of findings unsolicited.
7. Follow up once after four to seven days, then stop.

Reusable template:

> Hey [name] — I checked the public security posture of [app] and noticed [specific finding]. In plain English, [short consequence]. The smallest fix is [one-line next step].
>
> I found it with Prefunk, a free preflight I’m building for apps shipped fast. This was a limited passive check—no login or exploit attempts. I can send the full free report if it would be useful.

Follow-up:

> Quick follow-up on the [specific finding] note for [app]. No pitch or paid tier—Prefunk is free. If the report would save you time, I’m happy to send it; otherwise I’ll leave you to it.

## Prioritized launch plan

### P0 — before any outreach

1. Deploy to a private cPanel subdomain and complete the end-to-end checklist.
2. Confirm the configured legal/privacy/security contact receives mail and document the manual deletion process.
3. Confirm Idaho is the correct governing law and venue for the operator.
4. Test target blocking against loopback, private IPs, IPv6 local addresses, DNS failures, and redirect responses.
5. Test account isolation, CSRF rejection, login throttling, scan limits, and database backup restore.
6. Run ten scans on domains you own and manually verify every generated claim.

### P1 — first 25 prospects

1. Curate prospects manually; do not automate scraping or bulk messaging.
2. Send five verified, specific messages per day.
3. Track only prospect, app, finding, contact date, reply, report requested, and feedback.
4. Rewrite or remove checks that repeatedly create low-value outreach.
5. Measure reply rate and report-request rate, not vanity traffic.

### P2 — after evidence of use

1. Add email verification, password reset, account deletion, and configurable report retention.
2. Add a copy button and opt-in share link with expiry.
3. Add a lightweight consent checkbox confirming ownership or authorization.
4. Add structured server logs without storing response bodies or sensitive headers.
5. Only consider a queue or separate worker if synchronous scans visibly hit cPanel limits.

### P3 — explicitly deferred

- repository connections and source uploads
- authenticated scanning
- active security testing or exploit validation
- scheduled recurring scans
- teams, roles, billing, AI summaries, microservices, containers, or Kubernetes
