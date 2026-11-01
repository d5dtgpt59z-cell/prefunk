# Prefunk Web

The lean hosted edition of Prefunk is a free PHP/MySQL app designed for ordinary cPanel hosting. It adds:

- account registration and sign-in
- a same-origin JSON backend API used by the dashboard
- passive public-URL scan intake
- private saved reports and a simple dashboard
- concise, reusable value-first outreach copy
- SSRF protection, CSRF protection, login throttling, secure sessions, prepared SQL, output escaping, and daily scan limits

It deliberately does not upload repositories, run the native source-code scanner on a server, exploit targets, use billing, require AI, or need a background worker.

## cPanel deployment

1. Create a subdomain such as `prefunk.builtbymagnus.com`, pointed at this folder's `public/` directory.
2. Create a MySQL database and database user in cPanel, granting that user all privileges on the new database.
3. Import `schema.sql` with phpMyAdmin.
4. Copy `config.example.php` to `config.php`, fill in the database values, and keep `config.php` outside the public web root.
5. Confirm the host provides PHP 8.1 or newer with PDO MySQL, cURL, OpenSSL, and DNS functions.
6. Enable AutoSSL, force HTTPS, and keep the session `secure` setting enabled.
7. Load the landing page, create a test account, scan a domain you control, open the saved report, sign out, and confirm the report URL is inaccessible from another account.
8. Confirm `legal_contact` receives mail, confirm Idaho is the correct governing law and venue, and test the manual privacy/account-deletion process before outreach.

If the host cannot point the subdomain document root to `web/public`, place only the contents of `public/` in the public directory and update its `dirname(__DIR__)` references to the private application directory. Never put `config.php` or database credentials in `public_html`.

## Operations

- Keep PHP and dependencies supplied by the host patched.
- Back up the database daily and test a restore monthly.
- Review cPanel disk, CPU, outbound-request, and database limits after the first 100 scans.
- Delete rate-limit rows older than two days with a daily cPanel cron job.
- Keep the deployed Terms version aligned with `terms_version`; require renewed acceptance before making material changes.
- Do not add authenticated scanning, source uploads, active probing, or arbitrary ports without a separate threat model and abuse-control design.
