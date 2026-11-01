<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/app.php';
require dirname(__DIR__) . '/src/scanner.php';
boot_session();

$path = route();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($path === '/register' && $method === 'POST') {
    verify_csrf();
    $email = strtolower(trim((string)($_POST['email'] ?? '')));
    $password = (string)($_POST['password'] ?? '');
    $accepted = ($_POST['accept_terms'] ?? '') === 'yes';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
        flash('Enter a valid email address.', 'error');
    } elseif (strlen($password) < 12) {
        flash('Use at least 12 characters for your password.', 'error');
    } elseif (!$accepted) {
        flash('You must accept the Terms and authorized-use policy.', 'error');
    } elseif (!enforce_rate_limit('register:' . ($_SERVER['REMOTE_ADDR'] ?? ''), 10, 3600)) {
        flash('Too many attempts. Try again later.', 'error');
    } else {
        try {
            $stmt = db()->prepare('INSERT INTO users (email, password_hash, terms_accepted_at, terms_version) VALUES (?, ?, NOW(), ?)');
            $stmt->execute([$email, password_hash($password, PASSWORD_DEFAULT), prefunk_config()['terms_version']]);
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int)db()->lastInsertId();
            redirect('/dashboard');
        } catch (PDOException $error) {
            flash($error->getCode() === '23000' ? 'An account already exists for that email.' : 'Account creation failed.', 'error');
        }
    }
    redirect('/register');
}

if ($path === '/login' && $method === 'POST') {
    verify_csrf();
    $email = strtolower(trim((string)($_POST['email'] ?? '')));
    $password = (string)($_POST['password'] ?? '');
    $rateKey = 'login:' . ($_SERVER['REMOTE_ADDR'] ?? '') . ':' . $email;
    if (!enforce_rate_limit($rateKey, 10, 900)) {
        flash('Too many attempts. Try again in 15 minutes.', 'error');
    } else {
        $stmt = db()->prepare('SELECT id, password_hash FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $account = $stmt->fetch();
        if ($account && password_verify($password, $account['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int)$account['id'];
            redirect('/dashboard');
        }
        flash('Email or password was not recognized.', 'error');
    }
    redirect('/login');
}

if ($path === '/logout' && $method === 'POST') {
    verify_csrf();
    $_SESSION = [];
    session_destroy();
    redirect('/');
}

if ($path === '/api/v1/scan' && $method === 'POST') {
    $current = require_user();
    verify_csrf();
    if (!str_starts_with(strtolower((string)($_SERVER['CONTENT_TYPE'] ?? '')), 'application/json')) {
        json_response(['error' => 'JSON body required.'], 415);
    }
    try {
        $input = json_decode((string)file_get_contents('php://input'), true, 8, JSON_THROW_ON_ERROR);
        $limit = (int)prefunk_config()['scan']['daily_limit_per_account'];
        if (!enforce_rate_limit('scan:user:' . $current['id'], $limit, 86400)) {
            json_response(['error' => "Free daily limit of {$limit} scans reached."], 429);
        }
        $url = normalize_public_url((string)($input['url'] ?? ''));
        $host = (string)parse_url($url, PHP_URL_HOST);
        $publicId = bin2hex(random_bytes(16));
        $stmt = db()->prepare('INSERT INTO scans (user_id, public_id, target_url, target_host) VALUES (?, ?, ?, ?)');
        $stmt->execute([$current['id'], $publicId, $url, $host]);
        try {
            $result = passive_scan($url);
            $stmt = db()->prepare("UPDATE scans SET status='complete', summary=?, http_status=?, findings_json=?, completed_at=NOW() WHERE public_id=? AND user_id=?");
            $stmt->execute([$result['summary'], $result['status'], json_encode($result['findings'], JSON_THROW_ON_ERROR), $publicId, $current['id']]);
        } catch (Throwable $error) {
            $stmt = db()->prepare("UPDATE scans SET status='failed', error_message=?, completed_at=NOW() WHERE public_id=? AND user_id=?");
            $stmt->execute(['The public page could not be checked safely.', $publicId, $current['id']]);
        }
        json_response(['report_id' => $publicId, 'report_url' => '/reports/' . $publicId], 201);
    } catch (InvalidArgumentException|JsonException $error) {
        json_response(['error' => $error instanceof JsonException ? 'Invalid JSON.' : $error->getMessage()], 422);
    }
}

if ($path === '/scan' && $method === 'POST') {
    $current = require_user();
    verify_csrf();
    $limit = (int)prefunk_config()['scan']['daily_limit_per_account'];
    if (!enforce_rate_limit('scan:user:' . $current['id'], $limit, 86400)) {
        flash("You have reached the free daily limit of {$limit} scans.", 'error');
        redirect('/dashboard');
    }
    try {
        $url = normalize_public_url((string)($_POST['url'] ?? ''));
        $host = (string)parse_url($url, PHP_URL_HOST);
        $publicId = bin2hex(random_bytes(16));
        $stmt = db()->prepare('INSERT INTO scans (user_id, public_id, target_url, target_host) VALUES (?, ?, ?, ?)');
        $stmt->execute([$current['id'], $publicId, $url, $host]);
        try {
            $result = passive_scan($url);
            $stmt = db()->prepare(
                "UPDATE scans SET status='complete', summary=?, http_status=?, findings_json=?, completed_at=NOW() WHERE public_id=? AND user_id=?"
            );
            $stmt->execute([$result['summary'], $result['status'], json_encode($result['findings'], JSON_THROW_ON_ERROR), $publicId, $current['id']]);
        } catch (Throwable $error) {
            $stmt = db()->prepare("UPDATE scans SET status='failed', error_message=?, completed_at=NOW() WHERE public_id=? AND user_id=?");
            $stmt->execute(['The public page could not be checked. Confirm the address and try again.', $publicId, $current['id']]);
        }
        redirect('/reports/' . $publicId);
    } catch (InvalidArgumentException $error) {
        flash($error->getMessage(), 'error');
        redirect('/dashboard');
    }
}

$current = user();
$flash = take_flash();
$pageTitle = 'Free security preflight for apps built fast';
$legalContact = (string)prefunk_config()['legal_contact'];
$termsVersion = (string)prefunk_config()['terms_version'];
$content = '';

ob_start();
if ($path === '/') {
?>
<main>
  <section class="hero">
    <p class="eyebrow">A calm check before you ship</p>
    <h1>Your app is live.<br><span>What did you miss?</span></h1>
    <p class="lede">Prefunk runs a limited, passive security preflight on your public app and turns the results into plain-English fixes. Free. No source-code upload. No exploit attempts. No enterprise-security maze.</p>
    <div class="actions">
      <a class="button primary" href="<?= $current ? '/dashboard' : '/register' ?>">Scan a public app</a>
      <a class="button quiet" href="#how-it-works">See what it checks</a>
    </div>
    <div class="trust"><span>Read-only public checks</span><span>Reports saved privately</span><span>Always free</span></div>
  </section>
  <section class="proof" id="how-it-works">
    <div><b>01</b><h2>Paste a public URL</h2><p>Use a site you own or are authorized to assess.</p></div>
    <div><b>02</b><h2>Get concrete findings</h2><p>See HTTPS, browser-policy, cookie, and exposure signals ranked by potential impact.</p></div>
    <div><b>03</b><h2>Fix what matters</h2><p>Every finding includes a short explanation and a practical next step.</p></div>
  </section>
  <section class="boundary">
    <p class="eyebrow">What Prefunk is—and is not</p>
    <h2>A useful first look, not a penetration test.</h2>
    <p>Prefunk checks only what a normal visitor can receive from a public page. It does not log in, submit forms, fuzz endpoints, bypass controls, or prove an app is secure.</p>
  </section>
</main>
<?php
} elseif ($path === '/register' || $path === '/login') {
    $isRegister = $path === '/register';
    $pageTitle = ($isRegister ? 'Create account' : 'Sign in') . ' · Prefunk';
?>
<main class="auth-shell"><section class="auth-card">
  <p class="eyebrow"><?= $isRegister ? 'Start free' : 'Welcome back' ?></p>
  <h1><?= $isRegister ? 'Save your first preflight.' : 'Open your reports.' ?></h1>
  <form method="post" action="<?= $path ?>">
    <input type="hidden" name="_csrf" value="<?= e(csrf_token()) ?>">
    <label>Email<input type="email" name="email" autocomplete="email" maxlength="254" required></label>
    <label>Password<input type="password" name="password" autocomplete="<?= $isRegister ? 'new-password' : 'current-password' ?>" minlength="12" required></label>
    <?php if ($isRegister): ?><label class="check"><input type="checkbox" name="accept_terms" value="yes" required><span>I agree to the <a href="/terms" target="_blank">Terms</a>, will scan only apps I own or am authorized to assess, and understand Prefunk is not a security audit or guarantee.</span></label><?php endif; ?>
    <button class="button primary" type="submit"><?= $isRegister ? 'Create free account' : 'Sign in' ?></button>
  </form>
  <p class="switch"><?= $isRegister ? 'Already have an account? <a href="/login">Sign in</a>' : 'New to Prefunk? <a href="/register">Create an account</a>' ?></p>
</section></main>
<?php
} elseif ($path === '/dashboard') {
    $current = require_user();
    $pageTitle = 'Dashboard · Prefunk';
    $stmt = db()->prepare('SELECT public_id, target_host, status, summary, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 25');
    $stmt->execute([$current['id']]);
    $scans = $stmt->fetchAll();
?>
<main class="dashboard">
  <section class="scan-panel">
    <p class="eyebrow">New passive preflight</p>
    <h1>What are you about to ship?</h1>
    <form class="scan-form" id="scan-form" method="post" action="/scan" data-api="/api/v1/scan">
      <input type="hidden" name="_csrf" value="<?= e(csrf_token()) ?>">
      <label class="sr-only" for="url">Public app URL</label>
      <input id="url" type="url" name="url" placeholder="https://your-app.com" required>
      <button class="button primary" type="submit">Run free scan</button>
    </form>
    <p class="fine">Authorized targets only. Prefunk makes one limited passive request. Results are automated leads—not verified vulnerabilities, legal advice, an audit, certification, or a guarantee of security.</p>
  </section>
  <section class="reports">
    <div class="section-heading"><div><p class="eyebrow">Saved reports</p><h2>Your recent preflights</h2></div><span><?= count($scans) ?> shown</span></div>
    <?php if (!$scans): ?><div class="empty">Your first report will appear here.</div><?php endif; ?>
    <?php foreach ($scans as $scan): ?>
      <a class="report-row" href="/reports/<?= e($scan['public_id']) ?>">
        <span class="status <?= e($scan['status']) ?>"></span>
        <span><b><?= e($scan['target_host']) ?></b><small><?= e($scan['summary'] ?: ucfirst($scan['status'])) ?></small></span>
        <time><?= e(date('M j, Y', strtotime($scan['created_at']))) ?></time>
      </a>
    <?php endforeach; ?>
  </section>
</main>
<?php
} elseif (preg_match('~^/reports/([a-f0-9]{32})$~', $path, $match)) {
    $current = require_user();
    $stmt = db()->prepare('SELECT * FROM scans WHERE public_id = ? AND user_id = ?');
    $stmt->execute([$match[1], $current['id']]);
    $report = $stmt->fetch();
    if (!$report) { http_response_code(404); $content = '<main class="auth-shell"><h1>Report not found.</h1></main>'; }
    else {
        $pageTitle = e($report['target_host']) . ' report · Prefunk';
        $findings = $report['findings_json'] ? json_decode($report['findings_json'], true) : [];
?>
<main class="dashboard report">
  <a class="back" href="/dashboard">← All reports</a>
  <section class="report-head">
    <p class="eyebrow">Passive public preflight</p>
    <h1><?= e($report['target_host']) ?></h1>
    <p class="lede"><?= e($report['summary'] ?: $report['error_message']) ?></p>
    <div class="report-meta"><span>HTTP <?= e((string)$report['http_status']) ?></span><span><?= e(date('M j, Y · g:i a', strtotime($report['created_at']))) ?></span></div>
  </section>
  <section class="finding-list">
    <?php if (!$findings && $report['status'] === 'complete'): ?><div class="empty">No issues matched this limited check. This is not proof the app is secure.</div><?php endif; ?>
    <?php foreach ($findings as $finding): ?>
      <article class="finding">
        <span class="pill <?= e($finding['severity']) ?>"><?= e($finding['severity']) ?></span>
        <div><h2><?= e($finding['title']) ?></h2><p><?= e($finding['detail']) ?></p><h3>Suggested next step</h3><p><?= e($finding['fix']) ?></p></div>
      </article>
    <?php endforeach; ?>
  </section>
  <section class="outreach-card">
    <p class="eyebrow">Value-first outreach summary</p>
    <h2>Share the useful part first.</h2>
    <textarea readonly rows="7">Hey — I ran a limited passive check on <?= e($report['target_host']) ?> and noticed <?= e($report['summary'] ?: 'a few things worth reviewing') ?>

The clearest item: <?= e($findings[0]['title'] ?? 'the public security posture could use a second look') ?>. <?= e($findings[0]['detail'] ?? '') ?>

I made the check with Prefunk. No login or exploit attempts—just public signals. Happy to send the full free report if it would be useful.</textarea>
  </section>
</main>
<?php
    }
} elseif ($path === '/privacy') {
    $pageTitle = 'Privacy · Prefunk';
?>
<main class="legal">
  <p class="eyebrow">Privacy notice · Effective July 25, 2026</p>
  <h1>Minimal data, plainly stated.</h1>
  <h2>Who operates Prefunk</h2>
  <p>Prefunk is operated by Built by Magnus in Idaho, United States. Privacy questions and requests may be sent to <a href="mailto:<?= e($legalContact) ?>"><?= e($legalContact) ?></a>.</p>
  <h2>Information we collect</h2>
  <p>We collect the email address you provide, a one-way password hash, your Terms acceptance date and version, public URLs you submit, scan timestamps and status, generated findings, and limited operational logs needed to prevent abuse and diagnose failures. We do not request or intentionally store source code, repository credentials, payment information, secret values, private application data, or response bodies.</p>
  <h2>How we use information</h2>
  <p>We use this information only to provide accounts and reports, run requested passive checks, secure and troubleshoot Prefunk, enforce usage limits, prevent abuse, comply with law, and communicate about material service or policy changes. Prefunk is free and we do not sell personal information or use it for cross-context behavioral advertising.</p>
  <h2>Public-target requests</h2>
  <p>When you submit a URL, the Prefunk server sends a limited request to that public target. The target operator may receive Prefunk’s IP address, user-agent string, request time, and requested path in its normal server logs. Do not submit confidential URLs, embedded credentials, private addresses, or targets you are not authorized to assess.</p>
  <h2>Service providers and disclosure</h2>
  <p>Our hosting, domain, email, security, and backup providers may process limited information solely to provide their services. We may disclose information when reasonably necessary to comply with law, address abuse or security threats, protect rights and safety, or complete a business transfer subject to this notice. We do not disclose report contents for advertising.</p>
  <h2>Retention and deletion</h2>
  <p>Account and report records are retained while your account remains active. Operational and rate-limit records are retained only as reasonably necessary for security and abuse prevention. You may request deletion of your account and associated reports by emailing <a href="mailto:<?= e($legalContact) ?>"><?= e($legalContact) ?></a> from your account email. We may retain limited records when legally required or reasonably necessary to document abuse, resolve disputes, or enforce agreements. Backups may persist temporarily until their ordinary expiration.</p>
  <h2>Security</h2>
  <p>We use reasonable safeguards appropriate to the limited information Prefunk maintains, but no service can guarantee absolute security. You are responsible for using a unique password and protecting access to your email and device.</p>
  <h2>Your choices</h2>
  <p>You may request access, correction, or deletion by contacting us. Depending on where you live, applicable law may provide additional rights. We will not discriminate against you for making a lawful privacy request.</p>
  <h2>Children</h2>
  <p>Prefunk is not directed to children under 13, and accounts are limited to people who are at least 18 years old or the age of legal majority where they live. If you believe a child provided personal information, contact us for deletion.</p>
  <h2>Changes</h2>
  <p>We may update this notice as Prefunk changes. We will post the revised version with a new effective date and provide additional notice when a change is material.</p>
</main>
<?php
} elseif ($path === '/terms') {
    $pageTitle = 'Terms and disclaimer · Prefunk';
?>
<main class="legal">
  <p class="eyebrow">Terms of Service · Version <?= e($termsVersion) ?></p>
  <h1>Build fast. Check responsibly.</h1>
  <p>These Terms of Service (“Terms”) are an agreement between you and Built by Magnus (“Built by Magnus,” “we,” “us,” or “our”), the Idaho-based operator of Prefunk. By creating an account, checking the acceptance box, or using Prefunk, you agree to these Terms and the <a href="/privacy">Privacy Notice</a>. If you do not agree, do not use Prefunk.</p>
  <h2>1. Eligibility and accounts</h2>
  <p>You must be at least 18 years old and legally able to enter this agreement. You must provide accurate account information, safeguard your credentials, and promptly notify <a href="mailto:<?= e($legalContact) ?>"><?= e($legalContact) ?></a> of suspected unauthorized access. You are responsible for activity conducted through your account.</p>
  <h2>2. The service</h2>
  <p>Prefunk is a free, limited, automated security preflight for public web applications. Features, limits, checks, availability, and supported targets may change. We may impose reasonable limits to protect Prefunk and others. We do not promise that Prefunk will remain available indefinitely or that every feature will always be free, but we will not charge you without clearly asking you to agree first.</p>
  <h2>3. Critical security disclaimer</h2>
  <p><strong>Prefunk is not a penetration test, professional security audit, certification, compliance assessment, legal opinion, warranty, or guarantee.</strong> Findings are automated, unverified indicators and may be incomplete, inaccurate, outdated, duplicative, or false positives. Prefunk can miss serious vulnerabilities. “No matches” does not mean an application is secure. You must independently verify every finding and obtain qualified professional review when the risk warrants it.</p>
  <h2>4. Authorized use only</h2>
  <p>You may submit only public targets that you own or have explicit authorization to assess. Your authorization must cover the type of passive request Prefunk performs. You are solely responsible for confirming authorization and complying with applicable laws, contracts, program rules, and disclosure requirements.</p>
  <p>You may not use Prefunk to: assess an unauthorized target; access nonpublic systems; bypass authentication or technical controls; submit credentials or confidential URLs; probe custom ports; exploit or verify exploitation; disrupt or degrade a service; collect personal or proprietary data; introduce malware; conceal unlawful conduct; overwhelm Prefunk or another service; reverse engineer Prefunk except where law expressly permits; resell access; impersonate another person; or infringe another party’s rights.</p>
  <h2>5. Findings and responsible disclosure</h2>
  <p>You control whether and how to use or share a report. You are responsible for verifying findings, avoiding harmful disclosure, protecting target information, and following the target owner’s vulnerability-disclosure or bug-bounty rules. Prefunk does not authorize testing, contact target owners for you, or assume responsibility for remediation decisions.</p>
  <h2>6. Your content and license</h2>
  <p>You retain any rights you have in URLs and information you submit. You grant us a limited, worldwide, nonexclusive license to process that information only as needed to operate, secure, troubleshoot, and improve Prefunk and comply with law. You represent that you have the rights and authorization needed to submit it.</p>
  <h2>7. Prefunk ownership</h2>
  <p>Built by Magnus and its licensors retain all rights in Prefunk, including its software, interface, branding, documentation, and original report presentation. Subject to these Terms, we grant you a personal, revocable, nonexclusive, nontransferable license to use the hosted service and use, copy, and share reports generated for your authorized targets. Open-source components remain governed by their applicable licenses.</p>
  <h2>8. Privacy</h2>
  <p>Our <a href="/privacy">Privacy Notice</a> explains what we collect and why. Do not submit source code, passwords, access tokens, private URLs, personal information, or other sensitive material. You acknowledge that submitted public targets receive a request from Prefunk and may log it.</p>
  <h2>9. Suspension and termination</h2>
  <p>You may stop using Prefunk at any time and request account deletion. We may limit, suspend, or terminate access when reasonably necessary to address abuse, security risk, legal exposure, excessive load, violation of these Terms, or discontinuation of the service. When practical, we will provide notice. Provisions that by their nature should survive termination—including ownership, disclaimers, liability limits, indemnity, and dispute terms—will survive.</p>
  <h2>10. No warranties</h2>
  <p>TO THE FULLEST EXTENT PERMITTED BY LAW, PREFUNK IS PROVIDED “AS IS” AND “AS AVAILABLE.” BUILT BY MAGNUS DISCLAIMS ALL EXPRESS, IMPLIED, AND STATUTORY WARRANTIES, INCLUDING MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, ACCURACY, AVAILABILITY, AND SECURITY. WE DO NOT WARRANT THAT PREFUNK OR ANY FINDING WILL BE COMPLETE, CORRECT, UNINTERRUPTED, OR ERROR-FREE. Some jurisdictions do not allow certain disclaimers, so some of this section may not apply to you.</p>
  <h2>11. Limitation of liability</h2>
  <p>TO THE FULLEST EXTENT PERMITTED BY LAW, BUILT BY MAGNUS AND ITS OWNERS, CONTRIBUTORS, AND SERVICE PROVIDERS WILL NOT BE LIABLE FOR INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES; LOST PROFITS, REVENUE, DATA, GOODWILL, OR BUSINESS; SECURITY INCIDENTS; THIRD-PARTY CLAIMS; OR COSTS OF SUBSTITUTE SERVICES ARISING FROM PREFUNK OR THESE TERMS, EVEN IF ADVISED OF THE POSSIBILITY.</p>
  <p>TO THE FULLEST EXTENT PERMITTED BY LAW, OUR TOTAL LIABILITY FOR ALL CLAIMS ARISING FROM PREFUNK OR THESE TERMS WILL NOT EXCEED THE GREATER OF THE AMOUNT YOU PAID US FOR PREFUNK DURING THE 12 MONTHS BEFORE THE EVENT GIVING RISE TO THE CLAIM OR US$100. The limitations do not apply where prohibited by law.</p>
  <h2>12. Indemnity</h2>
  <p>To the extent permitted by law, you will defend, indemnify, and hold harmless Built by Magnus and its owners and contributors from third-party claims, damages, and reasonable costs arising from your unauthorized or unlawful use of Prefunk, your submitted targets, your violation of these Terms, or your infringement of another party’s rights. We will provide reasonable notice and allow you to control the defense, subject to our right to participate with counsel of our choice.</p>
  <h2>13. Changes</h2>
  <p>We may update these Terms. We will post the updated version and effective date, and provide additional notice for material changes. Changes apply prospectively. If a material change requires renewed consent, we will ask before continued use. Continued use after the stated effective date constitutes acceptance where permitted by law.</p>
  <h2>14. Governing law and disputes</h2>
  <p>Idaho law governs these Terms, without regard to conflict-of-law rules. Any dispute not resolved informally will be brought exclusively in the state or federal courts serving Idaho, and each party consents to their jurisdiction and venue. Before filing a claim, you and Built by Magnus agree to send written notice and attempt in good faith to resolve the dispute for 30 days. Nothing prevents either party from seeking urgent injunctive relief or bringing an eligible matter in small-claims court.</p>
  <h2>15. General terms</h2>
  <p>These Terms and the Privacy Notice are the entire agreement concerning the hosted Prefunk service. If a provision is unenforceable, it will be limited to the minimum extent necessary and the remainder will remain effective. Failure to enforce a provision is not a waiver. You may not assign these Terms without our consent; we may assign them as part of a reorganization, financing, merger, acquisition, or transfer of the service. Headings are for convenience only. Electronic acceptance and records may be used in connection with these Terms.</p>
  <h2>16. Contact</h2>
  <p>Questions, legal notices, privacy requests, security reports, and account-deletion requests: <a href="mailto:<?= e($legalContact) ?>"><?= e($legalContact) ?></a>.</p>
</main>
<?php
} elseif ($path === '/security') {
    $pageTitle = 'Security reporting · Prefunk';
?>
<main class="legal">
  <p class="eyebrow">Security reporting</p>
  <h1>Found a problem in Prefunk?</h1>
  <p>Email <a href="mailto:<?= e($legalContact) ?>"><?= e($legalContact) ?></a> with a concise description, affected URL or feature, reproduction steps that avoid exposing sensitive data, and your preferred contact information.</p>
  <p>Please do not access other users’ accounts or reports, disrupt service, use automated high-volume testing, retain personal data, publicly disclose an unresolved issue, or exceed the minimum access necessary to demonstrate the problem. Stop testing and contact us if you encounter credentials, private reports, or personal information.</p>
  <p>We will make a good-faith effort to acknowledge credible reports, investigate them, and communicate about remediation. This page does not create a bug bounty, promise payment, waive any rights, or authorize testing that would otherwise be unlawful or outside these guidelines.</p>
</main>
<?php
} else {
    http_response_code(404);
?>
<main class="auth-shell"><section><p class="eyebrow">404</p><h1>That page wandered off.</h1><a class="button primary" href="/">Back home</a></section></main>
<?php
}
if ($content === '') $content = (string)ob_get_clean(); else ob_end_clean();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= $pageTitle ?></title>
  <meta name="description" content="A free, passive security preflight for public apps built fast.">
  <link rel="stylesheet" href="/assets/app.css">
  <script src="/assets/app.js" defer></script>
</head>
<body>
<header class="site-header"><a class="logo" href="/"><i></i> PREFUNK</a><nav>
  <?php if ($current): ?><a href="/dashboard">Dashboard</a><form method="post" action="/logout"><input type="hidden" name="_csrf" value="<?= e(csrf_token()) ?>"><button>Sign out</button></form>
  <?php else: ?><a href="/login">Sign in</a><a class="nav-cta" href="/register">Run a free scan</a><?php endif; ?>
</nav></header>
<?php if ($flash): ?><div class="flash <?= e($flash['type']) ?>"><?= e($flash['message']) ?></div><?php endif; ?>
<?= $content ?>
<footer><a class="logo" href="/"><i></i> PREFUNK</a><p>Built by Magnus. Free security preflights, without the theater.</p><span><a href="/privacy">Privacy</a> · <a href="/terms">Terms</a> · <a href="/security">Security</a></span></footer>
</body></html>
