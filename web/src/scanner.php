<?php
declare(strict_types=1);

function normalize_public_url(string $input): string
{
    $input = trim($input);
    if (!preg_match('~^https?://~i', $input)) $input = 'https://' . $input;
    $parts = parse_url($input);
    if (!$parts || !isset($parts['scheme'], $parts['host'])) throw new InvalidArgumentException('Enter a valid public website URL.');
    $scheme = strtolower($parts['scheme']);
    if (!in_array($scheme, ['http', 'https'], true)) throw new InvalidArgumentException('Only HTTP and HTTPS URLs can be checked.');
    if (isset($parts['user']) || isset($parts['pass']) || isset($parts['port'])) {
        throw new InvalidArgumentException('Credentials and custom ports are not supported.');
    }
    $host = strtolower(rtrim($parts['host'], '.'));
    assert_public_host($host);
    $path = $parts['path'] ?? '/';
    $query = isset($parts['query']) ? '?' . $parts['query'] : '';
    return $scheme . '://' . $host . $path . $query;
}

function assert_public_host(string $host): void
{
    if ($host === 'localhost' || str_ends_with($host, '.local') || filter_var($host, FILTER_VALIDATE_IP)) {
        $ips = [$host];
    } else {
        $records = dns_get_record($host, DNS_A | DNS_AAAA);
        if (!$records) throw new InvalidArgumentException('That hostname does not resolve.');
        $ips = array_values(array_filter(array_map(fn($r) => $r['ip'] ?? $r['ipv6'] ?? null, $records)));
    }
    if (!$ips) throw new InvalidArgumentException('That hostname does not have a public address.');
    foreach ($ips as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            throw new InvalidArgumentException('Private, local, and reserved network targets are blocked.');
        }
    }
}

function passive_scan(string $url): array
{
    if (!extension_loaded('curl')) throw new RuntimeException('The server needs the PHP cURL extension enabled.');
    $config = prefunk_config()['scan'];
    $host = (string)parse_url($url, PHP_URL_HOST);
    $records = dns_get_record($host, DNS_A | DNS_AAAA);
    $publicIps = array_values(array_filter(array_map(
        fn($record) => $record['ip'] ?? $record['ipv6'] ?? null,
        $records ?: []
    ), fn($ip) => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false));
    if (!$publicIps) throw new RuntimeException('The hostname no longer resolves to a public address.');
    $pinnedIp = $publicIps[0];
    $curlIp = str_contains($pinnedIp, ':') ? '[' . $pinnedIp . ']' : $pinnedIp;
    $headers = [];
    $body = '';
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => (int)$config['timeout_seconds'],
        CURLOPT_USERAGENT => $config['user_agent'],
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_RESOLVE => [$host . ':443:' . $curlIp, $host . ':80:' . $curlIp],
        CURLOPT_MAXFILESIZE => 1_000_000,
        CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$headers) {
            $length = strlen($line);
            $parts = explode(':', $line, 2);
            if (count($parts) === 2) $headers[strtolower(trim($parts[0]))][] = trim($parts[1]);
            return $length;
        },
        CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use (&$body) {
            if (strlen($body) < 300_000) $body .= substr($chunk, 0, 300_000 - strlen($body));
            return strlen($chunk);
        },
    ]);
    curl_exec($ch);
    $error = curl_error($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $effective = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);
    if ($error !== '') throw new RuntimeException('The site could not be reached safely.');
    if ($status === 0) throw new RuntimeException('The site did not return an HTTP response.');

    $findings = [];
    $add = function (string $severity, string $title, string $detail, string $fix) use (&$findings) {
        $findings[] = compact('severity', 'title', 'detail', 'fix');
    };
    if (!str_starts_with(strtolower($effective), 'https://')) {
        $add('high', 'Page is not using HTTPS', 'Traffic can be intercepted or changed in transit.', 'Serve the application only over HTTPS and redirect HTTP to HTTPS.');
    }
    if (str_starts_with(strtolower($effective), 'https://') && empty($headers['strict-transport-security'])) {
        $add('medium', 'HSTS is missing', 'Browsers are not instructed to keep future visits on HTTPS.', 'Add a Strict-Transport-Security header after confirming all subdomains support HTTPS.');
    }
    if (empty($headers['content-security-policy'])) {
        $add('medium', 'Content Security Policy is missing', 'The browser has fewer restrictions on which scripts and resources may run.', 'Start with a report-only CSP, review violations, then enforce a narrow policy.');
    }
    if (empty($headers['x-content-type-options'])) {
        $add('low', 'MIME sniffing protection is missing', 'Some browsers may infer a different content type than the server declared.', 'Return X-Content-Type-Options: nosniff.');
    }
    if (empty($headers['referrer-policy'])) {
        $add('low', 'Referrer policy is missing', 'Full page paths may be shared with outbound destinations.', 'Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin.');
    }
    if (empty($headers['permissions-policy'])) {
        $add('low', 'Permissions Policy is missing', 'Unneeded browser capabilities are not explicitly disabled.', 'Add a Permissions-Policy that allows only features the app needs.');
    }
    foreach ($headers['set-cookie'] ?? [] as $cookie) {
        if (stripos($cookie, 'secure') === false) {
            $add('medium', 'A cookie may be missing Secure', 'A cookie was set without an explicit Secure attribute.', 'Mark sensitive cookies Secure and serve them only over HTTPS.');
            break;
        }
    }
    foreach ($headers['set-cookie'] ?? [] as $cookie) {
        if (stripos($cookie, 'httponly') === false) {
            $add('medium', 'A cookie may be readable by scripts', 'A cookie was set without an explicit HttpOnly attribute.', 'Mark session cookies HttpOnly unless client-side code truly needs them.');
            break;
        }
    }
    if (preg_match('~<meta[^>]+name=["\\\']generator["\\\'][^>]+content=["\\\']([^"\\\']+)~i', $body, $match)) {
        $add('low', 'Framework details are advertised', 'The page publishes a generator signature that may reveal implementation details.', 'Remove generator metadata if it is not needed.');
    }
    usort($findings, fn($a, $b) => severity_rank($b['severity']) <=> severity_rank($a['severity']));
    $counts = array_count_values(array_column($findings, 'severity'));
    $headline = count($findings) === 0
        ? 'No issues matched this limited passive check.'
        : sprintf('%d potential issue%s found: %d high, %d medium, %d low.',
            count($findings), count($findings) === 1 ? '' : 's',
            $counts['high'] ?? 0, $counts['medium'] ?? 0, $counts['low'] ?? 0);
    return ['status' => $status, 'effective_url' => $effective, 'summary' => $headline, 'findings' => $findings];
}

function severity_rank(string $severity): int
{
    return ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1][$severity] ?? 0;
}
