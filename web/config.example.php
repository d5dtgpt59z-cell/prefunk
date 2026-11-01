<?php
declare(strict_types=1);

return [
    'app_url' => 'https://prefunk.builtbymagnus.com',
    'app_name' => 'Prefunk',
    'legal_contact' => 'legal@builtbymagnus.com',
    'terms_version' => '2026-07-25',
    'db' => [
        'dsn' => 'mysql:host=localhost;dbname=CPANEL_DB;charset=utf8mb4',
        'user' => 'CPANEL_DB_USER',
        'password' => 'CHANGE_ME',
    ],
    'session' => [
        'name' => 'prefunk_session',
        'secure' => true,
    ],
    'scan' => [
        'user_agent' => 'Prefunk/1.0 passive security preflight (+https://prefunk.builtbymagnus.com/about)',
        'timeout_seconds' => 12,
        'max_redirects' => 4,
        'daily_limit_per_account' => 20,
    ],
];
