CREATE TABLE users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    terms_accepted_at TIMESTAMP NOT NULL,
    terms_version VARCHAR(20) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE scans (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    public_id CHAR(32) NOT NULL UNIQUE,
    target_url VARCHAR(2048) NOT NULL,
    target_host VARCHAR(253) NOT NULL,
    status ENUM('queued', 'complete', 'failed') NOT NULL DEFAULT 'queued',
    summary VARCHAR(500) NULL,
    error_message VARCHAR(500) NULL,
    http_status SMALLINT UNSIGNED NULL,
    findings_json LONGTEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    INDEX idx_scans_user_created (user_id, created_at),
    CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE rate_limits (
    bucket_key CHAR(64) PRIMARY KEY,
    hits INT UNSIGNED NOT NULL DEFAULT 1,
    window_started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
