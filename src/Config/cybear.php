<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Cybear Security Configuration
    |--------------------------------------------------------------------------
    |
    | WARNING: This package collects system information. Review all settings
    | carefully before enabling in production environments.
    |
    */
    'enabled' => env('CYBEAR_ENABLED', false),

    'app_id' => env('CYBEAR_APP_ID'),
    'deployment_id' => env('CYBEAR_DEPLOYMENT_ID'),

    'api' => [
        'endpoint' => env('CYBEAR_API_ENDPOINT', 'https://api.cybear.care'),
        'key' => env('CYBEAR_API_KEY'),
        'timeout' => env('CYBEAR_API_TIMEOUT', 30),
        'retry_attempts' => env('CYBEAR_API_RETRY_ATTEMPTS', 3),
        'retry_delay' => env('CYBEAR_API_RETRY_DELAY', 1000),
    ],

    'waf' => [
        'enabled' => env('CYBEAR_WAF_ENABLED', true),
        'mode' => env('CYBEAR_WAF_MODE', 'monitor'),
        'failure_mode' => env('CYBEAR_WAF_FAILURE_MODE', 'allow'),
        'cache_rules' => env('CYBEAR_WAF_CACHE_RULES', true),
        'cache_ttl' => env('CYBEAR_WAF_CACHE_TTL', 3600),
        'max_request_size' => env('CYBEAR_WAF_MAX_REQUEST_SIZE', 10485760),
        'max_inspection_bytes' => env('CYBEAR_WAF_MAX_INSPECTION_BYTES', 131072),
        'max_rules' => env('CYBEAR_WAF_MAX_RULES', 500),
        'max_conditions_per_rule' => env('CYBEAR_WAF_MAX_CONDITIONS', 50),
        'block_page' => env('CYBEAR_WAF_BLOCK_PAGE', null),
        'challenge_enabled' => env('CYBEAR_WAF_CHALLENGE_ENABLED', false),
        'log_allowed_requests' => env('CYBEAR_WAF_LOG_ALLOWED', false),
        'expose_rule_header' => env('CYBEAR_WAF_EXPOSE_RULE_HEADER', false),

        // Auto-sync settings
        'auto_sync' => env('CYBEAR_WAF_AUTO_SYNC', true),
    ],

    'dast' => [
        'correlation_enabled' => env('CYBEAR_DAST_CORRELATION_ENABLED', false),
        'signing_key' => env('CYBEAR_DAST_SIGNING_KEY'),
        'audience' => env('CYBEAR_DAST_AUDIENCE'),
        'issuer' => env('CYBEAR_DAST_ISSUER', 'cybear'),
        'max_token_ttl_seconds' => env('CYBEAR_DAST_MAX_TOKEN_TTL', 900),
    ],

    'audit' => [
        'enabled' => env('CYBEAR_AUDIT_ENABLED', true),
        'log_requests' => env('CYBEAR_AUDIT_LOG_REQUESTS', false),
        'log_authentication' => env('CYBEAR_AUDIT_LOG_AUTH', true),
        'capture_payload' => env('CYBEAR_AUDIT_CAPTURE_PAYLOAD', false),
        'capture_headers' => env('CYBEAR_AUDIT_CAPTURE_HEADERS', false),
        'capture_query_values' => env('CYBEAR_AUDIT_CAPTURE_QUERY_VALUES', false),
        'excluded_routes' => array_values(array_filter(array_map(
            static fn (string $route): string => trim($route),
            explode(',', (string) env(
                'CYBEAR_AUDIT_EXCLUDED_ROUTES',
                'telescope*,horizon*,_debugbar*'
            ))
        ))),
        'excluded_ips' => [],
        'retention_days' => env('CYBEAR_AUDIT_RETENTION_DAYS', 90),
    ],

    'rate_limiting' => [
        'enabled' => env('CYBEAR_RATE_LIMIT_ENABLED', false),
        'requests_per_minute' => env('CYBEAR_RATE_LIMIT_RPM', 60),
        'requests_per_hour' => env('CYBEAR_RATE_LIMIT_RPH', 1000),
        'requests_per_day' => env('CYBEAR_RATE_LIMIT_RPD', 10000),
        'exclude_authenticated' => env('CYBEAR_RATE_LIMIT_EXCLUDE_AUTH', false),
    ],

    'collectors' => [
        'auto_schedule' => env('CYBEAR_COLLECTORS_AUTO_SCHEDULE', true),
        'batch_size' => env('CYBEAR_COLLECTORS_BATCH_SIZE', 100),
        'compression' => env('CYBEAR_COLLECTORS_COMPRESSION', true),

        // Auto-transmission settings
        'auto_send' => env('CYBEAR_AUTO_SEND_ENABLED', true),
        'auto_cleanup' => env('CYBEAR_AUTO_CLEANUP_ENABLED', true),
        'cleanup_interval' => env('CYBEAR_CLEANUP_INTERVAL', 'weekly'),

        'packages' => [
            'enabled' => env('CYBEAR_COLLECTOR_PACKAGES', true),
            'include_dev' => env('CYBEAR_COLLECTOR_PACKAGES_DEV', false),
            'include_npm_dev' => env('CYBEAR_COLLECTOR_NPM_DEV', true),
            'scan_composer' => true,
            'scan_npm' => env('CYBEAR_COLLECTOR_NPM', true),
        ],

        'environment' => [
            'enabled' => env('CYBEAR_COLLECTOR_ENVIRONMENT', true),
            'include_sensitive' => env('CYBEAR_COLLECTOR_ENV_SENSITIVE', false),
            'scan_php_config' => true,
            'scan_server_info' => true,
        ],

        'security' => [
            'enabled' => env('CYBEAR_COLLECTOR_SECURITY', true),
            'scan_auth_config' => env('CYBEAR_SCAN_AUTH_CONFIG', false),
            'scan_database_config' => env('CYBEAR_SCAN_DATABASE_CONFIG', false),
            'scan_session_config' => env('CYBEAR_SCAN_SESSION_CONFIG', false),
            'scan_csrf_config' => env('CYBEAR_SCAN_CSRF_CONFIG', true),
            'scan_security_headers' => env('CYBEAR_SCAN_SECURITY_HEADERS', false),
        ],

        'application' => [
            'enabled' => env('CYBEAR_COLLECTOR_APPLICATION', true),
            'scan_routes' => true,
            'scan_middleware' => true,
            'scan_providers' => true,
            'scan_config' => true,
        ],

        'auth' => [
            'enabled' => env('CYBEAR_COLLECTOR_AUTH', true),
            'collect_user_stats' => env('CYBEAR_COLLECTOR_USER_STATS', false),
            'collect_guard_config' => true,
            'collect_session_config' => true,
        ],

        'database' => [
            'enabled' => env('CYBEAR_COLLECTOR_DATABASE', true),
            'collect_connections' => true,
            'collect_migrations' => true,
            'collect_stats' => true,
        ],

        'filesystem' => [
            'enabled' => env('CYBEAR_COLLECTOR_FILESYSTEM', false),
            'check_permissions' => true,
            'check_sensitive_files' => true,
            'collect_disk_usage' => true,
        ],

        'network' => [
            'enabled' => env('CYBEAR_COLLECTOR_NETWORK', true),
            'collect_server_info' => true,
            'collect_ssl_config' => true,
            'collect_proxy_config' => true,
        ],

        'performance' => [
            'enabled' => env('CYBEAR_COLLECTOR_PERFORMANCE', false),
            'memory_usage' => true,
            'cache_stats' => true,
            'queue_stats' => true,
            'database_stats' => true,
        ],
    ],

    'database' => [
        'retention_days' => env('CYBEAR_DB_RETENTION_DAYS', 30),
    ],

    /*
    |--------------------------------------------------------------------------
    | Laravel Security Posture
    |--------------------------------------------------------------------------
    |
    | Local posture scans work even while the runtime protection package is
    | disabled. Exclusions should be narrow, documented, and reviewed.
    |
    */
    'posture' => [
        'excluded_checks' => [],
        'csrf_excluded_routes' => [],
        'authorization_excluded_routes' => [],
        'signed_link_excluded_routes' => [],
        /*
        | Every suppression must include a reason and either a check_id or an
        | occurrence fingerprint. Prefer fingerprints for narrow exceptions.
        |
        | [
        |     'fingerprint' => 'sha256-from-a-scan-report',
        |     'reason' => 'Accepted until the legacy endpoint is retired.',
        |     'expires_at' => '2026-12-31',
        | ],
        */
        'suppressions' => [],
        'ci_fail_on' => env('CYBEAR_POSTURE_CI_FAIL_ON', 'high'),
        'max_evidence_items' => 25,
        'inspect_application_source' => true,
        'max_source_file_bytes' => 524288,
        'max_source_routes' => 500,
        'passport_max_access_token_days' => 90,
        'passport_max_refresh_token_days' => 365,
        'passport_max_personal_access_token_days' => 365,
    ],

    /*
    |--------------------------------------------------------------------------
    | Opportunistic Sync (Fallback)
    |--------------------------------------------------------------------------
    |
    | The package piggybacks on regular HTTP requests to sync data after the
    | response is sent. A cheap due-time check and distributed cache lock make
    | this safe to leave enabled alongside Laravel's scheduler.
    |
    */
    'sync' => [
        'opportunistic' => env('CYBEAR_SYNC_OPPORTUNISTIC', true),
        'send_interval_seconds' => env('CYBEAR_SYNC_SEND_INTERVAL', 900),       // 15 minutes
        'rules_interval_seconds' => env('CYBEAR_SYNC_RULES_INTERVAL', 21600),   // 6 hours
        'collect_interval_seconds' => env('CYBEAR_SYNC_COLLECT_INTERVAL', 7200), // 2 hours
        'lock_seconds' => env('CYBEAR_SYNC_LOCK_SECONDS', 300),
        'failure_backoff_seconds' => env('CYBEAR_SYNC_FAILURE_BACKOFF', 60),
        'max_failure_backoff_seconds' => env('CYBEAR_SYNC_MAX_FAILURE_BACKOFF', 3600),
        'scheduler_heartbeat_ttl_seconds' => env('CYBEAR_SYNC_SCHEDULER_HEARTBEAT_TTL', 600),
        'in_testing' => env('CYBEAR_SYNC_IN_TESTING', false),
    ],

    'security_headers' => [
        'enabled' => env('CYBEAR_SECURITY_HEADERS', false),
        'hsts' => [
            'enabled' => env('CYBEAR_HSTS', false),
            'max_age' => env('CYBEAR_HSTS_MAX_AGE', 31536000),
            'include_subdomains' => env('CYBEAR_HSTS_SUBDOMAINS', false),
            'preload' => env('CYBEAR_HSTS_PRELOAD', false),
        ],
        'content_type_options' => env('CYBEAR_CONTENT_TYPE_OPTIONS', true),
        'frame_options' => env('CYBEAR_FRAME_OPTIONS', 'SAMEORIGIN'),
        'xss_protection' => env('CYBEAR_XSS_PROTECTION', false),
        'referrer_policy' => env('CYBEAR_REFERRER_POLICY', 'strict-origin-when-cross-origin'),
        'permissions_policy' => env('CYBEAR_PERMISSIONS_POLICY', null),
        'coop' => env('CYBEAR_COOP', null),
        'corp' => env('CYBEAR_CORP', null),
        'coep' => env('CYBEAR_COEP', false),
        'csp' => env('CYBEAR_CSP', null),
        'csp_report_only' => env('CYBEAR_CSP_REPORT_ONLY', null),
    ],

    /*
    |--------------------------------------------------------------------------
    | Sensitive File Protection
    |--------------------------------------------------------------------------
    |
    | Blocks HTTP access to sensitive files that should never be served
    | publicly (.env, .git/, composer.json, etc.). Returns a 404 response
    | to avoid confirming the file exists.
    |
    */
    'sensitive_files' => [
        'enabled' => env('CYBEAR_SENSITIVE_FILES_ENABLED', true),

        // Additional paths to block (on top of the built-in defaults)
        'additional_blocked_paths' => [
            // '/my-custom-secret-file.txt',
        ],

        // Additional regex patterns to block
        'additional_blocked_patterns' => [
            // '#/my-pattern#i',
        ],

        // Paths to explicitly allow (overrides blocks)
        'allowed_paths' => [
            // '/.well-known/acme-challenge', // Let's Encrypt
        ],
    ],

    'debugging' => [
        'enabled' => env('CYBEAR_DEBUG_ENABLED', false),
        'performance_logging' => env('CYBEAR_DEBUG_PERFORMANCE', false),
        'waf_rules' => env('CYBEAR_DEBUG_WAF_RULES', false),
    ],
];
