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
    
    // Master switch for sensitive data collection
    'collect_sensitive_data' => env('CYBEAR_COLLECT_SENSITIVE_DATA', false),
    
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
        'cache_rules' => env('CYBEAR_WAF_CACHE_RULES', true),
        'cache_ttl' => env('CYBEAR_WAF_CACHE_TTL', 3600),
        'max_request_size' => env('CYBEAR_WAF_MAX_REQUEST_SIZE', 10485760),
        'block_page' => env('CYBEAR_WAF_BLOCK_PAGE', null),
        'challenge_enabled' => env('CYBEAR_WAF_CHALLENGE_ENABLED', false),
        
        // Auto-sync settings
        'auto_sync' => env('CYBEAR_WAF_AUTO_SYNC', true),
        'sync_interval' => env('CYBEAR_WAF_SYNC_INTERVAL', 'daily'),
    ],

    'audit' => [
        'enabled' => env('CYBEAR_AUDIT_ENABLED', true),
        'log_requests' => env('CYBEAR_AUDIT_LOG_REQUESTS', true),
        'log_responses' => env('CYBEAR_AUDIT_LOG_RESPONSES', false),
        'log_database' => env('CYBEAR_AUDIT_LOG_DATABASE', true),
        'log_authentication' => env('CYBEAR_AUDIT_LOG_AUTH', true),
        'log_file_operations' => env('CYBEAR_AUDIT_LOG_FILES', false),
        'excluded_routes' => [
            'telescope*',
            'horizon*',
            '_debugbar*',
        ],
        'excluded_ips' => [],
        'retention_days' => env('CYBEAR_AUDIT_RETENTION_DAYS', 90),
    ],

    'rate_limiting' => [
        'enabled' => env('CYBEAR_RATE_LIMIT_ENABLED', true),
        'requests_per_minute' => env('CYBEAR_RATE_LIMIT_RPM', 60),
        'requests_per_hour' => env('CYBEAR_RATE_LIMIT_RPH', 1000),
        'requests_per_day' => env('CYBEAR_RATE_LIMIT_RPD', 10000),
        'exclude_authenticated' => env('CYBEAR_RATE_LIMIT_EXCLUDE_AUTH', false),
        'cache_driver' => env('CYBEAR_RATE_LIMIT_CACHE', 'redis'),
    ],

    'collectors' => [
        'auto_schedule' => env('CYBEAR_COLLECTORS_AUTO_SCHEDULE', true),
        'collection_interval' => env('CYBEAR_COLLECTORS_INTERVAL', 'hourly'),
        'batch_size' => env('CYBEAR_COLLECTORS_BATCH_SIZE', 100),
        'compression' => env('CYBEAR_COLLECTORS_COMPRESSION', true),
        
        // Auto-transmission settings
        'auto_send' => env('CYBEAR_AUTO_SEND_ENABLED', true),
        'send_interval' => env('CYBEAR_SEND_INTERVAL', 'everyFifteenMinutes'),
        'auto_cleanup' => env('CYBEAR_AUTO_CLEANUP_ENABLED', true),
        'cleanup_interval' => env('CYBEAR_CLEANUP_INTERVAL', 'weekly'),
        
        'packages' => [
            'enabled' => env('CYBEAR_COLLECTOR_PACKAGES', true),
            'include_dev' => env('CYBEAR_COLLECTOR_PACKAGES_DEV', false),
            'scan_composer' => true,
            'scan_npm' => true,
            'scan_vendor' => true,
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
            'collect_user_stats' => true,
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
            'enabled' => env('CYBEAR_COLLECTOR_FILESYSTEM', true),
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
            'enabled' => env('CYBEAR_COLLECTOR_PERFORMANCE', true),
            'memory_usage' => true,
            'cache_stats' => true,
            'queue_stats' => true,
            'database_stats' => true,
        ],
    ],



    'database' => [
        'connection' => env('CYBEAR_DB_CONNECTION', config('database.default')),
        'table_prefix' => env('CYBEAR_DB_PREFIX', 'cybear_'),
        'cleanup_enabled' => env('CYBEAR_DB_CLEANUP', true),
        'cleanup_interval' => env('CYBEAR_DB_CLEANUP_INTERVAL', 'daily'),
        'retention_days' => env('CYBEAR_DB_RETENTION_DAYS', 30),
        'store_collections' => env('CYBEAR_DB_STORE_COLLECTIONS', true),
        'store_packages' => env('CYBEAR_DB_STORE_PACKAGES', true),
    ],

    'security_headers' => [
        'enabled' => env('CYBEAR_SECURITY_HEADERS', true),
        'hsts' => env('CYBEAR_HSTS', true),
        'content_type_options' => env('CYBEAR_CONTENT_TYPE_OPTIONS', true),
        'frame_options' => env('CYBEAR_FRAME_OPTIONS', 'DENY'),
        'xss_protection' => env('CYBEAR_XSS_PROTECTION', true),
        'referrer_policy' => env('CYBEAR_REFERRER_POLICY', 'strict-origin-when-cross-origin'),
        'csp' => env('CYBEAR_CSP', null),
    ],

    'debugging' => [
        'enabled' => env('CYBEAR_DEBUG_ENABLED', false),
        'log_level' => env('CYBEAR_DEBUG_LEVEL', 'info'),
        'log_channel' => env('CYBEAR_DEBUG_CHANNEL', 'single'),
        'performance_logging' => env('CYBEAR_DEBUG_PERFORMANCE', false),
        'waf_rules' => env('CYBEAR_DEBUG_WAF_RULES', false),
    ],
];