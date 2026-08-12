<?php

namespace CybearCare\LaravelSecurity\Core\Config;

class CybearConfig
{
    protected array $config;

    public function __construct(array $config = [])
    {
        $this->config = array_merge($this->defaults(), $config);
    }

    // API
    public function getApiEndpoint(): string
    {
        return $this->get('api.endpoint', 'https://api.cybear.care');
    }

    public function getApiKey(): ?string
    {
        return $this->get('api.key');
    }

    public function getApiTimeout(): int
    {
        return (int) $this->get('api.timeout', 30);
    }

    public function getApiRetryAttempts(): int
    {
        return (int) $this->get('api.retry_attempts', 3);
    }

    public function getApiRetryDelay(): int
    {
        return (int) $this->get('api.retry_delay', 1000);
    }

    // WAF
    public function isWafEnabled(): bool
    {
        return (bool) $this->get('waf.enabled', true);
    }

    public function getWafMode(): string
    {
        return $this->get('waf.mode', 'monitor');
    }

    public function getWafFailureMode(): string
    {
        return $this->get('waf.failure_mode', 'allow');
    }

    public function isWafCacheRulesEnabled(): bool
    {
        return (bool) $this->get('waf.cache_rules', true);
    }

    public function getWafCacheTtl(): int
    {
        return (int) $this->get('waf.cache_ttl', 3600);
    }

    public function getWafMaxInspectionBytes(): int
    {
        return (int) $this->get('waf.max_inspection_bytes', 131072);
    }

    public function getWafMaxRules(): int
    {
        return (int) $this->get('waf.max_rules', 500);
    }

    public function getWafMaxConditionsPerRule(): int
    {
        return (int) $this->get('waf.max_conditions_per_rule', 50);
    }

    public function getWafTruncationAction(): string
    {
        $action = (string) $this->get('waf.truncation_action', 'block');

        return in_array($action, ['allow', 'block'], true) ? $action : 'block';
    }

    public function getWafMaxRegexEvaluations(): int
    {
        return (int) $this->get('waf.max_regex_evaluations', 100);
    }

    // DAST correlation
    public function isDastCorrelationEnabled(): bool
    {
        return (bool) $this->get('dast.correlation_enabled', false);
    }

    public function getDastSigningKey(): ?string
    {
        return $this->nullableString('dast.signing_key');
    }

    public function getDastAudience(): ?string
    {
        return $this->nullableString('dast.audience');
    }

    public function getDastIssuer(): string
    {
        return (string) $this->get('dast.issuer', 'cybear');
    }

    public function getDastMaxTokenTtl(): int
    {
        return (int) $this->get('dast.max_token_ttl_seconds', 900);
    }

    // Audit
    public function isAuditEnabled(): bool
    {
        return (bool) $this->get('audit.enabled', true);
    }

    public function isAuditLogRequestsEnabled(): bool
    {
        return (bool) $this->get('audit.log_requests', true);
    }

    public function isAuditLogAuthEnabled(): bool
    {
        return (bool) $this->get('audit.log_authentication', true);
    }

    public function getAuditExcludedRoutes(): array
    {
        return (array) $this->get('audit.excluded_routes', []);
    }

    public function getAuditExcludedIps(): array
    {
        return (array) $this->get('audit.excluded_ips', []);
    }

    public function getAuditRetentionDays(): int
    {
        return (int) $this->get('audit.retention_days', 90);
    }

    // Rate Limiting
    public function isRateLimitEnabled(): bool
    {
        return (bool) $this->get('rate_limiting.enabled', true);
    }

    public function getRateLimitPerMinute(): int
    {
        return (int) $this->get('rate_limiting.requests_per_minute', 60);
    }

    public function getRateLimitPerHour(): int
    {
        return (int) $this->get('rate_limiting.requests_per_hour', 1000);
    }

    public function getRateLimitPerDay(): int
    {
        return (int) $this->get('rate_limiting.requests_per_day', 10000);
    }

    public function isRateLimitExcludeAuthEnabled(): bool
    {
        return (bool) $this->get('rate_limiting.exclude_authenticated', false);
    }

    // Collectors
    public function isCollectorEnabled(string $collector): bool
    {
        return (bool) $this->get("collectors.{$collector}.enabled", true);
    }

    public function isAutoScheduleEnabled(): bool
    {
        return (bool) $this->get('collectors.auto_schedule', true);
    }

    public function getBatchSize(): int
    {
        return (int) $this->get('collectors.batch_size', 100);
    }

    public function isCompressionEnabled(): bool
    {
        return (bool) $this->get('collectors.compression', true);
    }

    public function isIncludeDevPackages(): bool
    {
        return (bool) $this->get('collectors.packages.include_dev', false);
    }

    // Sync
    public function isOpportunisticSyncEnabled(): bool
    {
        return (bool) $this->get('sync.opportunistic', true);
    }

    public function getSyncSendInterval(): int
    {
        return (int) $this->get('sync.send_interval_seconds', 900);
    }

    public function getSyncRulesInterval(): int
    {
        return (int) $this->get('sync.rules_interval_seconds', 21600);
    }

    public function getSyncCollectInterval(): int
    {
        return (int) $this->get('sync.collect_interval_seconds', 7200);
    }

    // App info (set by the framework adapter)
    public function getAppId(): ?string
    {
        return $this->get('app_id');
    }

    public function getAppName(): string
    {
        return $this->get('app_name', 'unknown');
    }

    public function getAppUrl(): ?string
    {
        return $this->get('app_url');
    }

    public function getAppKey(): ?string
    {
        return $this->get('app_key');
    }

    public function getFrameworkVersion(): string
    {
        return $this->get('framework_version', 'unknown');
    }

    public function getBasePath(): string
    {
        return $this->get('base_path', getcwd());
    }

    public function getPublicPath(): string
    {
        return $this->get('public_path', $this->getBasePath().'/public');
    }

    public function getStoragePath(): string
    {
        return $this->get('storage_path', $this->getBasePath().'/storage');
    }

    // Debugging
    public function isDebugEnabled(): bool
    {
        return (bool) $this->get('debugging.enabled', false);
    }

    public function isWafDebugEnabled(): bool
    {
        return (bool) $this->get('debugging.waf_rules', false);
    }

    public function isPerformanceLoggingEnabled(): bool
    {
        return (bool) $this->get('debugging.performance_logging', false);
    }

    // Generic getter with dot notation
    public function get(string $key, mixed $default = null): mixed
    {
        $keys = explode('.', $key);
        $value = $this->config;

        foreach ($keys as $segment) {
            if (! is_array($value) || ! array_key_exists($segment, $value)) {
                return $default;
            }
            $value = $value[$segment];
        }

        return $value;
    }

    protected function nullableString(string $key): ?string
    {
        $value = $this->get($key);

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    protected function defaults(): array
    {
        return [
            'api' => [
                'endpoint' => 'https://api.cybear.care',
                'key' => null,
                'timeout' => 30,
                'retry_attempts' => 3,
                'retry_delay' => 1000,
            ],
            'waf' => [
                'enabled' => true,
                'mode' => 'monitor',
                'failure_mode' => 'allow',
                'cache_rules' => true,
                'cache_ttl' => 3600,
                'max_inspection_bytes' => 131072,
                'max_rules' => 500,
                'max_conditions_per_rule' => 50,
                'max_regex_evaluations' => 100,
                'truncation_action' => 'block',
            ],
            'dast' => [
                'correlation_enabled' => false,
                'signing_key' => null,
                'audience' => null,
                'issuer' => 'cybear',
                'max_token_ttl_seconds' => 900,
            ],
            'audit' => [
                'enabled' => true,
                'log_requests' => true,
                'log_authentication' => true,
                'excluded_routes' => [],
                'excluded_ips' => [],
                'retention_days' => 90,
            ],
            'rate_limiting' => [
                'enabled' => true,
                'requests_per_minute' => 60,
                'requests_per_hour' => 1000,
                'requests_per_day' => 10000,
                'exclude_authenticated' => false,
            ],
            'collectors' => [
                'auto_schedule' => true,
                'batch_size' => 100,
                'compression' => true,
                'packages' => ['enabled' => true, 'include_dev' => false],
                'environment' => ['enabled' => true],
                'security' => ['enabled' => true],
                'application' => ['enabled' => true],
                'performance' => ['enabled' => true],
                'auth' => ['enabled' => true],
                'database' => ['enabled' => true],
                'filesystem' => ['enabled' => true],
                'network' => ['enabled' => true],
            ],
            'sync' => [
                'opportunistic' => true,
                'send_interval_seconds' => 900,
                'rules_interval_seconds' => 21600,
                'collect_interval_seconds' => 7200,
                'lock_seconds' => 300,
                'failure_backoff_seconds' => 60,
                'max_failure_backoff_seconds' => 3600,
                'scheduler_heartbeat_ttl_seconds' => 600,
                'in_testing' => false,
            ],
            'debugging' => [
                'enabled' => false,
                'waf_rules' => false,
                'performance_logging' => false,
            ],
        ];
    }
}
