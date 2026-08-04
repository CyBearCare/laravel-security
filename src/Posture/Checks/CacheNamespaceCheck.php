<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\Severity;

final class CacheNamespaceCheck extends AbstractCheck
{
    private const SHARED_DRIVERS = ['redis', 'memcached', 'database', 'dynamodb', 'mongodb'];

    public function id(): string
    {
        return 'laravel.cache.namespace_prefix';
    }

    public function name(): string
    {
        return 'Shared cache namespace';
    }

    public function category(): string
    {
        return 'deployment';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function confidence(): Confidence
    {
        return Confidence::Medium;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->isProduction()) {
            return $this->skipped('Shared-cache namespacing is evaluated only for production.', [
                'environment' => $context->environment(),
            ]);
        }

        $driver = strtolower((string) $context->capabilities->runtime('cache_driver', ''));
        if (!in_array($driver, self::SHARED_DRIVERS, true)) {
            return $this->skipped('The active cache driver is not normally shared between applications.', [
                'driver' => $driver !== '' ? $driver : null,
            ]);
        }

        $prefix = $context->config('cache.prefix');
        $configured = is_string($prefix) && trim($prefix) !== '';
        $evidence = ['driver' => $driver, 'prefix_configured' => $configured];

        if (!$configured) {
            return $this->warning(
                'A shared cache driver has no application namespace prefix.',
                'Set a unique CACHE_PREFIX for this application to prevent cache, lock, and rate-limit key collisions.',
                $evidence,
            );
        }

        return $this->pass('The shared cache driver has an application namespace prefix.', $evidence);
    }
}
