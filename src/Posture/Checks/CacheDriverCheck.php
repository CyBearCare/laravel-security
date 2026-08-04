<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class CacheDriverCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.cache.persistent_store';
    }

    public function name(): string
    {
        return 'Production cache persistence';
    }

    public function category(): string
    {
        return 'deployment';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function run(CheckContext $context): CheckResult
    {
        $store = strtolower((string) $context->config('cache.default', ''));

        if (!$context->isProduction()) {
            return $this->skipped('Cache persistence is evaluated only for production.', [
                'environment' => $context->environment(),
                'store' => $store,
            ]);
        }

        if ($store === '' || $store === 'array' || $store === 'null') {
            return $this->fail(
                'Production uses a non-persistent cache store.',
                'Configure a persistent cache store so rate limits, locks, and security state survive across requests.',
                ['store' => $store !== '' ? $store : null],
            );
        }

        return $this->pass('Production uses a persistent cache store.', ['store' => $store]);
    }
}
