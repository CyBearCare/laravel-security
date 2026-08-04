<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class ConfigurationCacheCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.deployment.config_cache';
    }

    public function name(): string
    {
        return 'Production configuration cache';
    }

    public function category(): string
    {
        return 'deployment';
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->isProduction()) {
            return $this->skipped('Configuration caching is evaluated only for production.', [
                'environment' => $context->environment(),
            ]);
        }

        $cached = $context->application->configurationIsCached();

        if (!$cached) {
            return $this->warning(
                'Laravel configuration is not cached in production.',
                'Run `php artisan config:cache` during deployment after all environment values are available.',
                ['configuration_cached' => false],
            );
        }

        return $this->pass('Laravel configuration is cached.', ['configuration_cached' => true]);
    }
}
