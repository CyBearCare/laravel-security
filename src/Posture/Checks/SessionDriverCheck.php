<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class SessionDriverCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.session.persistent_driver';
    }

    public function name(): string
    {
        return 'Production session persistence';
    }

    public function category(): string
    {
        return 'session';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function run(CheckContext $context): CheckResult
    {
        $driver = strtolower((string) $context->config('session.driver', ''));

        if (!$context->hasWebRoutes()) {
            return $this->skipped('No routes using Laravel’s web middleware group were detected.', [
                'driver' => $driver,
            ]);
        }

        if (!$context->isProduction()) {
            return $this->skipped('Session persistence is evaluated only for production.', [
                'environment' => $context->environment(),
                'driver' => $driver,
            ]);
        }

        if ($driver === '' || $driver === 'array') {
            return $this->fail(
                'Production sessions use a non-persistent driver.',
                'Use a persistent Laravel session driver such as database or Redis in production.',
                ['driver' => $driver !== '' ? $driver : null],
            );
        }

        return $this->pass('Production sessions use a persistent driver.', ['driver' => $driver]);
    }
}
