<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class QueueDriverCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.queue.async_driver';
    }

    public function name(): string
    {
        return 'Production queue driver';
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
        $driver = $context->capabilities->runtime('queue_driver');

        if (!$context->isProduction()) {
            return $this->skipped('Queue driver hardening is evaluated only for production.', [
                'environment' => $context->environment(),
                'driver' => $driver,
            ]);
        }

        if (!is_string($driver) || $driver === '') {
            return $this->warning(
                'The active queue driver could not be determined.',
                'Configure a named production queue connection and verify workers are supervised.',
                ['driver' => null],
            );
        }

        if (in_array(strtolower($driver), ['sync', 'null', 'deferred', 'background'], true)) {
            return $this->warning(
                'Production jobs are not using a durable asynchronous queue.',
                'Use a durable Laravel queue driver and supervised workers so security exports and application jobs survive request failures.',
                ['driver' => $driver],
            );
        }

        return $this->pass('Production jobs use a durable asynchronous queue driver.', ['driver' => $driver]);
    }
}
