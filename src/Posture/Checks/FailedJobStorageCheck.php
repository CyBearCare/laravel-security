<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class FailedJobStorageCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.queue.failed_job_storage';
    }

    public function name(): string
    {
        return 'Failed job retention';
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
        if (!$context->isProduction()) {
            return $this->skipped('Failed-job retention is evaluated only for production.', [
                'environment' => $context->environment(),
            ]);
        }

        $driver = $context->config('queue.failed.driver');
        $driver = is_string($driver) ? strtolower($driver) : null;

        if ($driver === null || $driver === '' || $driver === 'null') {
            return $this->warning(
                'Failed queued jobs are not retained in production.',
                'Configure Laravel failed-job storage and operational alerts so failed security and application work remains diagnosable.',
                ['failed_job_driver' => $driver],
            );
        }

        return $this->pass('Failed queued jobs are retained.', ['failed_job_driver' => $driver]);
    }
}
