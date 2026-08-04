<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class AppDebugCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.app.debug';
    }

    public function name(): string
    {
        return 'Application debug mode';
    }

    public function category(): string
    {
        return 'application';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function run(CheckContext $context): CheckResult
    {
        $debug = (bool) $context->config('app.debug', false);
        $evidence = ['environment' => $context->environment(), 'debug' => $debug];

        if ($context->isProduction() && $debug) {
            return $this->fail(
                'Laravel debug mode is enabled in production.',
                'Set APP_DEBUG=false in the production environment, clear cached configuration, and redeploy.',
                $evidence,
            );
        }

        if ($debug) {
            return $this->warning(
                'Debug mode is enabled outside production.',
                'Keep debug mode limited to controlled development environments and ensure deployment configuration disables it.',
                $evidence,
                Severity::Low,
            );
        }

        return $this->pass('Laravel debug mode is disabled.', $evidence);
    }
}
