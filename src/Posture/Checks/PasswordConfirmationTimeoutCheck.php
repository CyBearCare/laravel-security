<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class PasswordConfirmationTimeoutCheck extends AbstractCheck
{
    private const LARAVEL_DEFAULT_SECONDS = 10800;
    private const MAXIMUM_RECOMMENDED_SECONDS = 86400;

    public function id(): string
    {
        return 'laravel.auth.password_confirmation_timeout';
    }

    public function name(): string
    {
        return 'Password confirmation timeout';
    }

    public function category(): string
    {
        return 'authentication';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->hasWebRoutes()) {
            return $this->skipped('No routes using Laravel’s web middleware group were detected.');
        }

        $timeout = (int) $context->config('auth.password_timeout', self::LARAVEL_DEFAULT_SECONDS);
        $evidence = [
            'timeout_seconds' => $timeout,
            'laravel_default_seconds' => self::LARAVEL_DEFAULT_SECONDS,
        ];

        if ($timeout > self::MAXIMUM_RECOMMENDED_SECONDS) {
            return $this->fail(
                'Password confirmation remains valid for more than 24 hours.',
                'Shorten auth.password_timeout and require fresh confirmation before sensitive account operations.',
                $evidence,
            );
        }

        if ($timeout > self::LARAVEL_DEFAULT_SECONDS) {
            return $this->warning(
                'Password confirmation remains valid longer than Laravel’s default.',
                'Confirm the longer window is intentional; prefer Laravel’s default or a shorter timeout for sensitive applications.',
                $evidence,
                Severity::Low,
            );
        }

        return $this->pass('The password confirmation timeout does not exceed Laravel’s default.', $evidence);
    }
}
