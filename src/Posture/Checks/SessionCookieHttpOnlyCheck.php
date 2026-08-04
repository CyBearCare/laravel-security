<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class SessionCookieHttpOnlyCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.session.http_only';
    }

    public function name(): string
    {
        return 'HTTP-only session cookie';
    }

    public function category(): string
    {
        return 'session';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->hasWebRoutes()) {
            return $this->skipped('No routes using Laravel’s web middleware group were detected.');
        }

        $httpOnly = $context->config('session.http_only', true);

        if ($httpOnly !== true) {
            return $this->fail(
                'JavaScript can access the Laravel session cookie.',
                'Set SESSION_HTTP_ONLY=true so browser scripts cannot read the session identifier.',
                ['http_only' => $httpOnly],
            );
        }

        return $this->pass('The session cookie is HTTP-only.', ['http_only' => true]);
    }
}
