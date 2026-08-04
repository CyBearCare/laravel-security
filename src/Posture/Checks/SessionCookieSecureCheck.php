<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class SessionCookieSecureCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.session.secure_cookie';
    }

    public function name(): string
    {
        return 'Secure session cookie';
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

        if (!$context->isProduction()) {
            return $this->skipped('Secure-cookie enforcement is evaluated only for production.', [
                'environment' => $context->environment(),
            ]);
        }

        $secure = $context->config('session.secure');

        if ($secure !== true) {
            return $this->fail(
                'Laravel session cookies are not explicitly restricted to HTTPS.',
                'Set SESSION_SECURE_COOKIE=true in production and clear cached configuration.',
                ['secure_cookie' => $secure],
            );
        }

        return $this->pass('Session cookies are restricted to HTTPS.', ['secure_cookie' => true]);
    }
}
