<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class SessionSameSiteCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.session.same_site';
    }

    public function name(): string
    {
        return 'Session SameSite policy';
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
        if (!$context->hasWebRoutes()) {
            return $this->skipped('No routes using Laravel’s web middleware group were detected.');
        }

        $sameSite = strtolower((string) $context->config('session.same_site', ''));
        $secure = $context->config('session.secure') === true;
        $evidence = ['same_site' => $sameSite !== '' ? $sameSite : null, 'secure_cookie' => $secure];

        if ($sameSite === 'lax' || $sameSite === 'strict') {
            return $this->pass('The session cookie has a restrictive SameSite policy.', $evidence);
        }

        if ($sameSite === 'none' && $secure) {
            return $this->warning(
                'The session cookie is intentionally available in cross-site requests.',
                'Confirm cross-site session use is required; prefer SameSite=Lax or Strict when possible.',
                $evidence,
                Severity::Low,
            );
        }

        return $this->fail(
            'The session SameSite policy is missing or unsafe.',
            'Set SESSION_SAME_SITE=lax (or strict). SameSite=None requires a secure cookie and a documented cross-site use case.',
            $evidence,
        );
    }
}
