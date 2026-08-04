<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class SessionPartitionedCookieCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.session.partitioned_cookie';
    }

    public function name(): string
    {
        return 'Partitioned session cookie';
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

        $partitioned = $context->config('session.partitioned', false) === true;
        if (!$partitioned) {
            return $this->pass('Partitioned session cookies are not enabled.', ['partitioned' => false]);
        }

        $secure = $context->config('session.secure') === true;
        $sameSite = strtolower((string) $context->config('session.same_site', ''));
        $evidence = [
            'partitioned' => true,
            'secure_cookie' => $secure,
            'same_site' => $sameSite !== '' ? $sameSite : null,
        ];

        if (!$secure || $sameSite !== 'none') {
            return $this->fail(
                'The partitioned session cookie is missing browser-required attributes.',
                'Partitioned cookies require SESSION_SECURE_COOKIE=true and SESSION_SAME_SITE=none.',
                $evidence,
            );
        }

        return $this->pass('The partitioned session cookie has compatible security attributes.', $evidence);
    }
}
