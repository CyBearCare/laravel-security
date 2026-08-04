<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class AppUrlHttpsCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.app.https_url';
    }

    public function name(): string
    {
        return 'Production application URL';
    }

    public function category(): string
    {
        return 'deployment';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->isProduction()) {
            return $this->skipped('HTTPS enforcement is evaluated only for production.', [
                'environment' => $context->environment(),
            ]);
        }

        $url = (string) $context->config('app.url', '');
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        $host = parse_url($url, PHP_URL_HOST);
        $evidence = [
            'scheme' => $scheme !== '' ? $scheme : null,
            'host' => is_string($host) ? strtolower($host) : null,
        ];

        if ($scheme !== 'https' || !is_string($host) || $host === '') {
            return $this->fail(
                'The production APP_URL is missing or does not use HTTPS.',
                'Set APP_URL to the canonical https:// URL, configure trusted proxies correctly, and clear cached configuration.',
                $evidence,
            );
        }

        return $this->pass('The production APP_URL uses HTTPS.', $evidence);
    }
}
