<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class WebCookieEncryptionCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.routes.encrypted_cookies';
    }

    public function name(): string
    {
        return 'Cookie encryption on web routes';
    }

    public function category(): string
    {
        return 'routing';
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

        if ($this->containsEncryptCookies($context->globalMiddleware())) {
            return $this->pass('Laravel cookie encryption is applied globally.');
        }

        $affected = [];
        $affectedCount = 0;
        $checked = 0;
        $limit = max(1, min(100, (int) $context->config('cybear.posture.max_evidence_items', 25)));

        foreach ($context->routes() as $route) {
            $raw = array_values(array_filter($route->gatherMiddleware(), 'is_string'));
            if (!in_array('web', $raw, true)) {
                continue;
            }

            $checked++;
            if ($this->containsEncryptCookies($context->resolvedMiddleware($route))) {
                continue;
            }

            $affectedCount++;
            if (count($affected) < $limit) {
                $affected[] = ['uri' => $route->uri(), 'name' => $route->getName()];
            }
        }

        if ($affectedCount > 0) {
            return $this->fail(
                'Web routes were found without Laravel’s EncryptCookies middleware.',
                'Restore EncryptCookies to the web middleware group. Use its explicit exception list only for cookies that must remain plaintext.',
                [
                    'routes_checked' => $checked,
                    'affected_route_count' => $affectedCount,
                    'affected_routes' => $affected,
                    'evidence_truncated' => $affectedCount > count($affected),
                ],
            );
        }

        return $this->pass('Laravel cookie encryption covers all explicit web routes.', [
            'routes_checked' => $checked,
        ]);
    }

    /**
     * @param list<string> $middleware
     */
    private function containsEncryptCookies(array $middleware): bool
    {
        foreach ($middleware as $item) {
            $class = explode(':', $item, 2)[0];
            if ($class === 'EncryptCookies' || str_ends_with($class, '\\EncryptCookies')) {
                return true;
            }
        }

        return false;
    }
}
