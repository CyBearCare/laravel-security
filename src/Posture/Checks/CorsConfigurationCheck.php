<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class CorsConfigurationCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.cors.credentialed_origins';
    }

    public function name(): string
    {
        return 'Credentialed CORS origins';
    }

    public function category(): string
    {
        return 'network';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(CheckContext $context): CheckResult
    {
        $cors = $context->config('cors');

        if (!is_array($cors)) {
            return $this->skipped('No application CORS configuration is loaded.');
        }

        $origins = array_values(array_filter((array) ($cors['allowed_origins'] ?? []), 'is_string'));
        $patterns = array_values(array_filter((array) ($cors['allowed_origins_patterns'] ?? []), 'is_string'));
        $credentials = ($cors['supports_credentials'] ?? false) === true;
        $wildcardPattern = false;

        foreach ($patterns as $pattern) {
            $compact = preg_replace('/[^a-z0-9.*+]/i', '', $pattern);
            if ($compact === '.*' || $compact === '^.*$' || $compact === '.+') {
                $wildcardPattern = true;
                break;
            }
        }

        $evidence = [
            'supports_credentials' => $credentials,
            'allows_any_origin' => in_array('*', $origins, true) || $wildcardPattern,
            'configured_origin_count' => count($origins) + count($patterns),
        ];

        if ($credentials && $evidence['allows_any_origin']) {
            return $this->fail(
                'CORS combines credential support with an unrestricted origin.',
                'Replace wildcard origins with an explicit allowlist and review every credentialed cross-origin flow.',
                $evidence,
            );
        }

        return $this->pass('CORS does not combine credentials with an unrestricted origin.', $evidence);
    }
}
