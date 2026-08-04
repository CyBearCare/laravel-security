<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\Severity;

final class SanctumTokenExpirationCheck extends AbstractCheck
{
    private const ONE_YEAR_MINUTES = 525600;

    public function id(): string
    {
        return 'laravel.sanctum.token_expiration';
    }

    public function name(): string
    {
        return 'Sanctum token expiration';
    }

    public function category(): string
    {
        return 'authentication';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function confidence(): Confidence
    {
        return Confidence::Medium;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->capabilities->hasPackage('sanctum')) {
            return $this->skipped('Laravel Sanctum is not installed.');
        }

        if (!$context->capabilities->hasRouteSurface('sanctum_protected')) {
            return $this->skipped('No routes explicitly protected by auth:sanctum were detected.', [
                'version' => $context->capabilities->packageVersion('sanctum'),
            ]);
        }

        $expiration = $context->config('sanctum.expiration');
        $evidence = [
            'expiration_minutes' => is_numeric($expiration) ? (int) $expiration : null,
            'protected_route_count' => $context->capabilities->routeCount('sanctum_protected'),
            'version' => $context->capabilities->packageVersion('sanctum'),
        ];

        if ($expiration === null || $expiration === '') {
            return $this->warning(
                'Sanctum personal access tokens do not expire automatically.',
                'Set a bounded Sanctum expiration or implement documented token rotation and revocation appropriate to the application.',
                $evidence,
            );
        }

        if (!is_numeric($expiration) || (int) $expiration < 0) {
            return $this->warning(
                'Sanctum token expiration is not a valid non-negative minute value.',
                'Set sanctum.expiration to null for deliberate non-expiring tokens or to a non-negative integer minute value.',
                $evidence,
            );
        }

        $minutes = (int) $expiration;
        if ($minutes > self::ONE_YEAR_MINUTES) {
            return $this->warning(
                'Sanctum personal access tokens remain valid for more than one year.',
                'Use shorter-lived tokens with rotation and revoke tokens after credential or account-risk changes.',
                $evidence,
            );
        }

        return $this->pass('Sanctum personal access tokens have a bounded expiration.', $evidence);
    }
}
