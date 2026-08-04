<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\Severity;
use DateInterval;
use DateTimeImmutable;
use Throwable;

final class PassportTokenLifetimeCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.passport.token_lifetimes';
    }

    public function name(): string
    {
        return 'Passport token lifetimes';
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
        if (!$context->capabilities->hasPackage('passport')) {
            return $this->skipped('Laravel Passport is not installed.');
        }

        try {
            $passportLoaded = class_exists(\Laravel\Passport\Passport::class);
        } catch (Throwable) {
            $passportLoaded = false;
        }

        if (!$passportLoaded) {
            return $this->warning(
                'Passport is installed, but its runtime configuration class could not be loaded.',
                'Confirm the Passport installation and application bootstrap, then rerun the scan.',
                ['version' => $context->capabilities->packageVersion('passport')],
            );
        }

        $thresholds = [
            'access' => $this->threshold($context, 'access', 90),
            'refresh' => $this->threshold($context, 'refresh', 365),
            'personal_access' => $this->threshold($context, 'personal_access', 365),
        ];

        try {
            $lifetimes = [
                'access' => $this->days(
                    \Laravel\Passport\Passport::$tokensExpireIn ?? new DateInterval('P1Y'),
                ),
                'refresh' => $this->days(
                    \Laravel\Passport\Passport::$refreshTokensExpireIn ?? new DateInterval('P1Y'),
                ),
                'personal_access' => $this->days(
                    \Laravel\Passport\Passport::$personalAccessTokensExpireIn ?? new DateInterval('P1Y'),
                ),
            ];
        } catch (Throwable) {
            return $this->warning(
                'Passport token lifetimes could not be interpreted safely.',
                'Set explicit access, refresh, and personal access token intervals during application boot.',
                ['version' => $context->capabilities->packageVersion('passport')],
            );
        }

        $excessive = [];
        foreach ($lifetimes as $type => $days) {
            if ($days <= 0 || $days > $thresholds[$type]) {
                $excessive[] = $type;
            }
        }

        $evidence = [
            'version' => $context->capabilities->packageVersion('passport'),
            'effective_lifetime_days' => $lifetimes,
            'maximum_recommended_days' => $thresholds,
            'excessive_lifetimes' => $excessive,
        ];

        if ($excessive !== []) {
            return $this->warning(
                'One or more Passport token lifetimes exceed the configured security thresholds.',
                'Set explicit tokensExpireIn, refreshTokensExpireIn, and personalAccessTokensExpireIn intervals appropriate to the client and rotation model.',
                $evidence,
            );
        }

        return $this->pass('Passport token lifetimes are positive and within the configured thresholds.', $evidence);
    }

    private function threshold(CheckContext $context, string $type, int $default): int
    {
        $value = $context->config("cybear.posture.passport_max_{$type}_token_days", $default);

        return max(1, min(3650, is_numeric($value) ? (int) $value : $default));
    }

    private function days(DateInterval $interval): int
    {
        $start = new DateTimeImmutable('2024-01-01T00:00:00+00:00');
        $end = $start->add($interval);
        $days = $start->diff($end)->days;

        if (!is_int($days)) {
            return 0;
        }

        return $interval->invert === 1 ? -$days : $days;
    }
}
