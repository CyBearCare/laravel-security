<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\Severity;
use Throwable;

final class PassportOAuthHardeningCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.passport.oauth_hardening';
    }

    public function name(): string
    {
        return 'Passport OAuth grant hardening';
    }

    public function category(): string
    {
        return 'authentication';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function confidence(): Confidence
    {
        return Confidence::High;
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
                'Passport is installed, but its runtime security flags could not be loaded.',
                'Confirm the Passport installation and application bootstrap, then rerun the scan.',
                ['version' => $context->capabilities->packageVersion('passport')],
            );
        }

        try {
            $flags = [
                'implicit_grant_enabled' => $this->flag('implicitGrantEnabled'),
                'password_grant_enabled' => $this->flag('passwordGrantEnabled'),
                'refresh_token_revoked_after_use' => $this->flag('revokeRefreshTokenAfterUse'),
                'key_permission_validation_enabled' => $this->flag('validateKeyPermissions'),
                'csrf_ignored_for_cookie_tokens' => $this->flag('ignoreCsrfToken'),
            ];
        } catch (Throwable) {
            return $this->warning(
                'Passport runtime security flags could not be inspected safely.',
                'Review enabled OAuth grants, refresh-token rotation, key permissions, and cookie-token CSRF behavior manually.',
                ['version' => $context->capabilities->packageVersion('passport')],
            );
        }

        $critical = ($flags['implicit_grant_enabled'] ?? false)
            || ($flags['refresh_token_revoked_after_use'] === false)
            || ($flags['csrf_ignored_for_cookie_tokens'] ?? false);
        $deprecatedPasswordGrant = ($flags['password_grant_enabled'] ?? false) === true;
        $keyPermissionsDisabled = $flags['key_permission_validation_enabled'] === false;
        $unknownFlags = array_keys(array_filter(
            $flags,
            static fn (?bool $value): bool => $value === null,
        ));
        $evidence = [
            'version' => $context->capabilities->packageVersion('passport'),
            ...$flags,
            'unavailable_runtime_flags' => $unknownFlags,
        ];

        if ($critical) {
            return $this->fail(
                'Passport has a high-risk OAuth compatibility or token-reuse option enabled.',
                'Disable the implicit grant, keep refresh-token revocation after use enabled, and do not bypass CSRF validation for cookie tokens. Prefer authorization code with PKCE for public clients.',
                $evidence,
            );
        }

        if ($deprecatedPasswordGrant || $keyPermissionsDisabled) {
            return $this->warning(
                'Passport uses a deprecated grant or has encryption-key permission validation disabled.',
                'Migrate password-grant clients to a recommended OAuth flow and keep Passport key permission validation enabled.',
                $evidence,
                Severity::Medium,
            );
        }

        if ($unknownFlags !== []) {
            return $this->warning(
                'This Passport version does not expose every runtime hardening flag inspected by the scanner.',
                'Review the unavailable options against the installed Passport version, especially refresh-token rotation, grant types, key permissions, and cookie-token CSRF behavior.',
                $evidence,
                Severity::Medium,
            );
        }

        return $this->pass(
            'Passport avoids deprecated interactive grants, rotates refresh tokens, validates key permissions, and retains cookie-token CSRF checks.',
            $evidence,
        );
    }

    private function flag(string $property): ?bool
    {
        if (!property_exists(\Laravel\Passport\Passport::class, $property)) {
            return null;
        }

        $value = \Laravel\Passport\Passport::${$property};

        return is_bool($value) ? $value : null;
    }
}
