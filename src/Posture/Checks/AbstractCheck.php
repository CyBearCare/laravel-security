<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\CheckScope;
use CybearCare\LaravelSecurity\Posture\CheckStatus;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\Contracts\SecurityCheck;
use CybearCare\LaravelSecurity\Posture\Severity;

abstract class AbstractCheck implements SecurityCheck
{
    public function scope(): CheckScope
    {
        return match ($this->id()) {
            'laravel.dependencies.composer_lock' => CheckScope::Dependencies,
            'laravel.app.debug',
            'laravel.app.https_url',
            'laravel.cache.namespace_prefix',
            'laravel.cache.persistent_store',
            'laravel.database.public_sqlite',
            'laravel.deployment.config_cache',
            'laravel.filesystem.env_permissions',
            'laravel.filesystem.public_local_root',
            'laravel.public.sensitive_files',
            'laravel.queue.async_driver',
            'laravel.queue.failed_job_storage',
            'laravel.session.persistent_driver',
            'laravel.session.secure_cookie' => CheckScope::Environment,
            'laravel.admin_surfaces.authorization',
            'laravel.debugbar.production',
            'laravel.octane.runtime_safety',
            'laravel.telescope.production' => CheckScope::Runtime,
            default => CheckScope::Application,
        };
    }

    public function confidence(): Confidence
    {
        return Confidence::High;
    }

    public function references(): array
    {
        return match ($this->id()) {
            'laravel.app.debug' => ['https://laravel.com/docs/12.x/configuration#debug-mode'],
            'laravel.app.key' => ['https://laravel.com/docs/12.x/encryption'],
            'laravel.app.https_url',
            'laravel.deployment.config_cache' => ['https://laravel.com/docs/12.x/deployment'],
            'laravel.queue.async_driver',
            'laravel.queue.failed_job_storage' => ['https://laravel.com/docs/12.x/queues'],
            'laravel.cache.persistent_store',
            'laravel.cache.namespace_prefix' => ['https://laravel.com/docs/12.x/cache'],
            'laravel.session.secure_cookie',
            'laravel.session.http_only',
            'laravel.session.same_site',
            'laravel.session.persistent_driver',
            'laravel.session.partitioned_cookie' => ['https://laravel.com/docs/12.x/session'],
            'laravel.cors.credentialed_origins' => ['https://laravel.com/docs/12.x/routing#cors'],
            'laravel.public.sensitive_files',
            'laravel.filesystem.env_permissions',
            'laravel.filesystem.public_local_root' => ['https://laravel.com/docs/12.x/filesystem'],
            'laravel.database.public_sqlite' => ['https://laravel.com/docs/12.x/database'],
            'laravel.routes.csrf_middleware' => ['https://laravel.com/docs/12.x/csrf'],
            'laravel.routes.authorization_coverage' => ['https://laravel.com/docs/12.x/authorization'],
            'laravel.routes.signed_link_integrity' => ['https://laravel.com/docs/12.x/urls#validating-signed-route-requests'],
            'laravel.routes.encrypted_cookies' => ['https://laravel.com/docs/12.x/middleware'],
            'laravel.eloquent.mass_assignment_input' => ['https://laravel.com/docs/12.x/eloquent#mass-assignment'],
            'laravel.uploads.validation' => ['https://laravel.com/docs/12.x/validation#validating-files'],
            'laravel.auth.password_resets',
            'laravel.auth.password_confirmation_timeout' => ['https://laravel.com/docs/12.x/passwords'],
            'laravel.auth.hashing_cost' => ['https://laravel.com/docs/12.x/hashing'],
            'laravel.admin_surfaces.authorization' => [
                'https://laravel.com/docs/12.x/horizon#dashboard-authorization',
                'https://laravel.com/docs/12.x/telescope#dashboard-authorization',
                'https://laravel.com/docs/12.x/pulse#dashboard-authorization',
            ],
            'laravel.fortify.authentication_throttling' => [
                'https://laravel.com/docs/12.x/starter-kits#rate-limiting',
            ],
            'laravel.fortify.two_factor_hardening' => [
                'https://laravel.com/docs/12.x/starter-kits#two-factor-authentication',
            ],
            'laravel.sanctum.token_expiration' => ['https://laravel.com/docs/12.x/sanctum#token-expiration'],
            'laravel.passport.token_lifetimes' => [
                'https://laravel.com/docs/12.x/passport#token-lifetimes',
            ],
            'laravel.passport.oauth_hardening' => [
                'https://laravel.com/docs/12.x/passport#password-grant',
                'https://laravel.com/docs/12.x/passport#implicit-grant',
            ],
            'laravel.octane.runtime_safety' => [
                'https://laravel.com/docs/12.x/octane#dependency-injection-and-octane',
            ],
            'laravel.debugbar.production' => ['https://github.com/fruitcake/laravel-debugbar'],
            'laravel.telescope.production' => ['https://laravel.com/docs/12.x/telescope#dashboard-authorization'],
            'laravel.dependencies.composer_lock' => [
                'https://getcomposer.org/doc/01-basic-usage.md#installing-dependencies',
            ],
            default => ['https://laravel.com/docs/12.x'],
        };
    }

    /**
     * @param array<string, mixed> $evidence
     * @param list<string> $references
     * @param list<\CybearCare\LaravelSecurity\Posture\FindingOccurrence> $occurrences
     */
    final protected function result(
        CheckStatus $status,
        string $summary,
        array $evidence = [],
        ?string $remediation = null,
        ?Severity $severity = null,
        array $references = [],
        array $occurrences = [],
    ): CheckResult {
        return new CheckResult(
            checkId: $this->id(),
            name: $this->name(),
            category: $this->category(),
            status: $status,
            severity: $severity ?? $this->severity(),
            confidence: $this->confidence(),
            summary: $summary,
            evidence: $evidence,
            remediation: $remediation,
            references: $references !== [] ? $references : $this->references(),
            scope: $this->scope(),
            occurrences: $occurrences,
        );
    }

    final protected function pass(string $summary, array $evidence = []): CheckResult
    {
        return $this->result(CheckStatus::Pass, $summary, $evidence);
    }

    final protected function warning(
        string $summary,
        string $remediation,
        array $evidence = [],
        ?Severity $severity = null,
        array $occurrences = [],
    ): CheckResult {
        return $this->result(
            CheckStatus::Warning,
            $summary,
            $evidence,
            $remediation,
            $severity,
            occurrences: $occurrences,
        );
    }

    final protected function fail(
        string $summary,
        string $remediation,
        array $evidence = [],
        ?Severity $severity = null,
        array $occurrences = [],
    ): CheckResult {
        return $this->result(
            CheckStatus::Fail,
            $summary,
            $evidence,
            $remediation,
            $severity,
            occurrences: $occurrences,
        );
    }

    final protected function skipped(string $summary, array $evidence = []): CheckResult
    {
        return $this->result(CheckStatus::Skipped, $summary, $evidence, severity: Severity::Info);
    }
}
