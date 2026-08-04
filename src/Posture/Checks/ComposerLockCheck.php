<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;
use JsonException;

final class ComposerLockCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.dependencies.composer_lock';
    }

    public function name(): string
    {
        return 'Composer dependency lock';
    }

    public function category(): string
    {
        return 'dependencies';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function run(CheckContext $context): CheckResult
    {
        $path = $context->basePath('composer.lock');

        if (!is_file($path)) {
            return $this->fail(
                'The Laravel application has no composer.lock file.',
                'Commit composer.lock for applications and deploy with `composer install` so dependency versions are reproducible and auditable.',
                ['lock_file_present' => false],
            );
        }

        $contents = file_get_contents($path);
        if ($contents === false) {
            return $this->warning(
                'composer.lock exists but could not be read.',
                'Correct file ownership and permissions so deployment and security tooling can read composer.lock.',
                ['lock_file_present' => true, 'readable' => false],
            );
        }

        try {
            $lock = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $this->fail(
                'composer.lock is not valid JSON.',
                'Regenerate composer.lock with Composer, review the dependency changes, and commit the corrected lock file.',
                ['lock_file_present' => true, 'valid_json' => false],
            );
        }

        $packages = is_array($lock['packages'] ?? null) ? $lock['packages'] : [];
        $hasLaravel = false;
        foreach ($packages as $package) {
            if (is_array($package) && ($package['name'] ?? null) === 'laravel/framework') {
                $hasLaravel = true;
                break;
            }
        }

        if (!$hasLaravel) {
            return $this->warning(
                'composer.lock does not contain laravel/framework.',
                'Ensure the scan runs from the Laravel application root and that the lock file matches the deployed application.',
                ['lock_file_present' => true, 'valid_json' => true, 'package_count' => count($packages)],
                Severity::Low,
            );
        }

        return $this->pass('Composer dependencies are locked and include Laravel.', [
            'lock_file_present' => true,
            'valid_json' => true,
            'content_hash_present' => is_string($lock['content-hash'] ?? null),
            'package_count' => count($packages),
        ]);
    }
}
