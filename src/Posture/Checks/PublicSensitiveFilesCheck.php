<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class PublicSensitiveFilesCheck extends AbstractCheck
{
    private const CANDIDATES = [
        '.env',
        '.env.backup',
        '.git',
        'composer.json',
        'composer.lock',
        'phpunit.xml',
        'phpunit.xml.dist',
        'server.php',
        'phpinfo.php',
        'info.php',
        'test.php',
        'storage/logs/laravel.log',
    ];

    public function id(): string
    {
        return 'laravel.public.sensitive_files';
    }

    public function name(): string
    {
        return 'Sensitive files under public root';
    }

    public function category(): string
    {
        return 'filesystem';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function run(CheckContext $context): CheckResult
    {
        $found = [];

        foreach (self::CANDIDATES as $candidate) {
            if (file_exists($context->publicPath($candidate))) {
                $found[] = $candidate;
            }
        }

        if ($found !== []) {
            return $this->fail(
                'Sensitive development or configuration files exist under Laravel’s public root.',
                'Remove these files from the public directory, verify web-server document-root configuration, and rotate any exposed secrets.',
                ['files' => $found, 'count' => count($found)],
            );
        }

        return $this->pass('No known sensitive files were found under the public root.', [
            'candidates_checked' => count(self::CANDIDATES),
        ]);
    }
}
