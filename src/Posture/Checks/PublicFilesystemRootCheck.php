<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\PathInspector;
use CybearCare\LaravelSecurity\Posture\Severity;

final class PublicFilesystemRootCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.filesystem.public_local_root';
    }

    public function name(): string
    {
        return 'Local filesystem roots under public';
    }

    public function category(): string
    {
        return 'filesystem';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(CheckContext $context): CheckResult
    {
        $disks = $context->config('filesystems.disks', []);
        if (!is_array($disks)) {
            return $this->skipped('Laravel filesystem disks could not be inspected.');
        }

        $publicPath = PathInspector::resolve($context->publicPath(), $context->basePath());
        if ($publicPath === null) {
            return $this->skipped('Laravel’s public path could not be resolved.');
        }

        $localDisks = 0;
        $exposed = [];

        foreach ($disks as $name => $disk) {
            if (!is_array($disk) || strtolower((string) ($disk['driver'] ?? '')) !== 'local') {
                continue;
            }

            $root = $disk['root'] ?? null;
            if (!is_string($root) || $root === '') {
                continue;
            }

            $localDisks++;
            $path = PathInspector::resolve($root, $context->basePath());

            if ($path !== null && PathInspector::isWithin($path, $publicPath)) {
                $exposed[] = [
                    'disk' => (string) $name,
                    'public_relative_root' => PathInspector::relativeTo($path, $publicPath),
                ];
            }
        }

        if ($exposed !== []) {
            return $this->fail(
                'A local filesystem disk is rooted directly under Laravel’s public directory.',
                'Store uploads outside public and expose only an intentionally public storage link. Prevent uploaded content from being executed by the web server.',
                ['exposed_disks' => $exposed],
            );
        }

        return $this->pass('No configured local filesystem disk is rooted under the public directory.', [
            'local_disk_count' => $localDisks,
        ]);
    }
}
