<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\PathInspector;
use CybearCare\LaravelSecurity\Posture\Severity;

final class PublicDatabaseFileCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.database.public_sqlite';
    }

    public function name(): string
    {
        return 'SQLite files under public root';
    }

    public function category(): string
    {
        return 'database';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function run(CheckContext $context): CheckResult
    {
        $connections = $context->config('database.connections', []);
        if (!is_array($connections)) {
            return $this->skipped('Laravel database connections could not be inspected.');
        }

        $publicPath = PathInspector::resolve($context->publicPath(), $context->basePath());
        if ($publicPath === null) {
            return $this->skipped('Laravel’s public path could not be resolved.');
        }

        $sqliteConnections = 0;
        $exposed = [];

        foreach ($connections as $name => $connection) {
            if (!is_array($connection) || strtolower((string) ($connection['driver'] ?? '')) !== 'sqlite') {
                continue;
            }

            $database = $connection['database'] ?? null;
            if (!is_string($database) || $database === '' || $database === ':memory:') {
                continue;
            }

            $sqliteConnections++;
            $path = PathInspector::resolve($database, $context->basePath());

            if ($path !== null && PathInspector::isWithin($path, $publicPath)) {
                $exposed[] = [
                    'connection' => (string) $name,
                    'public_relative_path' => PathInspector::relativeTo($path, $publicPath),
                ];
            }
        }

        if ($exposed !== []) {
            return $this->fail(
                'A configured SQLite database file is located under Laravel’s public root.',
                'Move the database outside the public directory, update the connection path, deny static database-file access, and rotate any exposed data or credentials.',
                ['exposed_connections' => $exposed],
            );
        }

        if ($sqliteConnections === 0) {
            return $this->skipped('No file-backed SQLite connections are configured.');
        }

        return $this->pass('Configured SQLite database files are outside the public root.', [
            'sqlite_connection_count' => $sqliteConnections,
        ]);
    }
}
