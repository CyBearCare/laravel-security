<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\Severity;

final class HashingCostCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.auth.hashing_cost';
    }

    public function name(): string
    {
        return 'Password hashing cost';
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
        $driver = strtolower((string) $context->config('hashing.driver', 'bcrypt'));

        if ($driver === 'bcrypt') {
            $rounds = (int) $context->config('hashing.bcrypt.rounds', 12);
            if ($rounds < 12) {
                return $this->warning(
                    'The bcrypt work factor is below Laravel’s current default.',
                    'Benchmark the application and raise BCRYPT_ROUNDS to at least 12 where operationally safe.',
                    ['driver' => $driver, 'rounds' => $rounds, 'baseline' => 12],
                );
            }

            return $this->pass('The bcrypt work factor meets Laravel’s current default.', [
                'driver' => $driver,
                'rounds' => $rounds,
                'baseline' => 12,
            ]);
        }

        if ($driver === 'argon' || $driver === 'argon2id') {
            $memory = (int) $context->config('hashing.argon.memory', 65536);
            $time = (int) $context->config('hashing.argon.time', 4);
            $threads = (int) $context->config('hashing.argon.threads', 1);
            $evidence = compact('driver', 'memory', 'time', 'threads');

            if ($memory < 65536 || $time < 4 || $threads < 1) {
                return $this->warning(
                    'The Argon work factors are below Laravel’s current defaults.',
                    'Benchmark the application and restore at least Laravel’s default Argon memory, time, and thread settings.',
                    $evidence,
                );
            }

            return $this->pass('The Argon work factors meet Laravel’s current defaults.', $evidence);
        }

        return $this->warning(
            'A non-standard Laravel hashing driver is configured.',
            'Confirm the driver is a deliberate, maintained password hasher with an appropriate adaptive work factor.',
            ['driver' => $driver !== '' ? $driver : null],
            Severity::Low,
        );
    }
}
