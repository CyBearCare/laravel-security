<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class PasswordResetConfigurationCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.auth.password_resets';
    }

    public function name(): string
    {
        return 'Password reset token policy';
    }

    public function category(): string
    {
        return 'authentication';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(CheckContext $context): CheckResult
    {
        $brokers = $context->config('auth.passwords', []);
        if (!is_array($brokers) || $brokers === []) {
            return $this->skipped('No Laravel password reset brokers are configured.');
        }

        $unsafe = [];
        $weak = [];
        $reviewed = [];

        foreach ($brokers as $name => $broker) {
            if (!is_array($broker)) {
                continue;
            }

            $expire = (int) ($broker['expire'] ?? 60);
            $throttle = (int) ($broker['throttle'] ?? 0);
            $reviewed[] = ['broker' => (string) $name, 'expire_minutes' => $expire, 'throttle_seconds' => $throttle];

            if ($throttle <= 0) {
                $unsafe[] = (string) $name;
            }

            if ($expire <= 0 || $expire > 120) {
                $weak[] = (string) $name;
            }
        }

        if ($unsafe !== []) {
            return $this->fail(
                'One or more password reset brokers have no request throttle.',
                'Set a positive throttle value for every password reset broker to limit token-request abuse.',
                ['brokers' => $reviewed, 'without_throttle' => $unsafe],
            );
        }

        if ($weak !== []) {
            return $this->warning(
                'One or more password reset tokens have an unusually long or invalid lifetime.',
                'Use a short, positive token expiry appropriate to the application; Laravel’s default is 60 minutes.',
                ['brokers' => $reviewed, 'weak_expiry' => $weak],
                Severity::Medium,
            );
        }

        return $this->pass('Password reset brokers use bounded expiry and request throttling.', [
            'brokers' => $reviewed,
        ]);
    }
}
