<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;
use Illuminate\Encryption\Encrypter;

final class AppKeyCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.app.key';
    }

    public function name(): string
    {
        return 'Application encryption key';
    }

    public function category(): string
    {
        return 'cryptography';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function run(CheckContext $context): CheckResult
    {
        $configured = (string) $context->config('app.key', '');
        $cipher = (string) $context->config('app.cipher', 'AES-256-CBC');

        if ($configured === '') {
            return $this->fail(
                'Laravel has no application encryption key.',
                'Generate APP_KEY with `php artisan key:generate`, then restart long-running workers.',
                ['cipher' => $cipher, 'key_configured' => false],
            );
        }

        $encoding = str_starts_with($configured, 'base64:') ? 'base64' : 'plain';
        $key = $encoding === 'base64'
            ? base64_decode(substr($configured, 7), true)
            : $configured;

        if (!is_string($key)) {
            return $this->fail(
                'APP_KEY uses invalid base64 encoding.',
                'Generate a valid key with `php artisan key:generate`; do not hand-edit the encoded value.',
                ['cipher' => $cipher, 'encoding' => $encoding, 'key_configured' => true],
            );
        }

        $evidence = [
            'cipher' => $cipher,
            'encoding' => $encoding,
            'key_length_bytes' => strlen($key),
            'key_configured' => true,
        ];

        if (!Encrypter::supported($key, $cipher)) {
            return $this->fail(
                'APP_KEY is not valid for the configured Laravel cipher.',
                'Generate a key of the correct length with `php artisan key:generate` and rotate encrypted data deliberately.',
                $evidence,
            );
        }

        return $this->pass('APP_KEY is valid for the configured cipher.', $evidence);
    }
}
