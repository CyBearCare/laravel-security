<?php

namespace CybearCare\LaravelSecurity\Posture;

final class EvidenceSanitizer
{
    private const MAX_DEPTH = 6;
    private const MAX_ITEMS = 100;
    private const MAX_STRING_BYTES = 2000;

    private const SENSITIVE_KEY_PARTS = [
        'authorization',
        'cookie',
        'credential',
        'database_url',
        'password',
        'passphrase',
        'private_key',
        'secret',
        'token',
        'api_key',
        'app_key',
    ];

    /**
     * @param array<string|int, mixed> $evidence
     * @return array<string|int, mixed>
     */
    public static function sanitize(array $evidence): array
    {
        return self::sanitizeArray($evidence, 0);
    }

    /**
     * @param array<string|int, mixed> $values
     * @return array<string|int, mixed>
     */
    private static function sanitizeArray(array $values, int $depth): array
    {
        if ($depth >= self::MAX_DEPTH) {
            return ['_truncated' => 'maximum evidence depth reached'];
        }

        $sanitized = [];
        $count = 0;

        foreach ($values as $key => $value) {
            if (++$count > self::MAX_ITEMS) {
                $sanitized['_truncated'] = 'maximum evidence items reached';
                break;
            }

            if (is_string($key) && self::isSensitiveKey($key)) {
                $sanitized[$key] = '[REDACTED]';
                continue;
            }

            $sanitized[$key] = self::sanitizeValue($value, $depth + 1);
        }

        return $sanitized;
    }

    private static function sanitizeValue(mixed $value, int $depth): mixed
    {
        if (is_array($value)) {
            return self::sanitizeArray($value, $depth);
        }

        if (is_string($value)) {
            if (strlen($value) <= self::MAX_STRING_BYTES) {
                return $value;
            }

            return substr($value, 0, self::MAX_STRING_BYTES) . '…[TRUNCATED]';
        }

        if (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
            return $value;
        }

        return '[UNSUPPORTED_VALUE]';
    }

    private static function isSensitiveKey(string $key): bool
    {
        $normalized = strtolower(preg_replace('/[^a-z0-9]+/i', '_', $key) ?? $key);

        foreach (self::SENSITIVE_KEY_PARTS as $sensitive) {
            if ($normalized === $sensitive
                || str_starts_with($normalized, $sensitive . '_')
                || str_ends_with($normalized, '_' . $sensitive)
                || str_contains($normalized, '_' . $sensitive . '_')) {
                return true;
            }
        }

        return false;
    }
}
