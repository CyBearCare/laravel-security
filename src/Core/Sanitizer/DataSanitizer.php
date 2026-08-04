<?php

namespace CybearCare\LaravelSecurity\Core\Sanitizer;

class DataSanitizer
{
    private const MAX_DEPTH = 6;
    private const MAX_ITEMS = 100;
    private const MAX_STRING_BYTES = 2000;
    private const MAX_URL_BYTES = 4096;

    protected const SENSITIVE_HEADERS = [
        'authorization', 'cookie', 'proxy-authorization', 'set-cookie',
        'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-xsrf-token',
    ];

    protected const SENSITIVE_FIELDS = [
        'password', 'password_confirmation', 'token', 'secret', 'api_key',
        'credit_card', 'cvv', 'ssn', 'private_key', 'auth_token',
        'access_token', 'refresh_token', 'client_secret',
    ];

    protected const SENSITIVE_KEYS_BROAD = [
        'password', 'secret', 'key', 'token', 'auth', 'credential',
        'private', 'confidential', 'sensitive', 'api_key', 'database_url',
    ];

    public static function sanitizeHeaders(array $headers): array
    {
        $sanitized = [];
        $count = 0;

        foreach ($headers as $key => $value) {
            if (++$count > self::MAX_ITEMS) {
                $sanitized['_truncated'] = 'maximum header count reached';
                break;
            }

            $name = substr((string) $key, 0, 200);
            $sanitized[$name] = in_array(strtolower($name), self::SENSITIVE_HEADERS, true)
                ? '[REDACTED]'
                : self::boundedValue($value, 1);
        }

        return $sanitized;
    }

    public static function sanitizePayload(array $payload): array
    {
        $count = 0;

        return self::recursiveSanitize($payload, self::SENSITIVE_FIELDS, 0, $count);
    }

    public static function sanitizeCollectedData(array $data): array
    {
        return self::recursiveSanitizeBroad($data);
    }

    public static function sanitizeUrl(string $url, bool $includeQueryValues = false): string
    {
        $parts = parse_url(substr($url, 0, self::MAX_URL_BYTES));
        if ($parts === false) {
            return '[INVALID_URL]';
        }

        $sanitized = '';
        if (isset($parts['scheme'])) {
            $sanitized .= $parts['scheme'] . '://';
        }
        $sanitized .= $parts['host'] ?? '';
        if (isset($parts['port'])) {
            $sanitized .= ':' . $parts['port'];
        }
        $sanitized .= $parts['path'] ?? '/';

        if (isset($parts['query']) && $parts['query'] !== '') {
            parse_str($parts['query'], $query);
            if ($includeQueryValues) {
                $count = 0;
                $query = self::recursiveSanitize($query, self::SENSITIVE_FIELDS, 0, $count);
            } else {
                $query = array_map(fn () => '[REDACTED]', array_slice($query, 0, self::MAX_ITEMS, true));
            }
            $sanitized .= '?' . http_build_query($query);
        }

        return substr($sanitized, 0, self::MAX_URL_BYTES);
    }

    public static function hashSessionId(?string $sessionId, ?string $appKey = null): ?string
    {
        if (!$sessionId) {
            return null;
        }

        $salt = $appKey ?: 'cybear-unconfigured-app-key';

        return substr(hash_hmac('sha256', $sessionId, $salt), 0, 32);
    }

    public static function sanitizeText(?string $value, int $maximumBytes = self::MAX_STRING_BYTES): ?string
    {
        if ($value === null) {
            return null;
        }

        $maximumBytes = max(1, min(16384, $maximumBytes));

        return substr(str_replace("\0", '', $value), 0, $maximumBytes);
    }

    public static function sanitizeSensitiveData(array &$data): void
    {
        $sensitiveKeys = ['password', 'token', 'secret', 'api_key', 'private_key', 'credit_card'];

        foreach ($data as $key => &$value) {
            if (is_array($value)) {
                self::sanitizeSensitiveData($value);
            } elseif (is_string($key)) {
                foreach ($sensitiveKeys as $sensitive) {
                    if (stripos($key, $sensitive) !== false) {
                        $data[$key] = '[REDACTED]';
                    }
                }
            }
        }
    }

    protected static function recursiveSanitize(
        array $data,
        array $sensitiveFields,
        int $depth,
        int &$count,
    ): array
    {
        if ($depth >= self::MAX_DEPTH) {
            return ['_truncated' => 'maximum payload depth reached'];
        }

        $sanitized = [];
        foreach ($data as $key => $value) {
            if (++$count > self::MAX_ITEMS) {
                $sanitized['_truncated'] = 'maximum payload items reached';
                break;
            }

            $normalizedKey = is_string($key) ? substr($key, 0, 200) : $key;
            $sensitive = false;
            if (is_string($normalizedKey)) {
                foreach ($sensitiveFields as $sensitiveField) {
                    if (stripos($normalizedKey, $sensitiveField) !== false) {
                        $sensitive = true;
                        break;
                    }
                }
            }

            if ($sensitive) {
                $sanitized[$normalizedKey] = '[REDACTED]';
            } elseif (is_array($value)) {
                $sanitized[$normalizedKey] = self::recursiveSanitize(
                    $value,
                    $sensitiveFields,
                    $depth + 1,
                    $count,
                );
            } else {
                $sanitized[$normalizedKey] = self::boundedValue($value, $depth + 1);
            }
        }

        return $sanitized;
    }

    protected static function recursiveSanitizeBroad(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = self::recursiveSanitizeBroad($value);
            } elseif (is_string($value) && self::isSensitiveKey((string) $key)) {
                $data[$key] = self::maskValue($value);
            }
        }

        return $data;
    }

    protected static function isSensitiveKey(string $key): bool
    {
        $key = strtolower($key);

        foreach (self::SENSITIVE_KEYS_BROAD as $sensitiveKey) {
            if (str_contains($key, $sensitiveKey)) {
                return true;
            }
        }

        return false;
    }

    protected static function maskValue(string $value): string
    {
        return '[REDACTED]';
    }

    private static function boundedValue(mixed $value, int $depth): mixed
    {
        if (is_array($value)) {
            $count = 0;

            return self::recursiveSanitize($value, self::SENSITIVE_FIELDS, $depth, $count);
        }

        if (is_string($value)) {
            return strlen($value) > self::MAX_STRING_BYTES
                ? substr($value, 0, self::MAX_STRING_BYTES) . '…[TRUNCATED]'
                : $value;
        }

        if (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
            return $value;
        }

        return '[UNSUPPORTED_VALUE]';
    }
}
