<?php

namespace CybearCare\LaravelSecurity\Posture;

final class PathInspector
{
    public static function resolve(string $path, string $basePath): ?string
    {
        $path = trim($path);
        if ($path === '' || str_contains($path, "\0")) {
            return null;
        }

        $candidate = self::isAbsolute($path)
            ? $path
            : rtrim($basePath, '/\\') . DIRECTORY_SEPARATOR . $path;
        $real = realpath($candidate);

        return self::normalize(is_string($real) ? $real : $candidate);
    }

    public static function isWithin(string $path, string $directory): bool
    {
        $path = self::normalize($path);
        $directory = rtrim(self::normalize($directory), '/');

        if (DIRECTORY_SEPARATOR === '\\') {
            $path = strtolower($path);
            $directory = strtolower($directory);
        }

        return $path === $directory || str_starts_with($path, $directory . '/');
    }

    public static function relativeTo(string $path, string $directory): string
    {
        $path = self::normalize($path);
        $directory = rtrim(self::normalize($directory), '/');

        if ($path === $directory) {
            return '.';
        }

        if (!self::isWithin($path, $directory)) {
            return basename($path);
        }

        return ltrim(substr($path, strlen($directory)), '/');
    }

    private static function isAbsolute(string $path): bool
    {
        return str_starts_with($path, '/')
            || str_starts_with($path, '\\\\')
            || preg_match('/^[a-z]:[\\\\\\/]/i', $path) === 1;
    }

    private static function normalize(string $path): string
    {
        $path = str_replace('\\', '/', $path);
        $prefix = '';

        if (preg_match('/^[a-z]:/i', $path, $matches) === 1) {
            $prefix = strtoupper($matches[0]);
            $path = substr($path, 2);
        } elseif (str_starts_with($path, '//')) {
            $prefix = '//';
            $path = substr($path, 2);
        } elseif (str_starts_with($path, '/')) {
            $prefix = '/';
            $path = ltrim($path, '/');
        }

        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }

            if ($segment === '..') {
                array_pop($segments);
                continue;
            }

            $segments[] = $segment;
        }

        $joined = implode('/', $segments);

        return match ($prefix) {
            '/' => '/' . $joined,
            '//' => '//' . $joined,
            '' => $joined,
            default => $prefix . '/' . $joined,
        };
    }
}
