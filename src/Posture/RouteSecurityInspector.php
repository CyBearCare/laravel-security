<?php

namespace CybearCare\LaravelSecurity\Posture;

use Illuminate\Routing\Route;
use Throwable;

final class RouteSecurityInspector
{
    /**
     * @return array{middleware: list<string>, resolution_failed: bool}
     */
    public function middleware(CheckContext $context, Route $route): array
    {
        $raw = array_values(array_filter($route->gatherMiddleware(), 'is_string'));
        $resolutionFailed = false;

        try {
            $resolved = $context->resolvedMiddleware($route);
        } catch (Throwable) {
            $resolved = [];
            $resolutionFailed = true;
        }

        return [
            'middleware' => array_values(array_unique([
                ...$context->globalMiddleware(),
                ...$raw,
                ...$resolved,
            ])),
            'resolution_failed' => $resolutionFailed,
        ];
    }

    /**
     * @param list<string> $middleware
     */
    public function hasAuthentication(array $middleware): bool
    {
        return $this->contains(
            $middleware,
            ['auth', 'auth.basic'],
            ['Authenticate', 'AuthenticateSession'],
        );
    }

    /**
     * @param list<string> $middleware
     */
    public function hasAuthorization(array $middleware): bool
    {
        return $this->contains($middleware, ['can'], ['Authorize']);
    }

    /**
     * @param list<string> $middleware
     */
    public function hasRateLimit(array $middleware): bool
    {
        return $this->contains(
            $middleware,
            ['throttle'],
            ['ThrottleRequests', 'ThrottleRequestsWithRedis', 'RateLimitMiddleware'],
        );
    }

    /**
     * @param list<string> $middleware
     */
    public function hasPasswordConfirmation(array $middleware): bool
    {
        return $this->contains($middleware, ['password.confirm'], ['RequirePassword']);
    }

    /**
     * @param list<string> $middleware
     */
    public function hasSignedUrlValidation(array $middleware): bool
    {
        return $this->contains($middleware, ['signed'], ['ValidateSignature']);
    }

    /**
     * @param list<string> $middleware
     * @param list<string> $classSuffixes
     */
    public function hasPackageBoundary(
        array $middleware,
        string $namespacePrefix,
        array $classSuffixes,
    ): bool {
        $namespacePrefix = strtolower(trim($namespacePrefix, '\\') . '\\');

        foreach ($middleware as $item) {
            $name = strtolower($this->baseName($item));
            if (!str_starts_with($name, $namespacePrefix)) {
                continue;
            }

            foreach ($classSuffixes as $suffix) {
                if (str_ends_with($name, '\\' . strtolower($suffix))) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return array{methods: list<string>, uri: string, name: string|null}
     */
    public function evidence(Route $route): array
    {
        return [
            'methods' => array_values(array_filter(
                $route->methods(),
                static fn (string $method): bool => $method !== 'HEAD',
            )),
            'uri' => substr($route->uri(), 0, 500),
            'name' => $route->getName() !== null
                ? substr((string) $route->getName(), 0, 200)
                : null,
        ];
    }

    /**
     * @param list<string> $aliases
     * @param list<string> $classSuffixes
     * @param list<string> $middleware
     */
    private function contains(array $middleware, array $aliases, array $classSuffixes): bool
    {
        foreach ($middleware as $item) {
            $name = $this->baseName($item);
            $normalized = strtolower($name);

            if (in_array($normalized, $aliases, true)) {
                return true;
            }

            foreach ($classSuffixes as $suffix) {
                $normalizedSuffix = strtolower($suffix);
                if ($normalized === $normalizedSuffix
                    || str_ends_with($normalized, '\\' . $normalizedSuffix)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function baseName(string $middleware): string
    {
        return trim(explode(':', $middleware, 2)[0]);
    }
}
