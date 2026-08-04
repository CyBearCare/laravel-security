<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Support\Facades\Route;
use Illuminate\Routing\Route as LaravelRoute;

class ApplicationStructureCollector extends BaseDataCollector
{
    public function getCollectorName(): string
    {
        return 'application_structure_collector';
    }

    protected function getConfigKey(): string
    {
        return 'application';
    }

    protected function collectData(): array
    {
        $routes = $this->collectRoutes();

        return [
            'schema_version' => 2,
            'application_fingerprint' => $this->applicationFingerprint($routes),
            'deployment_id' => config('cybear.deployment_id'),
            'routes' => $routes,
            'middleware' => $this->collectMiddleware(),
            'providers' => $this->collectServiceProviders(),
            'config' => $this->collectAppConfig(),
        ];
    }

    protected function collectRoutes(): array
    {
        $routes = [];
        
        foreach (Route::getRoutes() as $route) {
            $declaredMiddleware = array_values(array_map('strval', $route->gatherMiddleware()));
            $resolvedMiddleware = $this->resolveMiddleware($route);
            $methods = array_values(array_diff($route->methods(), ['HEAD']));
            sort($methods);

            $identity = [
                'domain' => $route->getDomain(),
                'uri' => $route->uri(),
                'methods' => $methods,
                'name' => $route->getName(),
                'action' => $route->getActionName(),
                'middleware' => $declaredMiddleware,
            ];

            $routes[] = [
                'fingerprint' => hash('sha256', json_encode($identity, JSON_UNESCAPED_SLASHES)),
                'domain' => $route->getDomain(),
                'uri' => $route->uri(),
                'methods' => $methods,
                'name' => $route->getName(),
                'action' => $route->getActionName(),
                'middleware' => $declaredMiddleware,
                'resolved_middleware' => $resolvedMiddleware,
                'authentication' => $this->authenticationStatus($declaredMiddleware, $resolvedMiddleware),
                'csrf' => $this->csrfStatus($methods, $declaredMiddleware, $resolvedMiddleware),
            ];
        }

        usort($routes, fn (array $left, array $right) => $left['fingerprint'] <=> $right['fingerprint']);

        return $routes;
    }

    protected function resolveMiddleware(LaravelRoute $route): array
    {
        try {
            return array_values(array_map(
                'strval',
                app('router')->gatherRouteMiddleware($route),
            ));
        } catch (\Throwable) {
            return [];
        }
    }

    protected function authenticationStatus(array $declared, array $resolved): array
    {
        $middleware = array_merge($declared, $resolved);
        $matches = array_values(array_filter($middleware, function (string $name): bool {
            $normalized = ltrim(strtolower($name), '\\');

            return $normalized === 'auth'
                || str_starts_with($normalized, 'auth:')
                || str_contains($normalized, 'middleware\\authenticate');
        }));

        return [
            'required' => $matches !== [],
            'middleware' => array_values(array_unique($matches)),
        ];
    }

    protected function csrfStatus(array $methods, array $declared, array $resolved): array
    {
        $unsafe = array_intersect($methods, ['POST', 'PUT', 'PATCH', 'DELETE']) !== [];
        if (!$unsafe) {
            return ['status' => 'not_applicable', 'reason' => 'safe_http_method'];
        }

        $middleware = array_merge($declared, $resolved);
        $matches = array_values(array_filter($middleware, function (string $name): bool {
            $normalized = strtolower($name);

            return $normalized === 'web'
                || str_contains($normalized, 'validatecsrftoken')
                || str_contains($normalized, 'verifycsrftoken');
        }));

        return [
            'status' => $matches === [] ? 'not_detected' : 'likely_protected',
            'middleware' => array_values(array_unique($matches)),
            'reason' => $matches === []
                ? 'no_csrf_middleware_resolved'
                : 'route_exclusions_cannot_be_proven_statically',
        ];
    }

    protected function applicationFingerprint(array $routes): string
    {
        $composerLock = base_path('composer.lock');
        $lockHash = is_file($composerLock) ? hash_file('sha256', $composerLock) : null;

        return hash('sha256', json_encode([
            'laravel' => app()->version(),
            'php' => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION,
            'composer_lock' => $lockHash,
            'routes' => array_column($routes, 'fingerprint'),
        ], JSON_UNESCAPED_SLASHES));
    }

    protected function collectMiddleware(): array
    {
        $router = app('router');
        
        $middleware = [
            'global' => $router->getMiddleware(),
            'groups' => $router->getMiddlewareGroups(),
        ];
        
        if (method_exists($router, 'getMiddlewareAliases')) {
            $middleware['route_middleware'] = $router->getMiddlewareAliases();
        } else {
            $middleware['route_middleware'] = [];
        }
        
        return $middleware;
    }

    protected function collectServiceProviders(): array
    {
        $app = app();
        $providers = [];
        
        foreach ($app->getLoadedProviders() as $provider => $loaded) {
            $providers[] = [
                'class' => $provider,
                'loaded' => $loaded,
            ];
        }

        return $providers;
    }

    protected function collectAppConfig(): array
    {
        return [
            'name' => config('app.name'),
            'env' => config('app.env'),
            'debug' => config('app.debug'),
            'timezone' => config('app.timezone'),
            'locale' => config('app.locale'),
            'fallback_locale' => config('app.fallback_locale'),
            'laravel_version' => app()->version(),
        ];
    }
}
