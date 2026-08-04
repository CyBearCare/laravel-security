<?php

namespace CybearCare\LaravelSecurity\Posture\Capabilities;

use Composer\InstalledVersions;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Throwable;

final readonly class CapabilityDetector
{
    private const PACKAGES = [
        'sanctum' => ['laravel/sanctum'],
        'passport' => ['laravel/passport'],
        'fortify' => ['laravel/fortify'],
        'jetstream' => ['laravel/jetstream'],
        'socialite' => ['laravel/socialite'],
        'horizon' => ['laravel/horizon'],
        'telescope' => ['laravel/telescope'],
        'octane' => ['laravel/octane'],
        'pulse' => ['laravel/pulse'],
        'reverb' => ['laravel/reverb'],
        'cashier_stripe' => ['laravel/cashier'],
        'livewire' => ['livewire/livewire'],
        'inertia' => ['inertiajs/inertia-laravel'],
        'debugbar' => ['fruitcake/laravel-debugbar', 'barryvdh/laravel-debugbar'],
        'spatie_permission' => ['spatie/laravel-permission'],
    ];

    private const ROUTE_SURFACES = [
        'sanctum' => [
            'names' => ['sanctum.'],
            'uris' => ['sanctum/'],
            'actions' => ['Laravel\\Sanctum\\'],
        ],
        'fortify' => [
            'names' => ['two-factor.', 'passkey.', 'password.', 'verification.'],
            'uris' => [],
            'actions' => ['Laravel\\Fortify\\', 'Laravel\\Passkeys\\'],
        ],
        'passport' => [
            'names' => ['passport.'],
            'uris' => ['oauth'],
            'actions' => ['Laravel\\Passport\\'],
        ],
        'horizon' => [
            'names' => ['horizon.'],
            'uris' => ['horizon'],
            'actions' => ['Laravel\\Horizon\\'],
        ],
        'telescope' => [
            'names' => ['telescope.'],
            'uris' => ['telescope'],
            'actions' => ['Laravel\\Telescope\\'],
        ],
        'pulse' => [
            'names' => ['pulse.'],
            'uris' => ['pulse'],
            'actions' => ['Laravel\\Pulse\\'],
        ],
        'debugbar' => [
            'names' => ['debugbar.'],
            'uris' => ['_debugbar'],
            'actions' => ['Fruitcake\\LaravelDebugbar\\', 'Barryvdh\\Debugbar\\'],
        ],
    ];

    public function __construct(
        private Application $application,
        private Repository $config,
        private Router $router,
    ) {
    }

    public function detect(): CapabilitySet
    {
        $packages = $this->detectPackages();
        $routes = array_values(iterator_to_array($this->router->getRoutes()));

        return new CapabilitySet(
            packages: $packages,
            routeSurfaces: $this->detectRouteSurfaces($routes, $packages),
            runtime: $this->detectRuntime($routes),
        );
    }

    /**
     * @return array<string, array{package: string, version: string|null}>
     */
    private function detectPackages(): array
    {
        $detected = [];

        foreach (self::PACKAGES as $capability => $candidates) {
            foreach ($candidates as $package) {
                try {
                    if (!class_exists(InstalledVersions::class) || !InstalledVersions::isInstalled($package)) {
                        continue;
                    }

                    $version = InstalledVersions::getPrettyVersion($package);
                    $detected[$capability] = [
                        'package' => $package,
                        'version' => is_string($version) ? substr($version, 0, 100) : null,
                    ];
                    break;
                } catch (Throwable) {

                }
            }
        }

        ksort($detected);

        return $detected;
    }

    /**
     * @param list<Route> $routes
     * @param array<string, array{package: string, version: string|null}> $packages
     * @return array<string, array{present: bool, route_count: int}>
     */
    private function detectRouteSurfaces(array $routes, array $packages): array
    {
        $surfaces = [];

        foreach (self::ROUTE_SURFACES as $capability => $patterns) {
            if (!isset($packages[$capability])) {
                continue;
            }

            $count = 0;
            foreach ($routes as $route) {
                if ($this->routeMatches(
                    $route,
                    $patterns['names'],
                    $patterns['uris'],
                    $patterns['actions'],
                )) {
                    $count++;
                }
            }

            $surfaces[$capability] = [
                'present' => $count > 0,
                'route_count' => $count,
            ];
        }

        if (isset($packages['sanctum'])) {
            $count = 0;

            foreach ($routes as $route) {
                foreach (array_filter($route->gatherMiddleware(), 'is_string') as $middleware) {
                    if ($middleware === 'auth:sanctum'
                        || str_starts_with($middleware, 'auth:sanctum,')) {
                        $count++;
                        break;
                    }
                }
            }

            $surfaces['sanctum_protected'] = [
                'present' => $count > 0,
                'route_count' => $count,
            ];
        }

        ksort($surfaces);

        return $surfaces;
    }

    /**
     * @param list<Route> $routes
     * @return array<string, scalar|null>
     */
    private function detectRuntime(array $routes): array
    {
        $counts = [
            'route_count' => count($routes),
            'web_route_count' => 0,
            'api_route_count' => 0,
            'state_changing_route_count' => 0,
            'authenticated_route_count' => 0,
        ];

        foreach ($routes as $route) {
            $middleware = array_values(array_filter($route->gatherMiddleware(), 'is_string'));

            if (in_array('web', $middleware, true)) {
                $counts['web_route_count']++;
            }

            if (in_array('api', $middleware, true)) {
                $counts['api_route_count']++;
            }

            if (array_intersect(['POST', 'PUT', 'PATCH', 'DELETE'], $route->methods()) !== []) {
                $counts['state_changing_route_count']++;
            }

            if ($this->containsMiddleware($middleware, 'auth', 'Authenticate')) {
                $counts['authenticated_route_count']++;
            }
        }

        $queueConnection = $this->stringConfig('queue.default');
        $cacheStore = $this->stringConfig('cache.default');
        $databaseConnection = $this->stringConfig('database.default');

        return array_merge($counts, [
            'configuration_cached' => $this->application->configurationIsCached(),
            'routes_cached' => $this->application->routesAreCached(),
            'queue_driver' => $this->driver('queue.connections', $queueConnection),
            'cache_driver' => $this->driver('cache.stores', $cacheStore),
            'session_driver' => $this->stringConfig('session.driver'),
            'database_driver' => $this->driver('database.connections', $databaseConnection),
        ]);
    }

    /**
     * @param list<string> $namePrefixes
     * @param list<string> $uriPrefixes
     * @param list<string> $actionPrefixes
     */
    private function routeMatches(
        Route $route,
        array $namePrefixes,
        array $uriPrefixes,
        array $actionPrefixes,
    ): bool {
        $name = strtolower((string) ($route->getName() ?? ''));
        $uri = strtolower(trim($route->uri(), '/'));
        $action = strtolower($route->getActionName());

        foreach ($namePrefixes as $prefix) {
            if (str_starts_with($name, strtolower($prefix))) {
                return true;
            }
        }

        foreach ($uriPrefixes as $prefix) {
            $prefix = strtolower(trim($prefix, '/'));
            if ($uri === $prefix || str_starts_with($uri, $prefix . '/')) {
                return true;
            }
        }

        foreach ($actionPrefixes as $prefix) {
            if (str_starts_with($action, strtolower($prefix))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string> $middleware
     */
    private function containsMiddleware(array $middleware, string $alias, string $classSuffix): bool
    {
        foreach ($middleware as $item) {
            $name = explode(':', $item, 2)[0];
            if ($name === $alias || str_ends_with($name, '\\' . $classSuffix)) {
                return true;
            }
        }

        return false;
    }

    private function driver(string $prefix, ?string $connection): ?string
    {
        if ($connection === null) {
            return null;
        }

        return $this->stringConfig("{$prefix}.{$connection}.driver");
    }

    private function stringConfig(string $key): ?string
    {
        $value = $this->config->get($key);

        return is_string($value) && $value !== '' ? substr($value, 0, 100) : null;
    }
}
