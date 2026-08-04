<?php

namespace CybearCare\LaravelSecurity\Posture;

use CybearCare\LaravelSecurity\Posture\Capabilities\CapabilitySet;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;

final readonly class CheckContext
{
    public function __construct(
        public Application $application,
        public Repository $config,
        public Router $router,
        public CapabilitySet $capabilities,
    ) {
    }

    public function environment(): string
    {
        return $this->application->environment();
    }

    public function isProduction(): bool
    {
        return $this->application->environment('production');
    }

    public function config(string $key, mixed $default = null): mixed
    {
        return $this->config->get($key, $default);
    }

    public function hasConfig(string $key): bool
    {
        return $this->config->has($key);
    }

    public function basePath(string $path = ''): string
    {
        return $this->application->basePath($path);
    }

    public function publicPath(string $path = ''): string
    {
        return $this->application->publicPath($path);
    }

    /**
     * @return array<int, Route>
     */
    public function routes(): array
    {
        return array_values(iterator_to_array($this->router->getRoutes()));
    }

    public function hasWebRoutes(): bool
    {
        foreach ($this->routes() as $route) {
            if (in_array('web', array_filter($route->gatherMiddleware(), 'is_string'), true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    public function globalMiddleware(): array
    {
        try {
            $kernel = $this->application->make(\Illuminate\Contracts\Http\Kernel::class);

            if (!method_exists($kernel, 'getMiddleware')) {
                return [];
            }

            return array_values(array_filter($kernel->getMiddleware(), 'is_string'));
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * @return list<string>
     */
    public function resolvedMiddleware(Route $route): array
    {
        return array_values(array_filter(
            $this->router->gatherRouteMiddleware($route),
            'is_string',
        ));
    }
}
