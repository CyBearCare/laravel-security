<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Support\Facades\Route;

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
        return [
            'routes' => $this->collectRoutes(),
            'middleware' => $this->collectMiddleware(),
            'providers' => $this->collectServiceProviders(),
            'config' => $this->collectAppConfig(),
        ];
    }

    protected function collectRoutes(): array
    {
        $routes = [];
        
        foreach (Route::getRoutes() as $route) {
            $routes[] = [
                'uri' => $route->uri(),
                'methods' => $route->methods(),
                'name' => $route->getName(),
                'action' => $route->getActionName(),
                'middleware' => $route->middleware(),
                'has_auth' => in_array('auth', $route->middleware()),
                'has_csrf' => in_array('web', $route->middleware()),
            ];
        }

        return $routes;
    }

    protected function collectMiddleware(): array
    {
        $router = app('router');
        
        $middleware = [
            'global' => $router->getMiddleware(),
            'groups' => $router->getMiddlewareGroups(),
        ];
        
        // Handle different Laravel versions for route middleware aliases
        if (method_exists($router, 'getMiddlewareAliases')) {
            // Laravel 10+
            $middleware['route_middleware'] = $router->getMiddlewareAliases();
        } elseif (method_exists($router, 'getRouteMiddleware')) {
            // Laravel 9 and earlier
            $middleware['route_middleware'] = $router->getRouteMiddleware();
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