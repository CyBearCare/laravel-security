<?php

namespace CybearCare\LaravelSecurity;

use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;
use CybearCare\LaravelSecurity\Middleware\WafMiddleware;
use CybearCare\LaravelSecurity\Middleware\AuditLogMiddleware;
use CybearCare\LaravelSecurity\Middleware\RateLimitMiddleware;
use CybearCare\LaravelSecurity\Services\WafEngine;
use CybearCare\LaravelSecurity\Services\AuditLogger;
use CybearCare\LaravelSecurity\Services\CybearApiClient;
use CybearCare\LaravelSecurity\Services\DataCollectionManager;
use CybearCare\LaravelSecurity\Services\DomainVerificationService;
use CybearCare\LaravelSecurity\Console\Commands\SetupCommand;
use CybearCare\LaravelSecurity\Console\Commands\SyncRulesCommand;
use CybearCare\LaravelSecurity\Console\Commands\SecurityScanCommand;
use CybearCare\LaravelSecurity\Console\Commands\CollectDataCommand;
use CybearCare\LaravelSecurity\Console\Commands\SendDataCommand;
use CybearCare\LaravelSecurity\Console\Commands\StatusCommand;
use CybearCare\LaravelSecurity\Console\Commands\VerifyDomainCommand;

class CybearSecurityServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__ . '/Config/cybear.php',
            'cybear'
        );

        $this->app->singleton(CybearApiClient::class, function ($app) {
            return new CybearApiClient(
                config('cybear.api.endpoint', 'https://api.cybear.care'),
                config('cybear.api.key'),
                config('cybear.api.timeout', 30)
            );
        });

        $this->app->singleton(WafEngine::class, function ($app) {
            return new WafEngine(
                $app->make(CybearApiClient::class),
                config('cybear.waf.enabled', true),
                config('cybear.waf.mode', 'monitor')
            );
        });

        $this->app->singleton(AuditLogger::class);
        $this->app->singleton(DataCollectionManager::class);
        $this->app->singleton(DomainVerificationService::class);
    }

    public function boot()
    {
        $this->publishes([
            __DIR__ . '/Config/cybear.php' => config_path('cybear.php'),
        ], 'cybear-config');

        $this->loadMigrationsFrom(__DIR__ . '/Database/Migrations');

        $this->loadViewsFrom(__DIR__ . '/Resources/views', 'cybear');

        $this->publishes([
            __DIR__ . '/Resources/views' => resource_path('views/vendor/cybear'),
        ], 'cybear-views');

        $this->registerMiddleware();
        $this->registerCommands();
        $this->scheduleAutomaticTasks();
    }

    protected function registerMiddleware()
    {
        $router = $this->app->make(Router::class);
        
        $router->aliasMiddleware('cybear.waf', WafMiddleware::class);
        $router->aliasMiddleware('cybear.audit', AuditLogMiddleware::class);
        $router->aliasMiddleware('cybear.ratelimit', RateLimitMiddleware::class);

        if (config('cybear.waf.enabled', true)) {
            $router->pushMiddlewareToGroup('web', WafMiddleware::class);
            $router->pushMiddlewareToGroup('api', WafMiddleware::class);
        }

        if (config('cybear.audit.enabled', true)) {
            $router->pushMiddlewareToGroup('web', AuditLogMiddleware::class);
            $router->pushMiddlewareToGroup('api', AuditLogMiddleware::class);
        }
    }

    protected function registerCommands()
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                SetupCommand::class,
                SyncRulesCommand::class,
                CollectDataCommand::class,
                SendDataCommand::class,
                StatusCommand::class,
                VerifyDomainCommand::class,
            ]);
        }
    }

    protected function scheduleAutomaticTasks()
    {
        $schedule = $this->app->make(\Illuminate\Console\Scheduling\Schedule::class);
        
        // Schedule data collection
        if (config('cybear.collectors.auto_schedule', true)) {
            $collectionInterval = config('cybear.collectors.collection_interval', 'hourly');
            
            $schedule->command('cybear:collect')
                ->$collectionInterval()
                ->withoutOverlapping()
                ->runInBackground();
        }
        
        // Schedule data transmission
        if (config('cybear.collectors.auto_send', true)) {
            $sendInterval = config('cybear.collectors.send_interval', 'everyFifteenMinutes');
            
            $schedule->command('cybear:send')
                ->$sendInterval()
                ->withoutOverlapping()
                ->runInBackground();
        }
        
        // Schedule data cleanup (only cleanup, no sending)
        if (config('cybear.collectors.auto_cleanup', true)) {
            $cleanupInterval = config('cybear.collectors.cleanup_interval', 'weekly');
            
            $schedule->command('cybear:send --cleanup-only')
                ->$cleanupInterval()
                ->withoutOverlapping()
                ->runInBackground();
        }
        
        // Schedule WAF rule syncing
        if (config('cybear.waf.auto_sync', true)) {
            $syncInterval = config('cybear.waf.sync_interval', 'daily');
            
            $schedule->command('cybear:sync')
                ->$syncInterval()
                ->withoutOverlapping()
                ->runInBackground();
        }
    }
}