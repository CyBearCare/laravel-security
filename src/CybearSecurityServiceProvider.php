<?php

namespace CybearCare\LaravelSecurity;

use CybearCare\LaravelSecurity\Adapter\LaravelCacheAdapter;
use CybearCare\LaravelSecurity\Adapter\LaravelRequestAdapter;
use CybearCare\LaravelSecurity\Console\Commands\CollectDataCommand;
// Middleware
use CybearCare\LaravelSecurity\Console\Commands\ExportSchemaCommand;
use CybearCare\LaravelSecurity\Console\Commands\ScanCommand;
use CybearCare\LaravelSecurity\Console\Commands\SendDataCommand;
use CybearCare\LaravelSecurity\Console\Commands\SetupCommand;
use CybearCare\LaravelSecurity\Console\Commands\StatusCommand;
use CybearCare\LaravelSecurity\Console\Commands\SyncRulesCommand;
use CybearCare\LaravelSecurity\Console\Commands\VerifyDomainCommand;
use CybearCare\LaravelSecurity\Core\Api\CybearApiClient;
// Core classes
use CybearCare\LaravelSecurity\Core\Audit\AuditLogger;
use CybearCare\LaravelSecurity\Core\Collection\Collector\EnvironmentCollector;
use CybearCare\LaravelSecurity\Core\Collection\Collector\PackageCollector;
use CybearCare\LaravelSecurity\Core\Collection\DataCollectionManager as CoreDataCollectionManager;
use CybearCare\LaravelSecurity\Core\Config\CybearConfig;
use CybearCare\LaravelSecurity\Core\Contract\AuditLogRepositoryInterface;
use CybearCare\LaravelSecurity\Core\Contract\BlockedRequestRepositoryInterface;
use CybearCare\LaravelSecurity\Core\Contract\CacheInterface;
use CybearCare\LaravelSecurity\Core\Contract\CollectedDataRepositoryInterface;
use CybearCare\LaravelSecurity\Core\Contract\PackageDataRepositoryInterface;
// Core contracts
use CybearCare\LaravelSecurity\Core\Contract\WafRuleRepositoryInterface;
use CybearCare\LaravelSecurity\Core\Dast\DastCorrelationVerifier;
use CybearCare\LaravelSecurity\Core\Headers\SecurityHeadersManager;
use CybearCare\LaravelSecurity\Core\Protection\SensitiveFileGuard;
use CybearCare\LaravelSecurity\Core\Waf\WafEngine;
use CybearCare\LaravelSecurity\Middleware\AuditLogMiddleware;
// Laravel adapters
use CybearCare\LaravelSecurity\Middleware\DastCorrelationMiddleware;
// Eloquent repositories
use CybearCare\LaravelSecurity\Middleware\RateLimitMiddleware;
use CybearCare\LaravelSecurity\Middleware\SecurityHeadersMiddleware;
use CybearCare\LaravelSecurity\Middleware\SensitiveFileMiddleware;
use CybearCare\LaravelSecurity\Middleware\SyncMiddleware;
use CybearCare\LaravelSecurity\Middleware\WafMiddleware;
// Core collectors
use CybearCare\LaravelSecurity\Posture\Capabilities\CapabilityDetector;
use CybearCare\LaravelSecurity\Posture\Capabilities\CapabilitySet;
// Laravel-specific collectors
use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckRegistry;
use CybearCare\LaravelSecurity\Posture\Checks\AdministrativeSurfaceAuthorizationCheck;
use CybearCare\LaravelSecurity\Posture\Checks\AppDebugCheck;
use CybearCare\LaravelSecurity\Posture\Checks\AppKeyCheck;
use CybearCare\LaravelSecurity\Posture\Checks\AppUrlHttpsCheck;
use CybearCare\LaravelSecurity\Posture\Checks\CacheDriverCheck;
// Laravel-specific services (stay in this package)
use CybearCare\LaravelSecurity\Posture\Checks\CacheNamespaceCheck;
use CybearCare\LaravelSecurity\Posture\Checks\ComposerLockCheck;
// Console commands
use CybearCare\LaravelSecurity\Posture\Checks\ConfigurationCacheCheck;
use CybearCare\LaravelSecurity\Posture\Checks\CorsConfigurationCheck;
use CybearCare\LaravelSecurity\Posture\Checks\DebugbarProductionCheck;
use CybearCare\LaravelSecurity\Posture\Checks\EnvironmentFilePermissionsCheck;
use CybearCare\LaravelSecurity\Posture\Checks\FailedJobStorageCheck;
use CybearCare\LaravelSecurity\Posture\Checks\FortifyAuthenticationThrottlingCheck;
use CybearCare\LaravelSecurity\Posture\Checks\FortifyTwoFactorHardeningCheck;
use CybearCare\LaravelSecurity\Posture\Checks\HashingCostCheck;
use CybearCare\LaravelSecurity\Posture\Checks\MassAssignmentInputCheck;
use CybearCare\LaravelSecurity\Posture\Checks\OctaneRuntimeSafetyCheck;
use CybearCare\LaravelSecurity\Posture\Checks\PassportOAuthHardeningCheck;
use CybearCare\LaravelSecurity\Posture\Checks\PassportTokenLifetimeCheck;
use CybearCare\LaravelSecurity\Posture\Checks\PasswordConfirmationTimeoutCheck;
use CybearCare\LaravelSecurity\Posture\Checks\PasswordResetConfigurationCheck;
use CybearCare\LaravelSecurity\Posture\Checks\PublicDatabaseFileCheck;
use CybearCare\LaravelSecurity\Posture\Checks\PublicFilesystemRootCheck;
use CybearCare\LaravelSecurity\Posture\Checks\PublicSensitiveFilesCheck;
use CybearCare\LaravelSecurity\Posture\Checks\QueueDriverCheck;
use CybearCare\LaravelSecurity\Posture\Checks\SanctumTokenExpirationCheck;
use CybearCare\LaravelSecurity\Posture\Checks\SensitiveRouteAuthorizationCheck;
use CybearCare\LaravelSecurity\Posture\Checks\SessionCookieHttpOnlyCheck;
use CybearCare\LaravelSecurity\Posture\Checks\SessionCookieSecureCheck;
use CybearCare\LaravelSecurity\Posture\Checks\SessionDriverCheck;
use CybearCare\LaravelSecurity\Posture\Checks\SessionPartitionedCookieCheck;
use CybearCare\LaravelSecurity\Posture\Checks\SessionSameSiteCheck;
use CybearCare\LaravelSecurity\Posture\Checks\SignedLinkIntegrityCheck;
use CybearCare\LaravelSecurity\Posture\Checks\TelescopeProductionCheck;
use CybearCare\LaravelSecurity\Posture\Checks\UnsafeWebRoutesCsrfCheck;
use CybearCare\LaravelSecurity\Posture\Checks\UploadValidationCheck;
use CybearCare\LaravelSecurity\Posture\Checks\WebCookieEncryptionCheck;
use CybearCare\LaravelSecurity\Posture\PhpSourceInspector;
use CybearCare\LaravelSecurity\Posture\PostureRunner;
use CybearCare\LaravelSecurity\Posture\RouteSecurityInspector;
use CybearCare\LaravelSecurity\Repository\EloquentAuditLogRepository;
use CybearCare\LaravelSecurity\Repository\EloquentBlockedRequestRepository;
use CybearCare\LaravelSecurity\Repository\EloquentCollectedDataRepository;
use CybearCare\LaravelSecurity\Repository\EloquentPackageDataRepository;
use CybearCare\LaravelSecurity\Repository\EloquentWafRuleRepository;
use CybearCare\LaravelSecurity\Services\ApplicationStructureCollector;
use CybearCare\LaravelSecurity\Services\AuthCollector;
use CybearCare\LaravelSecurity\Services\DatabaseCollector;
use CybearCare\LaravelSecurity\Services\DataCollectionManager;
use CybearCare\LaravelSecurity\Services\DomainVerificationService;
use CybearCare\LaravelSecurity\Services\FileSystemCollector;
use CybearCare\LaravelSecurity\Services\NetworkCollector;
use CybearCare\LaravelSecurity\Services\OpenApiSchemaGenerator;
use CybearCare\LaravelSecurity\Services\PerformanceCollector;
use CybearCare\LaravelSecurity\Services\SecurityDataCollector;
use CybearCare\LaravelSecurity\Services\SyncOrchestrator;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Verified;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;
use Throwable;

class CybearSecurityServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__.'/Config/cybear.php',
            'cybear'
        );

        $this->app->singleton(CybearConfig::class, function ($app) {
            return new CybearConfig(array_merge(
                config('cybear', []),
                [
                    'app_id' => config('cybear.app_id', config('app.name')),
                    'app_name' => config('app.name'),
                    'app_url' => config('app.url'),
                    'app_key' => config('app.key'),
                    'framework_version' => $app->version(),
                    'base_path' => base_path(),
                    'public_path' => public_path(),
                    'storage_path' => storage_path(),
                ]
            ));
        });

        $this->app->singleton(CacheInterface::class, function () {
            return new LaravelCacheAdapter;
        });

        $this->app->singleton(DastCorrelationVerifier::class, function ($app) {
            return new DastCorrelationVerifier(
                $app->make(CybearConfig::class),
                $app->make(CacheInterface::class),
            );
        });


        $this->app->singleton(CybearApiClient::class, function ($app) {
            return new CybearApiClient(
                $app->make(CybearConfig::class),
                $app->make(LoggerInterface::class),
                $app->make(CacheInterface::class)
            );
        });


        $this->app->singleton(WafRuleRepositoryInterface::class, EloquentWafRuleRepository::class);
        $this->app->singleton(AuditLogRepositoryInterface::class, EloquentAuditLogRepository::class);
        $this->app->singleton(BlockedRequestRepositoryInterface::class, EloquentBlockedRequestRepository::class);
        $this->app->singleton(CollectedDataRepositoryInterface::class, EloquentCollectedDataRepository::class);
        $this->app->singleton(PackageDataRepositoryInterface::class, EloquentPackageDataRepository::class);


        $this->app->singleton(WafEngine::class, function ($app) {
            return new WafEngine(
                $app->make(CybearApiClient::class),
                $app->make(WafRuleRepositoryInterface::class),
                $app->make(CacheInterface::class),
                $app->make(LoggerInterface::class),
                $app->make(CybearConfig::class)
            );
        });


        $this->app->singleton(AuditLogger::class, function ($app) {
            return new AuditLogger(
                $app->make(AuditLogRepositoryInterface::class),
                $app->make(BlockedRequestRepositoryInterface::class),
                $app->make(WafRuleRepositoryInterface::class),
                $app->make(LoggerInterface::class),
                $app->make(CybearConfig::class)
            );
        });


        $this->app->singleton(DataCollectionManager::class, function ($app) {
            return new DataCollectionManager(
                $app->make(CybearApiClient::class),
                $app->make(LoggerInterface::class),
                $app->make(CybearConfig::class),
                $app->make(CollectedDataRepositoryInterface::class),
                $app->make(PackageDataRepositoryInterface::class),
                $app->make(DomainVerificationService::class)
            );
        });


        $this->app->singleton(CoreDataCollectionManager::class, function ($app) {
            return $app->make(DataCollectionManager::class);
        });


        $this->app->singleton(SyncOrchestrator::class, function ($app) {
            return new SyncOrchestrator(
                $app->make(DataCollectionManager::class),
                $app->make(WafEngine::class),
            );
        });


        $this->app->singleton(DomainVerificationService::class);
        $this->app->singleton(OpenApiSchemaGenerator::class);


        $this->app->singleton(CapabilityDetector::class, function ($app) {
            return new CapabilityDetector(
                $app,
                $app->make(ConfigRepository::class),
                $app->make(Router::class),
            );
        });
        $this->app->singleton(CapabilitySet::class, function ($app) {
            return $app->make(CapabilityDetector::class)->detect();
        });
        $this->app->singleton(CheckContext::class, function ($app) {
            return new CheckContext(
                $app,
                $app->make(ConfigRepository::class),
                $app->make(Router::class),
                $app->make(CapabilitySet::class),
            );
        });
        $this->app->singleton(RouteSecurityInspector::class);
        $this->app->singleton(PhpSourceInspector::class);
        $this->app->singleton(CheckRegistry::class, function ($app) {
            $registry = new CheckRegistry;

            foreach ([
                AdministrativeSurfaceAuthorizationCheck::class,
                AppDebugCheck::class,
                AppKeyCheck::class,
                AppUrlHttpsCheck::class,
                CacheDriverCheck::class,
                CacheNamespaceCheck::class,
                ComposerLockCheck::class,
                ConfigurationCacheCheck::class,
                CorsConfigurationCheck::class,
                DebugbarProductionCheck::class,
                EnvironmentFilePermissionsCheck::class,
                FailedJobStorageCheck::class,
                FortifyAuthenticationThrottlingCheck::class,
                FortifyTwoFactorHardeningCheck::class,
                HashingCostCheck::class,
                MassAssignmentInputCheck::class,
                OctaneRuntimeSafetyCheck::class,
                PassportOAuthHardeningCheck::class,
                PassportTokenLifetimeCheck::class,
                PasswordConfirmationTimeoutCheck::class,
                PasswordResetConfigurationCheck::class,
                PublicDatabaseFileCheck::class,
                PublicFilesystemRootCheck::class,
                PublicSensitiveFilesCheck::class,
                QueueDriverCheck::class,
                SanctumTokenExpirationCheck::class,
                SensitiveRouteAuthorizationCheck::class,
                SessionCookieHttpOnlyCheck::class,
                SessionCookieSecureCheck::class,
                SessionDriverCheck::class,
                SessionPartitionedCookieCheck::class,
                SessionSameSiteCheck::class,
                SignedLinkIntegrityCheck::class,
                TelescopeProductionCheck::class,
                UnsafeWebRoutesCsrfCheck::class,
                UploadValidationCheck::class,
                WebCookieEncryptionCheck::class,
            ] as $check) {
                $registry->add($app->make($check));
            }

            return $registry;
        });
        $this->app->singleton(PostureRunner::class);


        $this->app->singleton(SensitiveFileGuard::class, function () {
            return new SensitiveFileGuard(config('cybear.sensitive_files', []));
        });


        $this->app->singleton(SecurityHeadersManager::class, function () {
            return new SecurityHeadersManager(config('cybear.security_headers', []));
        });
    }

    public function boot()
    {
        $this->publishes([
            __DIR__.'/Config/cybear.php' => config_path('cybear.php'),
        ], 'cybear-config');

        $this->loadMigrationsFrom(__DIR__.'/Database/Migrations');

        $this->loadViewsFrom(__DIR__.'/Resources/views', 'cybear');

        $this->publishes([
            __DIR__.'/Resources/views' => resource_path('views/vendor/cybear'),
        ], 'cybear-views');

        $this->registerCollectors();
        $this->registerMiddleware();
        $this->registerAuthenticationListeners();
        $this->registerCommands();
        $this->scheduleAutomaticTasks();
    }

    protected function registerCollectors()
    {
        $dataManager = $this->app->make(DataCollectionManager::class);
        $cache = $this->app->make(CacheInterface::class);
        $logger = $this->app->make(LoggerInterface::class);
        $config = $this->app->make(CybearConfig::class);


        $dataManager->addCollector('environment', new EnvironmentCollector($cache, $logger, $config));
        $dataManager->addCollector('packages', new PackageCollector($cache, $logger, $config));


        $dataManager->addCollector('application_structure', new ApplicationStructureCollector);
        $dataManager->addCollector('auth', new AuthCollector);
        $dataManager->addCollector('database', new DatabaseCollector);
        $dataManager->addCollector('filesystem', new FileSystemCollector);
        $dataManager->addCollector('network', new NetworkCollector);
        $dataManager->addCollector('performance', new PerformanceCollector);
        $dataManager->addCollector('security', new SecurityDataCollector);
    }

    protected function registerMiddleware()
    {
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('cybear.waf', WafMiddleware::class);
        $router->aliasMiddleware('cybear.dast', DastCorrelationMiddleware::class);
        $router->aliasMiddleware('cybear.audit', AuditLogMiddleware::class);
        $router->aliasMiddleware('cybear.ratelimit', RateLimitMiddleware::class);
        $router->aliasMiddleware('cybear.sync', SyncMiddleware::class);
        $router->aliasMiddleware('cybear.sensitive-files', SensitiveFileMiddleware::class);
        $router->aliasMiddleware('cybear.headers', SecurityHeadersMiddleware::class);

        if (! config('cybear.enabled', false)) {
            return;
        }

        $kernel = $this->app->make(Kernel::class);

        if (config('cybear.security_headers.enabled', true)) {
            $kernel->appendMiddlewareToGroup('web', SecurityHeadersMiddleware::class);
        }

        if (config('cybear.sensitive_files.enabled', true)) {
            $kernel->appendMiddlewareToGroup('web', SensitiveFileMiddleware::class);
            $kernel->appendMiddlewareToGroup('api', SensitiveFileMiddleware::class);
        }

        if (config('cybear.dast.correlation_enabled', false)) {
            $kernel->appendMiddlewareToGroup('web', DastCorrelationMiddleware::class);
            $kernel->appendMiddlewareToGroup('api', DastCorrelationMiddleware::class);
        }

        if (config('cybear.waf.enabled', true)) {
            $kernel->appendMiddlewareToGroup('web', WafMiddleware::class);
            $kernel->appendMiddlewareToGroup('api', WafMiddleware::class);
        }

        if (config('cybear.audit.enabled', true) && config('cybear.audit.log_requests', false)) {
            $kernel->appendMiddlewareToGroup('web', AuditLogMiddleware::class);
            $kernel->appendMiddlewareToGroup('api', AuditLogMiddleware::class);
        }

        if (config('cybear.sync.opportunistic', true)) {
            $kernel->appendMiddlewareToGroup('web', SyncMiddleware::class);
            $kernel->appendMiddlewareToGroup('api', SyncMiddleware::class);
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
                ExportSchemaCommand::class,
                ScanCommand::class,
            ]);
        }
    }

    protected function registerAuthenticationListeners(): void
    {
        if (! config('cybear.enabled', false)
            || ! config('cybear.audit.enabled', true)
            || ! config('cybear.audit.log_authentication', true)) {
            return;
        }

        Event::listen(Login::class, function ($event): void {
            $this->logAuthenticationEvent('login_succeeded', $event->user);
        });

        Event::listen(Failed::class, function ($event): void {
            $email = is_array($event->credentials ?? null)
                ? ($event->credentials['email'] ?? null)
                : null;
            $this->logAuthenticationEvent('login_failed', $event->user, $email);
        });

        Event::listen(Logout::class, function ($event): void {
            $this->logAuthenticationEvent('logout', $event->user);
        });

        Event::listen(Lockout::class, function (): void {
            $this->logAuthenticationEvent('login_lockout');
        });

        Event::listen(Verified::class, function ($event): void {
            $this->logAuthenticationEvent('email_verified', $event->user);
        });

        Event::listen(PasswordReset::class, function ($event): void {
            $this->logAuthenticationEvent('password_reset', $event->user);
        });
    }

    protected function logAuthenticationEvent(
        string $event,
        mixed $user = null,
        ?string $email = null,
    ): void {
        if ($this->app->runningInConsole() || ! $this->app->bound('request')) {
            return;
        }

        try {
            $request = request();
            $userId = is_object($user) && method_exists($user, 'getAuthIdentifier')
                ? (string) $user->getAuthIdentifier()
                : null;

            $this->app->make(AuditLogger::class)->logAuthenticationEvent(
                $event,
                new LaravelRequestAdapter($request),
                $userId,
                $email,
                $request->hasSession() ? $request->session()->getId() : null,
            );
        } catch (Throwable $exception) {
            Log::warning('Failed to record a Cybear authentication event', [
                'event' => $event,
                'error' => $exception->getMessage(),
            ]);
        }
    }

    protected function scheduleAutomaticTasks()
    {
        if (! config('cybear.enabled', false)) {
            return;
        }

        $schedule = $this->app->make(Schedule::class);

        $schedule->call(
            fn () => $this->app->make(SyncOrchestrator::class)->runDueSyncs('scheduler'),
        )
            ->name('cybear:runtime-sync')
            ->everyMinute()
            ->withoutOverlapping();

        if (config('cybear.collectors.auto_cleanup', true)) {
            $cleanupInterval = (string) config('cybear.collectors.cleanup_interval', 'weekly');

            $this->applyScheduleInterval(
                $schedule->command('cybear:send --cleanup-only')->withoutOverlapping()->runInBackground(),
                $cleanupInterval,
                'weekly',
            );
        }

    }

    protected function applyScheduleInterval(object $event, string $interval, string $fallback): void
    {
        $allowed = [
            'everyMinute',
            'everyFiveMinutes',
            'everyTenMinutes',
            'everyFifteenMinutes',
            'everyThirtyMinutes',
            'hourly',
            'daily',
            'weekly',
        ];

        $method = in_array($interval, $allowed, true) ? $interval : $fallback;
        $event->{$method}();
    }
}
