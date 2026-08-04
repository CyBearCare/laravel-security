<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class DebugbarProductionCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.debugbar.production';
    }

    public function name(): string
    {
        return 'Laravel Debugbar in production';
    }

    public function category(): string
    {
        return 'debugging';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->capabilities->hasPackage('debugbar')) {
            return $this->skipped('Laravel Debugbar is not installed.');
        }

        if (!$context->isProduction()) {
            return $this->skipped('Debugbar production exposure is evaluated only for production.', [
                'environment' => $context->environment(),
                'version' => $context->capabilities->packageVersion('debugbar'),
            ]);
        }

        $configured = $context->config('debugbar.enabled');
        $configuredEnabled = is_bool($configured)
            ? $configured
            : (bool) $context->config('app.debug', false);
        $package = $context->capabilities->packageName('debugbar');
        $forceAllowed = $context->config('debugbar.force_allow_enable', false) === true;
        $enabled = $package === 'fruitcake/laravel-debugbar'
            ? $configuredEnabled && $forceAllowed
            : $configuredEnabled;
        $evidence = [
            'enabled' => $enabled,
            'configured_enabled' => $configuredEnabled,
            'production_enable_allowed' => $forceAllowed,
            'route_surface_present' => $context->capabilities->hasRouteSurface('debugbar'),
            'package' => $package,
            'version' => $context->capabilities->packageVersion('debugbar'),
        ];

        if ($enabled) {
            return $this->fail(
                'Laravel Debugbar is enabled in production.',
                'Set DEBUGBAR_ENABLED=false, disable APP_DEBUG, clear cached configuration, and exclude development packages from production builds.',
                $evidence,
            );
        }

        return $this->pass('Laravel Debugbar is installed but disabled in production.', $evidence);
    }
}
