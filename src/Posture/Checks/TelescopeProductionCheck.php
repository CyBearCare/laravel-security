<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class TelescopeProductionCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.telescope.production';
    }

    public function name(): string
    {
        return 'Laravel Telescope in production';
    }

    public function category(): string
    {
        return 'debugging';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->capabilities->hasPackage('telescope')) {
            return $this->skipped('Laravel Telescope is not installed.');
        }

        if (!$context->isProduction()) {
            return $this->skipped('Telescope production posture is evaluated only for production.', [
                'environment' => $context->environment(),
                'version' => $context->capabilities->packageVersion('telescope'),
            ]);
        }

        $enabled = $context->config('telescope.enabled', true) === true;
        $routed = $context->capabilities->hasRouteSurface('telescope');
        $evidence = [
            'enabled' => $enabled,
            'route_surface_present' => $routed,
            'route_count' => $context->capabilities->routeCount('telescope'),
            'version' => $context->capabilities->packageVersion('telescope'),
        ];

        if ($enabled && $routed) {
            return $this->warning(
                'Laravel Telescope is enabled and routed in production.',
                'Confirm Telescope is operationally necessary, prune retained entries, and disable watchers that are not required. Dashboard Gate enforcement is evaluated separately.',
                $evidence,
            );
        }

        return $this->pass('Laravel Telescope is not both enabled and routed in production.', $evidence);
    }
}
