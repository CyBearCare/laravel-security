<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\RouteSecurityInspector;
use CybearCare\LaravelSecurity\Posture\Severity;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Routing\Route;
use Throwable;

final class AdministrativeSurfaceAuthorizationCheck extends AbstractCheck
{
    private const SURFACES = [
        'horizon' => [
            'ability' => 'viewHorizon',
            'namespace' => 'Laravel\\Horizon',
            'middleware' => ['Authenticate', 'Authorize'],
            'names' => ['horizon.'],
            'uris' => ['horizon'],
        ],
        'telescope' => [
            'ability' => 'viewTelescope',
            'namespace' => 'Laravel\\Telescope',
            'middleware' => ['Authorize'],
            'names' => ['telescope.'],
            'uris' => ['telescope'],
        ],
        'pulse' => [
            'ability' => 'viewPulse',
            'namespace' => 'Laravel\\Pulse',
            'middleware' => ['Authorize'],
            'names' => ['pulse.'],
            'uris' => ['pulse'],
        ],
    ];

    public function __construct(private RouteSecurityInspector $inspector)
    {
    }

    public function id(): string
    {
        return 'laravel.admin_surfaces.authorization';
    }

    public function name(): string
    {
        return 'Administrative dashboard authorization';
    }

    public function category(): string
    {
        return 'authorization';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->isProduction()) {
            return $this->skipped('Administrative dashboard authorization is evaluated only for production.', [
                'environment' => $context->environment(),
            ]);
        }

        $gate = $this->gate($context);
        $surfaces = [];
        $unprotected = [];
        $missingGates = [];
        $resolutionFailures = 0;
        $unprotectedCount = 0;
        $limit = max(1, min(100, (int) $context->config('cybear.posture.max_evidence_items', 25)));

        foreach (self::SURFACES as $capability => $definition) {
            if (!$context->capabilities->hasPackage($capability)
                || !$context->capabilities->hasRouteSurface($capability)
                || ($capability === 'telescope' && $context->config('telescope.enabled', true) !== true)) {
                continue;
            }

            $routeCount = 0;
            $protectedCount = 0;
            $surfaceUnprotectedCount = 0;
            $surfaceUnresolvedCount = 0;

            foreach ($context->routes() as $route) {
                if (!$this->matches($route, $definition['names'], $definition['uris'])) {
                    continue;
                }

                $routeCount++;
                $inspection = $this->inspector->middleware($context, $route);
                $resolutionFailures += $inspection['resolution_failed'] ? 1 : 0;
                $surfaceUnresolvedCount += $inspection['resolution_failed'] ? 1 : 0;
                $middleware = $inspection['middleware'];
                $hasBoundary = $this->inspector->hasPackageBoundary(
                    $middleware,
                    $definition['namespace'],
                    $definition['middleware'],
                ) || (
                    $this->inspector->hasAuthentication($middleware)
                    && $this->inspector->hasAuthorization($middleware)
                );

                if ($hasBoundary) {
                    $protectedCount++;
                } elseif (!$inspection['resolution_failed']) {
                    $surfaceUnprotectedCount++;
                    $unprotectedCount++;

                    if (count($unprotected) < $limit) {
                        $unprotected[] = [
                            'surface' => $capability,
                            ...$this->inspector->evidence($route),
                        ];
                    }
                }
            }

            $gateDefined = $gate?->has($definition['ability']);
            if ($gate !== null && !$gateDefined) {
                $missingGates[] = [
                    'surface' => $capability,
                    'ability' => $definition['ability'],
                ];
            }

            $surfaces[$capability] = [
                'version' => $context->capabilities->packageVersion($capability),
                'route_count' => $routeCount,
                'authorization_boundary_count' => $protectedCount,
                'unprotected_route_count' => $surfaceUnprotectedCount,
                'unresolved_route_count' => $surfaceUnresolvedCount,
                'gate_ability' => $definition['ability'],
                'gate_defined' => $gateDefined,
            ];
        }

        if ($surfaces === []) {
            return $this->skipped('No enabled Horizon, Telescope, or Pulse route surface was detected in production.');
        }

        $evidence = [
            'surfaces' => $surfaces,
            'unprotected_routes' => $unprotected,
            'unprotected_route_count' => $unprotectedCount,
            'missing_gates' => $missingGates,
            'gate_service_available' => $gate !== null,
            'middleware_resolution_failure_count' => $resolutionFailures,
            'evidence_truncated' => $unprotectedCount > count($unprotected),
        ];

        if ($evidence['unprotected_route_count'] > 0) {
            return $this->fail(
                'Administrative dashboard routes were found without a verifiable authentication and authorization boundary.',
                'Restore the package authorization middleware or protect every dashboard route with both authentication and a restrictive Gate or policy middleware.',
                $evidence,
            );
        }

        if ($resolutionFailures > 0 || $gate === null) {
            return $this->warning(
                'Some administrative dashboard authorization signals could not be fully resolved.',
                'Resolve missing middleware aliases, classes, or the Gate service, then rerun the scan so the dashboard boundary can be verified.',
                $evidence,
            );
        }

        if ($missingGates !== []) {
            return $this->warning(
                'Administrative dashboard middleware is present, but one or more documented authorization gates are not defined.',
                'Define restrictive viewHorizon, viewTelescope, or viewPulse gates for the enabled production dashboards. Missing gates normally deny access, but explicit policy is safer and operationally clearer.',
                $evidence,
                Severity::Medium,
            );
        }

        return $this->pass(
            'Administrative dashboard routes have authorization middleware and their documented gates are defined.',
            $evidence,
        );
    }

    private function gate(CheckContext $context): ?Gate
    {
        try {
            $gate = $context->application->make(Gate::class);

            return $gate instanceof Gate ? $gate : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @param list<string> $namePrefixes
     * @param list<string> $uriPrefixes
     */
    private function matches(Route $route, array $namePrefixes, array $uriPrefixes): bool
    {
        $name = strtolower((string) ($route->getName() ?? ''));
        $uri = strtolower(trim($route->uri(), '/'));

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

        return false;
    }
}
