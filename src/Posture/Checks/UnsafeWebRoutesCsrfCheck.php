<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;
use Illuminate\Routing\Route;
use Illuminate\Support\Str;

final class UnsafeWebRoutesCsrfCheck extends AbstractCheck
{
    private const STATE_CHANGING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    public function id(): string
    {
        return 'laravel.routes.csrf_middleware';
    }

    public function name(): string
    {
        return 'CSRF protection on state-changing web routes';
    }

    public function category(): string
    {
        return 'routing';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(CheckContext $context): CheckResult
    {
        $unsafe = [];
        $unsafeCount = 0;
        $webRoutesChecked = 0;
        $excluded = array_values(array_filter(
            (array) $context->config('cybear.posture.csrf_excluded_routes', []),
            'is_string',
        ));
        $limit = max(1, min(100, (int) $context->config('cybear.posture.max_evidence_items', 25)));

        foreach ($context->routes() as $route) {
            $methods = array_values(array_intersect(self::STATE_CHANGING_METHODS, $route->methods()));
            if ($methods === [] || $this->isExcluded($route, $excluded)) {
                continue;
            }

            $raw = array_values(array_filter($route->gatherMiddleware(), 'is_string'));
            $resolved = $context->resolvedMiddleware($route);
            $isWeb = in_array('web', $raw, true);

            if (!$isWeb) {
                continue;
            }

            $webRoutesChecked++;
            $hasCsrf = $this->containsMiddleware($resolved, 'ValidateCsrfToken')
                || $this->containsMiddleware($resolved, 'VerifyCsrfToken');

            if (!$hasCsrf) {
                $unsafeCount++;

                if (count($unsafe) < $limit) {
                    $unsafe[] = [
                        'methods' => $methods,
                        'uri' => $route->uri(),
                        'name' => $route->getName(),
                    ];
                }
            }
        }

        if ($unsafe !== []) {
            return $this->fail(
                'State-changing web routes were found without Laravel CSRF middleware.',
                'Place browser/session routes in the web middleware group or attach ValidateCsrfToken. Keep stateless token APIs outside the web group.',
                [
                    'routes_checked' => $webRoutesChecked,
                    'affected_route_count' => $unsafeCount,
                    'affected_routes' => $unsafe,
                    'evidence_truncated' => $unsafeCount > count($unsafe),
                ],
            );
        }

        return $this->pass('State-changing web routes include Laravel CSRF middleware.', [
            'routes_checked' => $webRoutesChecked,
        ]);
    }

    /**
     * @param list<string> $middleware
     */
    private function containsMiddleware(array $middleware, string $classSuffix): bool
    {
        foreach ($middleware as $item) {
            $class = explode(':', $item, 2)[0];
            if ($class === $classSuffix || str_ends_with($class, '\\' . $classSuffix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string> $patterns
     */
    private function isExcluded(Route $route, array $patterns): bool
    {
        $name = (string) ($route->getName() ?? '');
        $uri = $route->uri();

        foreach ($patterns as $pattern) {
            if (Str::is($pattern, $name) || Str::is($pattern, $uri)) {
                return true;
            }
        }

        return false;
    }
}
