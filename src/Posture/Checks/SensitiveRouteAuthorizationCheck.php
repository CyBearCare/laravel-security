<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\FindingOccurrence;
use CybearCare\LaravelSecurity\Posture\PhpSourceInspector;
use CybearCare\LaravelSecurity\Posture\RouteSecurityInspector;
use CybearCare\LaravelSecurity\Posture\Severity;
use Illuminate\Routing\Route;
use Illuminate\Support\Str;

final class SensitiveRouteAuthorizationCheck extends AbstractCheck
{
    private const STATE_CHANGING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    private const AUTHORIZATION_SIGNALS = [
        'controller_authorize' => '/->\s*authorize\s*\(/i',
        'gate_authorization' => '/\bGate\s*::\s*(?:authorize|allows|denies|check|inspect|forUser)\s*\(/i',
        'actor_authorization' => '/->\s*(?:can|cannot|cant)\s*\(/i',
        'authorization_exception' => '/\bthrow\s+new\s+AuthorizationException\b/i',
    ];

    public function __construct(
        private RouteSecurityInspector $routes,
        private PhpSourceInspector $source,
    ) {
    }

    public function id(): string
    {
        return 'laravel.routes.authorization_coverage';
    }

    public function name(): string
    {
        return 'Sensitive route authorization coverage';
    }

    public function category(): string
    {
        return 'authorization';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function confidence(): Confidence
    {
        return Confidence::Medium;
    }

    public function run(CheckContext $context): CheckResult
    {
        if ($context->config('cybear.posture.inspect_application_source', true) !== true) {
            return $this->skipped('Local application source inspection is disabled.');
        }

        $excluded = array_values(array_filter(
            (array) $context->config('cybear.posture.authorization_excluded_routes', []),
            'is_string',
        ));
        $routeLimit = $this->routeLimit($context);
        $evidenceLimit = $this->evidenceLimit($context);
        $inspected = 0;
        $candidates = 0;
        $assessed = 0;
        $unknown = 0;
        $outOfScope = 0;
        $uncoveredCount = 0;
        $uncovered = [];
        $occurrences = [];
        $scanTruncated = false;

        foreach ($context->routes() as $route) {
            if (!$this->isPotentiallySensitive($route) || $this->isExcluded($route, $excluded)) {
                continue;
            }

            $middleware = $this->routes->middleware($context, $route);
            if (!$this->routes->hasAuthentication($middleware['middleware'])) {
                continue;
            }

            $candidates++;
            if ($inspected >= $routeLimit) {
                $scanTruncated = true;
                continue;
            }
            $inspected++;

            if ($this->routes->hasAuthorization($middleware['middleware'])) {
                $assessed++;
                continue;
            }

            $method = $this->source->routeAction($context, $route);
            if (!$method->available) {
                if ($this->isOutOfScope($method->unavailableReason)) {
                    $outOfScope++;
                } else {
                    $unknown++;
                }
                continue;
            }
            $assessed++;

            $signals = [];
            foreach ($this->source->relatedMethods($context, $method) as $related) {
                $signals = [
                    ...$signals,
                    ...$related->matchingSignals(self::AUTHORIZATION_SIGNALS),
                ];
            }

            foreach ($this->source->formRequestTypes($context, $method) as $formRequest) {
                $authorize = $this->source->method($context, $formRequest, 'authorize');
                if ($authorize->available) {
                    $signals = [
                        ...$signals,
                        ...array_map(
                            static fn (string $signal): string => 'form_request_' . $signal,
                            $authorize->matchingSignals(self::AUTHORIZATION_SIGNALS),
                        ),
                    ];

                    if ($authorize->hasAnySignal([
                        'contextual_authorize_result' => '/\breturn\s+(?!true\s*;|false\s*;)[^;]+;/i',
                    ])) {
                        $signals[] = 'form_request_contextual_authorize_result';
                    }
                }
            }

            if ($signals !== []) {
                continue;
            }

            if ($middleware['resolution_failed']) {
                $unknown++;
                continue;
            }

            $uncoveredCount++;
            $routeEvidence = [
                ...$this->routes->evidence($route),
                'action' => substr($method->action, 0, 500),
                'location' => $method->location(),
            ];
            $occurrences[] = new FindingOccurrence(
                identity: [
                    'methods' => $routeEvidence['methods'],
                    'uri' => $routeEvidence['uri'],
                    'action' => $routeEvidence['action'],
                ],
                evidence: $routeEvidence,
            );
            if (count($uncovered) < $evidenceLimit) {
                $uncovered[] = $routeEvidence;
            }
        }

        $evidence = [
            'candidate_route_count' => $candidates,
            'inspected_route_count' => $inspected,
            'assessed_route_count' => $assessed,
            'unknown_route_count' => $unknown,
            'out_of_scope_route_count' => $outOfScope,
            'uncovered_route_count' => $uncoveredCount,
            'uncovered_routes' => $uncovered,
            'scan_truncated' => $scanTruncated,
            'evidence_truncated' => $uncoveredCount > count($uncovered),
            'source_shared' => false,
        ];

        if ($uncoveredCount > 0) {
            return $this->warning(
                'Authenticated, state-changing routes were found without a verifiable route, controller, or FormRequest authorization decision.',
                'Enforce object-level authorization with can middleware, controller authorization, a Gate, or a contextual FormRequest authorize method. Add narrow exclusions only for deliberately authorization-free routes.',
                $evidence,
                occurrences: $occurrences,
            );
        }

        if ($candidates === 0 || ($assessed === 0 && $unknown === 0)) {
            return $this->skipped('No authenticated, state-changing controller routes requiring authorization analysis were detected.', $evidence);
        }

        if ($unknown > 0 || $scanTruncated) {
            return $this->warning(
                'No authorization gap was confirmed, but some applicable routes could not be fully inspected.',
                'Make controller source and middleware aliases locally resolvable, or raise the bounded source-route limit, then rerun the scan.',
                $evidence,
                Severity::Medium,
            );
        }

        return $this->pass(
            'Applicable authenticated routes have a verifiable authorization decision.',
            $evidence,
        );
    }

    private function isPotentiallySensitive(Route $route): bool
    {
        $methods = array_values(array_intersect(self::STATE_CHANGING_METHODS, $route->methods()));
        if ($methods === []) {
            return false;
        }

        $action = strtolower($route->getActionMethod());

        return array_intersect($methods, ['PUT', 'PATCH', 'DELETE']) !== []
            || str_contains($route->uri(), '{')
            || in_array($action, ['store', 'update', 'destroy', 'delete'], true)
            || preg_match('/(?:^|[._\/-])(admin|manage|management)(?:$|[._\/-])/i', (string) $route->getName() . '/' . $route->uri()) === 1;
    }

    /**
     * @param list<string> $patterns
     */
    private function isExcluded(Route $route, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (Str::is($pattern, (string) ($route->getName() ?? ''))
                || Str::is($pattern, $route->uri())) {
                return true;
            }
        }

        return false;
    }

    private function routeLimit(CheckContext $context): int
    {
        return max(1, min(5000, (int) $context->config('cybear.posture.max_source_routes', 500)));
    }

    private function evidenceLimit(CheckContext $context): int
    {
        return max(1, min(100, (int) $context->config('cybear.posture.max_evidence_items', 25)));
    }

    private function isOutOfScope(?string $reason): bool
    {
        return in_array($reason, ['source_not_local', 'unsupported_route_action'], true);
    }
}
