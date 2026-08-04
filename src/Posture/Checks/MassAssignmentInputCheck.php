<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\FindingOccurrence;
use CybearCare\LaravelSecurity\Posture\PhpSourceInspector;
use CybearCare\LaravelSecurity\Posture\RouteSecurityInspector;
use CybearCare\LaravelSecurity\Posture\Severity;

final class MassAssignmentInputCheck extends AbstractCheck
{
    private const STATE_CHANGING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    private const UNSAFE_SIGNALS = [
        'request_helper_to_mass_assignment' => '/(?:->|::)\s*(?:create|update|fill|forceFill|forceCreate|updateOrCreate)\s*\(\s*request\s*\(\s*\)\s*->\s*(?:all|input)\s*\(\s*\)/i',
        'global_model_unguard' => '/\b[A-Za-z_\\\\][A-Za-z0-9_\\\\]*\s*::\s*unguard\s*\(/i',
    ];

    private const TAINT_SOURCES = [
        'request_all' => '/request\s*\(\s*\)\s*->\s*all\s*\(\s*\)/i',
        'request_input' => '/request\s*\(\s*\)\s*->\s*input\s*\(\s*\)/i',
    ];

    private const TAINT_SINKS = [
        'instance_mass_assignment' => '/->\s*(?:create|update|fill|forceFill)\s*\(\s*{{variable}}\s*\)/i',
        'static_mass_assignment' => '/::\s*(?:create|forceCreate)\s*\(\s*{{variable}}\s*\)/i',
        'update_or_create_values' => '/::\s*updateOrCreate\s*\([^,]{0,1000},\s*{{variable}}\s*\)/is',
    ];

    public function __construct(
        private RouteSecurityInspector $routes,
        private PhpSourceInspector $source,
    ) {
    }

    public function id(): string
    {
        return 'laravel.eloquent.mass_assignment_input';
    }

    public function name(): string
    {
        return 'Unvalidated mass-assignment input';
    }

    public function category(): string
    {
        return 'data handling';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function confidence(): Confidence
    {
        return Confidence::High;
    }

    public function run(CheckContext $context): CheckResult
    {
        if ($context->config('cybear.posture.inspect_application_source', true) !== true) {
            return $this->skipped('Local application source inspection is disabled.');
        }

        $routeLimit = max(1, min(5000, (int) $context->config('cybear.posture.max_source_routes', 500)));
        $evidenceLimit = max(1, min(100, (int) $context->config('cybear.posture.max_evidence_items', 25)));
        $inspected = 0;
        $attempted = 0;
        $applicable = 0;
        $unknown = 0;
        $outOfScope = 0;
        $affectedCount = 0;
        $affected = [];
        $occurrences = [];
        $scanTruncated = false;

        foreach ($context->routes() as $route) {
            if (array_intersect(self::STATE_CHANGING_METHODS, $route->methods()) === []) {
                continue;
            }

            if ($attempted >= $routeLimit) {
                $scanTruncated = true;
                continue;
            }
            $attempted++;

            $method = $this->source->routeAction($context, $route);
            if (!$method->available) {
                if (in_array($method->unavailableReason, ['source_not_local', 'unsupported_route_action'], true)) {
                    $outOfScope++;
                } else {
                    $unknown++;
                }
                continue;
            }

            $applicable++;
            $inspected++;
            $signals = [];
            foreach ($this->source->relatedMethods($context, $method) as $related) {
                $requestPatterns = self::TAINT_SOURCES;
                $directPatterns = self::UNSAFE_SIGNALS;
                $requestVariables = $this->source->requestVariableNames($context, $related);
                if ($requestVariables !== []) {
                    $variable = '(?:' . implode('|', array_map(
                        static fn (string $name): string => preg_quote($name, '/'),
                        $requestVariables,
                    )) . ')';
                    $requestPatterns['request_all'] = '/(?:' . $variable . '\s*->\s*all\s*\(\s*\)|request\s*\(\s*\)\s*->\s*all\s*\(\s*\))/i';
                    $requestPatterns['request_input'] = '/(?:' . $variable . '\s*->\s*input\s*\(\s*\)|request\s*\(\s*\)\s*->\s*input\s*\(\s*\))/i';
                    $directPatterns['request_all_to_instance_mass_assignment'] = '/->\s*(?:create|update|fill|forceFill)\s*\(\s*' . $variable . '\s*->\s*(?:all|input)\s*\(\s*\)\s*\)/i';
                    $directPatterns['request_all_to_static_mass_assignment'] = '/::\s*(?:create|forceCreate|updateOrCreate)\s*\(\s*' . $variable . '\s*->\s*(?:all|input)\s*\(\s*\)\s*[,)]/i';
                    $directPatterns['request_all_to_update_or_create_values'] = '/::\s*updateOrCreate\s*\(\s*(?:\[[^\]]{0,500}\]|\$[A-Za-z_][A-Za-z0-9_]*)\s*,\s*' . $variable . '\s*->\s*(?:all|input)\s*\(\s*\)\s*\)/i';
                }
                $signals = [
                    ...$signals,
                    ...$related->matchingSignals($directPatterns),
                    ...$related->matchingTaintedVariableFlows($requestPatterns, self::TAINT_SINKS),
                ];
            }
            $signals = array_values(array_unique($signals));
            if ($signals === []) {
                continue;
            }

            $affectedCount++;
            $routeEvidence = [
                ...$this->routes->evidence($route),
                'action' => substr($method->action, 0, 500),
                'location' => $method->location(),
                'signals' => $signals,
            ];
            $occurrences[] = new FindingOccurrence(
                identity: [
                    'methods' => $routeEvidence['methods'],
                    'uri' => $routeEvidence['uri'],
                    'action' => $routeEvidence['action'],
                ],
                evidence: $routeEvidence,
            );
            if (count($affected) < $evidenceLimit) {
                $affected[] = $routeEvidence;
            }
        }

        $evidence = [
            'source_route_attempt_count' => $attempted,
            'locally_inspected_route_count' => $inspected,
            'unavailable_source_route_count' => $unknown,
            'out_of_scope_route_count' => $outOfScope,
            'affected_route_count' => $affectedCount,
            'affected_routes' => $affected,
            'scan_truncated' => $scanTruncated,
            'evidence_truncated' => $affectedCount > count($affected),
            'source_shared' => false,
        ];

        if ($affectedCount > 0) {
            return $this->fail(
                'Controller code directly passes unrestricted request input into an Eloquent mass-assignment operation.',
                'Pass only validated and explicitly selected fields, such as $request->validated() or $request->safe()->only([...]), and keep model fillable or guarded rules restrictive.',
                $evidence,
                occurrences: $occurrences,
            );
        }

        if ($applicable === 0 && $unknown === 0) {
            return $this->skipped('No local state-changing controller methods were available for mass-assignment analysis.', $evidence);
        }

        if ($unknown > 0 || $scanTruncated) {
            return $this->warning(
                'No unsafe mass-assignment input flow was detected, but some local source could not be inspected completely.',
                'Make local controller source readable and raise cybear.posture.max_source_routes if the bounded route limit was reached.',
                $evidence,
                Severity::Medium,
            );
        }

        return $this->pass(
            'No direct unrestricted request-to-Eloquent mass-assignment pattern was detected in local controller methods.',
            $evidence,
        );
    }
}
