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

final class SignedLinkIntegrityCheck extends AbstractCheck
{
    private const LINK_KEYWORDS = [
        'verify', 'verification', 'unsubscribe', 'invite', 'invitation',
        'magic', 'confirm', 'confirmation',
    ];

    private const MUTATION_SIGNALS = [
        'verification_mutation' => '/->\s*markEmailAsVerified\s*\(/i',
        'model_mutation' => '/->\s*(?:save|update|delete|forceFill|increment|decrement)\s*\(/i',
        'relationship_mutation' => '/->\s*(?:attach|detach|sync|syncWithoutDetaching)\s*\(/i',
        'static_mutation' => '/::\s*(?:create|forceCreate|updateOrCreate|firstOrCreate)\s*\(/i',
    ];

    private const SIGNATURE_SIGNALS = [
        'request_signature_validation' => '/->\s*(?:hasValidSignature|hasValidRelativeSignature|hasValidSignatureWhileIgnoring)\s*\(/i',
        'url_signature_validation' => '/\bURL\s*::\s*(?:hasValidSignature|hasValidRelativeSignature)\s*\(/i',
    ];

    public function __construct(
        private RouteSecurityInspector $routes,
        private PhpSourceInspector $source,
    ) {
    }

    public function id(): string
    {
        return 'laravel.routes.signed_link_integrity';
    }

    public function name(): string
    {
        return 'Sensitive signed-link integrity';
    }

    public function category(): string
    {
        return 'routing';
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
            (array) $context->config('cybear.posture.signed_link_excluded_routes', []),
            'is_string',
        ));
        $routeLimit = max(1, min(5000, (int) $context->config('cybear.posture.max_source_routes', 500)));
        $evidenceLimit = max(1, min(100, (int) $context->config('cybear.posture.max_evidence_items', 25)));
        $inspected = 0;
        $candidates = 0;
        $unknown = 0;
        $outOfScope = 0;
        $unprotectedCount = 0;
        $unprotected = [];
        $occurrences = [];
        $scanTruncated = false;

        foreach ($context->routes() as $route) {
            if (!$this->looksLikeSensitiveLink($route) || $this->isExcluded($route, $excluded)) {
                continue;
            }

            if ($inspected >= $routeLimit) {
                $scanTruncated = true;
                continue;
            }
            $inspected++;

            $middleware = $this->routes->middleware($context, $route);
            $method = $this->source->routeAction($context, $route);
            if (!$method->available) {
                if (in_array($method->unavailableReason, ['source_not_local', 'unsupported_route_action'], true)) {
                    $outOfScope++;
                } else {
                    $unknown++;
                }
                continue;
            }
            $relatedMethods = $this->source->relatedMethods($context, $method);
            if (!$this->hasAnySignal($relatedMethods, self::MUTATION_SIGNALS)) {
                continue;
            }
            $candidates++;

            if ($this->routes->hasSignedUrlValidation($middleware['middleware'])
                || $this->hasAnySignal($relatedMethods, self::SIGNATURE_SIGNALS)) {
                continue;
            }

            if ($middleware['resolution_failed']) {
                $unknown++;
                continue;
            }

            $unprotectedCount++;
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
            if (count($unprotected) < $evidenceLimit) {
                $unprotected[] = $routeEvidence;
            }
        }

        $evidence = [
            'inspected_named_link_route_count' => $inspected,
            'state_mutating_candidate_count' => $candidates,
            'unknown_route_count' => $unknown,
            'out_of_scope_route_count' => $outOfScope,
            'unsigned_candidate_count' => $unprotectedCount,
            'unsigned_candidates' => $unprotected,
            'scan_truncated' => $scanTruncated,
            'evidence_truncated' => $unprotectedCount > count($unprotected),
            'source_shared' => false,
        ];

        if ($unprotectedCount > 0) {
            return $this->warning(
                'Parameterized verification, invitation, confirmation, or unsubscribe routes mutate state without verifiable signed-URL validation.',
                'Generate temporary signed URLs and enforce Laravel signed middleware or an explicit valid-signature check before changing state.',
                $evidence,
                occurrences: $occurrences,
            );
        }

        if ($candidates === 0 && $unknown === 0) {
            return $this->skipped('No parameterized, state-mutating sensitive-link controller routes were detected.', $evidence);
        }

        if ($unknown > 0 || $scanTruncated) {
            return $this->warning(
                'No unsigned sensitive-link mutation was confirmed, but some applicable routes could not be fully inspected.',
                'Make middleware aliases locally resolvable, or raise the bounded source-route limit, then rerun the scan.',
                $evidence,
                Severity::Medium,
            );
        }

        return $this->pass(
            'Detected state-mutating sensitive-link routes validate Laravel URL signatures.',
            $evidence,
        );
    }

    private function looksLikeSensitiveLink(Route $route): bool
    {
        if (!str_contains($route->uri(), '{')) {
            return false;
        }

        $identity = strtolower((string) ($route->getName() ?? '') . '/' . $route->uri());
        foreach (self::LINK_KEYWORDS as $keyword) {
            if (preg_match('/(?:^|[._\/-])' . preg_quote($keyword, '/') . '(?:$|[._\/-])/', $identity) === 1) {
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
        foreach ($patterns as $pattern) {
            if (Str::is($pattern, (string) ($route->getName() ?? ''))
                || Str::is($pattern, $route->uri())) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<\CybearCare\LaravelSecurity\Posture\SourceMethod> $methods
     * @param array<string, string> $patterns
     */
    private function hasAnySignal(array $methods, array $patterns): bool
    {
        foreach ($methods as $method) {
            if ($method->hasAnySignal($patterns)) {
                return true;
            }
        }

        return false;
    }
}
