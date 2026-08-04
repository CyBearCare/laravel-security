<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\FindingOccurrence;
use CybearCare\LaravelSecurity\Posture\PhpSourceInspector;
use CybearCare\LaravelSecurity\Posture\RouteSecurityInspector;
use CybearCare\LaravelSecurity\Posture\Severity;
use CybearCare\LaravelSecurity\Posture\SourceMethod;

final class UploadValidationCheck extends AbstractCheck
{
    private const STATE_CHANGING_METHODS = ['POST', 'PUT', 'PATCH'];

    private const UPLOAD_SIGNALS = [
        'request_file_access' => '/->\s*(?:file|hasFile)\s*\(/i',
        'uploaded_file_type' => '/\bUploadedFile\b/',
        'request_file_bag' => '/->\s*files(?:\s*->|\s*\[)/i',
    ];

    private const TYPE_CONSTRAINTS = [
        'image_rule' => '/[\'"]image[\'"]/i',
        'mimes_rule' => '/[\'"]mimes\s*:/i',
        'mimetypes_rule' => '/[\'"]mimetypes\s*:/i',
        'extensions_rule' => '/[\'"]extensions\s*:/i',
        'fluent_file_type_rule' => '/\bFile\s*::\s*(?:types|image)\s*\(/i',
        'fluent_extensions_rule' => '/->\s*extensions\s*\(/i',
    ];

    private const FILE_RULE_SIGNALS = [
        'file_rule' => '/[\'"]file[\'"]/i',
        ...self::TYPE_CONSTRAINTS,
    ];

    private const SIZE_CONSTRAINTS = [
        'max_rule' => '/[\'"]max\s*:/i',
        'size_rule' => '/[\'"]size\s*:/i',
        'between_rule' => '/[\'"]between\s*:/i',
        'fluent_max_rule' => '/->\s*max\s*\(/i',
        'fluent_size_rule' => '/->\s*size\s*\(/i',
        'fluent_between_rule' => '/->\s*between\s*\(/i',
    ];

    public function __construct(
        private RouteSecurityInspector $routes,
        private PhpSourceInspector $source,
    ) {
    }

    public function id(): string
    {
        return 'laravel.uploads.validation';
    }

    public function name(): string
    {
        return 'Uploaded file validation';
    }

    public function category(): string
    {
        return 'input validation';
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

        $routeLimit = max(1, min(5000, (int) $context->config('cybear.posture.max_source_routes', 500)));
        $evidenceLimit = max(1, min(100, (int) $context->config('cybear.posture.max_evidence_items', 25)));
        $inspected = 0;
        $attempted = 0;
        $uploadCount = 0;
        $unknown = 0;
        $outOfScope = 0;
        $incompleteCount = 0;
        $incomplete = [];
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
            $inspected++;

            $handlerSources = $this->source->relatedMethods($context, $method);
            $validationSources = $handlerSources;
            foreach ($this->source->formRequestTypes($context, $method) as $formRequest) {
                $rules = $this->source->method($context, $formRequest, 'rules');
                if ($rules->available) {
                    $validationSources[] = $rules;
                }
            }

            if (!$this->handlesUpload($handlerSources)
                && $this->signals($validationSources, self::FILE_RULE_SIGNALS) === []) {
                continue;
            }
            $uploadCount++;

            $fields = [];
            foreach ($handlerSources as $handlerSource) {
                $fields = [...$fields, ...$handlerSource->requestFileFields()];
            }
            $fields = array_values(array_unique($fields));

            $typeSignals = [];
            $sizeSignals = [];
            $missingTypeFields = [];
            $missingSizeFields = [];

            if ($fields !== []) {
                foreach ($fields as $field) {
                    $fieldTypeSignals = $this->fieldSignals($validationSources, $field, self::TYPE_CONSTRAINTS);
                    $fieldSizeSignals = $this->fieldSignals($validationSources, $field, self::SIZE_CONSTRAINTS);
                    $typeSignals = [...$typeSignals, ...$fieldTypeSignals];
                    $sizeSignals = [...$sizeSignals, ...$fieldSizeSignals];
                    if ($fieldTypeSignals === []) {
                        $missingTypeFields[] = $field;
                    }
                    if ($fieldSizeSignals === []) {
                        $missingSizeFields[] = $field;
                    }
                }
            } else {
                $typeSignals = $this->signals($validationSources, self::TYPE_CONSTRAINTS);
                $sizeSignals = $this->signals($validationSources, self::SIZE_CONSTRAINTS);
            }

            $typeSignals = array_values(array_unique($typeSignals));
            $sizeSignals = array_values(array_unique($sizeSignals));
            if (($fields === [] && $typeSignals !== [] && $sizeSignals !== [])
                || ($fields !== [] && $missingTypeFields === [] && $missingSizeFields === [])) {
                continue;
            }

            $incompleteCount++;
            $routeEvidence = [
                ...$this->routes->evidence($route),
                'action' => substr($method->action, 0, 500),
                'location' => $method->location(),
                'upload_fields' => $fields,
                'missing_type_constraint_fields' => $missingTypeFields,
                'missing_size_constraint_fields' => $missingSizeFields,
                'has_type_constraint' => $typeSignals !== [],
                'has_size_constraint' => $sizeSignals !== [],
                'type_signals' => $typeSignals,
                'size_signals' => $sizeSignals,
            ];
            $occurrences[] = new FindingOccurrence(
                identity: [
                    'methods' => $routeEvidence['methods'],
                    'uri' => $routeEvidence['uri'],
                    'action' => $routeEvidence['action'],
                    'upload_fields' => $fields,
                ],
                evidence: $routeEvidence,
            );
            if (count($incomplete) < $evidenceLimit) {
                $incomplete[] = $routeEvidence;
            }
        }

        $evidence = [
            'source_route_attempt_count' => $attempted,
            'locally_inspected_route_count' => $inspected,
            'unavailable_source_route_count' => $unknown,
            'out_of_scope_route_count' => $outOfScope,
            'upload_route_count' => $uploadCount,
            'incomplete_validation_route_count' => $incompleteCount,
            'incomplete_validation_routes' => $incomplete,
            'scan_truncated' => $scanTruncated,
            'evidence_truncated' => $incompleteCount > count($incomplete),
            'source_shared' => false,
        ];

        if ($incompleteCount > 0) {
            return $this->warning(
                'File-upload handling was found without both a verifiable file-type constraint and a size constraint.',
                'Validate every uploaded file with explicit MIME or extension expectations and a maximum size before storage or processing. Keep storage outside executable public paths.',
                $evidence,
                occurrences: $occurrences,
            );
        }

        if ($uploadCount === 0 && $unknown === 0) {
            return $this->skipped('No local controller file-upload handling was detected.', $evidence);
        }

        if ($unknown > 0 || $scanTruncated) {
            return $this->warning(
                'No incomplete upload validation was confirmed, but some local source could not be inspected completely.',
                'Make local controller source readable and raise cybear.posture.max_source_routes if the bounded route limit was reached.',
                $evidence,
                Severity::Medium,
            );
        }

        return $this->pass(
            'Detected upload handlers include verifiable file-type and size constraints.',
            $evidence,
        );
    }

    /**
     * @param list<SourceMethod> $methods
     */
    private function handlesUpload(array $methods): bool
    {
        foreach ($methods as $method) {
            if ($method->hasAnySignal(self::UPLOAD_SIGNALS)) {
                return true;
            }

            foreach ($method->parameterTypes as $type) {
                if ($type === 'Illuminate\\Http\\UploadedFile'
                    || str_ends_with($type, '\\UploadedFile')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param list<SourceMethod> $methods
     * @param array<string, string> $patterns
     * @return list<string>
     */
    private function signals(array $methods, array $patterns): array
    {
        $signals = [];
        foreach ($methods as $method) {
            $signals = [...$signals, ...$method->matchingSignals($patterns)];
        }

        return array_values(array_unique($signals));
    }

    /**
     * @param list<SourceMethod> $methods
     * @param array<string, string> $patterns
     * @return list<string>
     */
    private function fieldSignals(array $methods, string $field, array $patterns): array
    {
        $signals = [];
        foreach ($methods as $method) {
            $signals = [
                ...$signals,
                ...$method->matchingValidationSignalsForField($field, $patterns),
            ];
        }

        return array_values(array_unique($signals));
    }
}
