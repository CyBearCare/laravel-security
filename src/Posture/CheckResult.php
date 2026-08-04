<?php

namespace CybearCare\LaravelSecurity\Posture;

use CybearCare\LaravelSecurity\Posture\Contracts\SecurityCheck;
use JsonSerializable;

final readonly class CheckResult implements JsonSerializable
{
    public const SCHEMA_VERSION = '2.0';

    /**
     * @param array<string, mixed> $evidence
     * @param list<string> $references
     * @param list<FindingOccurrence> $occurrences
     * @param list<FindingOccurrence> $suppressedOccurrences
     */
    public function __construct(
        public string $checkId,
        public string $name,
        public string $category,
        public CheckStatus $status,
        public Severity $severity,
        public Confidence $confidence,
        public string $summary,
        public array $evidence = [],
        public ?string $remediation = null,
        public array $references = [],
        public float $durationMs = 0.0,
        public CheckScope $scope = CheckScope::Application,
        public array $occurrences = [],
        public array $suppressedOccurrences = [],
    ) {
    }

    public static function error(SecurityCheck $check, float $durationMs): self
    {
        return new self(
            checkId: $check->id(),
            name: $check->name(),
            category: $check->category(),
            status: CheckStatus::Error,
            severity: $check->severity(),
            confidence: $check->confidence(),
            summary: 'The check could not be completed safely.',
            remediation: 'Review the application log for the underlying error, then run this check again.',
            references: $check->references(),
            durationMs: $durationMs,
            scope: $check->scope(),
        );
    }

    public function withDuration(float $durationMs): self
    {
        return new self(
            checkId: $this->checkId,
            name: $this->name,
            category: $this->category,
            status: $this->status,
            severity: $this->severity,
            confidence: $this->confidence,
            summary: $this->summary,
            evidence: $this->evidence,
            remediation: $this->remediation,
            references: $this->references,
            durationMs: $durationMs,
            scope: $this->scope,
            occurrences: $this->occurrences,
            suppressedOccurrences: $this->suppressedOccurrences,
        );
    }

    /**
     * @param list<FindingOccurrence> $active
     * @param list<FindingOccurrence> $suppressed
     */
    public function withOccurrenceDisposition(
        array $active,
        array $suppressed,
        int $invalidSuppressionCount = 0,
    ): self {
        $status = $this->status;
        if ($status->isFinding() && $active === [] && $suppressed !== []) {
            $status = CheckStatus::Suppressed;
        }

        return new self(
            checkId: $this->checkId,
            name: $this->name,
            category: $this->category,
            status: $status,
            severity: $this->severity,
            confidence: $this->confidence,
            summary: $this->summary,
            evidence: [
                ...$this->evidence,
                'active_occurrence_count' => count($active),
                'suppressed_occurrence_count' => count($suppressed),
                'invalid_suppression_count' => $invalidSuppressionCount,
            ],
            remediation: $this->remediation,
            references: $this->references,
            durationMs: $this->durationMs,
            scope: $this->scope,
            occurrences: $active,
            suppressedOccurrences: $suppressed,
        );
    }

    public function fingerprint(): string
    {
        return hash('sha256', self::canonicalJson([
            'check_id' => $this->checkId,
            'scope' => $this->scope->value,
        ]));
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $safeEvidence = EvidenceSanitizer::sanitize($this->evidence);
        $result = [
            'schema_version' => self::SCHEMA_VERSION,
            'check_id' => $this->checkId,
            'name' => $this->name,
            'category' => $this->category,
            'scope' => $this->scope->value,
            'status' => $this->status->value,
            'severity' => $this->severity->value,
            'confidence' => $this->confidence->value,
            'summary' => $this->summary,
            'evidence' => $safeEvidence,
            'remediation' => $this->remediation,
            'references' => $this->references,
            'duration_ms' => round($this->durationMs, 2),
            'occurrences' => [
                ...array_map(
                    fn (FindingOccurrence $occurrence): array => $occurrence->serialize($this->checkId),
                    $this->occurrences,
                ),
                ...array_map(
                    fn (FindingOccurrence $occurrence): array => $occurrence->serialize($this->checkId),
                    $this->suppressedOccurrences,
                ),
            ],
        ];
        $result['fingerprint'] = $this->fingerprint();

        return $result;
    }

    public static function canonicalJson(mixed $value): string
    {
        $normalize = function (mixed $item) use (&$normalize): mixed {
            if (!is_array($item)) {
                return $item;
            }

            if (!array_is_list($item)) {
                ksort($item);
            }

            foreach ($item as $key => $nested) {
                $item[$key] = $normalize($nested);
            }

            return $item;
        };

        return (string) json_encode(
            $normalize($value),
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE,
        );
    }
}
