<?php

namespace CybearCare\LaravelSecurity\Posture;

use DateTimeImmutable;
use JsonSerializable;

final readonly class PostureReport implements JsonSerializable
{
    public const SCHEMA_VERSION = '2.0';

    /**
     * @param array<string, mixed> $application
     * @param array<string, mixed> $capabilities
     * @param list<CheckResult> $results
     * @param array<string, mixed> $selection
     */
    public function __construct(
        public DateTimeImmutable $startedAt,
        public DateTimeImmutable $completedAt,
        public array $application,
        public array $capabilities,
        public array $results,
        public array $selection = [],
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function summary(): array
    {
        $statuses = array_fill_keys(array_column(CheckStatus::cases(), 'value'), 0);
        $findings = array_fill_keys(array_column(Severity::cases(), 'value'), 0);
        $highest = null;

        foreach ($this->results as $result) {
            $statuses[$result->status->value]++;

            if (!$result->status->isFinding()) {
                continue;
            }

            $findings[$result->severity->value]++;
            if ($highest === null || $result->severity->rank() > $highest->rank()) {
                $highest = $result->severity;
            }
        }

        $availableChecks = count($this->results);
        $scoredChecks = $statuses[CheckStatus::Pass->value]
            + $statuses[CheckStatus::Warning->value]
            + $statuses[CheckStatus::Fail->value];
        $evaluatedChecks = $scoredChecks + $statuses[CheckStatus::Suppressed->value];

        return [
            'checks' => $availableChecks,
            'available_checks' => $availableChecks,
            'evaluated_checks' => $evaluatedChecks,
            'scored_checks' => $scoredChecks,
            'passed_checks' => $statuses[CheckStatus::Pass->value],
            'finding_checks' => $statuses[CheckStatus::Warning->value]
                + $statuses[CheckStatus::Fail->value],
            'skipped_checks' => $statuses[CheckStatus::Skipped->value],
            'suppressed_checks' => $statuses[CheckStatus::Suppressed->value],
            'error_checks' => $statuses[CheckStatus::Error->value],
            'coverage_percent' => $availableChecks === 0
                ? null
                : (int) round(($evaluatedChecks / $availableChecks) * 100),
            'statuses' => $statuses,
            'findings_by_severity' => $findings,
            'highest_finding_severity' => $highest?->value,
            'complete' => $statuses[CheckStatus::Error->value] === 0,
        ];
    }

    public function hasErrors(): bool
    {
        foreach ($this->results as $result) {
            if ($result->status === CheckStatus::Error) {
                return true;
            }
        }

        return false;
    }

    public function hasFindingAtOrAbove(Severity $threshold): bool
    {
        foreach ($this->results as $result) {
            if ($result->status->isFinding() && $result->severity->meets($threshold)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $results = array_map(
            static fn (CheckResult $result): array => $result->jsonSerialize(),
            $this->results,
        );
        $duration = max(
            0.0,
            ((float) $this->completedAt->format('U.u') - (float) $this->startedAt->format('U.u')) * 1000,
        );
        $reportId = hash('sha256', (string) json_encode([
            'application' => $this->application,
            'capabilities' => $this->capabilities,
            'started_at' => $this->startedAt->format(DATE_ATOM),
            'fingerprints' => array_column($results, 'fingerprint'),
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

        return [
            'schema_version' => self::SCHEMA_VERSION,
            'report_id' => $reportId,
            'scanner' => [
                'name' => 'cybear-laravel',
                'mode' => 'posture',
            ],
            'application' => $this->application,
            'capabilities' => $this->capabilities,
            'started_at' => $this->startedAt->format(DATE_ATOM),
            'completed_at' => $this->completedAt->format(DATE_ATOM),
            'duration_ms' => round($duration, 2),
            'selection' => $this->selection,
            'summary' => $this->summary(),
            'results' => $results,
        ];
    }
}
