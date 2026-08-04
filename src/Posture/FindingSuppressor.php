<?php

namespace CybearCare\LaravelSecurity\Posture;

use DateTimeImmutable;
use Throwable;

final class FindingSuppressor
{
    /**
     * @param list<array<string, mixed>> $configured
     * @param list<string> $baselineFingerprints
     */
    public function apply(
        CheckResult $result,
        array $configured,
        array $baselineFingerprints = [],
    ): CheckResult {
        if (!$result->status->isFinding()) {
            return $result;
        }

        $baseline = array_fill_keys($baselineFingerprints, true);
        $active = [];
        $suppressed = [];
        $invalid = 0;

        foreach ($result->occurrences as $occurrence) {
            $fingerprint = $occurrence->fingerprint($result->checkId);
            $policy = $this->configuredPolicy($result->checkId, $fingerprint, $configured, $invalid);

            if ($policy === null && isset($baseline[$fingerprint])) {
                $policy = [
                    'kind' => 'baseline',
                    'reason' => 'Present in the supplied baseline.',
                    'expires_at' => null,
                ];
            }

            if ($policy === null) {
                $active[] = $occurrence;
            } else {
                $suppressed[] = $occurrence->suppressedBy($policy);
            }
        }

        if ($result->occurrences === []) {
            $policy = $this->configuredPolicy(
                $result->checkId,
                $result->fingerprint(),
                $configured,
                $invalid,
            );

            if ($policy !== null || isset($baseline[$result->fingerprint()])) {
                $policy ??= [
                    'kind' => 'baseline',
                    'reason' => 'Present in the supplied baseline.',
                    'expires_at' => null,
                ];
                $suppressed[] = (new FindingOccurrence(
                    ['check_id' => $result->checkId],
                    ['check_id' => $result->checkId],
                ))->suppressedBy($policy);
            }
        }

        return $result->withOccurrenceDisposition($active, $suppressed, $invalid);
    }

    /**
     * @param list<array<string, mixed>> $configured
     * @param-out int $invalid
     * @return array{kind: string, reason: string, expires_at: string|null}|null
     */
    private function configuredPolicy(
        string $checkId,
        string $fingerprint,
        array $configured,
        int &$invalid,
    ): ?array {
        foreach ($configured as $entry) {
            $entryCheck = trim((string) ($entry['check_id'] ?? ''));
            $entryFingerprint = trim((string) ($entry['fingerprint'] ?? ''));
            $reason = trim((string) ($entry['reason'] ?? ''));

            if ($reason === '' || ($entryCheck === '' && $entryFingerprint === '')) {
                $invalid++;
                continue;
            }

            if ($entryCheck !== '' && $entryCheck !== $checkId) {
                continue;
            }

            if ($entryFingerprint !== '' && !hash_equals($entryFingerprint, $fingerprint)) {
                continue;
            }

            $expiresAt = $this->expiry($entry['expires_at'] ?? null);
            if (($entry['expires_at'] ?? null) !== null && $expiresAt === null) {
                $invalid++;
                continue;
            }

            if ($expiresAt instanceof DateTimeImmutable
                && $expiresAt < new DateTimeImmutable('today')) {
                continue;
            }

            return [
                'kind' => 'configured',
                'reason' => $reason,
                'expires_at' => $expiresAt?->format('Y-m-d'),
            ];
        }

        return null;
    }

    private function expiry(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || trim((string) $value) === '') {
            return null;
        }

        try {
            $date = DateTimeImmutable::createFromFormat('!Y-m-d', trim((string) $value));
            $errors = DateTimeImmutable::getLastErrors();

            return $date instanceof DateTimeImmutable
                && ($errors === false
                    || ($errors['warning_count'] === 0 && $errors['error_count'] === 0))
                ? $date
                : null;
        } catch (Throwable) {
            return null;
        }
    }
}
