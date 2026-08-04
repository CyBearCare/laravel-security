<?php

namespace CybearCare\LaravelSecurity\Posture;

final readonly class FindingOccurrence
{
    /**
     * @param array<string, mixed> $identity
     * @param array<string, mixed> $evidence
     * @param array{kind: string, reason: string, expires_at?: string|null}|null $suppression
     */
    public function __construct(
        public array $identity,
        public array $evidence,
        public ?array $suppression = null,
    ) {
    }

    public function fingerprint(string $checkId): string
    {
        return hash('sha256', CheckResult::canonicalJson([
            'check_id' => $checkId,
            'identity' => EvidenceSanitizer::sanitize($this->identity),
        ]));
    }

    /**
     * @param array{kind: string, reason: string, expires_at?: string|null} $suppression
     */
    public function suppressedBy(array $suppression): self
    {
        return new self($this->identity, $this->evidence, $suppression);
    }

    /**
     * @return array<string, mixed>
     */
    public function serialize(string $checkId): array
    {
        return [
            'fingerprint' => $this->fingerprint($checkId),
            'state' => $this->suppression === null ? 'active' : 'suppressed',
            'evidence' => EvidenceSanitizer::sanitize($this->evidence),
            'suppression' => $this->suppression,
        ];
    }
}
