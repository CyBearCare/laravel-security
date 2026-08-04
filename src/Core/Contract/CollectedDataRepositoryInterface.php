<?php

namespace CybearCare\LaravelSecurity\Core\Contract;

interface CollectedDataRepositoryInterface
{
    public function create(string $type, string $source, array $data, string $checksum): void;

    /**
     * @return array<int, array{id: int|string, collection_type: string, collected_data: array, collected_at: string}>
     */
    public function findUntransmittedGrouped(): array;

    public function markAsTransmitted(array $ids): void;

    public function count(): int;

    public function untransmittedCount(): int;

    public function latestCollectedAt(): ?string;

    public function oldestUntransmittedAt(): ?string;

    public function deleteTransmittedBefore(\DateTimeImmutable $before): int;
}
