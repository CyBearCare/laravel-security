<?php

namespace CybearCare\LaravelSecurity\Core\Contract;

interface AuditLogRepositoryInterface
{
    public function create(array $data): void;

    /**
     * @return array<int, array>
     */
    public function findUntransmitted(int $limit = 100): array;

    public function markAsTransmitted(array $ids): void;

    public function deleteTransmittedBefore(\DateTimeImmutable $before): int;
}
