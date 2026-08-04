<?php

namespace CybearCare\LaravelSecurity\Core\Contract;

interface PackageDataRepositoryInterface
{
    /**
     * @param  array<string, list<array<string, mixed>>>  $packagesByManager
     */
    public function replaceInventory(
        array $packagesByManager,
        \DateTimeImmutable $collectedAt,
    ): void;

    public function count(): int;

    public function untransmittedCount(): int;

    public function deleteTransmittedBefore(\DateTimeImmutable $before): int;
}
