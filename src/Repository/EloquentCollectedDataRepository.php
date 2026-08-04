<?php

namespace CybearCare\LaravelSecurity\Repository;

use CybearCare\LaravelSecurity\Models\CollectedData;
use CybearCare\LaravelSecurity\Core\Contract\CollectedDataRepositoryInterface;

class EloquentCollectedDataRepository implements CollectedDataRepositoryInterface
{
    public function create(string $type, string $source, array $data, string $checksum): void
    {
        CollectedData::create([
            'collection_type' => $type,
            'data_source' => $source,
            'collected_data' => $data,
            'collected_at' => now(),
            'checksum' => $checksum,
        ]);
    }

    public function findUntransmittedGrouped(): array
    {
        return CollectedData::untransmitted()
            ->orderBy('collected_at', 'asc')
            ->get()
            ->map(fn(CollectedData $record) => $record->toArray())
            ->toArray();
    }

    public function markAsTransmitted(array $ids): void
    {
        CollectedData::whereIn('id', $ids)->update([
            'transmitted' => true,
            'transmitted_at' => now(),
        ]);
    }

    public function count(): int
    {
        return CollectedData::count();
    }

    public function untransmittedCount(): int
    {
        return CollectedData::untransmitted()->count();
    }

    public function latestCollectedAt(): ?string
    {
        return CollectedData::orderBy('collected_at', 'desc')->first()?->collected_at?->toIso8601String();
    }

    public function oldestUntransmittedAt(): ?string
    {
        return CollectedData::untransmitted()
            ->orderBy('collected_at', 'asc')
            ->first()
            ?->collected_at
            ?->toIso8601String();
    }

    public function deleteTransmittedBefore(\DateTimeImmutable $before): int
    {
        return CollectedData::where('transmitted', true)
            ->where('collected_at', '<', $before)
            ->delete();
    }
}
