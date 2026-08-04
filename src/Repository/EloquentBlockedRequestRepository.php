<?php

namespace CybearCare\LaravelSecurity\Repository;

use CybearCare\LaravelSecurity\Models\BlockedRequest;
use CybearCare\LaravelSecurity\Core\Contract\BlockedRequestRepositoryInterface;

class EloquentBlockedRequestRepository implements BlockedRequestRepositoryInterface
{
    public function create(array $data): void
    {
        BlockedRequest::create($data);
    }

    public function findUntransmitted(int $limit = 100): array
    {
        return BlockedRequest::untransmitted()
            ->orderBy('blocked_at', 'asc')
            ->limit($limit)
            ->get()
            ->map(fn(BlockedRequest $record) => $record->toArray())
            ->toArray();
    }

    public function markAsTransmitted(array $ids): void
    {
        BlockedRequest::whereIn('id', $ids)->update([
            'transmitted' => true,
            'transmitted_at' => now(),
        ]);
    }

    public function deleteTransmittedBefore(\DateTimeImmutable $before): int
    {
        return BlockedRequest::where('transmitted', true)
            ->where('blocked_at', '<', $before)
            ->delete();
    }
}
