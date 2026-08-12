<?php

namespace CybearCare\LaravelSecurity\Repository;

use CybearCare\LaravelSecurity\Core\Contract\BlockedRequestRepositoryInterface;
use CybearCare\LaravelSecurity\Models\BlockedRequest;

class EloquentBlockedRequestRepository implements BlockedRequestRepositoryInterface
{
    public function create(array $data): void
    {
        $this->makeRoom();
        BlockedRequest::create($data);
    }

    private function makeRoom(): void
    {
        $maximum = max(100, min(50000, (int) config('cybear.audit.max_outbox_records', 5000)));
        $overflow = BlockedRequest::query()->count() - $maximum + 1;
        if ($overflow <= 0) {
            return;
        }

        $transmitted = BlockedRequest::query()->where('transmitted', true)
            ->orderBy('id')->limit($overflow)->pluck('id');
        BlockedRequest::query()->whereKey($transmitted->all())->delete();
        $overflow -= $transmitted->count();
        if ($overflow > 0) {
            $oldest = BlockedRequest::query()->orderBy('id')->limit($overflow)->pluck('id');
            BlockedRequest::query()->whereKey($oldest->all())->delete();
        }
    }

    public function findUntransmitted(int $limit = 100): array
    {
        return BlockedRequest::untransmitted()
            ->orderBy('blocked_at', 'asc')
            ->limit($limit)
            ->get()
            ->map(fn (BlockedRequest $record) => $record->toArray())
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
