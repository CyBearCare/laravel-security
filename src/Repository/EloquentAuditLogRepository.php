<?php

namespace CybearCare\LaravelSecurity\Repository;

use CybearCare\LaravelSecurity\Core\Contract\AuditLogRepositoryInterface;
use CybearCare\LaravelSecurity\Models\AuditLog;

class EloquentAuditLogRepository implements AuditLogRepositoryInterface
{
    public function create(array $data): void
    {
        $this->makeRoom();
        AuditLog::create($data);
    }

    private function makeRoom(): void
    {
        $maximum = max(100, min(50000, (int) config('cybear.audit.max_outbox_records', 5000)));
        $overflow = AuditLog::query()->count() - $maximum + 1;
        if ($overflow <= 0) {
            return;
        }

        $transmitted = AuditLog::query()->where('transmitted', true)
            ->orderBy('id')->limit($overflow)->pluck('id');
        AuditLog::query()->whereKey($transmitted->all())->delete();
        $overflow -= $transmitted->count();
        if ($overflow > 0) {
            $oldest = AuditLog::query()->orderBy('id')->limit($overflow)->pluck('id');
            AuditLog::query()->whereKey($oldest->all())->delete();
        }
    }

    public function findUntransmitted(int $limit = 100): array
    {
        return AuditLog::untransmitted()
            ->orderBy('occurred_at', 'asc')
            ->limit($limit)
            ->get()
            ->map(fn (AuditLog $log) => $log->toArray())
            ->toArray();
    }

    public function markAsTransmitted(array $ids): void
    {
        AuditLog::whereIn('id', $ids)->update([
            'transmitted' => true,
            'transmitted_at' => now(),
        ]);
    }

    public function deleteTransmittedBefore(\DateTimeImmutable $before): int
    {
        return AuditLog::where('transmitted', true)
            ->where('occurred_at', '<', $before)
            ->delete();
    }
}
