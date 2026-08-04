<?php

namespace CybearCare\LaravelSecurity\Repository;

use CybearCare\LaravelSecurity\Models\AuditLog;
use CybearCare\LaravelSecurity\Core\Contract\AuditLogRepositoryInterface;

class EloquentAuditLogRepository implements AuditLogRepositoryInterface
{
    public function create(array $data): void
    {
        AuditLog::create($data);
    }

    public function findUntransmitted(int $limit = 100): array
    {
        return AuditLog::untransmitted()
            ->orderBy('occurred_at', 'asc')
            ->limit($limit)
            ->get()
            ->map(fn(AuditLog $log) => $log->toArray())
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
