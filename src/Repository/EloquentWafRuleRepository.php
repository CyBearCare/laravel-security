<?php

namespace CybearCare\LaravelSecurity\Repository;

use CybearCare\LaravelSecurity\Core\Contract\WafRuleRepositoryInterface;
use CybearCare\LaravelSecurity\Models\WafRule;

class EloquentWafRuleRepository implements WafRuleRepositoryInterface
{
    /**
     * @return array<int, array{rule_id: string, name: string, description: ?string, category: string, severity: string, conditions: array, action: string, action_params: ?array, enabled: bool, priority: int, source: string, metadata: ?array}>
     */
    public function findEnabledOrderedByPriority(): array
    {
        return WafRule::where('enabled', true)
            ->orderByDesc('priority')
            ->orderByRaw(
                "CASE severity
                    WHEN 'critical' THEN 4
                    WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 1
                    ELSE 0
                END DESC"
            )
            ->orderBy('rule_id')
            ->limit(5001)
            ->get()
            ->map(fn (WafRule $rule) => $rule->toArray())
            ->toArray();
    }

    public function updateOrCreateByRuleId(string $ruleId, array $data): void
    {
        WafRule::updateOrCreate(
            ['rule_id' => $ruleId],
            $data
        );
    }

    public function deleteBySourceExcludingIds(string $source, array $ruleIds): int
    {
        $query = WafRule::where('source', $source);

        return ($ruleIds === [] ? $query : $query->whereNotIn('rule_id', $ruleIds))->delete();
    }

    public function incrementTriggerCount(string $ruleId): void
    {
        WafRule::where('rule_id', $ruleId)->increment('trigger_count');
    }

    public function updateLastTriggered(string $ruleId, \DateTimeImmutable $at): void
    {
        WafRule::where('rule_id', $ruleId)->update([
            'last_triggered' => $at,
        ]);
    }

    public function findByRuleId(string $ruleId): ?array
    {
        return WafRule::where('rule_id', $ruleId)->first()?->toArray();
    }
}
