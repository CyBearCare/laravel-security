<?php

namespace CybearCare\LaravelSecurity\Core\Contract;

interface WafRuleRepositoryInterface
{
    /**
     * @return array<int, array{rule_id: string, name: string, description: ?string, category: string, severity: string, conditions: array, action: string, action_params: ?array, enabled: bool, priority: int, source: string, metadata: ?array}>
     */
    public function findEnabledOrderedByPriority(): array;

    public function updateOrCreateByRuleId(string $ruleId, array $data): void;

    public function deleteBySourceExcludingIds(string $source, array $ruleIds): int;

    public function incrementTriggerCount(string $ruleId): void;

    public function updateLastTriggered(string $ruleId, \DateTimeImmutable $at): void;

    public function findByRuleId(string $ruleId): ?array;
}
