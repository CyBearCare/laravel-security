<?php

namespace CybearCare\LaravelSecurity\Services;

use CybearCare\LaravelSecurity\Core\Waf\WafEngine;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use Throwable;

class SyncOrchestrator
{
    public const SCHEDULER_HEARTBEAT_KEY = 'cybear:sync:scheduler_heartbeat';

    public const STATE_PREFIX = 'cybear:sync:state:';

    private const OPERATIONS = [
        'last_collect',
        'last_send',
        'last_rules_sync',
    ];

    public function __construct(
        protected DataCollectionManager $dataManager,
        protected WafEngine $wafEngine,
    ) {}


    public function shouldRun(): bool
    {
        return config('cybear.enabled', false)
            && config('cybear.sync.opportunistic', true)
            && $this->environmentAllowsSync();
    }

    /**
     * @return array{
     *     locked: bool,
     *     operations: array<string, array{ran: bool, success: bool|null, result?: array}>
     * }
     */
    public function runDueSyncs(string $source = 'request'): array
    {
        $summary = ['locked' => false, 'operations' => []];

        if (! config('cybear.enabled', false) || ! $this->environmentAllowsSync()) {
            return $summary;
        }

        $now = now()->timestamp;
        if ($source === 'scheduler') {
            Cache::put(
                self::SCHEDULER_HEARTBEAT_KEY,
                $now,
                max(300, (int) config('cybear.sync.scheduler_heartbeat_ttl_seconds', 600)),
            );
        }

        if (! $this->hasDueOperation($now)) {
            return $summary;
        }

        try {
            $result = Cache::lock(
                'cybear:runtime-sync',
                max(60, (int) config('cybear.sync.lock_seconds', 300)),
            )->get(function () use ($now): array {
                $operations = [];

                $collected = $this->operationEnabled('last_collect')
                    ? $this->runWhenDue(
                        'last_collect',
                        (int) config('cybear.sync.collect_interval_seconds', 7200),
                        fn (): array => $this->collect(),
                        $now,
                    )
                    : ['ran' => false, 'success' => null];
                $operations['last_collect'] = $collected;

                $operations['last_send'] = $this->operationEnabled('last_send')
                    ? $this->runWhenDue(
                        'last_send',
                        (int) config('cybear.sync.send_interval_seconds', 900),
                        fn (): array => $this->sendPending(),
                        $now,
                        $collected['ran'],
                    )
                    : ['ran' => false, 'success' => null];

                $operations['last_rules_sync'] = $this->operationEnabled('last_rules_sync')
                    ? $this->runWhenDue(
                        'last_rules_sync',
                        (int) config('cybear.sync.rules_interval_seconds', 21600),
                        fn (): array => ['rules_synced' => $this->wafEngine->syncRules()],
                        $now,
                    )
                    : ['ran' => false, 'success' => null];

                return ['locked' => true, 'operations' => $operations];
            });

            return is_array($result) ? $result : $summary;
        } catch (Throwable $exception) {
            Log::warning('Cybear runtime sync could not acquire or use its cache lock', [
                'error_type' => $exception::class,
                'error' => $exception->getMessage(),
            ]);

            return $summary;
        }
    }

    protected function hasDueOperation(int $now): bool
    {
        foreach (self::OPERATIONS as $operation) {
            if (! $this->operationEnabled($operation)) {
                continue;
            }

            if ($this->isDue($operation, $this->intervalFor($operation), $now)) {
                return true;
            }
        }

        return false;
    }

    protected function environmentAllowsSync(): bool
    {
        $runningTests = app()->environment('testing')
            || defined('PHPUNIT_COMPOSER_INSTALL');

        return ! $runningTests
            || config('cybear.sync.in_testing', false) === true;
    }

    protected function operationEnabled(string $operation): bool
    {
        return match ($operation) {
            'last_collect' => config('cybear.collectors.auto_schedule', true) === true,
            'last_send' => config('cybear.collectors.auto_send', true) === true,
            'last_rules_sync' => config('cybear.waf.auto_sync', true) === true,
            default => false,
        };
    }

    protected function intervalFor(string $operation): int
    {
        return match ($operation) {
            'last_collect' => (int) config('cybear.sync.collect_interval_seconds', 7200),
            'last_send' => (int) config('cybear.sync.send_interval_seconds', 900),
            'last_rules_sync' => (int) config('cybear.sync.rules_interval_seconds', 21600),
            default => 3600,
        };
    }

    /**
     * @return array{ran: bool, success: bool|null, result?: array}
     */
    protected function runWhenDue(
        string $operation,
        int $interval,
        callable $callback,
        int $now,
        bool $force = false,
    ): array {
        if (! $this->isDue($operation, $interval, $now, $force)) {
            return ['ran' => false, 'success' => null];
        }

        $state = $this->state($operation);
        $state['last_attempt_at'] = $now;
        Cache::forever(self::STATE_PREFIX.$operation, $state);

        try {
            $result = $callback();
            $successState = [
                'last_attempt_at' => $now,
                'last_success_at' => $now,
                'last_failure_at' => null,
                'last_error' => null,
                'consecutive_failures' => 0,
                'next_retry_at' => null,
                'last_result' => is_array($result) ? $result : [],
            ];

            Cache::forever("cybear:sync:{$operation}", $now);
            Cache::forever(self::STATE_PREFIX.$operation, $successState);

            return [
                'ran' => true,
                'success' => true,
                'result' => $successState['last_result'],
            ];
        } catch (Throwable $exception) {
            $failures = max(0, (int) ($state['consecutive_failures'] ?? 0)) + 1;
            $backoff = $this->backoffSeconds($failures);
            $failureState = [
                'last_attempt_at' => $now,
                'last_success_at' => $state['last_success_at'] ?? null,
                'last_failure_at' => $now,
                'last_error' => substr($exception->getMessage(), 0, 1000),
                'consecutive_failures' => $failures,
                'next_retry_at' => $now + $backoff,
                'last_result' => $state['last_result'] ?? [],
            ];

            Cache::forever(self::STATE_PREFIX.$operation, $failureState);
            Log::warning("Cybear sync operation {$operation} failed; it will be retried", [
                'error_type' => $exception::class,
                'error' => $exception->getMessage(),
                'consecutive_failures' => $failures,
                'retry_in_seconds' => $backoff,
            ]);

            return ['ran' => true, 'success' => false];
        }
    }

    protected function isDue(string $operation, int $interval, int $now, bool $force = false): bool
    {
        $state = $this->state($operation);
        $nextRetry = (int) ($state['next_retry_at'] ?? 0);

        if ($nextRetry > $now) {
            return false;
        }

        if ($force) {
            return true;
        }

        $lastSuccess = (int) ($state['last_success_at']
            ?? Cache::get("cybear:sync:{$operation}", 0));

        return ($now - $lastSuccess) >= max(60, $interval);
    }

    protected function state(string $operation): array
    {
        $state = Cache::get(self::STATE_PREFIX.$operation, []);

        return is_array($state) ? $state : [];
    }

    protected function backoffSeconds(int $failures): int
    {
        $base = max(15, (int) config('cybear.sync.failure_backoff_seconds', 60));
        $maximum = max($base, (int) config('cybear.sync.max_failure_backoff_seconds', 3600));
        $exponent = min(16, max(0, $failures - 1));

        return min($maximum, $base * (2 ** $exponent));
    }

    /**
     * @return array{collectors: int}
     */
    protected function collect(): array
    {
        $payload = $this->dataManager->collectAll();
        $health = is_array($payload['collection_health'] ?? null)
            ? $payload['collection_health']
            : [];
        $status = (string) ($health['status'] ?? 'healthy');

        if (in_array($status, ['degraded', 'failed'], true)) {
            $failedCollectors = [];
            foreach ($health['collectors'] ?? [] as $name => $state) {
                if (is_array($state) && ($state['status'] ?? null) === 'failed') {
                    $failedCollectors[] = (string) $name;
                }
            }
            $failed = implode(', ', $failedCollectors);

            throw new RuntimeException(
                'Collection completed with failed collectors'
                .($failed !== '' ? ": {$failed}." : '.'),
            );
        }

        return [
            'collectors' => count($payload['collectors'] ?? []),
            'status' => $status,
        ];
    }

    /**
     * @return array{sent: int, pending_before: int, pending_after: int}
     */
    protected function sendPending(): array
    {
        $before = $this->storageStats();
        $sent = $this->dataManager->sendUntransmittedData();
        $after = $this->storageStats();

        if ($after['pending_total'] > 0) {
            throw new RuntimeException(
                "Telemetry transmission is incomplete: {$sent} sent, "
                ."{$after['pending_total']} still pending.",
            );
        }

        return [
            'sent' => $sent,
            'pending_before' => $before['pending_total'],
            'pending_after' => $after['pending_total'],
        ];
    }

    /**
     * @return array{pending_total: int}
     */
    protected function storageStats(): array
    {
        $stats = $this->dataManager->getStorageStats();

        if (isset($stats['error']) || ! isset($stats['pending_total'])) {
            throw new RuntimeException(
                (string) ($stats['error'] ?? 'Cybear storage statistics are unavailable.'),
            );
        }

        return ['pending_total' => max(0, (int) $stats['pending_total'])];
    }
}
