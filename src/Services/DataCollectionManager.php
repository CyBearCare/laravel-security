<?php

namespace CybearCare\LaravelSecurity\Services;

use CybearCare\LaravelSecurity\Core\Api\CybearApiClient;
use CybearCare\LaravelSecurity\Core\Collection\DataCollectionManager as CoreDataCollectionManager;
use CybearCare\LaravelSecurity\Core\Config\CybearConfig;
use CybearCare\LaravelSecurity\Core\Contract\CollectedDataRepositoryInterface;
use CybearCare\LaravelSecurity\Core\Contract\PackageDataRepositoryInterface;
use CybearCare\LaravelSecurity\Models\AuditLog;
use CybearCare\LaravelSecurity\Models\BlockedRequest;
use CybearCare\LaravelSecurity\Models\CollectedData;
use CybearCare\LaravelSecurity\Models\PackageData;
use CybearCare\LaravelSecurity\Models\WafRule;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Psr\Log\LoggerInterface;
use Throwable;

class DataCollectionManager extends CoreDataCollectionManager
{
    public const COLLECTION_HEALTH_CACHE_KEY = 'cybear:collection:health';

    public function __construct(
        CybearApiClient $apiClient,
        LoggerInterface $logger,
        CybearConfig $config,
        CollectedDataRepositoryInterface $collectedDataRepo,
        PackageDataRepositoryInterface $packageDataRepo,
        protected DomainVerificationService $verificationService,
    ) {
        parent::__construct($apiClient, $logger, $config, $collectedDataRepo, $packageDataRepo);
    }

    public function collectAll(): array
    {
        try {
            return parent::collectAll();
        } finally {
            $this->persistCollectionHealth();
        }
    }

    public function collectByType(string $type): array
    {
        try {
            return parent::collectByType($type);
        } finally {
            $this->persistCollectionHealth();
        }
    }

    public function getCollectionHealth(): array
    {
        $health = Cache::get(self::COLLECTION_HEALTH_CACHE_KEY);

        return is_array($health) ? $health : $this->getLastCollectionHealth();
    }

    public function sendToApi(array $data): bool
    {
        try {
            if (! $this->verificationService->isVerified()) {
                $verification = $this->verificationService->autoVerify();
                if (! ($verification['success'] ?? false)) {
                    Log::warning('Cybear telemetry was retained because domain verification failed', [
                        'message' => $verification['message'] ?? 'Unknown error',
                    ]);

                    return false;
                }
            }

            $response = $this->apiClient->sendCollectedData($data);

            return ($response['success'] ?? true) !== false;
        } catch (Throwable $exception) {
            Log::warning('Cybear telemetry send failed; records remain queued', [
                'error' => $exception->getMessage(),
            ]);

            return false;
        }
    }

    public function sendUntransmittedData(): int
    {
        if (! $this->apiClient->isConfigured()) {
            Log::warning('Cybear telemetry was not sent because no API key is configured.');

            return 0;
        }

        if (! $this->verificationService->isVerified()) {
            $verification = $this->verificationService->autoVerify();
            if (! ($verification['success'] ?? false)) {
                Log::warning('Cybear telemetry remains queued until the domain is verified.');

                return 0;
            }
        }

        $sent = 0;
        foreach ([
            'collections' => fn () => $this->sendUntransmittedCollectedData(),
            'audit_logs' => fn () => $this->sendUntransmittedAuditLogs(),
            'blocked_requests' => fn () => $this->sendUntransmittedBlockedRequests(),
        ] as $stream => $send) {
            try {
                $sent += $send();
            } catch (Throwable $exception) {
                Log::error('A Cybear outbox stream could not be processed', [
                    'stream' => $stream,
                    'error' => $exception->getMessage(),
                ]);
            }
        }

        return $sent;
    }

    public function getStorageStats(): array
    {
        try {
            $stats = [
                'total_collections' => CollectedData::count(),
                'untransmitted_collections' => CollectedData::untransmitted()->count(),
                'total_packages' => PackageData::count(),
                'untransmitted_packages' => PackageData::untransmitted()->count(),
                'total_audit_logs' => AuditLog::count(),
                'untransmitted_audit_logs' => AuditLog::untransmitted()->count(),
                'total_blocked_requests' => BlockedRequest::count(),
                'untransmitted_blocked_requests' => BlockedRequest::untransmitted()->count(),
                'latest_collection' => CollectedData::latest('collected_at')->first()?->collected_at,
                'oldest_untransmitted' => CollectedData::untransmitted()
                    ->oldest('collected_at')
                    ->first()
                    ?->collected_at,
            ];
            $stats['pending_total'] = $stats['untransmitted_collections']
                + $stats['untransmitted_audit_logs']
                + $stats['untransmitted_blocked_requests'];

            return $stats;
        } catch (Throwable $exception) {
            return ['error' => 'Failed to get storage stats: '.$exception->getMessage()];
        }
    }

    /**
     * @param  array<string, mixed>  $report
     * @return array{queued: true, transmitted: bool, record_id: int}
     */
    public function queuePostureReport(array $report): array
    {
        $reportId = is_string($report['report_id'] ?? null)
            ? $report['report_id']
            : hash('sha256', (string) json_encode($report));

        $record = CollectedData::create([
            'collection_type' => 'posture',
            'data_source' => 'manual_scan',
            'collected_data' => $report,
            'collected_at' => now(),
            'checksum' => $reportId,
        ]);
        $transmitted = false;

        if ($this->apiClient->isConfigured() && $this->sendCollectedRecord($record)) {
            $record->markAsTransmitted();
            $transmitted = true;
        }

        return [
            'queued' => true,
            'transmitted' => $transmitted,
            'record_id' => (int) $record->getKey(),
        ];
    }

    protected function sendUntransmittedCollectedData(): int
    {
        $sent = 0;

        CollectedData::untransmitted()
            ->orderBy('id')
            ->chunkById($this->batchSize(), function (Collection $records) use (&$sent): void {
                foreach ($records as $record) {
                    if ($this->sendCollectedRecord($record)) {
                        $record->markAsTransmitted();
                        $sent++;

                        if ($record->collection_type === 'packages') {
                            PackageData::untransmitted()
                                ->where('collected_at', '<=', $record->collected_at)
                                ->update(['transmitted' => true, 'transmitted_at' => now()]);
                        }
                    }
                }
            });

        return $sent;
    }

    protected function sendCollectedRecord(CollectedData $record): bool
    {
        return $this->sendToApi([
            'type' => 'collected_data',
            'protocol_version' => '1.0',
            'outbox_id' => $this->outboxId('collection', [$record->id], [
                $record->checksum,
                $record->collected_at->toISOString(),
            ]),
            'application_id' => $this->applicationId(),
            'collection_timestamp' => $record->collected_at->toISOString(),
            'collectors' => [$record->collection_type => $record->collected_data],
        ]);
    }

    protected function sendUntransmittedAuditLogs(): int
    {
        $sent = 0;

        AuditLog::untransmitted()
            ->orderBy('id')
            ->chunkById($this->batchSize(), function (Collection $logs) use (&$sent): void {
                $response = $this->apiClient->sendAuditLogs(
                    $logs->map(fn (AuditLog $log) => [
                        'app_id' => $this->applicationId(),
                        'event_type' => $log->event_type,
                        'user_id' => $log->user_id,
                        'session_id' => $log->session_id,
                        'ip_address' => $log->ip_address,
                        'user_agent' => $log->user_agent,
                        'url' => $log->url,
                        'method' => $log->method,
                        'headers' => $log->headers,
                        'payload' => $log->payload,
                        'context' => $log->context,
                        'response_code' => $log->response_code,
                        'processing_time' => $log->processing_time,
                        'occurred_at' => $log->occurred_at->toISOString(),
                    ])->all(),
                    $this->outboxId(
                        'audit',
                        $logs->modelKeys(),
                        $logs->map(fn (AuditLog $log): array => [
                            $log->event_type,
                            $log->occurred_at->toISOString(),
                        ])->all(),
                    ),
                );

                if ($this->batchWasAcknowledged($response, $logs->count())) {
                    AuditLog::whereKey($logs->modelKeys())->update([
                        'transmitted' => true,
                        'transmitted_at' => now(),
                    ]);
                    $sent += $logs->count();
                }
            });

        return $sent;
    }

    protected function sendUntransmittedBlockedRequests(): int
    {
        $sent = 0;

        BlockedRequest::untransmitted()
            ->orderBy('id')
            ->chunkById($this->batchSize(), function (Collection $requests) use (&$sent): void {
                $ruleIds = $requests->pluck('waf_rule_id')->filter()->unique();
                $rules = WafRule::whereKey($ruleIds)->pluck('rule_id', 'id');

                $response = $this->apiClient->sendBlockedRequests(
                    $requests->map(fn (BlockedRequest $request) => [
                        'ip_address' => $request->ip_address,
                        'user_agent' => $request->user_agent,
                        'url' => $request->url,
                        'method' => $request->method,
                        'headers' => $request->headers,
                        'payload' => $request->payload,
                        'reason' => $request->reason,
                        'waf_rule_id' => $request->waf_rule_key
                            ?: ($rules[$request->waf_rule_id] ?? null),
                        'incident_id' => $request->incident_id,
                        'session_id' => $request->session_id,
                        'user_id' => $request->user_id,
                        'blocked_at' => $request->blocked_at->toISOString(),
                    ])->all(),
                    $this->outboxId(
                        'blocked',
                        $requests->modelKeys(),
                        $requests->map(fn (BlockedRequest $request): array => [
                            $request->incident_id,
                            $request->blocked_at->toISOString(),
                        ])->all(),
                    ),
                );

                if ($this->batchWasAcknowledged($response, $requests->count())) {
                    BlockedRequest::whereKey($requests->modelKeys())->update([
                        'transmitted' => true,
                        'transmitted_at' => now(),
                    ]);
                    $sent += $requests->count();
                }
            });

        return $sent;
    }

    protected function batchWasAcknowledged(array|false $response, int $expected): bool
    {
        if ($response === false
            || ($response['success'] ?? true) === false
            || ($response['failed_count'] ?? 0) !== 0) {
            return false;
        }

        $processed = $response['processed_count'] ?? $response['accepted_count'] ?? null;

        return $processed === null || (int) $processed === $expected;
    }

    protected function batchSize(): int
    {
        return max(1, min(1000, (int) config('cybear.collectors.batch_size', 100)));
    }

    protected function applicationId(): string
    {
        return (string) (config('cybear.app_id') ?: config('app.name'));
    }

    protected function outboxId(string $stream, array $ids, array $fingerprints = []): string
    {
        return hash('sha256', json_encode([
            'application_id' => $this->applicationId(),
            'stream' => $stream,
            'ids' => array_values($ids),
            'fingerprints' => $fingerprints,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    protected function persistCollectionHealth(): void
    {
        try {
            Cache::forever(
                self::COLLECTION_HEALTH_CACHE_KEY,
                $this->getLastCollectionHealth(),
            );
        } catch (Throwable $exception) {
            Log::warning('Cybear collection health could not be persisted', [
                'error_type' => $exception::class,
                'error' => $exception->getMessage(),
            ]);
        }
    }
}
