<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use Carbon\Carbon;
use CybearCare\LaravelSecurity\Core\Api\CybearApiClient;
use CybearCare\LaravelSecurity\Models\AuditLog;
use CybearCare\LaravelSecurity\Models\BlockedRequest;
use CybearCare\LaravelSecurity\Models\WafRule;
use CybearCare\LaravelSecurity\Services\DataCollectionManager;
use CybearCare\LaravelSecurity\Services\SyncOrchestrator;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Throwable;

class StatusCommand extends Command
{
    protected $signature = 'cybear:status';

    protected $description = 'Show Cybear Laravel Security package status';

    protected CybearApiClient $apiClient;

    protected DataCollectionManager $collectionManager;

    public function __construct(CybearApiClient $apiClient, DataCollectionManager $collectionManager)
    {
        parent::__construct();
        $this->apiClient = $apiClient;
        $this->collectionManager = $collectionManager;
    }

    public function handle(): int
    {
        $this->info('Cybear Laravel Security - Status');
        $this->newLine();

        $steps = [
            'showConfigurationStatus',
            'showApiConnectionStatus',
            'showSyncStatus',
            'showWafStatus',
            'showAuditingStatus',
            'showDataCollectionStatus',
            'showSecurityMetrics',
        ];

        foreach ($steps as $method) {
            try {
                $this->{$method}();
            } catch (Throwable $exception) {
                $this->warn("  Unavailable: {$exception->getMessage()}");
            }
            $this->newLine();
        }

        return self::SUCCESS;
    }

    protected function showConfigurationStatus(): void
    {
        $this->line('<fg=blue>Configuration</>');

        $runtimeEnabled = config('cybear.enabled', false) === true;
        $configuredState = static function (bool $configured) use ($runtimeEnabled): string {
            if (! $configured) {
                return '[DISABLED]';
            }

            return $runtimeEnabled ? '[ACTIVE]' : '[CONFIGURED - INACTIVE]';
        };

        $config = [
            'Package' => $runtimeEnabled ? '[ACTIVE]' : '[DISABLED]',
            'API Key' => config('cybear.api.key') ? '[CONFIGURED]' : '[NOT SET]',
            'API Endpoint' => config('cybear.api.endpoint', 'Not set'),
            'WAF' => $configuredState(config('cybear.waf.enabled', false) === true),
            'WAF Mode' => config('cybear.waf.mode', 'Not set'),
            'WAF Failure Policy' => config('cybear.waf.failure_mode', 'allow'),
            'WAF Rule Budget' => number_format((int) config('cybear.waf.max_rules', 500)),
            'WAF Conditions Per Rule' => number_format((int) config('cybear.waf.max_conditions_per_rule', 50)),
            'WAF Inspection Limit' => $this->formatBytes((int) config('cybear.waf.max_inspection_bytes', 131072)),
            'DAST Correlation' => $configuredState(
                config('cybear.dast.correlation_enabled', false) === true
                && is_string(config('cybear.dast.signing_key'))
                && strlen((string) config('cybear.dast.signing_key')) >= 32
                && is_string(config('cybear.dast.audience'))
                && trim((string) config('cybear.dast.audience')) !== ''
            ),
            'Audit' => $configuredState(config('cybear.audit.enabled', false) === true),
            'Rate Limiting' => $configuredState(config('cybear.rate_limiting.enabled', false) === true),
        ];

        foreach ($config as $key => $value) {
            $this->line("  {$key}: {$value}");
        }
    }

    protected function showApiConnectionStatus(): void
    {
        $this->line('<fg=blue>API Connection</>');

        if (! is_string(config('cybear.api.key')) || trim((string) config('cybear.api.key')) === '') {
            $this->line('  Status: [NOT CONFIGURED]');
            $this->line('  Local posture scanning remains available without an API key.');

            return;
        }

        try {
            $connection = $this->apiClient->testConnection();

            if ($connection['success']) {
                $this->line('  Status: <fg=green>[CONNECTED]</>');
                $this->line("  Response Time: {$connection['response_time']}ms");

                if (isset($connection['response']['version'])) {
                    $this->line("  Platform Version: {$connection['response']['version']}");
                }
            } else {
                $this->line('  Status: <fg=red>[FAILED]</>');
                $this->line("  Error: {$connection['error']}");
            }
        } catch (\Exception $e) {
            $this->line('  Status: <fg=red>[ERROR]</>');
            $this->line("  Error: {$e->getMessage()}");
        }
    }

    private function formatBytes(int $bytes): string
    {
        if ($bytes >= 1024 * 1024) {
            return number_format($bytes / (1024 * 1024), 1).' MiB';
        }

        if ($bytes >= 1024) {
            return number_format($bytes / 1024, 1).' KiB';
        }

        return $bytes.' bytes';
    }

    protected function showWafStatus(): void
    {
        $this->line('<fg=blue>WAF</>');

        $rulesCount = WafRule::count();
        $enabledRules = WafRule::where('enabled', true)->count();
        $expiredRules = WafRule::where('enabled', true)
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', now())
            ->count();
        $stagedRules = WafRule::where('enabled', true)
            ->where('rollout_percentage', '<', 100)
            ->count();
        $recentBlocks = BlockedRequest::where('created_at', '>=', now()->subDay())->count();

        $this->line("  Total Rules: {$rulesCount}");
        $this->line("  Enabled Rules: {$enabledRules}");
        $this->line("  Expired Rules: {$expiredRules}");
        $this->line("  Staged Rules: {$stagedRules}");
        $this->line("  Blocks (24h): {$recentBlocks}");

        if ($rulesCount > 0) {
            $topCategories = WafRule::where('enabled', true)
                ->selectRaw('category, COUNT(*) as count')
                ->groupBy('category')
                ->orderByDesc('count')
                ->limit(3)
                ->get();

            $this->line('  Top Categories: '.$topCategories->pluck('category')->implode(', '));
        }
    }

    protected function showAuditingStatus(): void
    {
        $this->line('<fg=blue>Audit Logging</>');

        $totalLogs = AuditLog::count();
        $recentLogs = AuditLog::where('created_at', '>=', now()->subDay())->count();
        $blockedRequests = BlockedRequest::where('created_at', '>=', now()->subDay())->count();

        $this->line('  Total Logs: '.number_format($totalLogs));
        $this->line('  Logs (24h): '.number_format($recentLogs));
        $this->line("  Blocked Requests (24h): {$blockedRequests}");

        if ($totalLogs > 0) {
            $topEvents = AuditLog::where('created_at', '>=', now()->subDay())
                ->selectRaw('event_type, COUNT(*) as count')
                ->groupBy('event_type')
                ->orderByDesc('count')
                ->limit(3)
                ->get();

            $this->line('  Top Events: '.$topEvents->map(function ($event) {
                return "{$event->event_type} ({$event->count})";
            })->implode(', '));
        }
    }

    protected function showDataCollectionStatus(): void
    {
        $this->line('<fg=blue>Data Collection</>');
        $runtimeEnabled = config('cybear.enabled', false) === true;

        foreach ($this->collectionManager->getCollectorStates() as $collectorName => $enabled) {
            $status = ! $enabled
                ? '[DISABLED]'
                : ($runtimeEnabled ? '[ACTIVE]' : '[CONFIGURED - INACTIVE]');
            $this->line("  {$collectorName}: {$status}");
        }

        $autoSchedule = config('cybear.collectors.auto_schedule', false)
            ? ($runtimeEnabled ? '[ACTIVE]' : '[CONFIGURED - INACTIVE]')
            : '[DISABLED]';
        $this->line("  Auto Schedule: {$autoSchedule}");

        $health = $this->collectionManager->getCollectionHealth();
        $healthStatus = strtoupper((string) ($health['status'] ?? 'never'));
        $this->line("  Collection Health: [{$healthStatus}]");

        if (is_string($health['completed_at'] ?? null)) {
            $this->line(
                '  Last Collection Attempt: '
                .Carbon::parse($health['completed_at'])->diffForHumans(),
            );
        }

        foreach ($health['collectors'] ?? [] as $name => $collector) {
            if (! is_array($collector) || ($collector['status'] ?? null) !== 'failed') {
                continue;
            }

            $this->warn("    {$name}: [FAILED] ".($collector['error'] ?? 'Unknown error'));
        }

        $this->showStorageStats();
    }

    protected function showStorageStats(): void
    {
        $stats = $this->collectionManager->getStorageStats();

        if (isset($stats['error'])) {
            $this->line("  Database Storage: [UNAVAILABLE] {$stats['error']}");

            return;
        }

        $this->line('  Database Storage: [ACTIVE]');
        $this->line("    - Total collections: {$stats['total_collections']}");
        $this->line("    - Pending transmission: {$stats['pending_total']}");
        $this->line("    - Total packages: {$stats['total_packages']}");

        if ($stats['latest_collection']) {
            $this->line("    - Latest: {$stats['latest_collection']->format('Y-m-d H:i:s')}");
        }
    }

    protected function showSyncStatus(): void
    {
        $this->line('<fg=blue>Runtime Sync</>');

        if (config('cybear.enabled', false) !== true) {
            $pending = AuditLog::where('transmitted', false)->count()
                + BlockedRequest::where('transmitted', false)->count();

            $this->line('  Status: [INACTIVE - PACKAGE DISABLED]');
            $this->line("  Pending records: {$pending}");
            $this->line('  Local posture scanning is independent of runtime sync.');

            return;
        }

        $schedulerRunning = $this->isSchedulerRunning();
        $this->line('  Scheduler (cron): '.($schedulerRunning ? '[RUNNING]' : '[NOT DETECTED]'));

        $opportunistic = config('cybear.sync.opportunistic', true);
        $this->line('  Opportunistic Sync: '.($opportunistic ? '[ENABLED]' : '[DISABLED]'));

        $syncOperations = [
            'last_send' => 'Last Data Send',
            'last_rules_sync' => 'Last Rules Sync',
            'last_collect' => 'Last Collection',
        ];
        $hasSync = false;
        foreach ($syncOperations as $key => $label) {
            $state = Cache::get(SyncOrchestrator::STATE_PREFIX.$key, []);
            $state = is_array($state) ? $state : [];
            $timestamp = $state['last_success_at'] ?? Cache::get("cybear:sync:{$key}");

            if ($timestamp) {
                $hasSync = true;
                $ago = Carbon::createFromTimestamp((int) $timestamp)->diffForHumans();
                $this->line("  {$label}: {$ago}");
            }

            if (($state['consecutive_failures'] ?? 0) > 0) {
                $failures = (int) $state['consecutive_failures'];
                $retryAt = (int) ($state['next_retry_at'] ?? 0);
                $retry = $retryAt > time()
                    ? Carbon::createFromTimestamp($retryAt)->diffForHumans()
                    : 'on the next sync trigger';
                $error = trim((string) ($state['last_error'] ?? 'Unknown error'));

                $this->warn("    {$failures} consecutive failure(s); retry {$retry}");
                $this->warn("    Last error: {$error}");
            }
        }

        if (! $hasSync) {
            $this->line('  Last Sync: Never (no sync has occurred yet)');
        }

        $storage = $this->collectionManager->getStorageStats();
        if (isset($storage['error'])) {
            $this->warn('  Pending: [UNAVAILABLE] '.$storage['error']);
        } elseif ((int) $storage['pending_total'] > 0) {
            $this->line(sprintf(
                '  <fg=yellow>Pending: %d total (%d collections, %d audit logs, %d blocked requests)</>',
                (int) $storage['pending_total'],
                (int) $storage['untransmitted_collections'],
                (int) $storage['untransmitted_audit_logs'],
                (int) $storage['untransmitted_blocked_requests'],
            ));
        } else {
            $this->line('  Pending: 0');
        }

        if ((int) ($storage['untransmitted_packages'] ?? 0) > 0) {
            $this->line(
                '  Package rows awaiting inventory acknowledgement: '
                .(int) $storage['untransmitted_packages'],
            );
        }

        if (! $schedulerRunning && ! $opportunistic) {
            $this->warn('  No sync mechanism is active. Runtime data will remain local.');
            $this->warn('  Set up cron: * * * * * php artisan schedule:run >> /dev/null 2>&1');
            $this->warn('  Or enable: CYBEAR_SYNC_OPPORTUNISTIC=true');
        }
    }

    protected function isSchedulerRunning(): bool
    {
        $heartbeat = (int) Cache::get(SyncOrchestrator::SCHEDULER_HEARTBEAT_KEY, 0);
        $ttl = max(300, (int) config('cybear.sync.scheduler_heartbeat_ttl_seconds', 600));

        return $heartbeat >= (time() - $ttl);
    }

    protected function showSecurityMetrics(): void
    {
        $this->line('<fg=blue>Security Metrics - Last 24 Hours</>');

        try {
            $metrics = [
                'Total Requests' => AuditLog::where('event_type', 'http_request')
                    ->where('created_at', '>=', now()->subDay())
                    ->count(),
                'Blocked Requests' => BlockedRequest::where('created_at', '>=', now()->subDay())->count(),
                'Failed Logins' => AuditLog::where('event_type', 'login_failed')
                    ->where('created_at', '>=', now()->subDay())
                    ->count(),
            ];

            foreach ($metrics as $metric => $value) {
                $formatted = number_format($value);
                $this->line("  {$metric}: {$formatted}");
            }

        } catch (\Exception $e) {
            $this->warn('  Unable to retrieve security metrics: '.$e->getMessage());
        }
    }
}
