<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use Illuminate\Console\Command;
use CybearCare\LaravelSecurity\Services\CybearApiClient;
use CybearCare\LaravelSecurity\Services\DataCollectionManager;
use CybearCare\LaravelSecurity\Models\WafRule;
use CybearCare\LaravelSecurity\Models\AuditLog;
use CybearCare\LaravelSecurity\Models\BlockedRequest;

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

    public function handle()
    {
        $this->info('🛡️  Cybear Laravel Security Status');
        $this->line('');

        $this->showConfigurationStatus();
        $this->line('');
        $this->showApiConnectionStatus();
        $this->line('');
        $this->showWafStatus();
        $this->line('');
        $this->showAuditingStatus();
        $this->line('');
        $this->showDataCollectionStatus();
        $this->line('');
        $this->showSecurityMetrics();

        return 0;
    }

    protected function showConfigurationStatus(): void
    {
        $this->line('<fg=blue>📋 Configuration Status</>');
        
        $config = [
            'API Key' => config('cybear.api.key') ? '✅ Configured' : '❌ Not set',
            'API Endpoint' => config('cybear.api.endpoint', 'Not set'),
            'WAF Enabled' => config('cybear.waf.enabled', false) ? '✅ Yes' : '❌ No',
            'WAF Mode' => config('cybear.waf.mode', 'Not set'),
            'Audit Enabled' => config('cybear.audit.enabled', false) ? '✅ Yes' : '❌ No',
            'Rate Limiting' => config('cybear.rate_limiting.enabled', false) ? '✅ Yes' : '❌ No',
        ];

        foreach ($config as $key => $value) {
            $this->line("  {$key}: {$value}");
        }
    }

    protected function showApiConnectionStatus(): void
    {
        $this->line('<fg=blue>🌐 API Connection Status</>');
        
        try {
            $connection = $this->apiClient->testConnection();
            
            if ($connection['success']) {
                $this->line("  Status: <fg=green>✅ Connected</>");
                $this->line("  Response Time: {$connection['response_time']}ms");
                
                if (isset($connection['response']['version'])) {
                    $this->line("  Platform Version: {$connection['response']['version']}");
                }
            } else {
                $this->line("  Status: <fg=red>❌ Failed</>");
                $this->line("  Error: {$connection['error']}");
            }
        } catch (\Exception $e) {
            $this->line("  Status: <fg=red>❌ Error</>");
            $this->line("  Error: {$e->getMessage()}");
        }
    }

    protected function showWafStatus(): void
    {
        $this->line('<fg=blue>🛡️  WAF Status</>');
        
        $rulesCount = WafRule::count();
        $enabledRules = WafRule::where('enabled', true)->count();
        $recentBlocks = BlockedRequest::where('created_at', '>=', now()->subDay())->count();
        
        $this->line("  Total Rules: {$rulesCount}");
        $this->line("  Enabled Rules: {$enabledRules}");
        $this->line("  Blocks (24h): {$recentBlocks}");
        
        if ($rulesCount > 0) {
            $topCategories = WafRule::where('enabled', true)
                ->selectRaw('category, COUNT(*) as count')
                ->groupBy('category')
                ->orderByDesc('count')
                ->limit(3)
                ->get();
                
            $this->line("  Top Categories: " . $topCategories->pluck('category')->implode(', '));
        }
    }

    protected function showAuditingStatus(): void
    {
        $this->line('<fg=blue>📊 Audit Logging Status</>');
        
        $totalLogs = AuditLog::count();
        $recentLogs = AuditLog::where('created_at', '>=', now()->subDay())->count();
        $blockedRequests = BlockedRequest::where('created_at', '>=', now()->subDay())->count();
        
        $this->line("  Total Logs: " . number_format($totalLogs));
        $this->line("  Logs (24h): " . number_format($recentLogs));
        $this->line("  Blocked Requests (24h): {$blockedRequests}");
        
        if ($totalLogs > 0) {
            $topEvents = AuditLog::where('created_at', '>=', now()->subDay())
                ->selectRaw('event_type, COUNT(*) as count')
                ->groupBy('event_type')
                ->orderByDesc('count')
                ->limit(3)
                ->get();
                
            $this->line("  Top Events: " . $topEvents->map(function($event) {
                return "{$event->event_type} ({$event->count})";
            })->implode(', '));
        }
    }

    protected function showDataCollectionStatus(): void
    {
        $this->line('<fg=blue>📦 Data Collection Status</>');
        
        $collectors = $this->collectionManager->getAvailableCollectors();
        
        foreach ($collectors as $collectorName) {
            try {
                $data = $this->collectionManager->collectByType($collectorName);
                $status = '✅';
            } catch (\Exception $e) {
                // If collector is disabled or fails, mark as disabled
                $status = '❌';
            }
            $this->line("  {$collectorName}: {$status}");
        }
        
        $autoSchedule = config('cybear.collectors.auto_schedule', false) ? '✅ Yes' : '❌ No';
        $this->line("  Auto Schedule: {$autoSchedule}");
        
        // Show storage statistics
        $this->showStorageStats();
    }

    protected function showStorageStats(): void
    {
        $stats = $this->collectionManager->getStorageStats();
        
        if (isset($stats['error'])) {
            $this->line("  Database Storage: ❌ {$stats['error']}");
            return;
        }
        
        $this->line("  Database Storage: ✅ Active");
        $this->line("    - Total collections: {$stats['total_collections']}");
        $this->line("    - Pending transmission: {$stats['untransmitted_collections']}");
        $this->line("    - Total packages: {$stats['total_packages']}");
        
        if ($stats['latest_collection']) {
            $this->line("    - Latest: {$stats['latest_collection']->format('Y-m-d H:i:s')}");
        }
    }

    protected function showSecurityMetrics(): void
    {
        $this->line('<fg=blue>📈 Security Metrics (Last 24h)</>');
        
        $metrics = [
            'Total Requests' => AuditLog::where('event_type', 'http_request')
                ->where('created_at', '>=', now()->subDay())
                ->count(),
            'Blocked Requests' => BlockedRequest::where('created_at', '>=', now()->subDay())->count(),
            'Failed Logins' => AuditLog::where('event_type', 'login_failure')
                ->where('created_at', '>=', now()->subDay())
                ->count(),
        ];

        foreach ($metrics as $metric => $value) {
            $formatted = number_format($value);
            $this->line("  {$metric}: {$formatted}");
        }

        // Show top blocked IPs
        $topBlockedIps = BlockedRequest::where('created_at', '>=', now()->subDay())
            ->selectRaw('ip_address, COUNT(*) as count')
            ->groupBy('ip_address')
            ->orderByDesc('count')
            ->limit(3)
            ->get();

        if ($topBlockedIps->count() > 0) {
            $this->line("  Top Blocked IPs: " . $topBlockedIps->map(function($ip) {
                return "{$ip->ip_address} ({$ip->count})";
            })->implode(', '));
        }
    }
}