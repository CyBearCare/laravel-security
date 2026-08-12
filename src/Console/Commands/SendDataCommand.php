<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use CybearCare\LaravelSecurity\Services\DataCollectionManager;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class SendDataCommand extends Command
{
    protected $signature = 'cybear:send {--cleanup : Clean up old transmitted data} {--cleanup-only : Only clean up, do not send data}';

    protected $description = 'Send untransmitted data to Cybear platform';

    protected DataCollectionManager $collectionManager;

    public function __construct(DataCollectionManager $collectionManager)
    {
        parent::__construct();
        $this->collectionManager = $collectionManager;
    }

    public function handle()
    {
        $cleanup = $this->option('cleanup');
        $cleanupOnly = $this->option('cleanup-only');

        if ($cleanupOnly) {
            $this->info('Cybear Data Cleanup');
            $this->line('');
            $this->performCleanup();

            return 0;
        }

        $this->info('Cybear Data Transmission');
        $this->line('');
        $this->showStorageStats();

        $stats = $this->collectionManager->getStorageStats();
        if (isset($stats['error'])) {
            $this->error($stats['error']);

            return 1;
        }

        $untransmittedCount = $stats['pending_total'];

        if ($untransmittedCount === 0) {
            $this->line('No pending data to send.');

            return 0;
        }

        $this->info('Sending untransmitted data...');

        $progressBar = $this->output->createProgressBar($untransmittedCount);
        $progressBar->setFormat(' %current%/%max% [%bar%] %percent:3s%% - %message%');
        $progressBar->setMessage('Sending data...');
        $progressBar->start();

        $sent = $this->collectionManager->sendUntransmittedData();

        $progressBar->advance($untransmittedCount);
        $progressBar->setMessage('Transmission completed');
        $progressBar->finish();
        $this->line('');
        $this->line('');

        if ($sent > 0) {
            $this->info("Sent {$sent} data collection(s).");
        } else {
            $this->warn('No data was transmitted.');
        }

        if ($cleanup) {
            $this->performCleanup();
        }

        $this->line('');
        $this->showStorageStats();

        return 0;
    }

    protected function showStorageStats(): void
    {
        $stats = $this->collectionManager->getStorageStats();

        if (isset($stats['error'])) {
            $this->error('Failed to get storage stats: '.$stats['error']);

            return;
        }

        $this->line('Storage Statistics');
        $this->line("  Total collections: {$stats['total_collections']}");
        $this->line("  Untransmitted: {$stats['untransmitted_collections']}");
        $this->line("  Total packages: {$stats['total_packages']}");
        $this->line("  Package rows awaiting inventory acknowledgement: {$stats['untransmitted_packages']}");
        $this->line("  Untransmitted audit logs: {$stats['untransmitted_audit_logs']}");
        $this->line("  Untransmitted blocked requests: {$stats['untransmitted_blocked_requests']}");
        $this->line("  Queued threat evidence: {$stats['untransmitted_threat_events']}");

        if ($stats['latest_collection']) {
            $this->line("  Latest collection: {$stats['latest_collection']->format('Y-m-d H:i:s')}");
        }

        if ($stats['oldest_untransmitted']) {
            $this->line("  Oldest untransmitted: {$stats['oldest_untransmitted']->format('Y-m-d H:i:s')}");
        }

        $this->line('');
    }

    protected function performCleanup(): void
    {
        $this->info('Cleaning old transmitted data...');

        try {
            $cutoffDate = now()->subDays(max(1, (int) config('cybear.database.retention_days', 30)));
            $auditCutoffDate = now()->subDays(max(1, (int) config('cybear.audit.retention_days', 90)));

            $deletedCollections = DB::table('cybear_collected_data')
                ->where('transmitted', true)
                ->where('transmitted_at', '<', $auditCutoffDate)
                ->delete();

            $deletedPackages = DB::table('cybear_package_data')
                ->where('transmitted', true)
                ->where('transmitted_at', '<', $auditCutoffDate)
                ->delete();

            $deletedAuditLogs = DB::table('cybear_audit_logs')
                ->where('transmitted', true)
                ->where('transmitted_at', '<', $cutoffDate)
                ->delete();

            $deletedBlockedRequests = DB::table('cybear_blocked_requests')
                ->where('transmitted', true)
                ->where('transmitted_at', '<', $cutoffDate)
                ->delete();

            $deletedThreatEvents = DB::table('cybear_threat_events')
                ->where('transmitted', true)
                ->where('transmitted_at', '<', $cutoffDate)
                ->delete();

            $this->info("Cleanup complete: {$deletedCollections} collections, {$deletedPackages} packages, {$deletedAuditLogs} audit logs, {$deletedBlockedRequests} blocked requests, and {$deletedThreatEvents} threat events removed.");

        } catch (\Exception $e) {
            $this->error('Failed to cleanup old data: '.$e->getMessage());
        }
    }
}
