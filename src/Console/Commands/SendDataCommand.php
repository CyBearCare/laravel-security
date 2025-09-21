<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use CybearCare\LaravelSecurity\Services\DataCollectionManager;

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
            $this->info('🧹 Cybear Data Cleanup');
            $this->line('');
            $this->performCleanup();
            return 0;
        }
        
        $this->info('📤 Cybear Data Transmission');
        $this->line('');

        // Show storage stats first
        $this->showStorageStats();
        
        // Get count of untransmitted data first
        $stats = $this->collectionManager->getStorageStats();
        $untransmittedCount = $stats['untransmitted_collections'] + $stats['untransmitted_packages'];
        
        if ($untransmittedCount === 0) {
            $this->warn('⚠️  No untransmitted data to send');
            return 0;
        }
        
        // Send untransmitted data with progress bar
        $this->info('Sending untransmitted data...');
        
        $progressBar = $this->output->createProgressBar($untransmittedCount);
        $progressBar->setFormat(' %current%/%max% [%bar%] %percent:3s%% - %message%');
        $progressBar->setMessage('Sending data...');
        $progressBar->start();
        
        $sentCount = 0;
        
        // This is a simplified progress tracking - in reality the sendUntransmittedData
        // method would need to be refactored to support progress callbacks
        $sent = $this->collectionManager->sendUntransmittedData();
        
        $progressBar->advance($untransmittedCount);
        $progressBar->setMessage('Transmission completed');
        $progressBar->finish();
        $this->line('');
        $this->line('');
        
        if ($sent > 0) {
            $this->info("✅ Successfully sent {$sent} data collection(s)");
        } else {
            $this->warn('⚠️  Transmission failed');
        }
        
        // Cleanup old data if requested
        if ($cleanup) {
            $this->performCleanup();
        }
        
        // Show updated stats
        $this->line('');
        $this->showStorageStats();

        return 0;
    }

    protected function showStorageStats(): void
    {
        $stats = $this->collectionManager->getStorageStats();
        
        if (isset($stats['error'])) {
            $this->error('Failed to get storage stats: ' . $stats['error']);
            return;
        }
        
        $this->line('📊 Storage Statistics:');
        $this->line("  Total collections: {$stats['total_collections']}");
        $this->line("  Untransmitted: {$stats['untransmitted_collections']}");
        $this->line("  Total packages: {$stats['total_packages']}");
        $this->line("  Untransmitted packages: {$stats['untransmitted_packages']}");
        
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
        $this->info('🧹 Cleaning up old transmitted data...');
        
        try {
            $retentionDays = config('cybear.database.retention_days', 30);
            $cutoffDate = now()->subDays($retentionDays);
            
            // Delete old transmitted data
            $deletedCollections = DB::table('cybear_collected_data')
                ->where('transmitted', true)
                ->where('transmitted_at', '<', $cutoffDate)
                ->delete();
                
            $deletedPackages = DB::table('cybear_package_data')
                ->where('transmitted', true)
                ->where('transmitted_at', '<', $cutoffDate)
                ->delete();
            
            // Delete old transmitted audit logs
            $deletedAuditLogs = DB::table('cybear_audit_logs')
                ->where('transmitted', true)
                ->where('transmitted_at', '<', $cutoffDate)
                ->delete();
            
            // Delete old transmitted blocked requests
            $deletedBlockedRequests = DB::table('cybear_blocked_requests')
                ->where('transmitted', true)
                ->where('transmitted_at', '<', $cutoffDate)
                ->delete();
            
            $this->info("✅ Cleaned up {$deletedCollections} collections, {$deletedPackages} packages, {$deletedAuditLogs} audit logs, and {$deletedBlockedRequests} blocked requests");
            
        } catch (\Exception $e) {
            $this->error('Failed to cleanup old data: ' . $e->getMessage());
        }
    }
}