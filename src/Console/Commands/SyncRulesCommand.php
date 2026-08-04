<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use Illuminate\Console\Command;
use CybearCare\LaravelSecurity\Core\Waf\WafEngine;

class SyncRulesCommand extends Command
{
    protected $signature = 'cybear:sync';
    protected $description = 'Synchronize WAF rules from Cybear platform';

    protected WafEngine $wafEngine;

    public function __construct(WafEngine $wafEngine)
    {
        parent::__construct();
        $this->wafEngine = $wafEngine;
    }

    public function handle()
    {
        $this->info('Synchronizing WAF rules with Cybear...');
        $this->line('');

        $progressBar = $this->output->createProgressBar(3);
        $progressBar->setFormat(' [%bar%] %percent:3s%% - %message%');
        
        try {
            $progressBar->setMessage('Connecting to Cybear API...');
            $progressBar->start();
            
            $progressBar->setMessage('Downloading rules...');
            $progressBar->advance();
            
            $syncedCount = $this->wafEngine->syncRules();
            
            $progressBar->setMessage('Updating local database...');
            $progressBar->advance();
            
            $progressBar->setMessage('Sync completed');
            $progressBar->advance();
            $progressBar->finish();
            $this->line('');
            $this->line('');
            
            if ($syncedCount > 0) {
                $this->info("Synchronized {$syncedCount} rules.");
            } else {
                $this->info('Rules are already current.');
            }
            
            $this->showRulesSummary();
            
        } catch (\Exception $e) {
            $progressBar->finish();
            $this->line('');
            $this->error('Rule synchronization failed: ' . $e->getMessage());
            return 1;
        }

        return 0;
    }

    protected function showRulesSummary(): void
    {
        $this->line('');
        $this->line('<fg=blue>Rules Summary</>');
        
        $rules = \CybearCare\LaravelSecurity\Models\WafRule::all();
        
        $this->line("Total rules: " . $rules->count());
        $this->line("Enabled rules: " . $rules->where('enabled', true)->count());
        
        $categoryCounts = $rules->groupBy('category')->map->count();
        $this->line('');
        $this->line('Rules by category:');
        foreach ($categoryCounts as $category => $count) {
            $this->line("  {$category}: {$count}");
        }
        
        $severityCounts = $rules->groupBy('severity')->map->count();
        $this->line('');
        $this->line('Rules by severity:');
        foreach ($severityCounts as $severity => $count) {
            $label = strtoupper((string) $severity);
            $this->line("  {$label}: {$count}");
        }
    }
}
