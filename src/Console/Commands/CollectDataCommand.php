<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use Illuminate\Console\Command;
use CybearCare\LaravelSecurity\Services\DataCollectionManager;

class CollectDataCommand extends Command
{
    protected $signature = 'cybear:collect {--type= : Specific collector type to run} {--send : Send data to platform immediately}';
    protected $description = 'Collect security and application data';

    protected DataCollectionManager $collectionManager;

    public function __construct(DataCollectionManager $collectionManager)
    {
        parent::__construct();
        $this->collectionManager = $collectionManager;
    }

    public function handle()
    {
        $this->info('🔍 Cybear Data Collection');
        $this->line('');

        $type = $this->option('type');
        $shouldSend = $this->option('send');

        try {
            if ($type) {
                $this->collectSpecificType($type, $shouldSend);
            } else {
                $this->collectAllData($shouldSend);
            }
        } catch (\Exception $e) {
            $this->error('Data collection failed: ' . $e->getMessage());
            return 1;
        }

        return 0;
    }

    protected function collectSpecificType(string $type, bool $shouldSend): void
    {
        $availableTypes = $this->collectionManager->getAvailableCollectors();
        
        if (!in_array($type, $availableTypes)) {
            $this->error("Unknown collector type: {$type}");
            $this->line('Available types: ' . implode(', ', $availableTypes));
            return;
        }

        $this->info("Collecting {$type} data...");
        
        $data = $this->collectionManager->collectByType($type);
        
        if (empty($data)) {
            $this->warn("No data collected for {$type} (collector may be disabled)");
            return;
        }

        $this->info("✅ Collected {$type} data (" . $this->formatDataSize($data) . ")");
        $this->showDataSummary($type, $data);

        if ($shouldSend) {
            $this->sendToApi([
                'application_id' => config('cybear.app_id', config('app.name')),
                'collection_timestamp' => now()->toISOString(),
                'collectors' => [$type => $data],
            ]);
        }
    }

    protected function collectAllData(bool $shouldSend): void
    {
        $this->info('Collecting all enabled data...');
        
        $data = $this->collectionManager->collectAll();
        $collectors = $data['collectors'] ?? [];
        
        if (empty($collectors)) {
            $this->warn('No data collected (all collectors may be disabled)');
            return;
        }

        $this->info("✅ Data collection completed");
        $this->line("Collectors run: " . count($collectors));
        $this->line("Total data size: " . $this->formatDataSize($data));
        
        foreach ($collectors as $type => $collectorData) {
            $this->showDataSummary($type, $collectorData);
        }

        if ($shouldSend) {
            $this->sendToApi($data);
        } else {
            $this->line('');
            $this->line('💡 Use --send flag to transmit data to Cybear platform');
        }
    }

    protected function showDataSummary(string $type, array $data): void
    {
        switch ($type) {
            case 'packages':
                $composerCount = count($data['composer_packages'] ?? []);
                $npmCount = count($data['npm_packages'] ?? []);
                $this->line("  📦 Packages: {$composerCount} Composer, {$npmCount} NPM");
                break;
                
            case 'security':
                $configCount = 0;
                if (is_array($data)) {
                    $configCount = count($data);
                }
                $this->line("  🔒 Security: {$configCount} configurations analyzed");
                break;
                
            case 'environment':
                $phpVersion = $data['php_config']['version'] ?? $data['php_version'] ?? 'unknown';
                $this->line("  🖥️  Environment: PHP {$phpVersion}");
                break;
                
            case 'application':
                $routeCount = count($data['routes'] ?? []);
                $middlewareCount = count($data['middleware'] ?? []);
                $this->line("  🏗️  Application: {$routeCount} routes, {$middlewareCount} middleware");
                break;
                
            case 'performance':
                $memoryUsage = $data['memory_usage'] ?? 'unknown';
                if (is_array($memoryUsage)) {
                    $memoryUsage = 'unknown';
                }
                $this->line("  ⚡ Performance: {$memoryUsage} memory");
                break;
                
            case 'auth':
                $guardCount = is_array($data['guards'] ?? null) ? count($data['guards']) : 0;
                $userCount = $data['user_statistics']['total_users'] ?? 'unknown';
                // Ensure userCount is a string or number, not array
                if (is_array($userCount)) {
                    $userCount = 'unknown';
                }
                $this->line("  🔐 Auth: {$guardCount} guards, {$userCount} users");
                break;
                
            case 'database':
                $connectionCount = is_array($data['connections'] ?? null) ? count($data['connections']) : 0;
                $migrationCount = $data['migrations']['total_migrations'] ?? 'unknown';
                if (is_array($migrationCount)) {
                    $migrationCount = 'unknown';
                }
                $this->line("  🗄️  Database: {$connectionCount} connections, {$migrationCount} migrations");
                break;
                
            case 'filesystem':
                $diskCount = is_array($data['disk_usage'] ?? null) ? count($data['disk_usage']) : 0;
                $sensitiveFiles = is_array($data['sensitive_files'] ?? null) ? count($data['sensitive_files']) : 0;
                $this->line("  📁 Filesystem: {$diskCount} disks, {$sensitiveFiles} sensitive files");
                break;
                
            case 'network':
                $serverSoftware = $data['server_info']['server_software'] ?? 'unknown';
                if (is_array($serverSoftware)) {
                    $serverSoftware = 'unknown';
                }
                $sslActive = $data['ssl_config']['ssl_active'] ?? false;
                $sslStatus = $sslActive ? 'SSL enabled' : 'SSL disabled';
                $this->line("  🌐 Network: {$serverSoftware}, {$sslStatus}");
                break;
                
            default:
                $itemCount = is_array($data) ? count($data) : 0;
                $this->line("  {$type}: {$itemCount} items");
        }
    }

    protected function sendToApi(array $data): void
    {
        $this->line('');
        $this->info('📤 Sending data to Cybear platform...');
        
        try {
            $success = $this->collectionManager->sendToApi($data);
            
            if ($success) {
                $this->info('✅ Data sent successfully');
            } else {
                $this->error('❌ Failed to send data');
                $this->line('');
                $this->warn('Common issues:');
                $this->line('  - Domain not verified (run: php artisan cybear:verify-domain)');
                $this->line('  - Invalid API key (check CYBEAR_API_KEY in .env)');
                $this->line('  - Network connectivity issues');
                $this->line('');
                $this->line('Run "php artisan cybear:status" to check your configuration');
            }
        } catch (\Exception $e) {
            $this->error('❌ Error: ' . $e->getMessage());
        }
    }

    protected function formatDataSize(array $data): string
    {
        try {
            $json = json_encode($data);
            if ($json === false) {
                return 'unknown size';
            }
            
            $bytes = strlen($json);
            
            if ($bytes < 1024) {
                return $bytes . ' B';
            } elseif ($bytes < 1048576) {
                return round($bytes / 1024, 1) . ' KB';
            } else {
                return round($bytes / 1048576, 1) . ' MB';
            }
        } catch (\Exception $e) {
            return 'unknown size';
        }
    }
}