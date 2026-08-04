<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use CybearCare\LaravelSecurity\Services\DataCollectionManager;
use Illuminate\Console\Command;

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
        $this->info('Cybear Data Collection');
        $this->line('');

        $type = $this->option('type');
        $shouldSend = $this->option('send');

        try {
            $successful = $type
                ? $this->collectSpecificType($type, $shouldSend)
                : $this->collectAllData($shouldSend);
        } catch (\Throwable $exception) {
            $this->error('Data collection failed: '.$exception->getMessage());

            return 1;
        }

        return $successful ? 0 : 1;
    }

    protected function collectSpecificType(string $type, bool $shouldSend): bool
    {
        $availableTypes = $this->collectionManager->getAvailableCollectors();

        if (! in_array($type, $availableTypes)) {
            $this->error("Unknown collector type: {$type}");
            $this->line('Available types: '.implode(', ', $availableTypes));

            return false;
        }

        $this->info("Collecting {$type} data...");

        $progressBar = $this->output->createProgressBar(1);
        $progressBar->setFormat(' [%bar%] %percent:3s%% - %message%');
        $progressBar->setMessage("Collecting {$type} data...");
        $progressBar->start();

        $data = $this->collectionManager->collectByType($type);

        $progressBar->advance();
        $progressBar->setMessage('Collection completed');
        $progressBar->finish();
        $this->line('');
        $this->line('');

        if (empty($data)) {
            $this->warn("No data collected for {$type} (collector may be disabled)");

            return true;
        }

        $this->info("Collected {$type} data (".$this->formatDataSize($data).')');
        $this->showDataSummary($type, $data);

        if ($shouldSend) {
            return $this->sendQueuedData();
        }

        return true;
    }

    protected function collectAllData(bool $shouldSend): bool
    {
        $this->info('Collecting all enabled data...');

        $collectedData = $this->collectionManager->collectAll();
        $collectors = $collectedData['collectors'];
        $health = $collectedData['collection_health'] ?? [];

        if (empty($collectors)) {
            $this->warn('No data collected (all collectors may be disabled)');
        } else {
            $this->info('Data collection completed');
            $this->line('Collectors stored: '.count($collectors));
            $this->line('Total data size: '.$this->formatDataSize($collectedData));

            foreach ($collectors as $type => $collectorData) {
                $this->showDataSummary($type, $collectorData);
            }
        }

        $collectionSuccessful = ! in_array(
            $health['status'] ?? 'healthy',
            ['degraded', 'failed'],
            true,
        );
        if (! $collectionSuccessful) {
            $this->warn('Collection completed with failures:');
            foreach ($health['collectors'] ?? [] as $type => $state) {
                if (is_array($state) && ($state['status'] ?? null) === 'failed') {
                    $this->line("  - {$type}: ".($state['error'] ?? 'Unknown error'));
                }
            }
        }

        if ($shouldSend) {
            return $this->sendQueuedData() && $collectionSuccessful;
        } else {
            $this->line('');
            $this->line('Use --send to transmit the collected data to Cybear.');
        }

        return $collectionSuccessful;
    }

    protected function showDataSummary(string $type, array $data): void
    {
        switch ($type) {
            case 'packages':
                $composerCount = count($data['composer_packages'] ?? []);
                $npmCount = count($data['npm_packages'] ?? []);
                $this->line("  Packages: {$composerCount} Composer, {$npmCount} NPM");
                break;

            case 'security':
                $configCount = 0;
                if (is_array($data)) {
                    $configCount = count($data);
                }
                $this->line("  Security: {$configCount} configurations analyzed");
                break;

            case 'environment':
                $phpVersion = $data['php_config']['version'] ?? $data['php_version'] ?? 'unknown';
                $this->line("  Environment: PHP {$phpVersion}");
                break;

            case 'application':
                $routeCount = count($data['routes'] ?? []);
                $middlewareCount = count($data['middleware'] ?? []);
                $this->line("  Application: {$routeCount} routes, {$middlewareCount} middleware");
                break;

            case 'performance':
                $memoryUsage = $data['memory_usage']['formatted']['current']
                    ?? (isset($data['memory_usage']['current_bytes'])
                        ? number_format($data['memory_usage']['current_bytes'] / 1024 / 1024, 2).' MB'
                        : 'not reported');
                $this->line("  Performance: {$memoryUsage} memory");
                break;

            case 'auth':
                $guardCount = is_array($data['guards'] ?? null) ? count($data['guards']) : 0;
                $userCount = $data['user_statistics']['total_users'] ?? 'unknown';
                if (is_array($userCount)) {
                    $userCount = 'unknown';
                }
                $this->line("  Authentication: {$guardCount} guards, {$userCount} users");
                break;

            case 'database':
                $connectionCount = is_array($data['connections'] ?? null) ? count($data['connections']) : 0;
                $migrationCount = $data['migrations']['total_migrations'] ?? 'unknown';
                if (is_array($migrationCount)) {
                    $migrationCount = 'unknown';
                }
                $this->line("  Database: {$connectionCount} connections, {$migrationCount} migrations");
                break;

            case 'filesystem':
                $diskCount = is_array($data['disk_usage'] ?? null) ? count($data['disk_usage']) : 0;
                $sensitiveFiles = is_array($data['sensitive_files'] ?? null) ? count($data['sensitive_files']) : 0;
                $this->line("  Filesystem: {$diskCount} disks, {$sensitiveFiles} sensitive files");
                break;

            case 'network':
                $serverSoftware = $data['server_info']['server_software'] ?? 'unknown';
                if (is_array($serverSoftware)) {
                    $serverSoftware = 'unknown';
                }
                $sslActive = $data['ssl_config']['ssl_active'] ?? false;
                $sslStatus = $sslActive ? 'SSL enabled' : 'SSL disabled';
                $this->line("  Network: {$serverSoftware}, {$sslStatus}");
                break;

            default:
                $itemCount = is_array($data) ? count($data) : 0;
                $this->line("  {$type}: {$itemCount} items");
        }
    }

    protected function sendQueuedData(): bool
    {
        $this->line('');
        $this->info('Sending queued data to Cybear...');

        try {
            $before = $this->collectionManager->getStorageStats();
            if (($before['pending_total'] ?? 0) === 0) {
                $this->info('No queued records are waiting for transmission.');

                return true;
            }

            $sent = $this->collectionManager->sendUntransmittedData();
            $after = $this->collectionManager->getStorageStats();

            if (! isset($after['error']) && ($after['pending_total'] ?? 0) === 0) {
                $this->info("Sent {$sent} queued record(s) successfully.");

                return true;
            } else {
                $this->error('Data transmission failed.');
                $this->line('');
                $this->warn('Common issues:');
                $this->line('  - Domain not verified (run: php artisan cybear:verify-domain)');
                $this->line('  - Invalid API key (check CYBEAR_API_KEY in .env)');
                $this->line('  - Network connectivity issues');
                $this->line('');
                $this->line('Run "php artisan cybear:status" to check your configuration');
            }
        } catch (\Throwable $exception) {
            $this->error('Data transmission failed: '.$exception->getMessage());
        }

        return false;
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
                return $bytes.' B';
            } elseif ($bytes < 1048576) {
                return round($bytes / 1024, 1).' KB';
            } else {
                return round($bytes / 1048576, 1).' MB';
            }
        } catch (\Exception $e) {
            return 'unknown size';
        }
    }
}
