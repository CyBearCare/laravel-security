<?php

namespace CybearCare\LaravelSecurity\Services;

use CybearCare\LaravelSecurity\Contracts\DataCollectorInterface;
use CybearCare\LaravelSecurity\Models\CollectedData;
use CybearCare\LaravelSecurity\Models\PackageData;
use CybearCare\LaravelSecurity\Models\AuditLog;
use CybearCare\LaravelSecurity\Models\BlockedRequest;
use Illuminate\Support\Facades\Log;

class DataCollectionManager
{
    protected array $collectors = [];
    protected CybearApiClient $apiClient;
    protected DomainVerificationService $verificationService;

    public function __construct(CybearApiClient $apiClient, DomainVerificationService $verificationService)
    {
        $this->apiClient = $apiClient;
        $this->verificationService = $verificationService;
        $this->registerCollectors();
    }

    protected function registerCollectors(): void
    {
        $collectorClasses = [
            'packages' => PackageCollector::class,
            'security' => SecurityDataCollector::class,
            'environment' => EnvironmentCollector::class,
            'application' => ApplicationStructureCollector::class,
            'performance' => PerformanceCollector::class,
            'auth' => AuthCollector::class,
            'database' => DatabaseCollector::class,
            'filesystem' => FileSystemCollector::class,
            'network' => NetworkCollector::class,
        ];

        foreach ($collectorClasses as $name => $class) {
            try {
                if (class_exists($class)) {
                    $this->collectors[$name] = new $class();
                }
            } catch (\Exception $e) {
                Log::warning("Failed to register collector: {$name}", [
                    'class' => $class,
                    'error' => $e->getMessage()
                ]);
            }
        }
    }

    public function collectAll(): array
    {
        $collectedData = [];
        
        foreach ($this->collectors as $name => $collector) {
            try {
                if ($collector->isEnabled()) {
                    $data = $collector->collect();
                    if (!empty($data)) {
                        $collectedData[$name] = $data;
                        
                        // Store in database
                        $this->storeCollectedData($name, $data);
                    }
                }
            } catch (\Exception $e) {
                Log::warning("Failed to collect data from {$name}", [
                    'collector' => $name,
                    'error' => $e->getMessage()
                ]);
            }
        }

        return [
            'application_id' => config('cybear.app_id') ?: config('app.name'),
            'collection_timestamp' => now()->toISOString(),
            'collectors' => $collectedData,
        ];
    }

    public function collectByType(string $type): array
    {
        if (!isset($this->collectors[$type])) {
            throw new \InvalidArgumentException("Unknown collector type: {$type}");
        }

        $collector = $this->collectors[$type];
        
        if (!$collector->isEnabled()) {
            return [];
        }

        $data = $collector->collect();
        
        if (!empty($data)) {
            // Store in database
            $this->storeCollectedData($type, $data);
        }
        
        return $data;
    }

    public function sendToApi(array $data): bool
    {
        try {
            // Check if domain is verified, auto-verify if needed
            if (!$this->verificationService->isVerified()) {
                Log::info('Domain not verified, attempting auto-verification...');
                $verificationResult = $this->verificationService->autoVerify();
                
                if (!$verificationResult['success']) {
                    $errorMessage = 'Auto-verification failed: ' . ($verificationResult['message'] ?? 'Unknown error');
                    Log::error($errorMessage);
                    throw new \Exception($errorMessage);
                }
                
                Log::info('Domain auto-verified successfully');
            }

            $response = $this->apiClient->sendCollectedData($data);
            
            Log::info('Data collection sent to Cybear platform', [
                'data_size' => strlen(json_encode($data)),
                'collectors_count' => count($data['collectors'] ?? []),
                'response_status' => $response['status'] ?? 'unknown'
            ]);

            return true;
        } catch (\Exception $e) {
            $errorMessage = 'Failed to send data to Cybear: ' . $e->getMessage();
            Log::error($errorMessage, [
                'exception' => get_class($e),
                'trace' => $e->getTraceAsString(),
                'data_size' => strlen(json_encode($data)),
            ]);

            return false;
        }
    }

    public function getAvailableCollectors(): array
    {
        return array_keys($this->collectors);
    }

    public function addCollector(string $name, DataCollectorInterface $collector): void
    {
        $this->collectors[$name] = $collector;
    }

    public function removeCollector(string $name): void
    {
        unset($this->collectors[$name]);
    }

    protected function storeCollectedData(string $type, array $data): void
    {
        try {
            if ($type === 'packages') {
                $this->storePackageData($data);
            }
            
            // Store all data in the general collected_data table
            CollectedData::createFromCollector($type, 'auto_collection', $data);
            
            Log::debug("Stored {$type} data to database", [
                'type' => $type,
                'data_size' => strlen(json_encode($data))
            ]);
            
        } catch (\Exception $e) {
            Log::error("Failed to store {$type} data to database", [
                'type' => $type,
                'error' => $e->getMessage()
            ]);
        }
    }

    protected function storePackageData(array $packageData): void
    {
        try {
            // Store Composer packages
            if (isset($packageData['composer_packages'])) {
                foreach ($packageData['composer_packages'] as $package) {
                    PackageData::updateOrCreate([
                        'package_name' => $package['name'] ?? 'unknown',
                        'package_manager' => 'composer'
                    ], [
                        'version' => $package['version'] ?? null,
                        'installed_version' => $package['version'] ?? null,
                        'package_info' => $package,
                        'collected_at' => now(),
                        'transmitted' => false,
                    ]);
                }
            }
            
            // Store NPM packages
            if (isset($packageData['npm_packages'])) {
                foreach ($packageData['npm_packages'] as $package) {
                    PackageData::updateOrCreate([
                        'package_name' => $package['name'] ?? 'unknown',
                        'package_manager' => 'npm'
                    ], [
                        'version' => $package['version'] ?? null,
                        'installed_version' => $package['version'] ?? null,
                        'package_info' => $package,
                        'collected_at' => now(),
                        'transmitted' => false,
                    ]);
                }
            }
            
        } catch (\Exception $e) {
            Log::error("Failed to store package data", [
                'error' => $e->getMessage()
            ]);
        }
    }

    public function sendUntransmittedData(): int
    {
        $sent = 0;
        
        try {
            // Send collected data (passive data)
            $sent += $this->sendUntransmittedCollectedData();
            
            // Send security events (active data)
            $sent += $this->sendUntransmittedSecurityEvents();
            
        } catch (\Exception $e) {
            Log::error("Failed to send untransmitted data", [
                'error' => $e->getMessage()
            ]);
        }
        
        return $sent;
    }

    protected function sendUntransmittedCollectedData(): int
    {
        $sent = 0;
        
        try {
            // Get untransmitted data grouped by collection time
            $untransmittedData = CollectedData::untransmitted()
                ->orderBy('collected_at', 'desc')
                ->get()
                ->groupBy(function ($item) {
                    return $item->collected_at->format('Y-m-d H:i');
                });
            
            foreach ($untransmittedData as $collectionTime => $dataGroup) {
                $collectedData = [];
                
                foreach ($dataGroup as $data) {
                    $collectedData[$data->collection_type] = $data->collected_data;
                }
                
                $payload = [
                    'type' => 'collected_data',
                    'application_id' => config('cybear.app_id') ?: config('app.name'),
                    'collection_timestamp' => $dataGroup->first()->collected_at->toISOString(),
                    'collectors' => $collectedData,
                ];
                
                if ($this->sendToApi($payload)) {
                    // Mark as transmitted
                    foreach ($dataGroup as $data) {
                        $data->markAsTransmitted();
                    }
                    $sent++;
                }
            }
            
        } catch (\Exception $e) {
            Log::error("Failed to send untransmitted collected data", [
                'error' => $e->getMessage()
            ]);
        }
        
        return $sent;
    }

    protected function sendUntransmittedSecurityEvents(): int
    {
        $sent = 0;
        
        try {
            // Send audit logs
            $sent += $this->sendUntransmittedAuditLogs();
            
            // Send blocked requests
            $sent += $this->sendUntransmittedBlockedRequests();
            
        } catch (\Exception $e) {
            Log::error("Failed to send untransmitted security events", [
                'error' => $e->getMessage()
            ]);
        }
        
        return $sent;
    }

    protected function sendUntransmittedAuditLogs(): int
    {
        $sent = 0;
        
        try {
            // Get untransmitted audit logs in batches
            $batchSize = config('cybear.collectors.batch_size', 100);
            
            AuditLog::where('transmitted', false)
                ->orderBy('occurred_at', 'desc')
                ->chunk($batchSize, function ($logs) use (&$sent) {
                    $auditLogsData = $logs->map(function ($log) {
                        return [
                            'app_id' => config('cybear.app_id', config('app.name')),
                            'event_type' => $log->event_type,
                            'user_id' => $log->user_id,
                            'ip_address' => $log->ip_address,
                            'user_agent' => $log->user_agent,
                            'url' => $log->url,
                            'method' => $log->method,
                            'payload' => $log->payload,
                            'occurred_at' => $log->occurred_at->toISOString(),
                        ];
                    })->toArray();
                    
                    if ($this->apiClient->sendAuditLogs($auditLogsData)) {
                        // Mark as transmitted
                        $logs->each->markAsTransmitted();
                        $sent++;
                    }
                });
                
        } catch (\Exception $e) {
            Log::error("Failed to send audit logs", [
                'error' => $e->getMessage()
            ]);
        }
        
        return $sent;
    }

    protected function sendUntransmittedBlockedRequests(): int
    {
        $sent = 0;
        
        try {
            $batchSize = config('cybear.collectors.batch_size', 100);
            
            BlockedRequest::where('transmitted', false)
                ->orderBy('blocked_at', 'desc')
                ->chunk($batchSize, function ($requests) use (&$sent) {
                    // Get the WAF rule_id for each blocked request
                    $blockedRequestsData = $requests->map(function ($request) {
                        $wafRule = null;
                        if ($request->waf_rule_id) {
                            $wafRule = \CybearCare\LaravelSecurity\Models\WafRule::find($request->waf_rule_id);
                        }
                        
                        return [
                            'ip_address' => $request->ip_address,
                            'user_agent' => $request->user_agent,
                            'url' => $request->url,
                            'method' => $request->method,
                            'headers' => $request->headers,
                            'payload' => $request->payload,
                            'reason' => $request->reason,
                            'waf_rule_id' => $wafRule ? $wafRule->rule_id : null,
                            'incident_id' => $request->incident_id,
                            'session_id' => $request->session_id,
                            'user_id' => $request->user_id,
                            'blocked_at' => $request->blocked_at->toISOString(),
                        ];
                    })->toArray();
                    
                    if ($this->apiClient->sendBlockedRequests($blockedRequestsData)) {
                        $requests->each->markAsTransmitted();
                        $sent++;
                    }
                });
                
        } catch (\Exception $e) {
            Log::error("Failed to send blocked requests", [
                'error' => $e->getMessage()
            ]);
        }
        
        return $sent;
    }


    public function getStorageStats(): array
    {
        try {
            return [
                'total_collections' => CollectedData::count(),
                'untransmitted_collections' => CollectedData::untransmitted()->count(),
                'total_packages' => PackageData::count(),
                'untransmitted_packages' => PackageData::untransmitted()->count(),
                'latest_collection' => CollectedData::latest('collected_at')->first()?->collected_at,
                'oldest_untransmitted' => CollectedData::untransmitted()
                    ->oldest('collected_at')->first()?->collected_at,
            ];
        } catch (\Exception $e) {
            return ['error' => 'Failed to get storage stats: ' . $e->getMessage()];
        }
    }
}