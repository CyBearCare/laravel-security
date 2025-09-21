<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class PerformanceCollector extends BaseDataCollector
{
    public function getCollectorName(): string
    {
        return 'performance_collector';
    }

    protected function getConfigKey(): string
    {
        return 'performance';
    }

    protected function collectData(): array
    {
        return [
            'memory_usage' => $this->collectMemoryUsage(),
            'cache_stats' => $this->collectCacheStats(),
            'database_stats' => $this->collectDatabaseStats(),
            'queue_stats' => $this->collectQueueStats(),
        ];
    }

    protected function collectMemoryUsage(): array
    {
        return [
            'current' => memory_get_usage(true),
            'peak' => memory_get_peak_usage(true),
            'limit' => ini_get('memory_limit'),
            'formatted' => [
                'current' => $this->formatBytes(memory_get_usage(true)),
                'peak' => $this->formatBytes(memory_get_peak_usage(true)),
            ],
        ];
    }

    protected function collectCacheStats(): array
    {
        try {
            $driver = config('cache.default');
            
            $stats = [
                'driver' => $driver,
                'stores' => array_keys(config('cache.stores', [])),
            ];

            // Try to get Redis stats if using Redis
            if ($driver === 'redis') {
                try {
                    $redis = Cache::getRedis();
                    $info = $redis->info();
                    $stats['redis_info'] = [
                        'used_memory' => $info['used_memory'] ?? null,
                        'used_memory_human' => $info['used_memory_human'] ?? null,
                        'keyspace_hits' => $info['keyspace_hits'] ?? null,
                        'keyspace_misses' => $info['keyspace_misses'] ?? null,
                    ];
                } catch (\Exception $e) {
                    $stats['redis_error'] = $e->getMessage();
                }
            }

            return $stats;
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    protected function collectDatabaseStats(): array
    {
        try {
            $stats = [
                'default_connection' => config('database.default'),
                'connections' => [],
            ];

            foreach (config('database.connections', []) as $name => $config) {
                try {
                    $connection = DB::connection($name);
                    $pdo = $connection->getPdo();
                    
                    $connectionStats = [
                        'driver' => $config['driver'],
                        'connected' => true,
                    ];

                    // Get query count if available
                    if (method_exists($connection, 'getQueryLog')) {
                        $connectionStats['query_count'] = count($connection->getQueryLog());
                    }

                    $stats['connections'][$name] = $connectionStats;
                } catch (\Exception $e) {
                    $stats['connections'][$name] = [
                        'driver' => $config['driver'],
                        'connected' => false,
                        'error' => $e->getMessage(),
                    ];
                }
            }

            return $stats;
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    protected function collectQueueStats(): array
    {
        try {
            $driver = config('queue.default');
            
            return [
                'driver' => $driver,
                'connections' => array_keys(config('queue.connections', [])),
                'failed_jobs' => $this->getFailedJobsCount(),
            ];
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    protected function getFailedJobsCount(): int
    {
        try {
            return DB::table('failed_jobs')->count();
        } catch (\Exception $e) {
            return 0;
        }
    }

    protected function formatBytes(int $size, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        
        for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
            $size /= 1024;
        }
        
        return round($size, $precision) . ' ' . $units[$i];
    }
}