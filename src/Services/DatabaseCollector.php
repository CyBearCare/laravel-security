<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class DatabaseCollector extends BaseDataCollector
{
    public function getCollectorName(): string
    {
        return 'database';
    }

    protected function getConfigKey(): string
    {
        return 'database';
    }

    protected function collectData(): array
    {
        return [
            'connections' => $this->getDatabaseConnections(),
            'default_connection' => config('database.default'),
            'redis_config' => $this->getRedisConfiguration(),
            'migrations' => $this->getMigrationInformation(),
            'database_stats' => $this->getDatabaseStatistics(),
        ];
    }

    protected function getDatabaseConnections(): array
    {
        $connections = [];
        $dbConfig = config('database.connections', []);
        
        foreach ($dbConfig as $name => $config) {
            $connections[$name] = [
                'driver' => $config['driver'] ?? null,
                'host' => !empty($config['host']) ? 'configured' : null,
                'port' => $config['port'] ?? null,
                'database' => !empty($config['database']) ? 'configured' : null,
                'prefix' => $config['prefix'] ?? null,
                'charset' => $config['charset'] ?? null,
                'collation' => $config['collation'] ?? null,
                'strict' => $config['strict'] ?? null,
                'engine' => $config['engine'] ?? null,
                'options' => !empty($config['options']) ? array_keys($config['options']) : [],
                'is_default' => $name === config('database.default'),
                'read_write_hosts' => [
                    'read' => !empty($config['read']['host']) ? 'configured' : null,
                    'write' => !empty($config['write']['host']) ? 'configured' : null,
                ],
            ];
        }
        
        return $connections;
    }

    protected function getRedisConfiguration(): array
    {
        $redisConfig = config('database.redis', []);
        
        if (empty($redisConfig)) {
            return ['configured' => false];
        }
        
        $config = [
            'configured' => true,
            'client' => $redisConfig['client'] ?? null,
            'clusters' => !empty($redisConfig['clusters']),
            'connections' => [],
        ];
        
        if (isset($redisConfig['default'])) {
            $config['connections']['default'] = [
                'host' => !empty($redisConfig['default']['host']) ? 'configured' : null,
                'port' => $redisConfig['default']['port'] ?? null,
                'database' => $redisConfig['default']['database'] ?? null,
                'prefix' => $redisConfig['default']['prefix'] ?? null,
            ];
        }
        
        if (isset($redisConfig['cache'])) {
            $config['connections']['cache'] = [
                'host' => !empty($redisConfig['cache']['host']) ? 'configured' : null,
                'port' => $redisConfig['cache']['port'] ?? null,
                'database' => $redisConfig['cache']['database'] ?? null,
                'prefix' => $redisConfig['cache']['prefix'] ?? null,
            ];
        }
        
        return $config;
    }

    protected function getMigrationInformation(): array
    {
        try {
            // Default Laravel migration table name
            $migrationTable = 'migrations';
            
            // In Laravel, the migration table name is usually just 'migrations'
            // Some configurations might have it under different keys
            $configValue = config('database.migrations');
            if (is_string($configValue) && !empty($configValue)) {
                $migrationTable = $configValue;
            }
            
            // Additional fallback checks for different config structures
            if (is_array($configValue)) {
                if (isset($configValue['table'])) {
                    $migrationTable = $configValue['table'];
                } elseif (isset($configValue['migration_table'])) {
                    $migrationTable = $configValue['migration_table'];
                }
            }
            
            if (!Schema::hasTable($migrationTable)) {
                return ['error' => 'Migration table not found'];
            }
            
            $migrations = DB::table($migrationTable)
                ->orderBy('batch', 'desc')
                ->orderBy('migration', 'desc')
                ->get(['migration', 'batch']);
            
            $info = [
                'total_migrations' => $migrations->count(),
                'latest_batch' => $migrations->first()->batch ?? 0,
                'recent_migrations' => $migrations->take(10)->pluck('migration')->toArray(),
                'migration_table' => $migrationTable,
            ];
            
            return $info;
            
        } catch (\Exception $e) {
            return ['error' => 'Failed to collect migration info: ' . $e->getMessage()];
        }
    }

    protected function getDatabaseStatistics(): array
    {
        try {
            $defaultConnection = config('database.default');
            $driver = config("database.connections.{$defaultConnection}.driver");
            
            $stats = [
                'driver' => $driver,
                'connection_name' => $defaultConnection,
            ];
            
            switch ($driver) {
                case 'mysql':
                    $stats = array_merge($stats, $this->getMysqlStatistics());
                    break;
                    
                case 'pgsql':
                    $stats = array_merge($stats, $this->getPostgresStatistics());
                    break;
                    
                case 'sqlite':
                    $stats = array_merge($stats, $this->getSqliteStatistics());
                    break;
                    
                default:
                    $stats['tables'] = $this->getGenericTableList();
            }
            
            return $stats;
            
        } catch (\Exception $e) {
            return ['error' => 'Failed to collect database statistics: ' . $e->getMessage()];
        }
    }

    protected function getMysqlStatistics(): array
    {
        try {
            $stats = [];
            
            // Get version
            $version = DB::select('SELECT VERSION() as version')[0]->version ?? null;
            $stats['version'] = $version;
            
            // Get table count
            $tables = DB::select('SHOW TABLES');
            $stats['table_count'] = count($tables);
            
            // Get database size (approximate)
            $dbName = config('database.connections.' . config('database.default') . '.database');
            if ($dbName) {
                $sizeQuery = DB::select("
                    SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 1) AS size_mb 
                    FROM information_schema.tables 
                    WHERE table_schema = ?
                ", [$dbName]);
                
                $stats['size_mb'] = $sizeQuery[0]->size_mb ?? null;
            }
            
            return $stats;
            
        } catch (\Exception $e) {
            return ['mysql_error' => $e->getMessage()];
        }
    }

    protected function getPostgresStatistics(): array
    {
        try {
            $stats = [];
            
            // Get version
            $version = DB::select('SELECT version()')[0]->version ?? null;
            $stats['version'] = $version;
            
            // Get table count
            $tableCount = DB::select("
                SELECT COUNT(*) as count 
                FROM information_schema.tables 
                WHERE table_type = 'BASE TABLE' 
                AND table_schema NOT IN ('information_schema', 'pg_catalog')
            ")[0]->count ?? 0;
            
            $stats['table_count'] = $tableCount;
            
            return $stats;
            
        } catch (\Exception $e) {
            return ['postgres_error' => $e->getMessage()];
        }
    }

    protected function getSqliteStatistics(): array
    {
        try {
            $stats = [];
            
            // Get SQLite version
            $version = DB::select('SELECT sqlite_version() as version')[0]->version ?? null;
            $stats['version'] = $version;
            
            // Get table count
            $tables = DB::select("SELECT name FROM sqlite_master WHERE type='table'");
            $stats['table_count'] = count($tables);
            
            // Get database file size
            $dbPath = config('database.connections.' . config('database.default') . '.database');
            if ($dbPath && file_exists($dbPath)) {
                $stats['file_size_mb'] = round(filesize($dbPath) / 1024 / 1024, 1);
            }
            
            return $stats;
            
        } catch (\Exception $e) {
            return ['sqlite_error' => $e->getMessage()];
        }
    }

    protected function getGenericTableList(): array
    {
        try {
            $tables = Schema::getAllTables();
            return [
                'count' => count($tables),
                'tables' => array_slice(array_column($tables, 'name'), 0, 20), // First 20 tables
            ];
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }
}