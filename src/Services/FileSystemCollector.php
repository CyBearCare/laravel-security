<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Storage;

class FileSystemCollector extends BaseDataCollector
{
    public function getCollectorName(): string
    {
        return 'filesystem';
    }

    protected function getConfigKey(): string
    {
        return 'filesystem';
    }

    protected function collectData(): array
    {
        return [
            'storage_config' => $this->getStorageConfiguration(),
            'disk_usage' => $this->getDiskUsage(),
            'directory_permissions' => $this->getDirectoryPermissions(),
            'sensitive_files' => $this->checkSensitiveFiles(),
            'upload_config' => $this->getUploadConfiguration(),
            'log_files' => $this->getLogFileInformation(),
        ];
    }

    protected function getStorageConfiguration(): array
    {
        $disks = [];
        $filesystemConfig = config('filesystems.disks', []);
        
        foreach ($filesystemConfig as $name => $config) {
            $disks[$name] = [
                'driver' => $config['driver'] ?? null,
                'root' => !empty($config['root']) ? 'configured' : null,
                'url' => !empty($config['url']) ? 'configured' : null,
                'visibility' => $config['visibility'] ?? null,
                'is_default' => $name === config('filesystems.default'),
                'bucket' => !empty($config['bucket']) ? 'configured' : null,
                'region' => $config['region'] ?? null,
            ];
        }
        
        return [
            'default_disk' => config('filesystems.default'),
            'default_cloud' => config('filesystems.cloud'),
            'disks' => $disks,
        ];
    }

    protected function getDiskUsage(): array
    {
        $usage = [];
        
        try {
            // Check main Laravel directories
            $directories = [
                'storage' => storage_path(),
                'bootstrap_cache' => $this->getBootstrapCachePath(),
                'public' => public_path(),
                'app' => app_path(),
            ];
            
            foreach ($directories as $name => $path) {
                if (is_dir($path)) {
                    $usage[$name] = [
                        'path' => $path,
                        'size_mb' => $this->getDirectorySize($path),
                        'files_count' => $this->countFiles($path),
                        'writable' => is_writable($path),
                    ];
                }
            }
            
        } catch (\Exception $e) {
            $usage['error'] = 'Failed to collect disk usage: ' . $e->getMessage();
        }
        
        return $usage;
    }

    protected function getDirectoryPermissions(): array
    {
        $permissions = [];
        
        try {
            $criticalDirectories = [
                'storage' => storage_path(),
                'storage/logs' => storage_path('logs'),
                'storage/app' => storage_path('app'),
                'storage/framework' => storage_path('framework'),
                'bootstrap/cache' => $this->getBootstrapCachePath(),
                'public' => public_path(),
                'config' => config_path(),
            ];
            
            foreach ($criticalDirectories as $name => $path) {
                if (is_dir($path)) {
                    $perms = fileperms($path);
                    $permissions[$name] = [
                        'path' => $path,
                        'permissions' => substr(sprintf('%o', $perms), -4),
                        'readable' => is_readable($path),
                        'writable' => is_writable($path),
                        'executable' => is_executable($path),
                        'owner_readable' => ($perms & 0x0100) ? true : false,
                        'owner_writable' => ($perms & 0x0080) ? true : false,
                        'group_readable' => ($perms & 0x0020) ? true : false,
                        'group_writable' => ($perms & 0x0010) ? true : false,
                        'world_readable' => ($perms & 0x0004) ? true : false,
                        'world_writable' => ($perms & 0x0002) ? true : false,
                    ];
                }
            }
            
        } catch (\Exception $e) {
            $permissions['error'] = 'Failed to collect permissions: ' . $e->getMessage();
        }
        
        return $permissions;
    }

    protected function checkSensitiveFiles(): array
    {
        $sensitiveFiles = [];
        
        try {
            $filesToCheck = [
                '.env' => base_path('.env'),
                '.env.example' => base_path('.env.example'),
                'composer.json' => base_path('composer.json'),
                'composer.lock' => base_path('composer.lock'),
                'package.json' => base_path('package.json'),
                'artisan' => base_path('artisan'),
            ];
            
            foreach ($filesToCheck as $name => $path) {
                if (file_exists($path)) {
                    $perms = fileperms($path);
                    $sensitiveFiles[$name] = [
                        'exists' => true,
                        'readable' => is_readable($path),
                        'writable' => is_writable($path),
                        'permissions' => substr(sprintf('%o', $perms), -4),
                        'size_bytes' => filesize($path),
                        'modified' => date('Y-m-d H:i:s', filemtime($path)),
                        'world_readable' => ($perms & 0x0004) ? true : false,
                        'world_writable' => ($perms & 0x0002) ? true : false,
                    ];
                } else {
                    $sensitiveFiles[$name] = ['exists' => false];
                }
            }
            
            // Check for backup files
            $backupPatterns = ['*.bak', '*.backup', '*.old', '*~'];
            $backupFiles = [];
            
            foreach ($backupPatterns as $pattern) {
                $files = glob(base_path($pattern));
                if (!empty($files)) {
                    $backupFiles = array_merge($backupFiles, $files);
                }
            }
            
            $sensitiveFiles['backup_files'] = [
                'count' => count($backupFiles),
                'files' => array_slice($backupFiles, 0, 10), // First 10
            ];
            
        } catch (\Exception $e) {
            $sensitiveFiles['error'] = 'Failed to check sensitive files: ' . $e->getMessage();
        }
        
        return $sensitiveFiles;
    }

    protected function getUploadConfiguration(): array
    {
        $config = [];
        
        try {
            // PHP upload settings
            $config['php'] = [
                'file_uploads' => ini_get('file_uploads') ? true : false,
                'upload_max_filesize' => ini_get('upload_max_filesize'),
                'post_max_size' => ini_get('post_max_size'),
                'max_file_uploads' => ini_get('max_file_uploads'),
                'upload_tmp_dir' => ini_get('upload_tmp_dir') ?: sys_get_temp_dir(),
            ];
            
            // Laravel-specific upload configurations
            if (function_exists('config')) {
                $config['laravel'] = [
                    'upload_path' => config('filesystems.disks.public.root', 'storage/app/public'),
                    'temp_path' => config('filesystems.disks.local.root', 'storage/app'),
                ];
            }
            
        } catch (\Exception $e) {
            $config['error'] = 'Failed to collect upload configuration: ' . $e->getMessage();
        }
        
        return $config;
    }

    protected function getLogFileInformation(): array
    {
        $logInfo = [];
        
        try {
            $logPath = storage_path('logs');
            
            if (!is_dir($logPath)) {
                return ['error' => 'Log directory not found'];
            }
            
            $logFiles = File::files($logPath);
            $totalSize = 0;
            $fileDetails = [];
            
            foreach ($logFiles as $file) {
                $size = $file->getSize();
                $totalSize += $size;
                
                $fileDetails[] = [
                    'name' => $file->getFilename(),
                    'size_mb' => round($size / 1024 / 1024, 2),
                    'modified' => date('Y-m-d H:i:s', $file->getMTime()),
                ];
            }
            
            // Sort by size, largest first
            usort($fileDetails, function($a, $b) {
                return $b['size_mb'] <=> $a['size_mb'];
            });
            
            $logInfo = [
                'log_path' => $logPath,
                'total_files' => count($logFiles),
                'total_size_mb' => round($totalSize / 1024 / 1024, 2),
                'largest_files' => array_slice($fileDetails, 0, 5),
                'log_channel' => config('logging.default'),
                'log_level' => config('logging.channels.' . config('logging.default') . '.level', 'debug'),
            ];
            
        } catch (\Exception $e) {
            $logInfo['error'] = 'Failed to collect log information: ' . $e->getMessage();
        }
        
        return $logInfo;
    }

    protected function getDirectorySize(string $directory): float
    {
        try {
            $size = 0;
            $files = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS)
            );
            
            foreach ($files as $file) {
                if ($file->isFile()) {
                    $size += $file->getSize();
                }
            }
            
            return round($size / 1024 / 1024, 2); // Convert to MB
            
        } catch (\Exception $e) {
            return 0;
        }
    }

    protected function countFiles(string $directory): int
    {
        try {
            $count = 0;
            $files = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS)
            );
            
            foreach ($files as $file) {
                if ($file->isFile()) {
                    $count++;
                }
            }
            
            return $count;
            
        } catch (\Exception $e) {
            return 0;
        }
    }

    protected function getBootstrapCachePath(): string
    {
        try {
            // Try using the global helper first
            if (function_exists('bootstrap_path')) {
                return bootstrap_path('cache');
            }
            
            // Fallback to using app() helper
            if (function_exists('app')) {
                return app()->bootstrapPath('cache');
            }
            
            // Last fallback - construct the path manually
            if (function_exists('base_path')) {
                return base_path('bootstrap/cache');
            }
            
            // Final fallback
            return dirname(__DIR__, 3) . '/bootstrap/cache';
            
        } catch (\Exception $e) {
            // If all else fails, return a sensible default
            return dirname(__DIR__, 3) . '/bootstrap/cache';
        }
    }
}