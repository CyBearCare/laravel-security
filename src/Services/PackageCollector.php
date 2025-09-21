<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Support\Facades\File;
use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\ProcessFailedException;

class PackageCollector extends BaseDataCollector
{
    public function getCollectorName(): string
    {
        return 'package_collector';
    }

    protected function getConfigKey(): string
    {
        return 'packages';
    }

    protected function collectData(): array
    {
        $data = [
            'composer_packages' => $this->collectComposerPackages(),
            'composer_dependencies' => $this->collectComposerDependencies(),
            'npm_packages' => $this->collectNpmPackages(),
            'npm_dependencies' => $this->collectNpmDependencies(),
            'system_info' => $this->collectSystemInfo(),
            'collection_timestamp' => now()->toISOString(),
        ];

        return $data;
    }

    protected function collectComposerPackages(): array
    {
        $packages = [];
        
        try {
            if (File::exists(base_path('composer.lock'))) {
                $composerLock = json_decode(File::get(base_path('composer.lock')), true);
                
                if (isset($composerLock['packages'])) {
                    foreach ($composerLock['packages'] as $package) {
                        $packages[] = [
                            'name' => $package['name'],
                            'version' => $package['version'],
                            'type' => $package['type'] ?? 'library',
                            'license' => $package['license'] ?? null,
                            'homepage' => $package['homepage'] ?? null,
                            'description' => $package['description'] ?? null,
                            'source' => $package['source'] ?? null,
                            'is_dev' => false,
                        ];
                    }
                }

                if (config('cybear.collectors.packages.include_dev', false) && isset($composerLock['packages-dev'])) {
                    foreach ($composerLock['packages-dev'] as $package) {
                        $packages[] = [
                            'name' => $package['name'],
                            'version' => $package['version'],
                            'type' => $package['type'] ?? 'library',
                            'license' => $package['license'] ?? null,
                            'homepage' => $package['homepage'] ?? null,
                            'description' => $package['description'] ?? null,
                            'source' => $package['source'] ?? null,
                            'is_dev' => true,
                        ];
                    }
                }
            }
        } catch (\Exception $e) {
            \Log::warning('Failed to collect Composer packages', ['error' => $e->getMessage()]);
        }

        return $packages;
    }

    protected function collectNpmPackages(): array
    {
        $packages = [];
        
        try {
            if (File::exists(base_path('package-lock.json'))) {
                $packageLock = json_decode(File::get(base_path('package-lock.json')), true);
                
                if (isset($packageLock['packages'])) {
                    foreach ($packageLock['packages'] as $name => $package) {
                        if (empty($name)) continue; // Skip root package
                        
                        // Remove node_modules/ prefix from package name
                        $cleanName = str_starts_with($name, 'node_modules/') 
                            ? substr($name, 13) 
                            : $name;
                        
                        // Extract repository information
                        $sourceUrl = null;
                        $sourceType = null;
                        if (isset($package['resolved'])) {
                            $sourceUrl = $package['resolved'];
                            $sourceType = 'registry';
                        }
                        
                        // Extract type from package data
                        $type = 'library'; // Default type
                        if (isset($package['engines'])) {
                            $type = 'module';
                        }
                        
                        $packages[] = [
                            'name' => $cleanName,
                            'version' => $package['version'] ?? null,
                            'type' => $type,
                            'license' => $package['license'] ?? null,
                            'homepage' => $package['homepage'] ?? $package['repository']['url'] ?? null,
                            'description' => $package['description'] ?? null,
                            'source_type' => $sourceType,
                            'source_url' => $sourceUrl,
                            'source_reference' => $package['integrity'] ?? null,
                            'is_dev' => $package['dev'] ?? false,
                        ];
                    }
                }
            } elseif (File::exists(base_path('package.json'))) {
                $packageJson = json_decode(File::get(base_path('package.json')), true);
                
                if (isset($packageJson['dependencies'])) {
                    foreach ($packageJson['dependencies'] as $name => $version) {
                        $packages[] = [
                            'name' => $name,
                            'version' => $version,
                            'type' => 'library',
                            'is_dev' => false,
                        ];
                    }
                }

                if (config('cybear.collectors.packages.include_dev', false) && isset($packageJson['devDependencies'])) {
                    foreach ($packageJson['devDependencies'] as $name => $version) {
                        $packages[] = [
                            'name' => $name,
                            'version' => $version,
                            'type' => 'library',
                            'is_dev' => true,
                        ];
                    }
                }
            }
        } catch (\Exception $e) {
            \Log::warning('Failed to collect NPM packages', ['error' => $e->getMessage()]);
        }

        return $packages;
    }

    protected function collectSystemInfo(): array
    {
        return [
            'php_version' => PHP_VERSION,
            'laravel_version' => app()->version(),
            'composer_version' => $this->getComposerVersion(),
            'npm_version' => $this->getNpmVersion(),
            'node_version' => $this->getNodeVersion(),
        ];
    }

    protected function getComposerVersion(): ?string
    {
        try {
            $process = new Process(['composer', '--version', '--no-ansi']);
            $process->run();
            
            if ($process->isSuccessful()) {
                $output = $process->getOutput();
                if (preg_match('/Composer version ([^\s]+)/', $output, $matches)) {
                    return $matches[1];
                }
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return null;
    }

    protected function getNpmVersion(): ?string
    {
        try {
            $process = new Process(['npm', '--version']);
            $process->run();
            
            if ($process->isSuccessful()) {
                return trim($process->getOutput());
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return null;
    }

    protected function getNodeVersion(): ?string
    {
        try {
            $process = new Process(['node', '--version']);
            $process->run();
            
            if ($process->isSuccessful()) {
                return trim($process->getOutput());
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return null;
    }

    protected function collectComposerDependencies(): array
    {
        $dependencies = [];
        
        try {
            if (File::exists(base_path('composer.lock'))) {
                $composerLock = json_decode(File::get(base_path('composer.lock')), true);
                
                // Collect dependencies for production packages
                if (isset($composerLock['packages'])) {
                    foreach ($composerLock['packages'] as $package) {
                        $packageName = $package['name'];
                        
                        // Collect requires
                        if (isset($package['require'])) {
                            foreach ($package['require'] as $depName => $constraint) {
                                if (!str_starts_with($depName, 'php') && !str_starts_with($depName, 'ext-')) {
                                    $dependencies[] = [
                                        'package_name' => $packageName,
                                        'package_version' => $package['version'],
                                        'dependency_name' => $depName,
                                        'dependency_type' => 'requires',
                                        'version_constraint' => $constraint,
                                        'is_dev' => false,
                                    ];
                                }
                            }
                        }
                        
                        // Collect suggests
                        if (isset($package['suggest'])) {
                            foreach ($package['suggest'] as $depName => $description) {
                                $dependencies[] = [
                                    'package_name' => $packageName,
                                    'package_version' => $package['version'],
                                    'dependency_name' => $depName,
                                    'dependency_type' => 'suggests',
                                    'version_constraint' => null,
                                    'is_dev' => false,
                                ];
                            }
                        }
                        
                        // Collect conflicts
                        if (isset($package['conflict'])) {
                            foreach ($package['conflict'] as $depName => $constraint) {
                                $dependencies[] = [
                                    'package_name' => $packageName,
                                    'package_version' => $package['version'],
                                    'dependency_name' => $depName,
                                    'dependency_type' => 'conflicts',
                                    'version_constraint' => $constraint,
                                    'is_dev' => false,
                                ];
                            }
                        }
                    }
                }
                
                // Collect dependencies for dev packages
                if (config('cybear.collectors.packages.include_dev', false) && isset($composerLock['packages-dev'])) {
                    foreach ($composerLock['packages-dev'] as $package) {
                        $packageName = $package['name'];
                        
                        if (isset($package['require'])) {
                            foreach ($package['require'] as $depName => $constraint) {
                                if (!str_starts_with($depName, 'php') && !str_starts_with($depName, 'ext-')) {
                                    $dependencies[] = [
                                        'package_name' => $packageName,
                                        'package_version' => $package['version'],
                                        'dependency_name' => $depName,
                                        'dependency_type' => 'requires-dev',
                                        'version_constraint' => $constraint,
                                        'is_dev' => true,
                                    ];
                                }
                            }
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            \Log::warning('Failed to collect Composer dependencies', ['error' => $e->getMessage()]);
        }
        
        return $dependencies;
    }

    protected function collectNpmDependencies(): array
    {
        $dependencies = [];
        
        try {
            if (File::exists(base_path('package-lock.json'))) {
                $packageLock = json_decode(File::get(base_path('package-lock.json')), true);
                
                if (isset($packageLock['packages'])) {
                    foreach ($packageLock['packages'] as $name => $package) {
                        if (empty($name)) continue; // Skip root package
                        
                        // Remove node_modules/ prefix from package name
                        $cleanName = str_starts_with($name, 'node_modules/') 
                            ? substr($name, 13) 
                            : $name;
                        
                        // Collect dependencies
                        if (isset($package['dependencies'])) {
                            foreach ($package['dependencies'] as $depName => $constraint) {
                                $dependencies[] = [
                                    'package_name' => $cleanName,
                                    'package_version' => $package['version'] ?? null,
                                    'dependency_name' => $depName,
                                    'dependency_type' => 'dependencies',
                                    'version_constraint' => $constraint,
                                    'is_dev' => $package['dev'] ?? false,
                                ];
                            }
                        }
                        
                        // Collect devDependencies
                        if (isset($package['devDependencies'])) {
                            foreach ($package['devDependencies'] as $depName => $constraint) {
                                $dependencies[] = [
                                    'package_name' => $cleanName,
                                    'package_version' => $package['version'] ?? null,
                                    'dependency_name' => $depName,
                                    'dependency_type' => 'devDependencies',
                                    'version_constraint' => $constraint,
                                    'is_dev' => true,
                                ];
                            }
                        }
                        
                        // Collect peerDependencies
                        if (isset($package['peerDependencies'])) {
                            foreach ($package['peerDependencies'] as $depName => $constraint) {
                                $dependencies[] = [
                                    'package_name' => $cleanName,
                                    'package_version' => $package['version'] ?? null,
                                    'dependency_name' => $depName,
                                    'dependency_type' => 'peerDependencies',
                                    'version_constraint' => $constraint,
                                    'is_dev' => $package['dev'] ?? false,
                                ];
                            }
                        }
                        
                        // Collect optionalDependencies
                        if (isset($package['optionalDependencies'])) {
                            foreach ($package['optionalDependencies'] as $depName => $constraint) {
                                $dependencies[] = [
                                    'package_name' => $cleanName,
                                    'package_version' => $package['version'] ?? null,
                                    'dependency_name' => $depName,
                                    'dependency_type' => 'optionalDependencies',
                                    'version_constraint' => $constraint,
                                    'is_dev' => $package['dev'] ?? false,
                                ];
                            }
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            \Log::warning('Failed to collect NPM dependencies', ['error' => $e->getMessage()]);
        }
        
        return $dependencies;
    }
}