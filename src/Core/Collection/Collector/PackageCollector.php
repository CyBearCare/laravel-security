<?php

namespace CybearCare\LaravelSecurity\Core\Collection\Collector;

use Composer\InstalledVersions;
use CybearCare\LaravelSecurity\Core\Collection\BaseDataCollector;

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
        $scanComposer = (bool) config('cybear.collectors.packages.scan_composer', true);
        $scanNpm = (bool) config('cybear.collectors.packages.scan_npm', true);
        $composerSource = $this->composerSourceState($scanComposer);
        $npmSource = $this->npmSourceState($scanNpm);

        foreach ([
            'Composer' => $composerSource,
            'NPM' => $npmSource,
        ] as $manager => $source) {
            if (! $source['authoritative']) {
                throw new \RuntimeException(
                    "{$manager} package inventory could not parse {$source['source']}.",
                );
            }
        }

        return [
            'composer_packages' => $scanComposer ? $this->collectComposerPackages() : [],
            'composer_dependencies' => $scanComposer ? $this->collectComposerDependencies() : [],
            'npm_packages' => $scanNpm ? $this->collectNpmPackages() : [],
            'npm_dependencies' => $scanNpm ? $this->collectNpmDependencies() : [],
            'inventory_sources' => [
                'composer' => $composerSource,
                'npm' => $npmSource,
            ],
            'system_info' => $this->collectSystemInfo(),
            'collection_timestamp' => (new \DateTimeImmutable)->format(\DateTimeInterface::ATOM),
        ];
    }

    protected function collectComposerPackages(): array
    {
        $packages = [];

        try {
            $composerLockPath = $this->config->getBasePath().'/composer.lock';

            if (file_exists($composerLockPath)) {
                $composerLock = json_decode(file_get_contents($composerLockPath), true);

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

                if ($this->config->isIncludeDevPackages() && isset($composerLock['packages-dev'])) {
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
            $this->logger->warning('Failed to collect Composer packages', ['error' => $e->getMessage()]);
            throw $e;
        }

        return $packages;
    }

    protected function collectNpmPackages(): array
    {
        $packages = [];
        $includeDev = (bool) config('cybear.collectors.packages.include_npm_dev', true);

        try {
            $packageLockPath = $this->config->getBasePath().'/package-lock.json';
            $packageJsonPath = $this->config->getBasePath().'/package.json';

            if (file_exists($packageLockPath)) {
                $packageLock = json_decode(file_get_contents($packageLockPath), true);

                if (isset($packageLock['packages'])) {
                    foreach ($packageLock['packages'] as $name => $package) {
                        if (empty($name)) {
                            continue;
                        }

                        if (! $includeDev && ($package['dev'] ?? false)) {
                            continue;
                        }

                        $cleanName = $this->npmPackageNameFromLockPath($name);


                        $sourceUrl = null;
                        $sourceType = null;
                        if (isset($package['resolved'])) {
                            $sourceUrl = $package['resolved'];
                            $sourceType = 'registry';
                        }


                        $type = 'library';
                        if (isset($package['engines'])) {
                            $type = 'module';
                        }

                        $packageKey = $cleanName.'@'.($package['version'] ?? '');
                        $packages[$packageKey] = [
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
            } elseif (file_exists($packageJsonPath)) {
                $packageJson = json_decode(file_get_contents($packageJsonPath), true);

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

                if ($includeDev && isset($packageJson['devDependencies'])) {
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
            $this->logger->warning('Failed to collect NPM packages', ['error' => $e->getMessage()]);
            throw $e;
        }

        return array_values($packages);
    }

    protected function collectSystemInfo(): array
    {
        return [
            'php_version' => PHP_VERSION,
            'framework_version' => $this->config->getFrameworkVersion(),
            'composer_runtime_available' => class_exists(InstalledVersions::class),
        ];
    }

    /**
     * @return array{authoritative: bool, source: string}
     */
    protected function composerSourceState(bool $enabled): array
    {
        if (! $enabled) {
            return ['authoritative' => true, 'source' => 'disabled'];
        }

        $path = $this->config->getBasePath().'/composer.lock';
        if (! is_file($path)) {
            return ['authoritative' => true, 'source' => 'not_present'];
        }

        $contents = file_get_contents($path);
        $decoded = is_string($contents) ? json_decode($contents, true) : null;

        return [
            'authoritative' => is_array($decoded) && is_array($decoded['packages'] ?? null),
            'source' => 'composer.lock',
        ];
    }

    /**
     * @return array{authoritative: bool, source: string}
     */
    protected function npmSourceState(bool $enabled): array
    {
        if (! $enabled) {
            return ['authoritative' => true, 'source' => 'disabled'];
        }

        $basePath = $this->config->getBasePath();
        foreach ([
            'package-lock.json' => 'packages',
            'package.json' => null,
        ] as $filename => $requiredKey) {
            $path = $basePath.'/'.$filename;
            if (! is_file($path)) {
                continue;
            }

            $contents = file_get_contents($path);
            $decoded = is_string($contents) ? json_decode($contents, true) : null;
            $authoritative = is_array($decoded)
                && ($requiredKey === null || is_array($decoded[$requiredKey] ?? null));

            return ['authoritative' => $authoritative, 'source' => $filename];
        }

        return ['authoritative' => true, 'source' => 'not_present'];
    }

    protected function collectComposerDependencies(): array
    {
        $dependencies = [];

        try {
            $composerLockPath = $this->config->getBasePath().'/composer.lock';

            if (file_exists($composerLockPath)) {
                $composerLock = json_decode(file_get_contents($composerLockPath), true);

                if (isset($composerLock['packages'])) {
                    foreach ($composerLock['packages'] as $package) {
                        $packageName = $package['name'];

                        if (isset($package['require'])) {
                            foreach ($package['require'] as $depName => $constraint) {
                                if (! str_starts_with($depName, 'php') && ! str_starts_with($depName, 'ext-')) {
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

                if ($this->config->isIncludeDevPackages() && isset($composerLock['packages-dev'])) {
                    foreach ($composerLock['packages-dev'] as $package) {
                        $packageName = $package['name'];

                        if (isset($package['require'])) {
                            foreach ($package['require'] as $depName => $constraint) {
                                if (! str_starts_with($depName, 'php') && ! str_starts_with($depName, 'ext-')) {
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
            $this->logger->warning('Failed to collect Composer dependencies', ['error' => $e->getMessage()]);
            throw $e;
        }

        return $dependencies;
    }

    protected function collectNpmDependencies(): array
    {
        $dependencies = [];
        $includeDev = (bool) config('cybear.collectors.packages.include_npm_dev', true);

        try {
            $packageLockPath = $this->config->getBasePath().'/package-lock.json';

            if (file_exists($packageLockPath)) {
                $packageLock = json_decode(file_get_contents($packageLockPath), true);

                if (isset($packageLock['packages'])) {
                    foreach ($packageLock['packages'] as $name => $package) {
                        if (empty($name)) {
                            continue;
                        }

                        if (! $includeDev && ($package['dev'] ?? false)) {
                            continue;
                        }

                        $cleanName = $this->npmPackageNameFromLockPath($name);

                        if (isset($package['dependencies'])) {
                            foreach ($package['dependencies'] as $depName => $constraint) {
                                $dependency = [
                                    'package_name' => $cleanName,
                                    'package_version' => $package['version'] ?? null,
                                    'dependency_name' => $depName,
                                    'dependency_type' => 'dependencies',
                                    'version_constraint' => $constraint,
                                    'is_dev' => $package['dev'] ?? false,
                                ];
                                $dependencies[$this->npmDependencyKey($dependency)] = $dependency;
                            }
                        }

                        if (isset($package['devDependencies'])) {
                            foreach ($package['devDependencies'] as $depName => $constraint) {
                                $dependency = [
                                    'package_name' => $cleanName,
                                    'package_version' => $package['version'] ?? null,
                                    'dependency_name' => $depName,
                                    'dependency_type' => 'devDependencies',
                                    'version_constraint' => $constraint,
                                    'is_dev' => true,
                                ];
                                $dependencies[$this->npmDependencyKey($dependency)] = $dependency;
                            }
                        }

                        if (isset($package['peerDependencies'])) {
                            foreach ($package['peerDependencies'] as $depName => $constraint) {
                                $dependency = [
                                    'package_name' => $cleanName,
                                    'package_version' => $package['version'] ?? null,
                                    'dependency_name' => $depName,
                                    'dependency_type' => 'peerDependencies',
                                    'version_constraint' => $constraint,
                                    'is_dev' => $package['dev'] ?? false,
                                ];
                                $dependencies[$this->npmDependencyKey($dependency)] = $dependency;
                            }
                        }

                        if (isset($package['optionalDependencies'])) {
                            foreach ($package['optionalDependencies'] as $depName => $constraint) {
                                $dependency = [
                                    'package_name' => $cleanName,
                                    'package_version' => $package['version'] ?? null,
                                    'dependency_name' => $depName,
                                    'dependency_type' => 'optionalDependencies',
                                    'version_constraint' => $constraint,
                                    'is_dev' => $package['dev'] ?? false,
                                ];
                                $dependencies[$this->npmDependencyKey($dependency)] = $dependency;
                            }
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            $this->logger->warning('Failed to collect NPM dependencies', ['error' => $e->getMessage()]);
            throw $e;
        }

        return array_values($dependencies);
    }

    protected function npmPackageNameFromLockPath(string $path): string
    {
        $marker = 'node_modules/';
        $position = strrpos($path, $marker);

        return $position === false
            ? $path
            : substr($path, $position + strlen($marker));
    }

    /**
     * @param  array<string, mixed>  $dependency
     */
    protected function npmDependencyKey(array $dependency): string
    {
        return implode('|', [
            $dependency['package_name'] ?? '',
            $dependency['package_version'] ?? '',
            $dependency['dependency_name'] ?? '',
            $dependency['dependency_type'] ?? '',
            $dependency['version_constraint'] ?? '',
        ]);
    }
}
