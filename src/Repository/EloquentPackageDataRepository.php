<?php

namespace CybearCare\LaravelSecurity\Repository;

use CybearCare\LaravelSecurity\Core\Contract\PackageDataRepositoryInterface;
use CybearCare\LaravelSecurity\Models\PackageData;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

class EloquentPackageDataRepository implements PackageDataRepositoryInterface
{
    public function replaceInventory(
        array $packagesByManager,
        \DateTimeImmutable $collectedAt,
    ): void {
        $normalized = $this->normalizeInventories($packagesByManager);

        DB::transaction(function () use ($normalized, $collectedAt): void {
            foreach ($normalized as $manager => $packages) {
                $currentIdentities = [];

                foreach ($packages as $package) {
                    $identity = $this->identity(
                        $manager,
                        $package['name'],
                        $package['version'],
                    );
                    $currentIdentities[] = $identity;

                    PackageData::updateOrCreate(
                        ['identity' => $identity],
                        [
                            'package_name' => $package['name'],
                            'package_manager' => $manager,
                            'version' => $package['version'],
                            'installed_version' => $package['version'],
                            'package_info' => $package['package_info'],
                            'collected_at' => $collectedAt,
                            'transmitted' => false,
                            'transmitted_at' => null,
                        ],
                    );
                }

                $stale = PackageData::where('package_manager', $manager);
                if ($currentIdentities !== []) {
                    $stale->whereNotIn('identity', $currentIdentities);
                }
                $stale->delete();
            }
        });
    }

    public function count(): int
    {
        return PackageData::count();
    }

    public function untransmittedCount(): int
    {
        return PackageData::untransmitted()->count();
    }

    public function deleteTransmittedBefore(\DateTimeImmutable $before): int
    {
        return PackageData::where('transmitted', true)
            ->where('collected_at', '<', $before)
            ->delete();
    }

    /**
     * @param  array<string, list<array<string, mixed>>>  $packagesByManager
     * @return array<string, list<array{
     *     name: string,
     *     version: string|null,
     *     package_info: array<string, mixed>
     * }>>
     */
    protected function normalizeInventories(array $packagesByManager): array
    {
        $normalized = [];

        foreach ($packagesByManager as $manager => $packages) {
            if (! is_string($manager) || trim($manager) === '' || ! is_array($packages)) {
                throw new InvalidArgumentException('Package inventories require a valid manager and package list.');
            }

            $byIdentity = [];
            foreach ($packages as $package) {
                if (! is_array($package)
                    || ! is_string($package['name'] ?? null)
                    || trim($package['name']) === '') {
                    throw new InvalidArgumentException("The {$manager} inventory contains an invalid package name.");
                }

                $name = trim($package['name']);
                $version = $package['version'] ?? null;
                if ($version !== null && ! is_string($version)) {
                    throw new InvalidArgumentException(
                        "Package {$name} in the {$manager} inventory has an invalid version.",
                    );
                }

                $identity = $this->identity($manager, $name, $version);
                $byIdentity[$identity] = [
                    'name' => $name,
                    'version' => $version,
                    'package_info' => $package,
                ];
            }

            $normalized[$manager] = array_values($byIdentity);
        }

        return $normalized;
    }

    protected function identity(string $manager, string $name, ?string $version): string
    {
        return hash('sha256', "{$manager}\0{$name}\0".($version ?? ''));
    }
}
