<?php

namespace CybearCare\LaravelSecurity\Posture\Capabilities;

use JsonSerializable;

final readonly class CapabilitySet implements JsonSerializable
{
    public const SCHEMA_VERSION = '1.1';

    /**
     * @param array<string, array{package: string, version: string|null}> $packages
     * @param array<string, array{present: bool, route_count: int}> $routeSurfaces
     * @param array<string, scalar|null> $runtime
     */
    public function __construct(
        private array $packages,
        private array $routeSurfaces,
        private array $runtime,
    ) {
    }

    public function hasPackage(string $capability): bool
    {
        return isset($this->packages[$capability]);
    }

    public function packageVersion(string $capability): ?string
    {
        return $this->packages[$capability]['version'] ?? null;
    }

    public function packageName(string $capability): ?string
    {
        return $this->packages[$capability]['package'] ?? null;
    }

    public function hasRouteSurface(string $capability): bool
    {
        return ($this->routeSurfaces[$capability]['present'] ?? false) === true;
    }

    public function routeCount(string $capability): int
    {
        return (int) ($this->routeSurfaces[$capability]['route_count'] ?? 0);
    }

    public function runtime(string $key, mixed $default = null): mixed
    {
        return $this->runtime[$key] ?? $default;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'schema_version' => self::SCHEMA_VERSION,
            'packages' => $this->packages,
            'route_surfaces' => $this->routeSurfaces,
            'runtime' => $this->runtime,
        ];
    }
}
