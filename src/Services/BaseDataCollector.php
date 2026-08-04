<?php

namespace CybearCare\LaravelSecurity\Services;

use CybearCare\LaravelSecurity\Core\Contract\DataCollectorInterface;
use Illuminate\Support\Facades\Cache;

abstract class BaseDataCollector implements DataCollectorInterface
{
    protected string $collectorName;

    protected bool $cacheEnabled = true;

    protected int $cacheTtl = 3600;

    public function __construct()
    {
        $this->collectorName = $this->getCollectorName();
    }

    public function collect(): array
    {
        if (! $this->isEnabled()) {
            return [];
        }

        if ($this->cacheEnabled && Cache::has($this->getCacheKey())) {
            return Cache::get($this->getCacheKey());
        }

        $data = $this->collectData();
        $sanitizedData = $this->sanitizeData($data);

        if ($this->cacheEnabled) {
            Cache::put($this->getCacheKey(), $sanitizedData, $this->getCacheTtl());
        }

        return $sanitizedData;
    }

    abstract protected function collectData(): array;

    public function isEnabled(): bool
    {
        return config("cybear.collectors.{$this->getConfigKey()}.enabled", true);
    }

    public function sanitizeData(array $data): array
    {
        return $this->recursiveSanitize($data);
    }

    protected function recursiveSanitize(array $data): array
    {
        $sensitiveKeys = [
            'password', 'secret', 'key', 'token', 'auth', 'credential',
            'private', 'confidential', 'sensitive', 'api_key', 'database_url',
        ];

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->recursiveSanitize($value);
            } elseif (is_string($value) && $this->isSensitiveKey($key, $sensitiveKeys)) {
                $data[$key] = $this->maskSensitiveValue($value);
            }
        }

        return $data;
    }

    protected function isSensitiveKey(string $key, array $sensitiveKeys): bool
    {
        $key = strtolower($key);

        foreach ($sensitiveKeys as $sensitiveKey) {
            if (str_contains($key, $sensitiveKey)) {
                return true;
            }
        }

        return false;
    }

    protected function maskSensitiveValue(string $value): string
    {
        if (strlen($value) <= 4) {
            return str_repeat('*', strlen($value));
        }

        return substr($value, 0, 2).str_repeat('*', strlen($value) - 4).substr($value, -2);
    }

    public function getCacheKey(): string
    {
        return "cybear_collector_{$this->collectorName}";
    }

    public function getCacheTtl(): int
    {
        return $this->cacheTtl;
    }

    public function forgetCache(): void
    {
        Cache::forget($this->getCacheKey());
    }

    abstract protected function getConfigKey(): string;
}
