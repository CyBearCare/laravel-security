<?php

namespace CybearCare\LaravelSecurity\Core\Collection;

use CybearCare\LaravelSecurity\Core\Config\CybearConfig;
use CybearCare\LaravelSecurity\Core\Contract\CacheInterface;
use CybearCare\LaravelSecurity\Core\Contract\DataCollectorInterface;
use CybearCare\LaravelSecurity\Core\Sanitizer\DataSanitizer;
use Psr\Log\LoggerInterface;

abstract class BaseDataCollector implements DataCollectorInterface
{
    protected string $collectorName;

    protected bool $cacheEnabled = true;

    protected int $cacheTtl = 3600;

    public function __construct(
        protected CacheInterface $cache,
        protected LoggerInterface $logger,
        protected CybearConfig $config
    ) {
        $this->collectorName = $this->getCollectorName();
    }

    public function collect(): array
    {
        if (! $this->isEnabled()) {
            return [];
        }

        if ($this->cacheEnabled && $this->cache->has($this->getCacheKey())) {
            return $this->cache->get($this->getCacheKey());
        }

        $data = $this->collectData();
        $sanitizedData = $this->sanitizeData($data);

        if ($this->cacheEnabled) {
            $this->cache->put($this->getCacheKey(), $sanitizedData, $this->getCacheTtl());
        }

        return $sanitizedData;
    }

    abstract protected function collectData(): array;

    public function isEnabled(): bool
    {
        return $this->config->isCollectorEnabled($this->getConfigKey());
    }

    public function sanitizeData(array $data): array
    {
        return DataSanitizer::sanitizeCollectedData($data);
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
        $this->cache->forget($this->getCacheKey());
    }

    abstract protected function getConfigKey(): string;
}
