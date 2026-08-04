<?php

namespace CybearCare\LaravelSecurity\Core\Collection;

use CybearCare\LaravelSecurity\Core\Api\CybearApiClient;
use CybearCare\LaravelSecurity\Core\Config\CybearConfig;
use CybearCare\LaravelSecurity\Core\Contract\CollectedDataRepositoryInterface;
use CybearCare\LaravelSecurity\Core\Contract\DataCollectorInterface;
use CybearCare\LaravelSecurity\Core\Contract\PackageDataRepositoryInterface;
use Psr\Log\LoggerInterface;

class DataCollectionManager
{
    protected array $collectors = [];

    protected array $lastCollectionHealth = [
        'status' => 'never',
        'attempted_at' => null,
        'completed_at' => null,
        'succeeded' => 0,
        'failed' => 0,
        'disabled' => 0,
        'collectors' => [],
    ];

    public function __construct(
        protected CybearApiClient $apiClient,
        protected LoggerInterface $logger,
        protected CybearConfig $config,
        protected CollectedDataRepositoryInterface $collectedDataRepo,
        protected PackageDataRepositoryInterface $packageDataRepo
    ) {}

    public function collectAll(): array
    {
        $collectedData = [];
        $attemptedAt = new \DateTimeImmutable;
        $collectorHealth = [];
        $succeeded = 0;
        $failed = 0;
        $disabled = 0;

        foreach ($this->collectors as $name => $collector) {
            try {
                if (! $collector->isEnabled()) {
                    $disabled++;
                    $collectorHealth[$name] = $this->collectorHealth('disabled');

                    continue;
                }

                $data = $collector->collect();
                $persisted = false;

                if (! empty($data)) {
                    $this->storeCollectedData($name, $data);
                    $collectedData[$name] = $data;
                    $persisted = true;
                }

                $succeeded++;
                $collectorHealth[$name] = $this->collectorHealth('succeeded', $persisted);
            } catch (\Throwable $exception) {
                $failed++;
                $this->forgetCollectorCache($name, $collector);
                $error = $this->collectionError($exception);
                $collectorHealth[$name] = $this->collectorHealth('failed', false, $error);
                $this->logger->warning("Failed to collect or persist {$name} data", [
                    'collector' => $name,
                    'error_type' => $exception::class,
                    'error' => $error,
                ]);
            }
        }

        $status = $failed > 0
            ? ($succeeded > 0 ? 'degraded' : 'failed')
            : ($succeeded > 0 ? 'healthy' : 'idle');
        $this->lastCollectionHealth = [
            'status' => $status,
            'attempted_at' => $attemptedAt->format(\DateTimeInterface::ATOM),
            'completed_at' => (new \DateTimeImmutable)->format(\DateTimeInterface::ATOM),
            'succeeded' => $succeeded,
            'failed' => $failed,
            'disabled' => $disabled,
            'collectors' => $collectorHealth,
        ];

        return [
            'application_id' => $this->config->getAppId() ?: $this->config->getAppName(),
            'collection_timestamp' => (new \DateTimeImmutable)->format(\DateTimeInterface::ATOM),
            'collectors' => $collectedData,
            'collection_health' => $this->lastCollectionHealth,
        ];
    }

    public function collectByType(string $type): array
    {
        if (! isset($this->collectors[$type])) {
            throw new \InvalidArgumentException("Unknown collector type: {$type}");
        }

        $collector = $this->collectors[$type];
        $attemptedAt = new \DateTimeImmutable;

        try {
            if (! $collector->isEnabled()) {
                $this->setSingleCollectorHealth($type, 'disabled', $attemptedAt);

                return [];
            }

            $data = $collector->collect();
            $persisted = false;

            if (! empty($data)) {
                $this->storeCollectedData($type, $data);
                $persisted = true;
            }

            $this->setSingleCollectorHealth(
                $type,
                'succeeded',
                $attemptedAt,
                $persisted,
            );

            return $data;
        } catch (\Throwable $exception) {
            $this->forgetCollectorCache($type, $collector);
            $error = $this->collectionError($exception);
            $this->setSingleCollectorHealth(
                $type,
                'failed',
                $attemptedAt,
                false,
                $error,
            );
            $this->logger->warning("Failed to collect or persist {$type} data", [
                'collector' => $type,
                'error_type' => $exception::class,
                'error' => $error,
            ]);

            throw $exception;
        }
    }

    public function sendToApi(array $data): bool
    {
        try {
            $response = $this->apiClient->sendCollectedData($data);

            $this->logger->info('Data collection sent to Cybear platform', [
                'data_size' => strlen(json_encode($data)),
                'collectors_count' => count($data['collectors'] ?? []),
                'response_status' => $response['status'] ?? 'unknown',
            ]);

            return true;
        } catch (\Throwable $exception) {
            $errorMessage = 'Failed to send data to Cybear: '.$exception->getMessage();
            $this->logger->error($errorMessage, [
                'exception' => $exception::class,
                'data_size' => strlen(json_encode($data)),
            ]);

            return false;
        }
    }

    public function addCollector(string $name, DataCollectorInterface $collector): void
    {
        $this->collectors[$name] = $collector;
    }

    public function removeCollector(string $name): void
    {
        unset($this->collectors[$name]);
    }

    public function getAvailableCollectors(): array
    {
        return array_keys($this->collectors);
    }

    public function getCollectorStates(): array
    {
        $states = [];

        foreach ($this->collectors as $name => $collector) {
            $states[$name] = $collector->isEnabled();
        }

        return $states;
    }

    public function getLastCollectionHealth(): array
    {
        return $this->lastCollectionHealth;
    }

    protected function storeCollectedData(string $type, array $data): void
    {
        if ($type === 'packages') {
            $this->storePackageData($data);
        }

        $encoded = json_encode(
            $data,
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
        );
        $this->collectedDataRepo->create(
            $type,
            'auto_collection',
            $data,
            hash('sha256', $encoded),
        );

        $this->logger->debug("Stored {$type} data to database", [
            'type' => $type,
            'data_size' => strlen($encoded),
        ]);
    }

    protected function storePackageData(array $packageData): void
    {
        $sourceStates = is_array($packageData['inventory_sources'] ?? null)
            ? $packageData['inventory_sources']
            : [];
        $inventories = [];

        foreach ([
            'composer' => 'composer_packages',
            'npm' => 'npm_packages',
        ] as $manager => $key) {
            $authoritative = $sourceStates[$manager]['authoritative'] ?? true;
            if ($authoritative === true && is_array($packageData[$key] ?? null)) {
                $inventories[$manager] = $packageData[$key];
            }
        }

        $collectedAt = new \DateTimeImmutable(
            is_string($packageData['collection_timestamp'] ?? null)
                ? $packageData['collection_timestamp']
                : 'now',
        );
        $this->packageDataRepo->replaceInventory($inventories, $collectedAt);
    }

    protected function setSingleCollectorHealth(
        string $type,
        string $status,
        \DateTimeImmutable $attemptedAt,
        bool $persisted = false,
        ?string $error = null,
    ): void {
        $this->lastCollectionHealth = [
            'status' => match ($status) {
                'succeeded' => 'healthy',
                'failed' => 'failed',
                default => 'idle',
            },
            'attempted_at' => $attemptedAt->format(\DateTimeInterface::ATOM),
            'completed_at' => (new \DateTimeImmutable)->format(\DateTimeInterface::ATOM),
            'succeeded' => $status === 'succeeded' ? 1 : 0,
            'failed' => $status === 'failed' ? 1 : 0,
            'disabled' => $status === 'disabled' ? 1 : 0,
            'collectors' => [
                $type => $this->collectorHealth($status, $persisted, $error),
            ],
        ];
    }

    protected function collectorHealth(
        string $status,
        bool $persisted = false,
        ?string $error = null,
    ): array {
        return [
            'status' => $status,
            'persisted' => $persisted,
            'error' => $error,
        ];
    }

    protected function collectionError(\Throwable $exception): string
    {
        $message = preg_replace('/\s+/', ' ', trim($exception->getMessage()));

        return substr($message ?: $exception::class, 0, 500);
    }

    protected function forgetCollectorCache(string $name, DataCollectorInterface $collector): void
    {
        try {
            $collector->forgetCache();
        } catch (\Throwable $exception) {
            $this->logger->warning("Failed to clear {$name} collector cache after an error", [
                'collector' => $name,
                'error_type' => $exception::class,
                'error' => $this->collectionError($exception),
            ]);
        }
    }
}
