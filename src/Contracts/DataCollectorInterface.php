<?php

namespace CybearCare\LaravelSecurity\Contracts;

interface DataCollectorInterface
{
    public function collect(): array;
    
    public function isEnabled(): bool;
    
    public function getCollectorName(): string;
    
    public function sanitizeData(array $data): array;
    
    public function getCacheKey(): string;
    
    public function getCacheTtl(): int;
}