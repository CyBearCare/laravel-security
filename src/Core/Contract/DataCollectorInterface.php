<?php

namespace CybearCare\LaravelSecurity\Core\Contract;

interface DataCollectorInterface
{
    public function getCollectorName(): string;

    public function collect(): array;

    public function isEnabled(): bool;

    public function forgetCache(): void;
}
