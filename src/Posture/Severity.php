<?php

namespace CybearCare\LaravelSecurity\Posture;

use InvalidArgumentException;

enum Severity: string
{
    case Info = 'info';
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    public function rank(): int
    {
        return match ($this) {
            self::Info => 0,
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }

    public function meets(self $threshold): bool
    {
        return $this->rank() >= $threshold->rank();
    }

    public static function parse(string $value): self
    {
        return self::tryFrom(strtolower(trim($value)))
            ?? throw new InvalidArgumentException("Unknown severity [{$value}].");
    }
}
