<?php

namespace CybearCare\LaravelSecurity\Posture;

enum CheckStatus: string
{
    case Pass = 'pass';
    case Warning = 'warning';
    case Fail = 'fail';
    case Suppressed = 'suppressed';
    case Skipped = 'skipped';
    case Error = 'error';

    public function isFinding(): bool
    {
        return $this === self::Warning || $this === self::Fail;
    }
}
