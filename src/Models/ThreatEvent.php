<?php

namespace CybearCare\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

class ThreatEvent extends Model
{
    protected $table = 'cybear_threat_events';

    protected $fillable = [
        'event_id',
        'payload',
        'attempts',
        'next_attempt_at',
        'transmitted',
        'transmitted_at',
    ];

    protected $casts = [
        'payload' => 'encrypted:array',
        'attempts' => 'integer',
        'next_attempt_at' => 'datetime',
        'transmitted' => 'boolean',
        'transmitted_at' => 'datetime',
    ];

    public function scopeUntransmitted(Builder $query): Builder
    {
        return $query->where('transmitted', false);
    }

    public function scopeDue(Builder $query): Builder
    {
        $maximumAttempts = max(1, (int) config('cybear.threat_reporting.max_attempts', 10));

        return $query->untransmitted()
            ->where('attempts', '<', $maximumAttempts)
            ->where(function (Builder $query): void {
                $query->whereNull('next_attempt_at')
                    ->orWhere('next_attempt_at', '<=', now());
            });
    }
}
