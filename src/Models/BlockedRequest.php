<?php

namespace CybearCare\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Model;

class BlockedRequest extends Model
{

    protected $table = 'cybear_blocked_requests';

    protected $fillable = [
        'ip_address',
        'user_agent',
        'url',
        'method',
        'headers',
        'payload',
        'waf_rule_id',
        'waf_rule_key',
        'reason',
        'incident_id',
        'session_id',
        'user_id',
        'blocked_at',
        'transmitted',
        'transmitted_at',
    ];

    protected $casts = [
        'session_id' => 'encrypted',
        'ip_address' => 'encrypted',
        'user_agent' => 'encrypted',
        'url' => 'encrypted',
        'headers' => 'encrypted:array',
        'payload' => 'encrypted:array',
        'blocked_at' => 'datetime',
        'transmitted' => 'boolean',
        'transmitted_at' => 'datetime',
    ];

    public function scopeUntransmitted($query)
    {
        return $query->where('transmitted', false);
    }

    public function markAsTransmitted(): void
    {
        $this->update([
            'transmitted' => true,
            'transmitted_at' => now(),
        ]);
    }
}
