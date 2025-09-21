<?php

namespace CybearCare\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class BlockedRequest extends Model
{
    use HasFactory;

    protected $table = 'cybear_blocked_requests';

    protected $fillable = [
        'ip_address',
        'user_agent',
        'url',
        'method',
        'headers',
        'payload',
        'waf_rule_id',
        'reason',
        'incident_id',
        'session_id',
        'user_id',
        'blocked_at',
        'transmitted',
        'transmitted_at',
    ];

    protected $casts = [
        'headers' => 'array',
        'payload' => 'array',
        'blocked_at' => 'datetime',
        'transmitted' => 'boolean',
        'transmitted_at' => 'datetime',
    ];

    public function wafRule()
    {
        return $this->belongsTo(WafRule::class);
    }


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