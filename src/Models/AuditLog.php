<?php

namespace CybearCare\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Model;

class AuditLog extends Model
{

    protected $table = 'cybear_audit_logs';

    protected $fillable = [
        'app_id',
        'event_type',
        'user_id',
        'session_id',
        'ip_address',
        'user_agent',
        'url',
        'method',
        'headers',
        'payload',
        'context',
        'response_code',
        'processing_time',
        'occurred_at',
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
        'context' => 'encrypted:array',
        'occurred_at' => 'datetime',
        'transmitted_at' => 'datetime',
        'transmitted' => 'boolean',
        'processing_time' => 'decimal:3',
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
