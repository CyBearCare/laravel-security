<?php

namespace CybearCare\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class AuditLog extends Model
{
    use HasFactory;

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
        'headers' => 'array',
        'payload' => 'array',
        'context' => 'array',
        'occurred_at' => 'datetime',
        'transmitted_at' => 'datetime',
        'transmitted' => 'boolean',
        'processing_time' => 'decimal:3',
    ];


    public function scopeRecent($query, $hours = 24)
    {
        return $query->where('created_at', '>=', now()->subHours($hours));
    }

    public function scopeByEventType($query, string $eventType)
    {
        return $query->where('event_type', $eventType);
    }

    public function scopeByUser($query, $userId)
    {
        return $query->where('user_id', $userId);
    }

    public function scopeByIp($query, string $ip)
    {
        return $query->where('ip_address', $ip);
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