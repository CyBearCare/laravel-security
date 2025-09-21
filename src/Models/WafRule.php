<?php

namespace CybearCare\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class WafRule extends Model
{
    use HasFactory;

    protected $table = 'cybear_waf_rules';

    protected $fillable = [
        'rule_id',
        'name',
        'description',
        'category',
        'severity',
        'conditions',
        'action',
        'action_params',
        'enabled',
        'priority',
        'source',
        'metadata',
        'last_triggered',
        'trigger_count',
    ];

    protected $attributes = [
        'enabled' => true,
        'trigger_count' => 0,
        'priority' => 100,
        'source' => 'cybear',
    ];

    protected $casts = [
        'conditions' => 'array',
        'action_params' => 'array',
        'metadata' => 'array',
        'enabled' => 'boolean',
        'last_triggered' => 'datetime',
        'trigger_count' => 'integer',
        'priority' => 'integer',
    ];

    public function scopeEnabled($query)
    {
        return $query->where('enabled', true);
    }



    public function blockedRequests()
    {
        return $this->hasMany(BlockedRequest::class);
    }

}