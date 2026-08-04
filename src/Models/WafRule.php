<?php

namespace CybearCare\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Model;

class WafRule extends Model
{
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
        'version',
        'scope',
        'rollout_percentage',
        'expires_at',
        'finding_id',
        'owner',
        'reason',
        'source',
        'metadata',
        'last_triggered',
        'trigger_count',
    ];

    protected $attributes = [
        'enabled' => true,
        'trigger_count' => 0,
        'priority' => 100,
        'version' => 1,
        'rollout_percentage' => 100,
        'source' => 'cybear',
    ];

    protected $casts = [
        'conditions' => 'array',
        'action_params' => 'array',
        'metadata' => 'array',
        'enabled' => 'boolean',
        'scope' => 'array',
        'expires_at' => 'immutable_datetime',
        'last_triggered' => 'datetime',
        'trigger_count' => 'integer',
        'priority' => 'integer',
        'version' => 'integer',
        'rollout_percentage' => 'integer',
    ];
}
