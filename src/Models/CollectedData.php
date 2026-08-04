<?php

namespace CybearCare\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Model;

class CollectedData extends Model
{

    protected $table = 'cybear_collected_data';

    protected $fillable = [
        'collection_type',
        'data_source',
        'collected_data',
        'collected_at',
        'transmitted',
        'transmitted_at',
        'checksum',
    ];

    protected $casts = [
        'collected_data' => 'encrypted:array',
        'collected_at' => 'datetime',
        'transmitted_at' => 'datetime',
        'transmitted' => 'boolean',
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
