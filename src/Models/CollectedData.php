<?php

namespace CybearCare\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class CollectedData extends Model
{
    use HasFactory;

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
        'collected_data' => 'array',
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

    public static function createFromCollector(string $type, string $source, array $data): self
    {
        $checksum = hash('sha256', json_encode($data));
        
        return static::create([
            'collection_type' => $type,
            'data_source' => $source,
            'collected_data' => $data,
            'collected_at' => now(),
            'checksum' => $checksum,
        ]);
    }

}