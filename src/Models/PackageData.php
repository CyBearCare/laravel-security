<?php

namespace CybearCare\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class PackageData extends Model
{
    use HasFactory;

    protected $table = 'cybear_package_data';

    protected $fillable = [
        'package_name',
        'package_manager',
        'version',
        'installed_version',
        'package_info',
        'collected_at',
        'transmitted',
        'transmitted_at',
    ];

    protected $casts = [
        'package_info' => 'array',
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