<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('cybear_threat_events', function (Blueprint $table): void {
            $table->id();
            $table->string('event_id', 128)->unique();
            $table->longText('payload');
            $table->unsignedSmallInteger('attempts')->default(0);
            $table->timestamp('next_attempt_at')->nullable();
            $table->boolean('transmitted')->default(false);
            $table->timestamp('transmitted_at')->nullable();
            $table->timestamps();

            $table->index(['transmitted', 'next_attempt_at'], 'cybear_threat_events_delivery_idx');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('cybear_threat_events');
    }
};
