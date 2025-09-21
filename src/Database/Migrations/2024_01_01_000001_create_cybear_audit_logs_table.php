<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('cybear_audit_logs', function (Blueprint $table) {
            $table->id();
            $table->string('app_id')->index()->comment('Application identifier');
            $table->string('event_type', 50)->index()->comment('Type of event logged');
            $table->string('user_id')->nullable()->index()->comment('User ID if authenticated');
            $table->string('session_id', 100)->nullable()->index()->comment('Session identifier');
            $table->ipAddress('ip_address')->index()->comment('Client IP address');
            $table->string('user_agent', 500)->nullable()->comment('Client user agent');
            $table->string('url', 1000)->comment('Request URL');
            $table->string('method', 10)->comment('HTTP method');
            $table->json('headers')->nullable()->comment('Request headers');
            $table->json('payload')->nullable()->comment('Request/response data');
            $table->json('context')->nullable()->comment('Additional context data');
            $table->integer('response_code')->nullable()->comment('HTTP response code');
            $table->decimal('processing_time', 8, 3)->nullable()->comment('Processing time in seconds');
            $table->timestamp('occurred_at')->index()->comment('When the event occurred');
            $table->boolean('transmitted')->default(false)->index()->comment('Whether sent to Cybear platform');
            $table->timestamp('transmitted_at')->nullable()->comment('When transmitted to platform');
            $table->timestamps();
            
            $table->index(['event_type', 'occurred_at']);
            $table->index(['ip_address', 'occurred_at']);
            $table->index(['user_id', 'event_type']);
            $table->index(['transmitted', 'occurred_at']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('cybear_audit_logs');
    }
};