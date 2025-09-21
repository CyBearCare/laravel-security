<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('cybear_blocked_requests', function (Blueprint $table) {
            $table->id();
            $table->ipAddress('ip_address')->index()->comment('Blocked IP address');
            $table->string('user_agent', 500)->nullable()->comment('User agent string');
            $table->string('url', 1000)->comment('Requested URL');
            $table->string('method', 10)->comment('HTTP method');
            $table->json('headers')->nullable()->comment('Request headers');
            $table->json('payload')->nullable()->comment('Request payload');
            $table->foreignId('waf_rule_id')->nullable()->constrained('cybear_waf_rules')->onDelete('cascade');
            $table->string('reason')->comment('Reason for blocking');
            $table->string('incident_id', 36)->nullable()->index()->comment('Unique incident identifier');
            $table->string('session_id', 100)->nullable()->comment('Session identifier');
            $table->string('user_id')->nullable()->index()->comment('User ID if authenticated');
            $table->timestamp('blocked_at')->index()->comment('When the request was blocked');
            $table->boolean('transmitted')->default(false)->index()->comment('Whether sent to Cybear platform');
            $table->timestamp('transmitted_at')->nullable()->comment('When transmitted to platform');
            $table->timestamps();
            
            $table->index(['ip_address', 'blocked_at']);
            $table->index(['waf_rule_id', 'blocked_at']);
            $table->index(['transmitted', 'blocked_at']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('cybear_blocked_requests');
    }
};