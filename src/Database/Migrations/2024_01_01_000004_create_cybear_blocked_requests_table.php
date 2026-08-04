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
            $table->text('ip_address')->comment('Encrypted blocked IP address');
            $table->text('user_agent')->nullable()->comment('Encrypted user agent string');
            $table->text('url')->comment('Encrypted requested URL');
            $table->string('method', 10)->comment('HTTP method');
            $table->longText('headers')->nullable()->comment('Encrypted request headers');
            $table->longText('payload')->nullable()->comment('Encrypted request payload');
            $table->foreignId('waf_rule_id')->nullable()->constrained('cybear_waf_rules')->nullOnDelete();
            $table->string('waf_rule_key', 100)->nullable()->index()->comment('Stable remote WAF rule identifier');
            $table->string('reason')->comment('Reason for blocking');
            $table->string('incident_id', 36)->nullable()->index()->comment('Unique incident identifier');
            $table->text('session_id')->nullable()->comment('Encrypted session identifier hash');
            $table->string('user_id')->nullable()->index()->comment('User ID if authenticated');
            $table->timestamp('blocked_at')->index()->comment('When the request was blocked');
            $table->boolean('transmitted')->default(false)->index()->comment('Whether sent to Cybear platform');
            $table->timestamp('transmitted_at')->nullable()->comment('When transmitted to platform');
            $table->timestamps();
            
            $table->index(['waf_rule_id', 'blocked_at']);
            $table->index(['transmitted', 'blocked_at']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('cybear_blocked_requests');
    }
};
