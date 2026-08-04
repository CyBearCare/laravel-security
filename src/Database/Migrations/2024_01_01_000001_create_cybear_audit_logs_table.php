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
            $table->text('session_id')->nullable()->comment('Encrypted session identifier hash');
            $table->text('ip_address')->comment('Encrypted client IP address');
            $table->text('user_agent')->nullable()->comment('Encrypted client user agent');
            $table->text('url')->comment('Encrypted request URL');
            $table->string('method', 10)->comment('HTTP method');
            $table->longText('headers')->nullable()->comment('Encrypted request headers');
            $table->longText('payload')->nullable()->comment('Encrypted request data');
            $table->longText('context')->nullable()->comment('Encrypted context data');
            $table->integer('response_code')->nullable()->comment('HTTP response code');
            $table->decimal('processing_time', 10, 3)->nullable()->comment('Processing time in milliseconds');
            $table->timestamp('occurred_at')->index()->comment('When the event occurred');
            $table->boolean('transmitted')->default(false)->index()->comment('Whether sent to Cybear platform');
            $table->timestamp('transmitted_at')->nullable()->comment('When transmitted to platform');
            $table->timestamps();
            
            $table->index(['event_type', 'occurred_at']);
            $table->index(['user_id', 'event_type']);
            $table->index(['transmitted', 'occurred_at']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('cybear_audit_logs');
    }
};
