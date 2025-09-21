<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('cybear_waf_rules', function (Blueprint $table) {
            $table->id();
            $table->string('rule_id', 100)->unique()->comment('Unique rule identifier');
            $table->string('name')->comment('Human readable rule name');
            $table->text('description')->nullable()->comment('Rule description');
            $table->string('category', 50)->index()->comment('Rule category (xss, sqli, etc.)');
            $table->enum('severity', ['low', 'medium', 'high', 'critical'])->default('medium')->index();
            $table->json('conditions')->comment('Rule conditions as JSON');
            $table->enum('action', ['block', 'monitor', 'challenge', 'redirect'])->default('monitor');
            $table->json('action_params')->nullable()->comment('Action parameters');
            $table->boolean('enabled')->default(true)->index();
            $table->integer('priority')->default(100)->index()->comment('Rule execution priority');
            $table->string('source', 50)->default('cybear')->comment('Rule source (cybear, custom, etc.)');
            $table->json('metadata')->nullable()->comment('Additional rule metadata');
            $table->timestamp('last_triggered')->nullable()->comment('Last time rule was triggered');
            $table->integer('trigger_count')->default(0)->comment('Number of times triggered');
            $table->timestamps();
            
            $table->index(['enabled', 'priority']);
            $table->index(['category', 'severity']);
            $table->index(['source', 'enabled']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('cybear_waf_rules');
    }
};