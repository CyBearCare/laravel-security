<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('cybear_package_data', function (Blueprint $table) {
            $table->id();
            $table->string('package_name')->index();
            $table->string('package_manager', 20)->index()->comment('composer, npm, etc');
            $table->string('version')->nullable();
            $table->string('installed_version')->nullable();
            $table->json('package_info')->nullable()->comment('Raw package data for transmission');
            $table->timestamp('collected_at')->index();
            $table->boolean('transmitted')->default(false)->index();
            $table->timestamp('transmitted_at')->nullable();
            $table->timestamps();
            
            $table->index(['package_manager', 'collected_at']);
            $table->index(['transmitted', 'collected_at']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('cybear_package_data');
    }
};