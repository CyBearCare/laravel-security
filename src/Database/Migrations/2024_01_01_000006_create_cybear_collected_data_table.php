<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('cybear_collected_data', function (Blueprint $table) {
            $table->id();
            $table->string('collection_type', 50)->index()->comment('Type of data: packages, environment, security, etc');
            $table->string('data_source', 100)->nullable()->comment('Source of the data');
            $table->json('collected_data')->comment('Raw collected data for transmission');
            $table->timestamp('collected_at')->index();
            $table->boolean('transmitted')->default(false)->index();
            $table->timestamp('transmitted_at')->nullable();
            $table->string('checksum', 64)->nullable()->comment('Data checksum to avoid duplicates');
            $table->timestamps();
            
            $table->index(['collection_type', 'collected_at']);
            $table->index(['transmitted', 'collected_at']);
            $table->index(['checksum', 'collection_type']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('cybear_collected_data');
    }
};