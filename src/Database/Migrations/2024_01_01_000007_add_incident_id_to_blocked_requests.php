<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::table('cybear_blocked_requests', function (Blueprint $table) {
            $table->string('incident_id', 36)->nullable()->index()->after('reason')->comment('Unique incident identifier');
        });
    }

    public function down()
    {
        Schema::table('cybear_blocked_requests', function (Blueprint $table) {
            $table->dropColumn('incident_id');
        });
    }
};