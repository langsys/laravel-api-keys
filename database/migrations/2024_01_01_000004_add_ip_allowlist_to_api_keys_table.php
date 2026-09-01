<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $name = config('api-keys.tables.api_keys', 'api_keys');

        if (! Schema::hasTable($name) || Schema::hasColumn($name, 'ip_allowlist')) {
            return;
        }

        Schema::table($name, function (Blueprint $table) {
            $table->json('ip_allowlist')->nullable();
        });
    }

    public function down(): void
    {
        $name = config('api-keys.tables.api_keys', 'api_keys');

        if (Schema::hasTable($name) && Schema::hasColumn($name, 'ip_allowlist')) {
            Schema::table($name, function (Blueprint $table) {
                $table->dropColumn('ip_allowlist');
            });
        }
    }
};
