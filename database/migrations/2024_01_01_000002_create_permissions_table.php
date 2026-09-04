<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Langsys\ApiKeys\Support\SchemaGuard;

return new class extends Migration
{
    public function up(): void
    {
        $name = config('api-keys.tables.permissions', 'permissions');

        // Shared with langsys/laravel-access-guard, which creates the same table
        // with the same shape — whichever package migrates first wins and the
        // other skips. Both must be pointed at the same table to share it.
        SchemaGuard::assertSharedPermissionsTable($name);

        if (! SchemaGuard::shouldCreate($name, ['id', 'value'], 'a uuid `id` primary key and a unique string `value`')) {
            return;
        }

        Schema::create($name, function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('value')->unique();
            $table->string('label')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(config('api-keys.tables.permissions', 'permissions'));
    }
};
