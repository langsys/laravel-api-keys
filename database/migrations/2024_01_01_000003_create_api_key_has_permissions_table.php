<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Langsys\ApiKeys\Support\SchemaGuard;

return new class extends Migration
{
    public function up(): void
    {
        $name = config('api-keys.tables.api_key_has_permissions', 'api_key_has_permissions');
        $keys = config('api-keys.tables.api_keys', 'api_keys');
        $permissions = config('api-keys.tables.permissions', 'permissions');

        if (! SchemaGuard::shouldCreate($name, ['api_key_id', 'permission_id'], 'a uuid `api_key_id` and a uuid `permission_id`')) {
            return;
        }

        Schema::create($name, function (Blueprint $table) use ($keys, $permissions) {
            $table->uuid('api_key_id');
            $table->uuid('permission_id');
            $table->timestamps();

            $table->foreign('api_key_id')->references('id')->on($keys)->cascadeOnDelete();
            $table->foreign('permission_id')->references('id')->on($permissions)->cascadeOnDelete();
            $table->primary(['permission_id', 'api_key_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(config('api-keys.tables.api_key_has_permissions', 'api_key_has_permissions'));
    }
};
