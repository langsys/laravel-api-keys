<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $name = config('api-keys.tables.api_key_has_permissions', 'api_key_has_permissions');

        if (Schema::hasTable($name)) {
            return;
        }

        Schema::create($name, function (Blueprint $table) {
            $table->id();
            $table->uuid('api_key_id');
            $table->string('permission');
            $table->timestamps();

            $table->foreign('api_key_id')
                ->references('id')->on(config('api-keys.tables.api_keys', 'api_keys'))
                ->cascadeOnDelete();
            $table->unique(['api_key_id', 'permission']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(config('api-keys.tables.api_key_has_permissions', 'api_key_has_permissions'));
    }
};
