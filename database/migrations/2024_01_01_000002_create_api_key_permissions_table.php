<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('api_key_permissions')) {
            return;
        }

        Schema::create('api_key_permissions', function (Blueprint $table) {
            $table->id();
            $table->uuid('api_key_id');
            $table->string('permission');
            $table->timestamps();

            $table->foreign('api_key_id')->references('id')->on('api_keys')->cascadeOnDelete();
            $table->unique(['api_key_id', 'permission']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('api_key_permissions');
    }
};
