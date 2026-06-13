<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $name = config('api-keys.tables.api_keys', 'api_keys');

        if (Schema::hasTable($name)) {
            return;
        }

        Schema::create($name, function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('name');
            $table->string('key_hash', 128)->unique();
            $table->string('type')->default('read');
            $table->boolean('active')->default(true);
            $table->timestamps();
            $table->softDeletes();

            $table->index('name');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(config('api-keys.tables.api_keys', 'api_keys'));
    }
};
