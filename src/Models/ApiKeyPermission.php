<?php

namespace Langsys\ApiKeys\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ApiKeyPermission extends Model
{
    protected $fillable = ['api_key_id', 'permission'];

    public function getTable(): string
    {
        return config('api-keys.tables.api_key_has_permissions', 'api_key_has_permissions');
    }

    public function apiKey(): BelongsTo
    {
        return $this->belongsTo(ApiKey::class, 'api_key_id');
    }
}
