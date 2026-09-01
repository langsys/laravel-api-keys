<?php

namespace Langsys\ApiKeys\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Langsys\ApiKeys\Concerns\HasUuid;

/**
 * A permission, stored once and referenced by id.
 *
 * This is the same `permissions` table langsys/laravel-access-guard uses, with
 * the same shape, so an app running both packages has one row per permission
 * rather than one representation per package.
 */
class Permission extends Model
{
    use HasUuid;

    protected $fillable = ['value', 'label'];

    public function getTable(): string
    {
        return config('api-keys.tables.permissions', 'permissions');
    }

    public function apiKeys(): BelongsToMany
    {
        return $this->belongsToMany(
            config('api-keys.model', ApiKey::class),
            config('api-keys.tables.api_key_has_permissions', 'api_key_has_permissions'),
            'permission_id',
            'api_key_id',
        )->using(ApiKeyPermission::class)->withTimestamps();
    }
}
