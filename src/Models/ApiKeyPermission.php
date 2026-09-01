<?php

namespace Langsys\ApiKeys\Models;

use Illuminate\Database\Eloquent\Relations\Pivot;

/**
 * The api_keys ↔ permissions pivot. Keyed by (permission_id, api_key_id); it
 * carries no surrogate id of its own.
 */
class ApiKeyPermission extends Pivot
{
    public $incrementing = false;

    public function getTable(): string
    {
        return config('api-keys.tables.api_key_has_permissions', 'api_key_has_permissions');
    }
}
