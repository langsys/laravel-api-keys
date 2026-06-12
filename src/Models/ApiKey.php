<?php

namespace Langsys\ApiKeys\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Str;
use Langsys\ApiKeys\Concerns\HasUuid;
use Langsys\ApiKeys\Enums\ApiKeyType;
use Langsys\ApiKeys\Events\ApiKeyActivated;
use Langsys\ApiKeys\Events\ApiKeyCreated;
use Langsys\ApiKeys\Events\ApiKeyDeactivated;
use Langsys\ApiKeys\Events\ApiKeyDeleted;

class ApiKey extends Model
{
    use HasUuid;
    use SoftDeletes;

    /**
     * The plaintext key. Only populated when a key is generated or looked up
     * by value — never persisted. Surface this to the user exactly once.
     */
    public ?string $plain_key = null;

    protected $table = 'api_keys';

    protected $fillable = ['name', 'type', 'active'];

    protected $hidden = ['key_hash'];

    protected $casts = [
        'type' => ApiKeyType::class,
        'active' => 'boolean',
    ];

    protected static function booted(): void
    {
        static::creating(function (self $apiKey) {
            if (! $apiKey->key_hash) {
                $apiKey->setPlainKey(static::generate());
            }

            $apiKey->type ??= ApiKeyType::READ;
            $apiKey->active ??= true;
        });

        static::created(function (self $apiKey) {
            $apiKey->grantPermissions(config('api-keys.default_permissions', []));

            event(new ApiKeyCreated($apiKey));
        });

        static::updated(function (self $apiKey) {
            if ($apiKey->wasChanged('active')) {
                event($apiKey->active
                    ? new ApiKeyActivated($apiKey)
                    : new ApiKeyDeactivated($apiKey));
            }
        });

        static::deleted(function (self $apiKey) {
            event(new ApiKeyDeleted($apiKey));
        });
    }

    /**
     * Generate a cryptographically random key that does not collide with an
     * existing one (including soft-deleted keys).
     */
    public static function generate(): string
    {
        do {
            $key = Str::random((int) config('api-keys.key_length', 64));
        } while (static::keyExists($key));

        return $key;
    }

    public static function hashKey(string $key): string
    {
        return hash((string) config('api-keys.hash_algorithm', 'sha256'), $key);
    }

    public function setPlainKey(string $plainKey): void
    {
        $this->plain_key = $plainKey;
        $this->key_hash = static::hashKey($plainKey);
    }

    /**
     * Resolve a key record from its plaintext value. The returned model carries
     * the plaintext on `$plain_key`. Does not filter by active state — callers
     * decide how to treat inactive keys (see isValidKey / the middleware).
     */
    public static function getByKey(?string $key): ?static
    {
        if (! $key) {
            return null;
        }

        $apiKey = static::query()->where('key_hash', static::hashKey($key))->first();

        if ($apiKey) {
            $apiKey->plain_key = $key;
        }

        return $apiKey;
    }

    public static function isValidKey(?string $key): bool
    {
        $apiKey = static::getByKey($key);

        return $apiKey !== null && $apiKey->active;
    }

    /**
     * Whether a key with this value exists, including soft-deleted keys, so a
     * revoked key's value is never re-issued.
     */
    public static function keyExists(string $key): bool
    {
        return static::withTrashed()->where('key_hash', static::hashKey($key))->exists();
    }

    public static function nameExists(string $name): bool
    {
        return static::where('name', $name)->exists();
    }

    public static function isValidName(?string $name): bool
    {
        return $name !== null && preg_match('/^[a-z0-9-]{1,255}$/', $name) === 1;
    }

    public function permissions(): HasMany
    {
        return $this->hasMany(ApiKeyPermission::class, 'api_key_id');
    }

    /**
     * @return array<int, string>
     */
    public function permissionValues(): array
    {
        return $this->permissions()->pluck('permission')->all();
    }

    public function hasPermission(string $permission): bool
    {
        return $this->permissions()->where('permission', $permission)->exists();
    }

    /**
     * @param string|array<int, string> $permissions
     */
    public function grantPermissions(string|array $permissions): static
    {
        foreach (array_filter((array) $permissions) as $permission) {
            if (! $this->hasPermission($permission)) {
                $this->permissions()->create(['permission' => $permission]);
            }
        }

        return $this;
    }

    /**
     * @param string|array<int, string> $permissions
     */
    public function revokePermissions(string|array $permissions): static
    {
        $this->permissions()->whereIn('permission', (array) $permissions)->delete();

        return $this;
    }

    /**
     * @param array<int, string> $permissions
     */
    public function syncPermissions(array $permissions): static
    {
        $this->permissions()->whereNotIn('permission', $permissions ?: [''])->delete();

        return $this->grantPermissions($permissions);
    }

    public function canWrite(): bool
    {
        return $this->type === ApiKeyType::WRITE;
    }
}
