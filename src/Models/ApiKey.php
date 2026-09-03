<?php

namespace Langsys\ApiKeys\Models;

use BackedEnum;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Langsys\ApiKeys\Concerns\HasUuid;
use Langsys\ApiKeys\Enums\ApiKeyType;
use Langsys\ApiKeys\Events\ApiKeyActivated;
use Langsys\ApiKeys\Events\ApiKeyCreated;
use Langsys\ApiKeys\Events\ApiKeyDeactivated;
use Langsys\ApiKeys\Events\ApiKeyDeleted;
use Langsys\ApiKeys\Support\IpMatcher;

class ApiKey extends Model
{
    use HasUuid;
    use SoftDeletes;

    /**
     * The plaintext key. Only populated when a key is generated or looked up
     * by value — never persisted. Surface this to the user exactly once.
     */
    public ?string $plain_key = null;

    protected $fillable = ['name', 'type', 'active', 'ip_allowlist'];

    protected $hidden = ['key_hash'];

    protected $casts = [
        'type' => ApiKeyType::class,
        'active' => 'boolean',
        'ip_allowlist' => 'array',
    ];

    public function getTable(): string
    {
        return config('api-keys.tables.api_keys', 'api_keys');
    }

    protected static function booted(): void
    {
        static::creating(function (self $apiKey) {
            if (! $apiKey->key_hash) {
                $apiKey->setPlainKey(static::generate());
            }

            $apiKey->type ??= ApiKeyType::READ->value;
            $apiKey->active ??= true;
        });

        static::saving(function (self $apiKey) {
            $apiKey->assertWriteConfigurationIsSafe();
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

    public function permissions(): BelongsToMany
    {
        return $this->belongsToMany(
            Permission::class,
            config('api-keys.tables.api_key_has_permissions', 'api_key_has_permissions'),
            'api_key_id',
            'permission_id',
        )->using(ApiKeyPermission::class)->withTimestamps();
    }

    /**
     * @return array<int, string>
     */
    public function permissionValues(): array
    {
        return $this->permissions()->pluck('value')->all();
    }

    public function hasPermission(Permission|string|BackedEnum $permission): bool
    {
        return $this->permissions()->where('value', static::permissionValue($permission))->exists();
    }

    /**
     * Grant permissions by value, creating any that do not exist yet.
     *
     * @param Permission|string|BackedEnum|array<int, Permission|string|BackedEnum> $permissions
     */
    public function grantPermissions(Permission|string|BackedEnum|array $permissions): static
    {
        $ids = $this->resolvePermissionIds($permissions);

        if ($ids !== []) {
            $this->permissions()->syncWithoutDetaching($ids);
        }

        return $this;
    }

    /**
     * @param Permission|string|BackedEnum|array<int, Permission|string|BackedEnum> $permissions
     */
    public function revokePermissions(Permission|string|BackedEnum|array $permissions): static
    {
        $values = array_map(
            static fn ($permission) => static::permissionValue($permission),
            static::wrapPermissions($permissions),
        );

        if ($values !== []) {
            $this->permissions()->detach(
                Permission::query()->whereIn('value', $values)->pluck('id')->all()
            );
        }

        return $this;
    }

    /**
     * @param array<int, Permission|string|BackedEnum> $permissions
     */
    public function syncPermissions(array $permissions): static
    {
        $this->permissions()->sync($this->resolvePermissionIds($permissions));

        return $this;
    }

    /**
     * @param Permission|string|BackedEnum|array<int, Permission|string|BackedEnum> $permissions
     * @return array<int, string>
     */
    protected function resolvePermissionIds(Permission|string|BackedEnum|array $permissions): array
    {
        $ids = [];

        foreach (static::wrapPermissions($permissions) as $permission) {
            $value = static::permissionValue($permission);

            if ($value === '') {
                continue;
            }

            $ids[] = Permission::query()->firstOrCreate(['value' => $value])->getKey();
        }

        return array_values(array_unique($ids));
    }

    protected static function permissionValue(Permission|string|BackedEnum $permission): string
    {
        return match (true) {
            $permission instanceof Permission => (string) $permission->value,
            $permission instanceof BackedEnum => (string) $permission->value,
            default => $permission,
        };
    }

    /**
     * @return array<int, Permission|string|BackedEnum>
     */
    protected static function wrapPermissions(Permission|string|BackedEnum|array $permissions): array
    {
        if (! is_array($permissions)) {
            return [$permissions];
        }

        return array_values(array_filter(
            $permissions,
            static fn ($permission) => $permission !== null && $permission !== ''
        ));
    }

    public function canWrite(): bool
    {
        return $this->type === ApiKeyType::WRITE;
    }

    /**
     * Whether this key may perform a mutating request. WRITE keys always may;
     * IP_WRITE keys only from an allow-listed address; READ keys never — unless
     * extraWriteAllowances() says otherwise.
     */
    public function allowsWrite(Request $request): bool
    {
        $allowed = match ($this->type) {
            ApiKeyType::WRITE => true,
            ApiKeyType::IP_WRITE => IpMatcher::matches($this->clientIp($request), $this->writeIpAllowlist()),
            default => false,
        };

        return $allowed || $this->extraWriteAllowances($request);
    }

    /**
     * The effective allow-list for this key: its own entries plus anything the
     * application contributes via additionalAllowlistEntries().
     *
     * @return array<int, mixed>
     */
    public function writeIpAllowlist(): array
    {
        $entries = [
            ...(array) $this->ip_allowlist,
            ...$this->additionalAllowlistEntries(),
        ];

        return array_values(array_filter(
            $entries,
            fn ($entry) => ! is_string($entry) || trim($entry) !== ''
        ));
    }

    /**
     * Extension point: extra allow-list entries contributed by the application
     * — e.g. the egress addresses of a trusted internal service. Merged into
     * the key's own ip_allowlist.
     *
     * @return array<int, mixed>
     */
    protected function additionalAllowlistEntries(): array
    {
        return [];
    }

    /**
     * Extension point: application-specific write authorisation, such as a
     * signed grant or device attestation. OR'd into the type decision, so
     * returning true lets a key write where its type alone would not.
     *
     * This deliberately bypasses the package's read/write guarantee. Anything
     * put here is doing the job of an auth check — keep it as strict as one.
     */
    protected function extraWriteAllowances(Request $request): bool
    {
        return false;
    }

    /**
     * The address an IP_WRITE key is matched against.
     *
     * SECURITY: $request->ip() honours X-Forwarded-For only for proxies the
     * application trusts. Laravel trusts none by default, which is safe — the
     * header is ignored and the socket address is used. An application that
     * trusts every proxy (TrustProxies at: '*') instead lets any caller forge
     * this value and walk straight through the allow-list. Trust specific
     * proxy addresses, or override this to read whatever your edge sets
     * (e.g. CF-Connecting-IP) after verifying the request came from the edge.
     */
    protected function clientIp(Request $request): ?string
    {
        return $request->ip();
    }

    /**
     * A malformed allow-list entry silently never matches, surfacing as an
     * unexplained 403 at request time, so reject it at write time instead.
     *
     * Note what is deliberately NOT checked: that the allow-list is non-empty.
     * An empty one looks like a key that can never write, but extraWriteAllowances()
     * exists precisely so an application can authorise writes by means this
     * package knows nothing about — attestation, a signed grant. Asserting
     * non-emptiness here would refuse to persist a configuration the package's
     * own extension point makes valid.
     */
    protected function assertWriteConfigurationIsSafe(): void
    {
        if ($this->type !== ApiKeyType::IP_WRITE) {
            return;
        }

        foreach ($this->writeIpAllowlist() as $entry) {
            if (! IpMatcher::isValidEntry($entry)) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid ip_allowlist entry [%s]. Use an exact IPv4/IPv6 address, or a CIDR range '
                    . 'such as 203.0.113.0/24. A /0 prefix is rejected: it would match every address.',
                    is_scalar($entry) ? (string) $entry : get_debug_type($entry)
                ));
            }
        }
    }
}
