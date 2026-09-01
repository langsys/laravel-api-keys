<?php

namespace Langsys\ApiKeys\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
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
     * An IP_WRITE key with no usable allow-list can never write, and one with a
     * malformed entry silently never matches. Both are configuration mistakes
     * that would surface as an unexplained 403 at request time, so reject them
     * at write time instead.
     */
    protected function assertWriteConfigurationIsSafe(): void
    {
        if ($this->type !== ApiKeyType::IP_WRITE) {
            return;
        }

        $entries = $this->writeIpAllowlist();

        if ($entries === []) {
            throw new InvalidArgumentException(
                'An ip_write API key requires a non-empty ip_allowlist; without one it could never write.'
            );
        }

        foreach ($entries as $entry) {
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
