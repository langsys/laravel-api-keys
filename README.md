# Laravel API Keys

Standalone API key authentication for Laravel. Hashed-at-rest keys, read/write
scopes, per-key permissions, lifecycle events, and a drop-in authentication
middleware. No other Langsys package is required — it works on its own, and
integrates cleanly with [`langsys/laravel-access-guard`](https://github.com/langsys/laravel-access-guard)
when you want entity-scoped authorization on top.

## Installation

```bash
composer require langsys/laravel-api-keys
php artisan vendor:publish --tag=api-keys-migrations
php artisan vendor:publish --tag=api-keys-config   # optional
php artisan migrate
```

The migrations skip tables your application already has, so publishing them into
an app that already models API keys or permissions is a safe no-op. A table that
exists with an *incompatible* shape is not skipped silently — the migration fails
with the table name and the missing columns, rather than installing cleanly and
failing later at query time.

## Creating keys

```php
use Langsys\ApiKeys\Models\ApiKey;

$key = ApiKey::create(['name' => 'mobile-app', 'type' => 'write']);

// The plaintext is available exactly once, right after generation:
$key->plain_key; // "x7Qa...64 chars" — show this to the user now; it is never stored.
```

Only a `sha256` hash of the key is persisted (`key_hash`). Resolve a key from a
plaintext value with `ApiKey::getByKey($plain)` (returns `null` if unknown).

## Protecting routes

Apply the `api-key` middleware (registered automatically):

```php
Route::middleware('api-key')->group(function () {
    Route::get('/projects', [ProjectController::class, 'index']);
    Route::post('/projects', [ProjectController::class, 'store']); // requires a `write` key
});
```

The client sends the key in the `X-Api-Key` header (configurable). The middleware:

- rejects missing (`401`), unknown (`401`), and inactive (`403`) keys;
- enforces read/write scope — `read` keys may only make `GET/HEAD/OPTIONS`
  requests, `ip_write` keys may write only from an allow-listed address
  (disable via `enforce_read_write`);
- stamps an `X-Request-ID` on the request and response for tracing;
- exposes the authenticated key on `$request->attributes->get('api_key')`, and
  the request id on `$request->attributes->get('api_key_request_id')`.

The request id is exposed as an attribute as well as a header because the header
can be overwritten by other middleware. The package always mints the id itself
and never honours a caller-supplied `X-Request-ID`, so the attribute is safe to
use as a correlation or lookup key; the header is not.

## IP-restricted write keys

A third key type, `ip_write`, reads from anywhere but writes only from an
allow-listed address. It lets one key ship into client code — read-only to the
public — while trusted networks (office or VPN egress, a partner's servers)
can still write.

```php
$key = ApiKey::create([
    'name' => 'field-app',
    'type' => 'ip_write',
    'ip_allowlist' => ['203.0.113.0/24', '2001:db8::/32', '198.51.100.7'],
]);
```

Entries are exact IPv4/IPv6 addresses or CIDR ranges. Matching fails closed: an
unparseable address, a malformed entry, a mismatched address family, or an empty
allow-list all deny the write. A `/0` prefix is rejected outright — as an
allow-list entry it would authorise every address, which is never intended.

A malformed entry silently never matches, so it is rejected when you save the
key rather than 403-ing mysteriously later:

```php
ApiKey::create(['name' => 'oops', 'type' => 'ip_write', 'ip_allowlist' => ['nonsense']]);
// InvalidArgumentException: Invalid ip_allowlist entry [nonsense]…
```

An **empty** allow-list is permitted. It looks like a key that can never write,
but `extraWriteAllowances()` (below) exists so an application can authorise
writes by means this package knows nothing about — device attestation, a signed
grant — and an attestation-only key legitimately has no addresses at all. The
package cannot know whether another path exists, so it does not guess.

> **Security — read this before using `ip_write` behind a proxy.**
> The address is taken from `$request->ip()`, which honours `X-Forwarded-For`
> only for proxies your application trusts. Laravel trusts none by default,
> which is safe. But an application that trusts *every* proxy (`TrustProxies`
> `at: '*'`) lets any caller forge `X-Forwarded-For` and walk straight through
> the allow-list. Trust specific proxy addresses, or override `clientIp()` (see
> below) to read whatever your edge sets.

## Extending the model

Point `api-keys.model` at your own subclass to add columns, relations, or
application-specific authorization:

```php
// config/api-keys.php
'model' => App\Models\ApiKey::class,
```

Three `protected` hooks are the supported extension points:

```php
class ApiKey extends \Langsys\ApiKeys\Models\ApiKey
{
    // Extra write authorization — a signed grant, device attestation, and so
    // on. OR'd into the type decision, so returning true lets a key write
    // where its type alone would not. This bypasses the read/write guarantee
    // by design; keep it as strict as the check it replaces.
    protected function extraWriteAllowances(Request $request): bool
    {
        return $this->hasValidWriteGrant($request);
    }

    // Allow-list entries contributed by the application rather than stored on
    // the key — e.g. the egress addresses of a trusted internal service.
    protected function additionalAllowlistEntries(): array
    {
        return config('services.renderer.egress_ips', []);
    }

    // Where the client address comes from, when $request->ip() is not it.
    protected function clientIp(Request $request): ?string
    {
        return $request->header('CF-Connecting-IP') ?: $request->ip();
    }
}
```

When subclassing, remember that Eloquent's `$fillable`, `$hidden` and `$casts`
**replace** rather than merge. In particular keep `'type' => ApiKeyType::class`
in `$casts` — without it the middleware's type check silently denies every
write. If you must keep your own enum for `type`, cast to it and set
`enforce_read_write => false` so the package stops making that decision at all.

## Permissions

Keys are granted permissions by value (think OAuth scopes):

```php
$key->grantPermissions(['view_projects', 'edit_projects']);
$key->hasPermission('view_projects'); // true
$key->revokePermissions('edit_projects');
$key->syncPermissions(['view_projects']);
$key->permissionValues();             // ['view_projects']
```

Permissions are stored **once** as rows in a shared `permissions` table
(`id`, `value`, `label`) and referenced from `api_key_has_permissions` by
`permission_id`. `grantPermissions()` creates any value that doesn't exist yet,
and `revokePermissions()` detaches the key without deleting the shared row.

This is deliberately the same table and shape that
[`langsys/laravel-access-guard`](https://github.com/langsys/laravel-access-guard)
uses for role and model permissions, so an application running both packages has
one row per permission rather than one representation per package. Whichever
package migrates first creates the table; the other skips it.

Anywhere a permission is accepted you may pass a value, a backed enum, or a
`Permission` model:

```php
$key->grantPermissions(Permission::create(['value' => 'ship_it']));
$key->hasPermission(MyPermission::ViewProjects);  // a BackedEnum
$key->hasPermission('view_projects');
```

Set `default_permissions` in the config to grant a baseline set to every new key.

## Events

Fired so you can plug in your own audit logging without this package owning an
audit table:

| Event | When |
| --- | --- |
| `ApiKeyAuthenticated` | a request authenticates with a key (carries the `Request`) |
| `ApiKeyCreated` | a key is created |
| `ApiKeyActivated` / `ApiKeyDeactivated` | the `active` flag flips |
| `ApiKeyDeleted` | a key is deleted |

## Using with laravel-access-guard

Install both and your API keys become first-class authorization subjects with no
glue code. `access-guard` detects this package and adapts its `ApiKey`
automatically — checking the key's permissions and whether it's linked to the
entity being accessed. You link keys to entities on the access-guard side
(`$entity->grantApiKey($key)`, see its README); no subclassing or contracts
required here.

If your application already links keys to entities through its own pivot, the
other supported path is to implement access-guard's `AuthorizableByKey` contract
on your own key subclass and set access-guard's `bridge => null`. Auto-detection
then stays out of the way and your existing relations keep being used.

## Testing

```bash
composer install
composer test
```
