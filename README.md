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

The migrations are guarded with `Schema::hasTable()` checks, so publishing them
into an app that already has `api_keys` tables is a safe no-op.

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
  requests (disable via `enforce_read_write`);
- stamps an `X-Request-ID` on the request and response for tracing;
- exposes the authenticated key on `$request->attributes->get('api_key')`.

## Permissions

Keys carry a flat list of permission strings (think OAuth scopes):

```php
$key->grantPermissions(['view_projects', 'edit_projects']);
$key->hasPermission('view_projects'); // true
$key->revokePermissions('edit_projects');
$key->syncPermissions(['view_projects']);
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

## Testing

```bash
composer install
composer test
```
