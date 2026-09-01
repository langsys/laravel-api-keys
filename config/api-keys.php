<?php

return [

    /*
    |--------------------------------------------------------------------------
    | API Key Model
    |--------------------------------------------------------------------------
    |
    | The Eloquent model used to represent API keys. Extend the bundled model
    | to add relations (e.g. link keys to your own entities) or override the
    | permission storage, then point this at your subclass.
    |
    */
    'model' => Langsys\ApiKeys\Models\ApiKey::class,

    /*
    |--------------------------------------------------------------------------
    | Request Header
    |--------------------------------------------------------------------------
    |
    | The HTTP header the AuthenticateApiKey middleware reads the key from.
    |
    */
    'header' => env('API_KEY_HEADER', 'X-Api-Key'),

    /*
    |--------------------------------------------------------------------------
    | Key Generation & Hashing
    |--------------------------------------------------------------------------
    |
    | Keys are stored only as a hash; the plaintext is returned once at
    | generation time via the model's transient `$plain_key` property.
    |
    */
    'hash_algorithm' => 'sha256',
    'key_length' => 64,

    /*
    |--------------------------------------------------------------------------
    | Read / Write Enforcement
    |--------------------------------------------------------------------------
    |
    | When enabled, keys of type `read` may only perform safe (GET/HEAD/OPTIONS)
    | requests; mutating requests require a `write` key, or an `ip_write` key
    | calling from an address on its allow-list.
    |
    | SECURITY (`ip_write` only): the client address comes from $request->ip(),
    | which honours X-Forwarded-For only for proxies your app trusts. Laravel
    | trusts none by default — safe. An app that trusts every proxy
    | (TrustProxies at: '*') lets any caller forge the address and walk through
    | the allow-list. Trust specific proxies, or override clientIp() on your key
    | model to read what your edge sets.
    |
    | Set this to false to skip the package's check entirely and enforce write
    | access yourself downstream.
    |
    */
    'enforce_read_write' => true,

    /*
    |--------------------------------------------------------------------------
    | Allow Already-Authenticated Users
    |--------------------------------------------------------------------------
    |
    | When no API key header is present but the request already has an
    | authenticated user (e.g. Sanctum/session), let it through instead of
    | rejecting it. Set to false to require an API key on guarded routes.
    |
    */
    'allow_authenticated_users' => true,

    /*
    |--------------------------------------------------------------------------
    | Default Permissions
    |--------------------------------------------------------------------------
    |
    | Permission strings automatically granted to every newly created key.
    |
    */
    'default_permissions' => [],

    /*
    |--------------------------------------------------------------------------
    | Table Names
    |--------------------------------------------------------------------------
    |
    | Pivot tables follow the `_has_` convention (matching spatie/laravel-permission
    | and langsys). Override here if your app uses different names.
    |
    */
    'tables' => [
        'api_keys' => 'api_keys',
        'api_key_has_permissions' => 'api_key_has_permissions',
    ],

];
