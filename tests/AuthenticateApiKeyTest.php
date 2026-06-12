<?php

namespace Langsys\ApiKeys\Tests;

use Langsys\ApiKeys\Http\Middleware\AuthenticateApiKey;
use Langsys\ApiKeys\Models\ApiKey;

class AuthenticateApiKeyTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        $router->middleware(AuthenticateApiKey::class)->group(function ($router) {
            $router->get('/guarded', fn () => response()->json(['ok' => true]));
            $router->post('/guarded', fn () => response()->json(['ok' => true]));
        });
    }

    public function test_request_without_a_key_is_rejected(): void
    {
        config()->set('api-keys.allow_authenticated_users', false);

        $this->getJson('/guarded')->assertStatus(401);
    }

    public function test_valid_key_passes_and_sets_request_id_header(): void
    {
        $key = ApiKey::create(['name' => 'test', 'type' => 'write']);

        $this->withHeader('X-Api-Key', $key->plain_key)
            ->getJson('/guarded')
            ->assertOk()
            ->assertHeader('X-Request-ID');
    }

    public function test_invalid_key_is_unauthorized(): void
    {
        $this->withHeader('X-Api-Key', 'bogus')->getJson('/guarded')->assertStatus(401);
    }

    public function test_inactive_key_is_forbidden(): void
    {
        $key = ApiKey::create(['name' => 'test']);
        $key->update(['active' => false]);

        $this->withHeader('X-Api-Key', $key->plain_key)->getJson('/guarded')->assertStatus(403);
    }

    public function test_read_key_cannot_perform_a_write(): void
    {
        $key = ApiKey::create(['name' => 'test', 'type' => 'read']);

        $this->withHeader('X-Api-Key', $key->plain_key)->postJson('/guarded')->assertStatus(403);
    }

    public function test_write_key_can_perform_a_write(): void
    {
        $key = ApiKey::create(['name' => 'test', 'type' => 'write']);

        $this->withHeader('X-Api-Key', $key->plain_key)->postJson('/guarded')->assertOk();
    }
}
