<?php

namespace Langsys\ApiKeys\Tests;

use Illuminate\Http\Request;
use InvalidArgumentException;
use Langsys\ApiKeys\Enums\ApiKeyType;
use Langsys\ApiKeys\Http\Middleware\AuthenticateApiKey;
use Langsys\ApiKeys\Models\ApiKey;

class IpWriteTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        $router->middleware(AuthenticateApiKey::class)->group(function ($router) {
            $router->get('/guarded', fn () => response()->json(['ok' => true]));
            $router->post('/guarded', fn () => response()->json(['ok' => true]));
        });
    }

    private function writeRequest(string $ip): Request
    {
        return Request::create('/guarded', 'POST', server: ['REMOTE_ADDR' => $ip]);
    }

    public function test_ip_write_key_allows_a_write_from_an_allowlisted_address(): void
    {
        $key = ApiKey::create([
            'name' => 'test',
            'type' => 'ip_write',
            'ip_allowlist' => ['203.0.113.0/24'],
        ]);

        $this->assertSame(ApiKeyType::IP_WRITE, $key->type);
        $this->assertTrue($key->allowsWrite($this->writeRequest('203.0.113.5')));
        $this->assertFalse($key->allowsWrite($this->writeRequest('198.51.100.5')));
    }

    public function test_read_and_write_types_are_unaffected(): void
    {
        $read = ApiKey::create(['name' => 'r', 'type' => 'read']);
        $write = ApiKey::create(['name' => 'w', 'type' => 'write']);

        $this->assertFalse($read->allowsWrite($this->writeRequest('203.0.113.5')));
        $this->assertTrue($write->allowsWrite($this->writeRequest('203.0.113.5')));

        // canWrite() means "writes unconditionally", so ip_write is not included.
        $ipWrite = ApiKey::create(['name' => 'i', 'type' => 'ip_write', 'ip_allowlist' => ['203.0.113.5']]);
        $this->assertTrue($write->canWrite());
        $this->assertFalse($ipWrite->canWrite());
    }

    public function test_ip_write_key_writes_through_the_middleware_from_an_allowlisted_address(): void
    {
        $key = ApiKey::create([
            'name' => 'test',
            'type' => 'ip_write',
            'ip_allowlist' => ['203.0.113.0/24'],
        ]);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])
            ->withHeader('X-Api-Key', $key->plain_key)
            ->postJson('/guarded')
            ->assertOk();
    }

    public function test_ip_write_key_is_denied_from_another_address_with_an_accurate_message(): void
    {
        $key = ApiKey::create([
            'name' => 'test',
            'type' => 'ip_write',
            'ip_allowlist' => ['203.0.113.0/24'],
        ]);

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.5'])
            ->withHeader('X-Api-Key', $key->plain_key)
            ->postJson('/guarded')
            ->assertStatus(403)
            ->assertJson(['message' => 'This API key may only write from an allow-listed IP address.']);
    }

    public function test_ip_write_key_still_reads_from_anywhere(): void
    {
        $key = ApiKey::create([
            'name' => 'test',
            'type' => 'ip_write',
            'ip_allowlist' => ['203.0.113.0/24'],
        ]);

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.5'])
            ->withHeader('X-Api-Key', $key->plain_key)
            ->getJson('/guarded')
            ->assertOk();
    }

    /**
     * An empty allow-list is NOT rejected. It looks like a key that can never
     * write, but extraWriteAllowances() may authorise writes by other means —
     * see SubclassExtensionTest. The package cannot know, so it does not guess.
     */
    public function test_an_ip_write_key_without_an_allowlist_is_allowed_but_cannot_write_on_its_own(): void
    {
        $key = ApiKey::create(['name' => 'test', 'type' => 'ip_write']);

        $this->assertSame(ApiKeyType::IP_WRITE, $key->type);
        $this->assertFalse($key->allowsWrite($this->writeRequest('203.0.113.5')));
    }

    public function test_a_malformed_allowlist_entry_is_rejected_at_write_time(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid ip_allowlist entry [nonsense]');

        ApiKey::create(['name' => 'test', 'type' => 'ip_write', 'ip_allowlist' => ['nonsense']]);
    }

    public function test_an_allow_everything_entry_is_rejected_at_write_time(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('would match every address');

        ApiKey::create(['name' => 'test', 'type' => 'ip_write', 'ip_allowlist' => ['0.0.0.0/0']]);
    }

    public function test_validation_also_runs_on_update(): void
    {
        $key = ApiKey::create(['name' => 'test', 'type' => 'ip_write', 'ip_allowlist' => ['203.0.113.0/24']]);

        $this->expectException(InvalidArgumentException::class);

        $key->update(['ip_allowlist' => ['0.0.0.0/0']]);
    }

    public function test_emptying_an_allowlist_on_update_is_permitted(): void
    {
        $key = ApiKey::create(['name' => 'test', 'type' => 'ip_write', 'ip_allowlist' => ['203.0.113.0/24']]);

        $key->update(['ip_allowlist' => []]);

        $this->assertSame([], $key->fresh()->writeIpAllowlist());
    }

    public function test_read_and_write_keys_skip_allowlist_validation(): void
    {
        $read = ApiKey::create(['name' => 'r', 'type' => 'read']);
        $write = ApiKey::create(['name' => 'w', 'type' => 'write', 'ip_allowlist' => ['garbage']]);

        $this->assertSame(ApiKeyType::READ, $read->type);
        $this->assertSame(ApiKeyType::WRITE, $write->type);
    }

    public function test_the_request_id_is_exposed_as_an_unforgeable_attribute(): void
    {
        $key = ApiKey::create(['name' => 'test', 'type' => 'write']);
        $seen = null;

        $this->app['router']->post('/attr', function (Request $request) use (&$seen) {
            $seen = $request->attributes->get('api_key_request_id');

            return response()->json(['ok' => true]);
        })->middleware(AuthenticateApiKey::class);

        $response = $this->withHeader('X-Api-Key', $key->plain_key)->postJson('/attr')->assertOk();

        $this->assertNotNull($seen);
        $this->assertSame($response->headers->get('X-Request-ID'), $seen);
    }
}
