<?php

namespace Langsys\ApiKeys\Tests;

use Illuminate\Http\Request;
use Langsys\ApiKeys\Enums\ApiKeyType;
use Langsys\ApiKeys\Http\Middleware\AuthenticateApiKey;
use Langsys\ApiKeys\Models\ApiKey;

class SubclassExtensionTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        $router->middleware(AuthenticateApiKey::class)->group(function ($router) {
            $router->post('/guarded', fn () => response()->json(['ok' => true]));
        });
    }

    private function writeRequest(string $ip = '198.51.100.5'): Request
    {
        return Request::create('/guarded', 'POST', server: ['REMOTE_ADDR' => $ip]);
    }

    public function test_extra_write_allowances_can_authorise_a_write_the_type_would_refuse(): void
    {
        $key = GrantingApiKey::create(['name' => 'test', 'type' => 'read']);

        $this->assertFalse($key->allowsWrite($this->writeRequest()));

        $granted = $this->writeRequest();
        $granted->headers->set('X-Grant', 'let-me-in');

        $this->assertTrue($key->allowsWrite($granted));
    }

    public function test_additional_allowlist_entries_are_merged_into_the_keys_own(): void
    {
        $key = RendererApiKey::create([
            'name' => 'test',
            'type' => 'ip_write',
            'ip_allowlist' => ['203.0.113.0/24'],
        ]);

        // Its own entry still matches...
        $this->assertTrue($key->allowsWrite($this->writeRequest('203.0.113.5')));
        // ...and so does the one the application contributes.
        $this->assertTrue($key->allowsWrite($this->writeRequest('192.0.2.7')));
        $this->assertFalse($key->allowsWrite($this->writeRequest('198.51.100.5')));
    }

    public function test_a_key_with_only_application_supplied_entries_passes_validation(): void
    {
        $key = RendererApiKey::create(['name' => 'test', 'type' => 'ip_write']);

        $this->assertTrue($key->allowsWrite($this->writeRequest('192.0.2.7')));
    }

    /**
     * Regression: an ip_write key with NO allow-list, writing purely through
     * extraWriteAllowances() (device attestation, a signed grant). The package
     * used to refuse to save this, which contradicted its own extension point —
     * and refused it for ip_write while permitting the identical setup on a
     * read key, punishing the stricter type.
     */
    public function test_an_ip_write_key_may_rely_solely_on_extra_write_allowances(): void
    {
        $key = GrantingApiKey::create(['name' => 'attested', 'type' => 'ip_write']);

        $this->assertSame([], $key->writeIpAllowlist());
        $this->assertFalse($key->allowsWrite($this->writeRequest()));

        $granted = $this->writeRequest();
        $granted->headers->set('X-Grant', 'let-me-in');

        $this->assertTrue($key->allowsWrite($granted));
    }

    public function test_a_malformed_entry_is_still_rejected_on_a_key_that_uses_the_hook(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        GrantingApiKey::create(['name' => 'attested', 'type' => 'ip_write', 'ip_allowlist' => ['nonsense']]);
    }

    public function test_client_ip_resolution_can_be_overridden(): void
    {
        $key = EdgeApiKey::create([
            'name' => 'test',
            'type' => 'ip_write',
            'ip_allowlist' => ['203.0.113.0/24'],
        ]);

        $request = $this->writeRequest('10.0.0.1');
        $this->assertFalse($key->allowsWrite($request));

        $request->headers->set('CF-Connecting-IP', '203.0.113.5');
        $this->assertTrue($key->allowsWrite($request));
    }

    public function test_the_configured_model_is_used_by_the_middleware(): void
    {
        config()->set('api-keys.model', GrantingApiKey::class);

        $key = GrantingApiKey::create(['name' => 'test', 'type' => 'read']);

        $this->withHeader('X-Api-Key', $key->plain_key)
            ->postJson('/guarded')
            ->assertStatus(403);

        $this->withHeader('X-Api-Key', $key->plain_key)
            ->withHeader('X-Grant', 'let-me-in')
            ->postJson('/guarded')
            ->assertOk();
    }

    /**
     * Regression: the model used to default `type` by assigning a package enum
     * INSTANCE, which Laravel 11+ rejects when a subclass casts `type` to its
     * own enum ("Value [...] is not of the expected enum type"). Laravel 10
     * coerced it silently, so this only ever failed after an upgrade.
     */
    public function test_a_subclass_may_cast_type_to_its_own_enum(): void
    {
        $key = ConsumerApiKey::create(['name' => 'test']);

        $this->assertSame(ConsumerApiKeyType::READ, $key->type);
        $this->assertSame('read', $key->getRawOriginal('type'));

        $found = ConsumerApiKey::getByKey($key->plain_key);

        $this->assertInstanceOf(ConsumerApiKey::class, $found);
        $this->assertSame(ConsumerApiKeyType::READ, $found->type);
    }

    public function test_a_subclass_with_its_own_enum_round_trips_an_explicit_type(): void
    {
        $key = ConsumerApiKey::create(['name' => 'test', 'type' => ConsumerApiKeyType::WRITE]);

        $this->assertSame(ConsumerApiKeyType::WRITE, ConsumerApiKey::find($key->id)->type);
    }

    public function test_the_package_enum_still_casts_normally(): void
    {
        $key = ApiKey::create(['name' => 'test']);

        $this->assertSame(ApiKeyType::READ, $key->type);
    }
}

/** Grants writes on a header, the way an app-specific signed grant would. */
class GrantingApiKey extends ApiKey
{
    protected function extraWriteAllowances(Request $request): bool
    {
        return $request->header('X-Grant') === 'let-me-in';
    }
}

/** Contributes a trusted internal service's egress address to every allow-list. */
class RendererApiKey extends ApiKey
{
    protected function additionalAllowlistEntries(): array
    {
        return ['192.0.2.0/24'];
    }
}

/** Reads the client address from the edge instead of the socket. */
class EdgeApiKey extends ApiKey
{
    protected function clientIp(Request $request): ?string
    {
        return $request->header('CF-Connecting-IP') ?: $request->ip();
    }
}

enum ConsumerApiKeyType: string
{
    case READ = 'read';
    case WRITE = 'write';
}

/** A consumer that kept its own enum rather than converging on the package's. */
class ConsumerApiKey extends ApiKey
{
    protected $casts = [
        'type' => ConsumerApiKeyType::class,
        'active' => 'boolean',
        'ip_allowlist' => 'array',
    ];
}
