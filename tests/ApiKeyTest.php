<?php

namespace Langsys\ApiKeys\Tests;

use Illuminate\Support\Facades\Event;
use Langsys\ApiKeys\Enums\ApiKeyType;
use Langsys\ApiKeys\Events\ApiKeyActivated;
use Langsys\ApiKeys\Events\ApiKeyCreated;
use Langsys\ApiKeys\Events\ApiKeyDeactivated;
use Langsys\ApiKeys\Models\ApiKey;

class ApiKeyTest extends TestCase
{
    public function test_creating_a_key_generates_and_hashes_a_plaintext_key(): void
    {
        $key = ApiKey::create(['name' => 'test']);

        $this->assertNotNull($key->plain_key);
        $this->assertSame(64, strlen($key->plain_key));
        $this->assertSame(hash('sha256', $key->plain_key), $key->key_hash);
        $this->assertNotSame($key->plain_key, $key->key_hash);
        $this->assertDatabaseMissing('api_keys', ['key_hash' => $key->plain_key]);
    }

    public function test_get_by_key_resolves_and_attaches_plaintext(): void
    {
        $key = ApiKey::create(['name' => 'test']);
        $plain = $key->plain_key;

        $found = ApiKey::getByKey($plain);

        $this->assertTrue($found->is($key));
        $this->assertSame($plain, $found->plain_key);
        $this->assertNull(ApiKey::getByKey('does-not-exist'));
        $this->assertNull(ApiKey::getByKey(null));
    }

    public function test_is_valid_key_requires_active(): void
    {
        $key = ApiKey::create(['name' => 'test']);
        $plain = $key->plain_key;

        $this->assertTrue(ApiKey::isValidKey($plain));

        $key->update(['active' => false]);

        $this->assertFalse(ApiKey::isValidKey($plain));
    }

    public function test_key_defaults_to_uuid_read_and_active(): void
    {
        $key = ApiKey::create(['name' => 'test']);

        $this->assertSame(ApiKeyType::READ, $key->type);
        $this->assertTrue($key->active);
        $this->assertMatchesRegularExpression('/^[0-9a-f-]{36}$/', $key->id);
    }

    public function test_permissions_can_be_granted_checked_and_revoked(): void
    {
        $key = ApiKey::create(['name' => 'test']);

        $key->grantPermissions(['view_projects', 'edit_projects']);

        $this->assertTrue($key->hasPermission('view_projects'));
        $this->assertEqualsCanonicalizing(['view_projects', 'edit_projects'], $key->permissionValues());

        // Granting is idempotent — no duplicate rows.
        $key->grantPermissions('view_projects');
        $this->assertCount(2, $key->permissions()->get());

        $key->revokePermissions('view_projects');
        $this->assertFalse($key->hasPermission('view_projects'));
    }

    public function test_default_permissions_are_attached_on_create(): void
    {
        config()->set('api-keys.default_permissions', ['ping']);

        $key = ApiKey::create(['name' => 'test']);

        $this->assertTrue($key->hasPermission('ping'));
    }

    public function test_a_revoked_keys_value_is_never_reissued(): void
    {
        $key = ApiKey::create(['name' => 'test']);
        $plain = $key->plain_key;
        $key->delete();

        $this->assertTrue(ApiKey::keyExists($plain));
    }

    public function test_lifecycle_events_are_fired(): void
    {
        Event::fake([ApiKeyCreated::class, ApiKeyActivated::class, ApiKeyDeactivated::class]);

        $key = ApiKey::create(['name' => 'test']);
        Event::assertDispatched(ApiKeyCreated::class);

        $key->update(['active' => false]);
        Event::assertDispatched(ApiKeyDeactivated::class);

        $key->update(['active' => true]);
        Event::assertDispatched(ApiKeyActivated::class);
    }
}
