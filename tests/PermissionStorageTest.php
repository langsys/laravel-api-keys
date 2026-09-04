<?php

namespace Langsys\ApiKeys\Tests;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Langsys\ApiKeys\Models\ApiKey;
use Langsys\ApiKeys\Models\Permission;
use Langsys\ApiKeys\Support\SchemaGuard;
use RuntimeException;

class PermissionStorageTest extends TestCase
{
    public function test_permissions_are_stored_once_and_referenced_by_id(): void
    {
        $a = ApiKey::create(['name' => 'a']);
        $b = ApiKey::create(['name' => 'b']);

        $a->grantPermissions('view_projects');
        $b->grantPermissions('view_projects');

        // One row in the shared table, referenced by both keys.
        $this->assertSame(1, Permission::where('value', 'view_projects')->count());
        $this->assertTrue($a->hasPermission('view_projects'));
        $this->assertTrue($b->hasPermission('view_projects'));

        $permission = Permission::where('value', 'view_projects')->sole();
        $this->assertCount(2, $permission->apiKeys()->get());
    }

    public function test_the_pivot_holds_a_foreign_key_not_a_string(): void
    {
        $key = ApiKey::create(['name' => 'a']);
        $key->grantPermissions('edit_projects');

        $permission = Permission::where('value', 'edit_projects')->sole();
        $row = DB::table('api_key_has_permissions')->where('api_key_id', $key->id)->first();

        $this->assertSame($permission->id, $row->permission_id);
        $this->assertFalse(Schema::hasColumn('api_key_has_permissions', 'permission'));
    }

    public function test_granting_is_idempotent(): void
    {
        $key = ApiKey::create(['name' => 'a']);

        $key->grantPermissions(['view_projects', 'view_projects']);
        $key->grantPermissions('view_projects');

        $this->assertSame(1, DB::table('api_key_has_permissions')->where('api_key_id', $key->id)->count());
    }

    public function test_a_permission_instance_is_accepted_everywhere_a_string_is(): void
    {
        $key = ApiKey::create(['name' => 'a']);
        $permission = Permission::create(['value' => 'ship_it', 'label' => 'Ship it']);

        $key->grantPermissions($permission);

        $this->assertTrue($key->hasPermission($permission));
        $this->assertTrue($key->hasPermission('ship_it'));
        $this->assertSame(['ship_it'], $key->permissionValues());

        $key->revokePermissions($permission);

        $this->assertFalse($key->hasPermission('ship_it'));
        // Revoking detaches the key, it does not delete the shared permission.
        $this->assertSame(1, Permission::where('value', 'ship_it')->count());
    }

    public function test_a_backed_enum_is_accepted_everywhere_a_string_is(): void
    {
        $key = ApiKey::create(['name' => 'a']);

        $key->grantPermissions(TestPermission::VIEW);

        $this->assertTrue($key->hasPermission(TestPermission::VIEW));
        $this->assertTrue($key->hasPermission('view_projects'));

        $key->syncPermissions([TestPermission::EDIT]);

        $this->assertSame(['edit_projects'], $key->permissionValues());
    }

    public function test_deleting_a_permission_cascades_to_the_pivot(): void
    {
        $key = ApiKey::create(['name' => 'a']);
        $key->grantPermissions('temporary');

        Permission::where('value', 'temporary')->sole()->delete();

        $this->assertSame(0, DB::table('api_key_has_permissions')->where('api_key_id', $key->id)->count());
    }

    public function test_an_existing_table_with_a_compatible_shape_is_skipped(): void
    {
        $this->assertFalse(SchemaGuard::shouldCreate('api_key_has_permissions', ['api_key_id', 'permission_id'], 'x'));
    }

    public function test_an_existing_table_with_an_incompatible_shape_fails_loudly(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('is missing the column(s) [permission_id]');

        // The old flat-string shape: same table name, different schema.
        SchemaGuard::shouldCreate('api_keys', ['permission_id'], 'a uuid `permission_id`');
    }

    public function test_a_missing_table_is_created(): void
    {
        $this->assertTrue(SchemaGuard::shouldCreate('does_not_exist', ['whatever'], 'x'));
    }

    public function test_the_shared_permissions_check_is_inert_without_access_guard(): void
    {
        $this->assertFalse(config()->has('access-guard.tables.permissions'));

        SchemaGuard::assertSharedPermissionsTable('permissions');
        SchemaGuard::assertSharedPermissionsTable('anything_at_all');

        $this->addToAssertionCount(2);
    }

    public function test_agreeing_config_keys_pass(): void
    {
        config()->set('access-guard.tables.permissions', 'acl_permissions');

        SchemaGuard::assertSharedPermissionsTable('acl_permissions');

        $this->addToAssertionCount(1);
    }

    public function test_disagreeing_config_keys_fail_at_migrate_time(): void
    {
        config()->set('access-guard.tables.permissions', 'acl_permissions');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('[api-keys.tables.permissions] is [permissions]');
        $this->expectExceptionMessage('[access-guard.tables.permissions] is [acl_permissions]');

        SchemaGuard::assertSharedPermissionsTable('permissions');
    }

    public function test_the_migration_itself_refuses_to_run_on_disagreement(): void
    {
        config()->set('access-guard.tables.permissions', 'somewhere_else');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('share one permissions table');

        (require __DIR__ . '/../database/migrations/2024_01_01_000002_create_permissions_table.php')->up();
    }
}

enum TestPermission: string
{
    case VIEW = 'view_projects';
    case EDIT = 'edit_projects';
}
