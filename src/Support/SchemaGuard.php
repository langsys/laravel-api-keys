<?php

namespace Langsys\ApiKeys\Support;

use Illuminate\Support\Facades\Schema;
use RuntimeException;

/**
 * Decides whether a package migration should create its table.
 *
 * The migrations skip tables an application already has, so this package can be
 * installed into an app that already models API keys. That skip used to be
 * unconditional, which meant a table sharing the name but not the shape passed
 * install silently and failed later at query time. This checks the columns the
 * models actually read and fails at migrate time instead.
 */
class SchemaGuard
{
    /**
     * The `permissions` table is shared with langsys/laravel-access-guard: both
     * packages create it with the same shape, whichever migrates first wins,
     * and both reference its rows by id.
     *
     * Each package resolves the table through its OWN config key, so setting
     * one without the other produces two separate tables with no error at any
     * point — roles referencing permission rows in one, API keys in the other,
     * the same value existing twice under different ids. It surfaces much later
     * as an authorization result nobody can explain.
     *
     * Checked at migrate time because that is where the second table would be
     * created; blocking here keeps the divergent schema from ever existing.
     */
    public static function assertSharedPermissionsTable(string $ours): void
    {
        // Absent unless access-guard is installed and has merged its config.
        if (! config()->has('access-guard.tables.permissions')) {
            return;
        }

        $theirs = config('access-guard.tables.permissions');

        if ($theirs === $ours) {
            return;
        }

        throw new RuntimeException(sprintf(
            'Config [api-keys.tables.permissions] is [%s] but [access-guard.tables.permissions] is [%s]. '
            . 'The two packages share one permissions table and reference its rows by id, so these must '
            . 'name the same table. Setting only one silently produces two separate permission tables. '
            . 'Set both to the same value.',
            $ours,
            $theirs,
        ));
    }

    /**
     * @param array<int, string> $requiredColumns
     */
    public static function shouldCreate(string $table, array $requiredColumns, string $expected): bool
    {
        if (! Schema::hasTable($table)) {
            return true;
        }

        $missing = array_values(array_filter(
            $requiredColumns,
            fn (string $column) => ! Schema::hasColumn($table, $column)
        ));

        if ($missing !== []) {
            throw new RuntimeException(sprintf(
                'Table [%s] already exists but is missing the column(s) [%s] that langsys/laravel-api-keys '
                . 'requires. Expected %s. Either migrate the existing table to that shape, or point the '
                . 'package at a different table via config("api-keys.tables").',
                $table,
                implode(', ', $missing),
                $expected,
            ));
        }

        return false;
    }
}
