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
