<?php

namespace Langsys\ApiKeys\Enums;

enum ApiKeyType: string
{
    case READ = 'read';
    case WRITE = 'write';

    public function canWrite(): bool
    {
        return $this === self::WRITE;
    }

    /**
     * @return array<int, string>
     */
    public static function values(): array
    {
        return array_map(fn (self $type) => $type->value, self::cases());
    }
}
