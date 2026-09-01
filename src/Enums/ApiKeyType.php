<?php

namespace Langsys\ApiKeys\Enums;

enum ApiKeyType: string
{
    case READ = 'read';
    case WRITE = 'write';

    /**
     * Read everywhere, write only from an allow-listed IP. Lets a single key
     * ship into client code (read-only to the public) while trusted networks
     * (office / VPN egress) can still write.
     */
    case IP_WRITE = 'ip_write';

    /**
     * Whether this type writes unconditionally. IP_WRITE is deliberately false:
     * it writes only from an allow-listed address, which needs the request. Use
     * ApiKey::allowsWrite() when a decision about an actual request is wanted.
     */
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
