<?php

namespace Langsys\ApiKeys\Support;

/**
 * Matches a client IP against an allow-list of exact addresses and CIDR ranges.
 *
 * This is write-authorization code: every path fails closed. A missing IP, an
 * empty allow-list, a malformed entry, or a mismatched address family all deny.
 */
class IpMatcher
{
    /**
     * Whether $ip falls within any entry of $allowlist. Entries may be exact
     * addresses (IPv4 or IPv6) or CIDR ranges (e.g. "203.0.113.0/24",
     * "2001:db8::/32").
     *
     * @param array<int, mixed>|null $allowlist
     */
    public static function matches(?string $ip, ?array $allowlist): bool
    {
        if (! $allowlist) {
            return false;
        }

        $binaryIp = self::toBinary($ip);

        if ($binaryIp === null) {
            return false;
        }

        foreach ($allowlist as $entry) {
            if (self::entryMatches($binaryIp, self::normalizeEntry($entry))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether an allow-list entry is well-formed enough to ever match. Used to
     * reject bad entries at write time rather than silently never matching.
     *
     * A "/0" prefix is rejected: as an allow-list entry it matches every address
     * in the family, silently turning a restricted key into an unrestricted one.
     */
    public static function isValidEntry(mixed $entry): bool
    {
        $entry = self::normalizeEntry($entry);

        if ($entry === '') {
            return false;
        }

        if (! str_contains($entry, '/')) {
            return self::toBinary($entry) !== null;
        }

        [$subnet, $prefix] = explode('/', $entry, 2);

        $binarySubnet = self::toBinary($subnet);

        if ($binarySubnet === null || ! ctype_digit($prefix)) {
            return false;
        }

        $prefixBits = (int) $prefix;

        return $prefixBits > 0 && $prefixBits <= strlen($binarySubnet) * 8;
    }

    private static function entryMatches(string $binaryIp, string $entry): bool
    {
        if ($entry === '') {
            return false;
        }

        if (! str_contains($entry, '/')) {
            $binaryEntry = self::toBinary($entry);

            return $binaryEntry !== null
                && strlen($binaryEntry) === strlen($binaryIp)
                && hash_equals($binaryEntry, $binaryIp);
        }

        [$subnet, $prefix] = explode('/', $entry, 2);

        $binarySubnet = self::toBinary($subnet);

        // Reject malformed prefixes and mismatched address families (v4 vs v6).
        if ($binarySubnet === null || ! ctype_digit($prefix) || strlen($binarySubnet) !== strlen($binaryIp)) {
            return false;
        }

        $prefixBits = (int) $prefix;

        // "/0" would match the whole address family — never an intentional
        // allow-list entry, so it is treated as malformed rather than honoured.
        if ($prefixBits === 0 || $prefixBits > strlen($binaryIp) * 8) {
            return false;
        }

        $fullBytes = intdiv($prefixBits, 8);
        $remainderBits = $prefixBits % 8;

        if ($fullBytes > 0 && ! hash_equals(substr($binarySubnet, 0, $fullBytes), substr($binaryIp, 0, $fullBytes))) {
            return false;
        }

        if ($remainderBits === 0) {
            return true;
        }

        $mask = chr((0xff << (8 - $remainderBits)) & 0xff);

        return (substr($binaryIp, $fullBytes, 1) & $mask) === (substr($binarySubnet, $fullBytes, 1) & $mask);
    }

    /**
     * Pack an address to its binary form, collapsing IPv4-mapped IPv6
     * (e.g. "::ffff:203.0.113.5") to plain IPv4 so a dual-stack socket does not
     * silently fail to match an IPv4 allow-list entry.
     */
    private static function toBinary(?string $ip): ?string
    {
        if ($ip === null || $ip === '') {
            return null;
        }

        $binary = @inet_pton($ip);

        if ($binary === false) {
            return null;
        }

        if (strlen($binary) === 16 && str_starts_with($binary, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")) {
            return substr($binary, 12);
        }

        return $binary;
    }

    private static function normalizeEntry(mixed $entry): string
    {
        return is_scalar($entry) ? trim((string) $entry) : '';
    }
}
