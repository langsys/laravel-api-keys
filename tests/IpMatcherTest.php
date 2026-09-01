<?php

namespace Langsys\ApiKeys\Tests;

use Langsys\ApiKeys\Support\IpMatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase as BaseTestCase;

class IpMatcherTest extends BaseTestCase
{
    #[DataProvider('matchCases')]
    public function test_matches(bool $expected, ?string $ip, ?array $allowlist, string $why): void
    {
        $this->assertSame($expected, IpMatcher::matches($ip, $allowlist), $why);
    }

    public static function matchCases(): array
    {
        return [
            // Exact addresses.
            [true,  '203.0.113.5', ['203.0.113.5'], 'exact IPv4'],
            [false, '203.0.113.6', ['203.0.113.5'], 'different IPv4'],
            [true,  '2001:db8::1', ['2001:db8::1'], 'exact IPv6'],
            [true,  '2001:db8::1', ['2001:0db8:0000::0001'], 'IPv6 written differently is the same address'],

            // CIDR ranges.
            [true,  '203.0.113.5',   ['203.0.113.0/24'], 'inside /24'],
            [false, '203.0.114.5',   ['203.0.113.0/24'], 'outside /24'],
            [true,  '203.0.113.5',   ['203.0.113.4/30'], 'inside a non-byte-aligned prefix'],
            [false, '203.0.113.8',   ['203.0.113.4/30'], 'outside a non-byte-aligned prefix'],
            [true,  '203.0.113.5',   ['203.0.113.5/32'], 'a /32 is the address itself'],
            [true,  '2001:db8::abc', ['2001:db8::/32'],  'inside an IPv6 prefix'],
            [false, '2001:db9::abc', ['2001:db8::/32'],  'outside an IPv6 prefix'],

            // Address families must not cross.
            [false, '203.0.113.5', ['2001:db8::/32'],   'IPv4 against an IPv6 range'],
            [false, '2001:db8::1', ['203.0.113.0/24'],  'IPv6 against an IPv4 range'],

            // A dual-stack socket may report IPv4 in mapped form; it should still
            // match a plain IPv4 entry rather than silently failing closed.
            [true,  '::ffff:203.0.113.5', ['203.0.113.0/24'], 'IPv4-mapped IPv6 against an IPv4 range'],
            [true,  '::ffff:203.0.113.5', ['203.0.113.5'],    'IPv4-mapped IPv6 against an exact IPv4'],
            [false, '::ffff:203.0.114.5', ['203.0.113.0/24'], 'IPv4-mapped IPv6 outside the range'],

            // Everything malformed or absent fails closed.
            [false, null,          ['203.0.113.0/24'], 'no client IP'],
            [false, '',            ['203.0.113.0/24'], 'empty client IP'],
            [false, 'not-an-ip',   ['203.0.113.0/24'], 'unparseable client IP'],
            [false, '203.0.113.5', [],                 'empty allow-list'],
            [false, '203.0.113.5', null,               'null allow-list'],
            [false, '203.0.113.5', [''],               'empty entry'],
            [false, '203.0.113.5', ['  '],             'whitespace entry'],
            [false, '203.0.113.5', ['garbage'],        'unparseable entry'],
            [false, '203.0.113.5', ['203.0.113.0/'],   'missing prefix'],
            [false, '203.0.113.5', ['203.0.113.0/-1'], 'negative prefix'],
            [false, '203.0.113.5', ['203.0.113.0/33'], 'prefix wider than the family'],
            [false, '203.0.113.5', ['203.0.113.0/24/8'], 'malformed double prefix'],
            [false, '203.0.113.5', [['nested']],       'non-scalar entry'],

            // A /0 entry would authorise the whole internet; treated as malformed.
            [false, '203.0.113.5', ['0.0.0.0/0'], 'IPv4 /0 is not honoured'],
            [false, '2001:db8::1', ['::/0'],      'IPv6 /0 is not honoured'],

            // A good entry alongside a bad one still matches.
            [true,  '203.0.113.5', ['garbage', '203.0.113.0/24'], 'valid entry after an invalid one'],
            [true,  '203.0.113.5', [' 203.0.113.0/24 '],          'entry with surrounding whitespace'],
        ];
    }

    #[DataProvider('validityCases')]
    public function test_is_valid_entry(bool $expected, mixed $entry): void
    {
        $this->assertSame($expected, IpMatcher::isValidEntry($entry));
    }

    public static function validityCases(): array
    {
        return [
            [true, '203.0.113.5'],
            [true, '203.0.113.0/24'],
            [true, '203.0.113.0/32'],
            [true, '2001:db8::1'],
            [true, '2001:db8::/32'],
            [true, '2001:db8::/128'],
            [false, ''],
            [false, '   '],
            [false, 'garbage'],
            [false, '203.0.113.0/'],
            [false, '203.0.113.0/33'],
            [false, '203.0.113.0/-1'],
            [false, '203.0.113.0/abc'],
            [false, '2001:db8::/129'],
            [false, '0.0.0.0/0'],
            [false, '::/0'],
            [false, ['nested']],
            [false, null],
        ];
    }
}
