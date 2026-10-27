<?php

declare(strict_types=1);

namespace LumoAuth\Tests;

use LumoAuth\Laravel\Http\Middleware\RequirePermission;

/**
 * The Laravel middleware must check the user's LumoAuth user ID, never the app's
 * own user ID. Illuminate is not installed in this monorepo, so this covers the
 * subject lookup, which needs no framework classes.
 */
final class LaravelRequirePermissionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__ . '/../../laravel/src/Http/Middleware/RequirePermission.php';
        RequirePermission::resolveSubjectUsing(null);
    }

    protected function tearDown(): void
    {
        RequirePermission::resolveSubjectUsing(null);
        parent::tearDown();
    }

    public function testReadsTheConfiguredAttributeAndNeverTheAppUserId(): void
    {
        $model = new class {
            public int $id = 42;
            /** @var array<string, mixed> */
            private array $attributes = ['lumoauth_sub' => '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b', 'idp_sub' => 'other'];

            public function getAttribute(string $key): mixed
            {
                return $this->attributes[$key] ?? null;
            }

            public function getAuthIdentifier(): int
            {
                return $this->id;
            }
        };

        self::assertSame('0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b', RequirePermission::subjectFor($model));
        self::assertSame('other', RequirePermission::subjectFor($model, 'idp_sub'));
        self::assertNull(RequirePermission::subjectFor($model, 'missing'), 'no fallback to getAuthIdentifier()');
    }

    public function testPlainObjectsArraysAndEmptyValues(): void
    {
        $plain = new \stdClass();
        $plain->lumoauth_sub = 'abc';
        self::assertSame('abc', RequirePermission::subjectFor($plain));
        self::assertSame('abc', RequirePermission::subjectFor(['lumoauth_sub' => 'abc']));
        self::assertNull(RequirePermission::subjectFor(['lumoauth_sub' => '']));
        self::assertNull(RequirePermission::subjectFor(null));
    }

    public function testResolverWins(): void
    {
        RequirePermission::resolveSubjectUsing(static fn (mixed $user): ?string => 'from-resolver');
        self::assertSame('from-resolver', RequirePermission::subjectFor(['lumoauth_sub' => 'abc']));
    }
}
