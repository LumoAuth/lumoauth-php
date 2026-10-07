<?php

declare(strict_types=1);

namespace LumoAuth\Tests;

use LumoAuth\Error\LumoAuthConfigError;
use LumoAuth\Routes;
use LumoAuth\Tests\Support\ContractFiles;

final class RoutesTest extends TestCase
{
    public function testRegistryMatchesTheContract(): void
    {
        if (ContractFiles::dir() === null) {
            self::markTestSkipped('sdk-contract not found (set LUMO_SDK_CONTRACT)');
        }
        $expected = [];
        foreach (ContractFiles::load('routes.json')['routes'] as $r) {
            $expected[$r['name']] = [$r['method'], $r['path']];
        }
        ksort($expected);
        $actual = Routes::ROUTES;
        ksort($actual);
        self::assertSame($expected, $actual, 'Routes.php is stale — run sdk-contract/scripts/gen-php-routes.py');
    }

    public function testEveryRouteHasAConstant(): void
    {
        $constants = (new \ReflectionClass(Routes::class))->getConstants();
        unset($constants['ROUTES']);
        self::assertEqualsCanonicalizing(array_keys(Routes::ROUTES), array_values($constants));
    }

    public function testBuildPathEncodesAndRejectsMissingParams(): void
    {
        self::assertSame('/orgs/acme%20corp/api/v1/jit/task/t%2F1/complete', Routes::buildPath(Routes::ROUTES[Routes::JIT_COMPLETE_TASK][1], ['orgId' => 'acme corp', 'taskId' => 't/1']));
        $this->expectException(LumoAuthConfigError::class);
        Routes::path(Routes::JIT_COMPLETE_TASK, ['orgId' => 'acme']);
    }

    public function testUnknownRouteThrows(): void
    {
        $this->expectException(LumoAuthConfigError::class);
        Routes::get('nope.route');
    }
}
