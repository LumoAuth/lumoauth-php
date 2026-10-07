<?php

declare(strict_types=1);

namespace LumoAuth\Tests;

use LumoAuth\Error\LumoAuthApiError;
use LumoAuth\Error\LumoAuthError;
use LumoAuth\Error\LumoAuthValidationError;
use LumoAuth\Tests\Support\ContractFiles;

final class ErrorsTest extends TestCase
{
    public function testTaxonomyMatchesTheContract(): void
    {
        if (ContractFiles::dir() === null) {
            self::markTestSkipped('sdk-contract not found (set LUMO_SDK_CONTRACT)');
        }
        foreach (ContractFiles::load('errors.json')['errors'] as $spec) {
            $class = 'LumoAuth\\Error\\' . $spec['name'];
            self::assertTrue(class_exists($class), "$class missing");
            $parent = get_parent_class($class);
            $expectedParent = $spec['parent'] === null ? \RuntimeException::class : 'LumoAuth\\Error\\' . $spec['parent'];
            self::assertSame($expectedParent, $parent, "{$spec['name']} parent");
            $instance = $this->instantiate($class, $spec);
            self::assertSame($spec['code'], $instance->errorCode, "{$spec['name']} code");
            self::assertSame($spec['status'], $instance->statusCode, "{$spec['name']} status");
        }
    }

    public function testRateLimitCarriesRetryAfterAndValidationCarriesIssues(): void
    {
        $e = new \LumoAuth\Error\LumoAuthRateLimitError(retryAfter: 2.5, body: ['x' => 1]);
        self::assertSame(2.5, $e->retryAfter);
        self::assertSame(['x' => 1], $e->body);
        self::assertSame(429, $e->getCode(), 'HTTP status doubles as the exception code');
        self::assertSame(['a'], (new LumoAuthValidationError('bad', ['a']))->issues);
    }

    /** @param array<string, mixed> $spec */
    private function instantiate(string $class, array $spec): LumoAuthError
    {
        return match ($spec['name']) {
            'LumoAuthError' => new LumoAuthError('m'),
            'LumoAuthApiError' => new LumoAuthApiError('m'),
            'LumoAuthValidationError' => new LumoAuthValidationError('m'),
            'LumoAuthConfigError', 'LumoAuthNetworkError' => new $class('m'),
            default => new $class(),
        };
    }
}
