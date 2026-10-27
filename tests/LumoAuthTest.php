<?php

declare(strict_types=1);

namespace LumoAuth\Tests;

use LumoAuth\Error\LumoAuthConfigError;
use LumoAuth\LumoAuth;
use Nyholm\Psr7\Factory\Psr17Factory;

final class LumoAuthTest extends TestCase
{
    public function testEnvironmentFallbacks(): void
    {
        putenv('LUMOAUTH_URL=https://eu.acme.test/');
        putenv('LUMOAUTH_ORG_ID=acme-eu');
        putenv('LUMOAUTH_API_KEY=lk_env');
        try {
            $factory = new Psr17Factory();
            $lumo = new LumoAuth(httpClient: $this->fake, requestFactory: $factory, streamFactory: $factory);
            self::assertSame('https://eu.acme.test', $lumo->baseUrl);
            self::assertSame('acme-eu', $lumo->orgId);
            $this->fake->queue(200, []);
            $lumo->permissions->list();
            self::assertSame('lk_env', $this->fake->last()->getHeaderLine('X-API-Key'));
            self::assertSame('https://eu.acme.test/api/v1/authz/permissions', (string) $this->fake->last()->getUri());
        } finally {
            putenv('LUMOAUTH_URL');
            putenv('LUMOAUTH_ORG_ID');
            putenv('LUMOAUTH_API_KEY');
        }
    }

    public function testDefaultsWhenNothingIsConfigured(): void
    {
        $factory = new Psr17Factory();
        $lumo = new LumoAuth(httpClient: $this->fake, requestFactory: $factory, streamFactory: $factory);
        self::assertSame(LumoAuth::DEFAULT_BASE_URL, $lumo->baseUrl);
        self::assertNull($lumo->orgId);
    }

    public function testApiEscapeHatchNeedsTheGeneratedClient(): void
    {
        if (class_exists('LumoAuth\\ApiClient\\Configuration')) {
            self::markTestSkipped('generated client installed');
        }
        $this->expectException(LumoAuthConfigError::class);
        $this->expectExceptionMessage('composer require lumoauth/api-client');
        $this->client()->api();
    }

    public function testResourcesShareOneTransport(): void
    {
        $lumo = $this->client();
        $this->fake->queue(200, ['allowed' => true])->queue(200, ['allowed' => true]);
        $lumo->permissions->check('x');
        $lumo->agents->isAllowed('y');
        self::assertCount(2, $this->fake->requests);
        self::assertSame('1.0.1', LumoAuth::VERSION);
    }
}
