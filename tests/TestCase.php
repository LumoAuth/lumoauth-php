<?php

declare(strict_types=1);

namespace LumoAuth\Tests;

use LumoAuth\LumoAuth;
use LumoAuth\Tests\Support\FakeHttpClient;
use Nyholm\Psr7\Factory\Psr17Factory;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    protected FakeHttpClient $fake;

    #[\Override]
    protected function setUp(): void
    {
        $this->fake = new FakeHttpClient();
    }

    /** @param (callable(): ?string)|null $tokenProvider */
    protected function client(?string $apiKey = 'lk_test', ?string $orgId = 'acme-corp', ?callable $tokenProvider = null, string $baseUrl = 'https://auth.acme.test'): LumoAuth
    {
        $factory = new Psr17Factory();

        return new LumoAuth(apiKey: $apiKey, baseUrl: $baseUrl, orgId: $orgId, tokenProvider: $tokenProvider, httpClient: $this->fake, requestFactory: $factory, streamFactory: $factory);
    }
}
