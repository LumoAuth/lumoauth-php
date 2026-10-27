<?php

declare(strict_types=1);

namespace LumoAuth\Tests;

use LumoAuth\Error\LumoAuthApiError;
use LumoAuth\Error\LumoAuthAuthenticationError;
use LumoAuth\Error\LumoAuthConfigError;
use LumoAuth\Error\LumoAuthNetworkError;
use LumoAuth\Error\LumoAuthNotFoundError;
use LumoAuth\Error\LumoAuthPermissionDeniedError;
use LumoAuth\Error\LumoAuthRateLimitError;
use LumoAuth\Routes;
use LumoAuth\Tests\Support\FakeTransportException;

final class HttpClientTest extends TestCase
{
    public function testApiKeyGoesInXApiKeyAndOrgIdFillsThePath(): void
    {
        $this->fake->queue(200, ['allowed' => true]);
        $http = $this->client()->http();
        $out = $http->call(Routes::ABAC_CHECK, json: ['resourceType' => 'doc', 'action' => 'read']);

        self::assertSame(['allowed' => true], $out);
        $req = $this->fake->last();
        self::assertSame('POST', $req->getMethod());
        self::assertSame('https://auth.acme.test/orgs/acme-corp/api/v1/abac/check', (string) $req->getUri());
        self::assertSame('lk_test', $req->getHeaderLine('X-API-Key'));
        self::assertSame('', $req->getHeaderLine('Authorization'));
        self::assertSame('application/json', $req->getHeaderLine('Content-Type'));
        self::assertSame('application/json', $req->getHeaderLine('Accept'));
        self::assertSame(['resourceType' => 'doc', 'action' => 'read'], $this->fake->lastJson());
    }

    public function testTokenProviderWinsOverApiKeyAndExplicitHeadersWinOverBoth(): void
    {
        $this->fake->queue(200, [])->queue(200, []);
        $http = $this->client(tokenProvider: static fn (): string => 'tok')->http();
        $http->call(Routes::PERMISSIONS_LIST);
        self::assertSame('Bearer tok', $this->fake->last()->getHeaderLine('Authorization'));
        self::assertFalse($this->fake->last()->hasHeader('X-API-Key'));

        $http->call(Routes::PERMISSIONS_LIST, headers: ['Authorization' => 'Bearer other']);
        self::assertSame('Bearer other', $this->fake->last()->getHeaderLine('Authorization'));
    }

    public function testAuthFalseSendsNoCredentialAndFormBodiesAreUrlEncoded(): void
    {
        $this->fake->queue(200, ['access_token' => 'x']);
        $http = $this->client()->http();
        $http->call(Routes::OAUTH_TOKEN, form: ['grant_type' => 'client_credentials', 'scope' => 'a b'], auth: false);
        $req = $this->fake->last();
        self::assertFalse($req->hasHeader('X-API-Key'));
        self::assertSame('application/x-www-form-urlencoded', $req->getHeaderLine('Content-Type'));
        self::assertSame('grant_type=client_credentials&scope=a%20b', (string) $req->getBody());
    }

    public function testQueryParamsSkipNulls(): void
    {
        $this->fake->queue(200, []);
        $this->client()->http()->call(Routes::ABAC_ATTRIBUTE_DEFINITIONS, query: ['type' => 'user', 'x' => null]);
        self::assertSame('https://auth.acme.test/orgs/acme-corp/api/v1/abac/attribute-definitions?type=user', (string) $this->fake->last()->getUri());
    }

    public function testMissingOrgIdFailsBeforeAnyRequest(): void
    {
        $http = $this->client(orgId: null)->http();
        try {
            $http->call(Routes::ABAC_CHECK, json: []);
            self::fail('expected LumoAuthConfigError');
        } catch (LumoAuthConfigError $e) {
            self::assertStringContainsString('LUMOAUTH_ORG_ID', $e->getMessage());
        }
        self::assertSame([], $this->fake->requests);
        // Bearer-scoped routes need no org.
        $this->fake->queue(200, ['permissions' => []]);
        self::assertSame(['permissions' => []], $http->call(Routes::PERMISSIONS_LIST));
    }

    public function testNoContentAndEmptyBodiesBecomeNull(): void
    {
        $this->fake->queue(204)->queue(200, '');
        $http = $this->client()->http();
        self::assertNull($http->call(Routes::JIT_PENDING));
        self::assertNull($http->call(Routes::JIT_PENDING));
    }

    /** @return iterable<string, array{0: int, 1: mixed, 2: class-string, 3: string, 4: string}> */
    public static function errorResponses(): iterable
    {
        yield '401 with code' => [401, ['error' => 'invalid_token', 'message' => 'Token expired'], LumoAuthAuthenticationError::class, 'Token expired', 'invalid_token'];
        yield '401 bare' => [401, '', LumoAuthAuthenticationError::class, 'HTTP 401', 'AUTHENTICATION_ERROR'];
        yield '403' => [403, ['error' => 'forbidden', 'error_description' => 'Insufficient scope'], LumoAuthPermissionDeniedError::class, 'Insufficient scope', 'forbidden'];
        yield '404' => [404, ['detail' => 'No such thing'], LumoAuthNotFoundError::class, 'No such thing', 'NOT_FOUND'];
        yield '500 text' => [500, 'boom', LumoAuthApiError::class, 'HTTP 500 — boom', 'API_ERROR'];
        yield '422 code field' => [422, ['message' => 'Bad', 'code' => 'validation_failed'], LumoAuthApiError::class, 'Bad', 'validation_failed'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('errorResponses')]
    public function testStatusesMapToTypedErrors(int $status, mixed $body, string $class, string $message, string $code): void
    {
        $this->fake->queue($status, $body);
        try {
            $this->client()->http()->call(Routes::PERMISSIONS_LIST);
            self::fail("expected $class");
        } catch (LumoAuthApiError $e) {
            self::assertInstanceOf($class, $e);
            self::assertSame($message, $e->getMessage());
            self::assertSame($code, $e->errorCode);
            self::assertSame($status, $e->statusCode);
            self::assertSame($body === '' ? null : $body, $e->body);
        }
    }

    public function testScopeRefusalExposesRequiredScopes(): void
    {
        $body = ['error' => 'forbidden', 'message' => 'Insufficient scope: this API key is missing a required scope', 'status' => 403,
            'details' => ['required_scopes' => ['authz:read'], 'granted_scopes' => ['admin:users:read'], 'key_scopes' => ['admin:users:read']]];
        $this->fake->queue(403, $body)->queue(403, ['error' => 'nope']);
        foreach ([['authz:read'], []] as $expected) {
            try {
                $this->client()->http()->call(Routes::PERMISSIONS_LIST);
                self::fail('expected 403');
            } catch (LumoAuthPermissionDeniedError $e) {
                self::assertSame($expected, $e->requiredScopes);
            }
        }
    }

    public function testRateLimitReadsRetryAfter(): void
    {
        $this->fake->queue(429, ['error' => 'rate_limited'], ['Retry-After' => '7']);
        try {
            $this->client()->http()->call(Routes::PERMISSIONS_LIST);
            self::fail('expected rate limit');
        } catch (LumoAuthRateLimitError $e) {
            self::assertSame(7.0, $e->retryAfter);
            self::assertSame('rate_limited', $e->errorCode);
        }
    }

    public function testTransportFailuresBecomeNetworkErrors(): void
    {
        $this->fake->fail(new FakeTransportException('dns'));
        try {
            $this->client()->http()->call(Routes::PERMISSIONS_LIST);
            self::fail('expected network error');
        } catch (LumoAuthNetworkError $e) {
            self::assertStringContainsString('dns', $e->getMessage());
            self::assertInstanceOf(FakeTransportException::class, $e->getPrevious());
        }
    }

    public function testRawReturnsThePsr7Response(): void
    {
        $this->fake->queue(418, 'teapot');
        $response = $this->client()->http()->request('GET', '/x', raw: true);
        self::assertSame(418, $response->getStatusCode());
    }
}
