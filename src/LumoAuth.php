<?php

declare(strict_types=1);

namespace LumoAuth;

use LumoAuth\Error\LumoAuthConfigError;
use LumoAuth\Http\HttpClient;
use LumoAuth\Resource\Abac;
use LumoAuth\Resource\Agents;
use LumoAuth\Resource\Approvals;
use LumoAuth\Resource\Auth;
use LumoAuth\Resource\Delegation;
use LumoAuth\Resource\Jit;
use LumoAuth\Resource\Mcp;
use LumoAuth\Resource\Permissions;
use LumoAuth\Resource\Zanzibar;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * The general-purpose LumoAuth client with resource namespaces — the same
 * shape as `LumoAuth` in Python, `createClient` in JS and `lumoauth.New` in Go.
 *
 *     $lumo = new LumoAuth(apiKey: 'lk_…', orgId: 'acme-corp');
 *     if ($lumo->permissions->check('document.edit')) { … }
 *     $decision = $lumo->abac->check('document', 'read', 'doc-123');
 *
 * Every constructor argument falls back to an environment variable:
 *
 *     baseUrl → LUMOAUTH_URL        (default https://app.lumoauth.dev)
 *     orgId   → LUMOAUTH_ORG_ID
 *     apiKey  → LUMOAUTH_API_KEY
 *
 * Transport is PSR-18: pass your own client and PSR-17 factories, or let
 * php-http/discovery find them (Guzzle, Symfony HttpClient, …).
 */
final class LumoAuth
{
    public const DEFAULT_BASE_URL = 'https://app.lumoauth.dev';
    public const VERSION = '1.0.1';

    public readonly string $baseUrl;
    public readonly ?string $orgId;

    public readonly Auth $auth;
    public readonly Permissions $permissions;
    public readonly Zanzibar $zanzibar;
    public readonly Abac $abac;
    public readonly Agents $agents;
    public readonly Approvals $approvals;
    public readonly Jit $jit;
    public readonly Mcp $mcp;
    public readonly Delegation $delegation;

    private readonly HttpClient $http;
    private mixed $api = null;

    /**
     * @param (callable(): ?string)|null $tokenProvider zero-argument callable returning a bearer token; when it yields one it wins over $apiKey
     */
    public function __construct(
        ?string $apiKey = null,
        ?string $baseUrl = null,
        ?string $orgId = null,
        ?callable $tokenProvider = null,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
    ) {
        $this->baseUrl = rtrim($baseUrl ?: (self::env('LUMOAUTH_URL') ?? self::DEFAULT_BASE_URL), '/');
        $this->orgId = $orgId ?: self::env('LUMOAUTH_ORG_ID');
        $apiKey = $apiKey ?: self::env('LUMOAUTH_API_KEY');

        $this->http = new HttpClient($this->baseUrl, $this->orgId, $apiKey, $tokenProvider, $httpClient, $requestFactory, $streamFactory);

        $this->auth = new Auth($this->http);
        $this->permissions = new Permissions($this->http);
        $this->zanzibar = new Zanzibar($this->http);
        $this->abac = new Abac($this->http);
        $this->agents = new Agents($this->http);
        $this->approvals = new Approvals($this->http);
        $this->jit = new Jit($this->http);
        $this->mcp = new Mcp($this->http);
        $this->delegation = new Delegation($this->http);
    }

    /** The internal transport, for custom calls: `$lumo->http()->request('GET', $lumo->http()->orgPath('/documents'))`. */
    public function http(): HttpClient
    {
        return $this->http;
    }

    /**
     * Escape hatch to the full generated REST surface (`lumoauth/api-client`):
     * a `LumoAuth\ApiClient\Configuration` carrying this client's base URL and
     * credential, ready for any generated API class.
     *
     *     $users = new \LumoAuth\ApiClient\Api\AdminUsersApi(null, $lumo->api());
     *
     * @return \LumoAuth\ApiClient\Configuration
     */
    public function api(): object
    {
        if ($this->api !== null) {
            return $this->api;
        }
        $class = 'LumoAuth\\ApiClient\\Configuration';
        if (!class_exists($class)) {
            throw new LumoAuthConfigError('The generated client is not installed: composer require lumoauth/api-client');
        }
        $config = (new $class())->setHost($this->baseUrl);
        $token = $this->http->currentToken();
        if ($token !== null) {
            $config->setAccessToken($token);
        } elseif (($apiKey = $this->http->apiKey()) !== null) {
            $config->setApiKey('X-API-Key', $apiKey);
        }

        return $this->api = $config;
    }

    private static function env(string $name): ?string
    {
        $v = getenv($name);
        if ($v === false || $v === '') {
            $v = $_ENV[$name] ?? $_SERVER[$name] ?? null;
        }

        return is_string($v) && $v !== '' ? $v : null;
    }
}
