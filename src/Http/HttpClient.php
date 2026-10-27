<?php

declare(strict_types=1);

namespace LumoAuth\Http;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use LumoAuth\Error\LumoAuthApiError;
use LumoAuth\Error\LumoAuthAuthenticationError;
use LumoAuth\Error\LumoAuthConfigError;
use LumoAuth\Error\LumoAuthNetworkError;
use LumoAuth\Error\LumoAuthNotFoundError;
use LumoAuth\Error\LumoAuthPermissionDeniedError;
use LumoAuth\Error\LumoAuthRateLimitError;
use LumoAuth\Routes;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Internal PSR-18 HTTP client used by every resource.
 *
 * - Injects credentials on each request: a token provider yields a bearer
 *   token (`Authorization: Bearer …`); an API key is sent as `X-API-Key`.
 *   Explicit `Authorization` / `X-API-Key` headers passed per request win.
 * - Maps error statuses to the typed errors in LumoAuth\Error, reading
 *   `error_description` / `message` / `detail` / `error` and `code` from JSON
 *   bodies (sdk-contract/errors.json).
 * - Wraps transport exceptions in LumoAuthNetworkError.
 * - Returns decoded JSON (array|scalar) or null for 204 / empty bodies.
 */
final class HttpClient
{
    /** @var array<int, class-string<LumoAuthApiError>> */
    private const STATUS_ERRORS = [
        401 => LumoAuthAuthenticationError::class,
        403 => LumoAuthPermissionDeniedError::class,
        404 => LumoAuthNotFoundError::class,
        429 => LumoAuthRateLimitError::class,
    ];

    private readonly string $baseUrl;
    private readonly ClientInterface $client;
    private readonly RequestFactoryInterface $requestFactory;
    private readonly StreamFactoryInterface $streamFactory;
    /** @var (\Closure(): ?string)|null */
    private readonly ?\Closure $tokenProvider;

    /** @param (callable(): ?string)|null $tokenProvider */
    public function __construct(
        string $baseUrl,
        private readonly ?string $orgId = null,
        private readonly ?string $apiKey = null,
        ?callable $tokenProvider = null,
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->tokenProvider = $tokenProvider === null ? null : \Closure::fromCallable($tokenProvider);
        $this->client = $client ?? Psr18ClientDiscovery::find();
        $this->requestFactory = $requestFactory ?? Psr17FactoryDiscovery::findRequestFactory();
        $this->streamFactory = $streamFactory ?? Psr17FactoryDiscovery::findStreamFactory();
    }

    public function baseUrl(): string
    {
        return $this->baseUrl;
    }

    public function orgId(): ?string
    {
        return $this->orgId;
    }

    public function apiKey(): ?string
    {
        return $this->apiKey !== null && $this->apiKey !== '' ? $this->apiKey : null;
    }

    /** The bearer token the client would send now, if any. */
    public function currentToken(): ?string
    {
        $t = $this->tokenProvider === null ? null : ($this->tokenProvider)();

        return is_string($t) && $t !== '' ? $t : null;
    }

    /** Prefix `$path` with the org-scoped API base (`/orgs/{org}/api/v1`). */
    public function orgPath(string $path): string
    {
        return '/orgs/' . rawurlencode($this->requireOrgId('this call')) . '/api/v1' . $path;
    }

    /**
     * Resolve a route from the registry to [method, concrete path], filling
     * `{orgId}` from the client when the caller did not pass it.
     *
     * @param array<string, string|int> $pathParams
     * @return array{0: string, 1: string}
     */
    public function route(string $route, array $pathParams = []): array
    {
        [, $template] = Routes::get($route);
        if (str_contains($template, '{orgId}') && !isset($pathParams['orgId'])) {
            $pathParams['orgId'] = $this->requireOrgId("'$route'");
        }

        return Routes::path($route, $pathParams);
    }

    /**
     * Invoke a route from the registry.
     *
     * @param array<string, string|int> $pathParams
     * @param array<string, mixed>|null $json    JSON body
     * @param array<string, string>|null $form   application/x-www-form-urlencoded body
     * @param array<string, string|int|null> $query
     * @param array<string, string> $headers
     */
    public function call(string $route, array $pathParams = [], ?array $json = null, ?array $form = null, array $query = [], array $headers = [], bool $auth = true): mixed
    {
        [$method, $path] = $this->route($route, $pathParams);

        return $this->request($method, $path, $json, $form, $query, $headers, $auth);
    }

    /**
     * Invoke a decision route: a 2xx body is returned, and so is a 403 whose JSON body
     * carries `"allowed": false`, because that 403 is a deny decision and not an error.
     * Every other status goes through the normal error mapping.
     *
     * @param array<string, string|int> $pathParams
     * @param array<string, mixed> $json
     * @return array<string, mixed>
     */
    public function callDecision(string $route, array $pathParams, array $json): array
    {
        [$method, $path] = $this->route($route, $pathParams);
        /** @var ResponseInterface $response */
        $response = $this->request($method, $path, $json, raw: true);
        if ($response->getStatusCode() === 403) {
            $body = self::parseBody($response);
            if (is_array($body) && array_key_exists('allowed', $body) && $body['allowed'] === false) {
                return $body;
            }
        }
        $body = $this->handle($response);

        return is_array($body) ? $body : [];
    }

    /**
     * Send a request to a path (joined to the base URL) or a full URL.
     * With `$raw` the PSR-7 response is returned without status mapping
     * (transport errors are still wrapped).
     *
     * @param array<string, mixed>|null $json
     * @param array<string, string>|null $form
     * @param array<string, string|int|null> $query
     * @param array<string, string> $headers
     * @param string|null $rawBody pre-encoded body (wins over $json/$form); used by AAuth where the signed bytes must be sent verbatim
     */
    public function request(string $method, string $pathOrUrl, ?array $json = null, ?array $form = null, array $query = [], array $headers = [], bool $auth = true, bool $raw = false, ?string $rawBody = null): mixed
    {
        $url = preg_match('#^https?://#i', $pathOrUrl) === 1 ? $pathOrUrl : $this->baseUrl . $pathOrUrl;
        $query = array_filter($query, static fn ($v) => $v !== null);
        if ($query !== []) {
            $url .= (str_contains($url, '?') ? '&' : '?') . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        }

        $request = $this->requestFactory->createRequest(strtoupper($method), $url);
        $normalized = [];
        foreach ($headers as $name => $value) {
            $normalized[strtolower($name)] = $value;
            $request = $request->withHeader($name, $value);
        }
        if ($auth && !isset($normalized['authorization']) && !isset($normalized['x-api-key'])) {
            $token = $this->currentToken();
            if ($token !== null) {
                $request = $request->withHeader('Authorization', 'Bearer ' . $token);
            } elseif ($this->apiKey !== null && $this->apiKey !== '') {
                // The server accepts API keys via X-API-Key, leaving Authorization free for bearer tokens.
                $request = $request->withHeader('X-API-Key', $this->apiKey);
            }
        }
        if (!isset($normalized['accept'])) {
            $request = $request->withHeader('Accept', 'application/json');
        }

        if ($rawBody !== null) {
            $request = $request->withBody($this->streamFactory->createStream($rawBody));
        } elseif ($json !== null) {
            $request = $request->withHeader('Content-Type', 'application/json')
                ->withBody($this->streamFactory->createStream(json_encode($json, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)));
        } elseif ($form !== null) {
            $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded')
                ->withBody($this->streamFactory->createStream(http_build_query($form, '', '&', PHP_QUERY_RFC3986)));
        }

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new LumoAuthNetworkError(sprintf('Request to %s failed: %s', $url, $e->getMessage()), $e);
        }

        return $raw ? $response : $this->handle($response);
    }

    public function handle(ResponseInterface $response): mixed
    {
        $status = $response->getStatusCode();
        if ($status === 204) {
            return null;
        }
        $body = self::parseBody($response);
        if ($status >= 200 && $status < 300) {
            return $body;
        }
        [$message, $code] = self::extractError($status, $body);
        $class = self::STATUS_ERRORS[$status] ?? null;
        if ($class === LumoAuthRateLimitError::class) {
            $retryAfter = $response->getHeaderLine('Retry-After');
            throw new LumoAuthRateLimitError($message, $code ?? 'RATE_LIMITED', $status, $body, is_numeric($retryAfter) ? (float) $retryAfter : null);
        }
        if ($class !== null) {
            /** @var LumoAuthApiError $default */
            $default = new $class();
            throw new $class($message, $code ?? $default->errorCode, $status, $body);
        }
        throw new LumoAuthApiError($message, $code ?? 'API_ERROR', $status, $body);
    }

    private function requireOrgId(string $what): string
    {
        if ($this->orgId === null || $this->orgId === '') {
            throw new LumoAuthConfigError("orgId is required for $what — pass orgId to the client constructor or set LUMOAUTH_ORG_ID.");
        }

        return $this->orgId;
    }

    private static function parseBody(ResponseInterface $response): mixed
    {
        $text = (string) $response->getBody();
        if ($text === '') {
            return null;
        }
        try {
            return json_decode($text, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $text;
        }
    }

    /** @return array{0: string, 1: ?string} [message, code] */
    private static function extractError(int $status, mixed $body): array
    {
        $message = "HTTP $status";
        $code = null;
        if (is_array($body)) {
            foreach (['error_description', 'message', 'detail', 'error'] as $key) {
                if (isset($body[$key]) && is_string($body[$key]) && $body[$key] !== '') {
                    $message = $body[$key];
                    break;
                }
            }
            foreach (['code', 'error'] as $key) {
                if (isset($body[$key]) && is_string($body[$key]) && $body[$key] !== '') {
                    $code = $body[$key];
                    break;
                }
            }
        } elseif (is_string($body) && trim($body) !== '') {
            $message = "HTTP $status — " . substr(trim($body), 0, 500);
        }

        return [$message, $code];
    }
}
