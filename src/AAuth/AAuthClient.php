<?php

declare(strict_types=1);

namespace LumoAuth\AAuth;

use LumoAuth\Error\LumoAuthApiError;
use LumoAuth\Error\LumoAuthValidationError;
use LumoAuth\Http\HttpClient;
use LumoAuth\Routes;
use Psr\Http\Message\ResponseInterface;

/**
 * AAuth agent client: signed token requests against `/aauth/agent/token`
 * (request_type auth | code | refresh), signed resource requests, and
 * discovery. Mirrors `AAuthClient` in Python and `@lumoauth/agent` in JS.
 *
 *     $aauth = new AAuthClient($privateKeyPem, orgId: 'acme-corp', http: $lumo->http());
 *     $grant = $aauth->requestAuthorization($resourceToken, 'read write', agentToken: $agentJwt);
 */
final class AAuthClient
{
    private readonly Signer $signer;

    public function __construct(string $privateKey, private readonly HttpClient $http, private readonly ?string $orgId = null)
    {
        $this->signer = new Signer($privateKey);
    }

    public function signer(): Signer
    {
        return $this->signer;
    }

    /**
     * Ask for an access token for a resource. When the server needs user
     * consent it answers 401 with an `auth_url`; that is returned as
     * `['authorization_required' => true, 'auth_url' => …, 'request_token' => …]`.
     *
     * @return array<string, mixed>
     */
    public function requestAuthorization(string $resourceToken, string $scope, ?string $agentToken = null, ?string $redirectUri = null): array
    {
        if ($agentToken === null || $agentToken === '') {
            throw new LumoAuthValidationError('agentToken is required — the /agent/token endpoint authenticates the agent via the Agent-Auth header, not the request body.');
        }
        $body = ['request_type' => 'auth', 'resource_token' => $resourceToken, 'scope' => $scope];
        if ($redirectUri) {
            $body['redirect_uri'] = $redirectUri;
        }
        $response = $this->post($body, $agentToken);
        if ($response->getStatusCode() === 401) {
            $data = self::json($response);

            return [
                'authorization_required' => true,
                'auth_url' => (string) ($data['auth_url'] ?? ''),
                'request_token' => (string) ($data['request_token'] ?? ''),
            ];
        }

        return $this->ok($response, 'AAuth authorization failed');
    }

    /** Redeem a consent code (single use; `$redirectUri` must match exactly). @return array<string, mixed> */
    public function exchangeCode(string $code, string $redirectUri, string $agentToken): array
    {
        return $this->ok($this->post(['request_type' => 'code', 'code' => $code, 'redirect_uri' => $redirectUri], $agentToken), 'AAuth code exchange failed');
    }

    /** Refresh; the server requires a fresh resource token every time. @return array<string, mixed> */
    public function refresh(string $refreshToken, string $resourceToken, string $agentToken, ?string $scope = null): array
    {
        $body = ['request_type' => 'refresh', 'refresh_token' => $refreshToken, 'resource_token' => $resourceToken];
        if ($scope) {
            $body['scope'] = $scope;
        }

        return $this->ok($this->post($body, $agentToken), 'AAuth refresh failed');
    }

    /**
     * Send a request to a resource server carrying the Bearer access token
     * AND an RFC 9421 signature proving possession of the key bound to the
     * token's `cnf.jwk`. The signature covers the actual Authorization value.
     *
     * @param array<string, mixed>|null $data JSON body
     */
    public function signedRequest(string $method, string $url, string $authToken, ?array $data = null): ResponseInterface
    {
        $body = $data === null ? '' : json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $authorization = 'Bearer ' . $authToken;
        $headers = $this->signer->sign($method, $url, $body, authorization: $authorization);
        $headers['Authorization'] = $authorization;
        /** @var ResponseInterface $response */
        $response = $this->http->request($method, $url, headers: $headers, auth: false, raw: true, rawBody: $body);

        return $response;
    }

    /** `/.well-known/aauth-issuer` of the authorization server. @return array<string, mixed> */
    public function discoverIssuer(): array
    {
        $path = $this->orgId !== null ? $this->http->route(Routes::AAUTH_ISSUER_METADATA, ['orgId' => $this->orgId])[1] : Routes::get(Routes::WELLKNOWN_AAUTH_ISSUER)[1];

        return (array) $this->http->request('GET', $path, auth: false);
    }

    /** `/.well-known/aauth-resource` of a resource server. @return array<string, mixed> */
    public function discoverResource(string $resourceUrl): array
    {
        return (array) $this->http->request('GET', rtrim($resourceUrl, '/') . '/.well-known/aauth-resource', auth: false);
    }

    public function tokenUrl(): string
    {
        $params = $this->orgId !== null ? ['orgId' => $this->orgId] : [];

        return $this->http->baseUrl() . $this->http->route(Routes::AAUTH_AGENT_TOKEN, $params)[1];
    }

    /** @param array<string, mixed> $body */
    private function post(array $body, string $agentToken): ResponseInterface
    {
        $url = $this->tokenUrl();
        // Encode once and sign exactly the bytes that are sent.
        $bytes = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $headers = $this->signer->sign('POST', $url, $bytes, agentToken: $agentToken);
        /** @var ResponseInterface $response */
        $response = $this->http->request('POST', $url, headers: $headers, auth: false, raw: true, rawBody: $bytes);

        return $response;
    }

    /** @return array<string, mixed> */
    private function ok(ResponseInterface $response, string $what): array
    {
        if ($response->getStatusCode() !== 200) {
            $text = (string) $response->getBody();
            throw new LumoAuthApiError(sprintf('%s: HTTP %d — %s', $what, $response->getStatusCode(), $text), 'API_ERROR', $response->getStatusCode(), self::json($response) ?? $text);
        }

        return self::json($response) ?? [];
    }

    /** @return array<string, mixed>|null */
    private static function json(ResponseInterface $response): ?array
    {
        $decoded = json_decode((string) $response->getBody(), true);

        return is_array($decoded) ? $decoded : null;
    }
}
