<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Http\HttpClient;
use LumoAuth\Routes;

/** OAuth 2.1 / OIDC: authorization URL, token-endpoint grants, revocation, userinfo. */
final class Auth
{
    public const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
    /**
     * RFC 8693 subject_token_type / actor_token_type values (sdk-contract/token-types.json).
     * The server checks the token against the declared type and answers a mismatch
     * with invalid_grant. ACCESS_TOKEN_TYPE (default): an opaque or at+jwt access token;
     * JWT_TOKEN_TYPE: an at+jwt access token or an external workload identity token;
     * ID_TOKEN_TYPE: an OpenID Connect ID token issued to the exchanging client;
     * REFRESH_TOKEN_TYPE: a refresh token issued to the exchanging client. JIT permission
     * tokens, logout tokens and other special-purpose JWTs are never accepted under any type.
     */
    public const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
    public const JWT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
    public const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';
    public const REFRESH_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:refresh_token';

    public function __construct(private readonly HttpClient $http)
    {
    }

    /** @param array<string, string>|null $extra */
    public function authorizationUrl(
        string $clientId,
        string $redirectUri,
        string $scope = 'openid profile email',
        ?string $state = null,
        string $responseType = 'code',
        ?string $codeChallenge = null,
        ?string $codeChallengeMethod = null,
        ?string $prompt = null,
        ?string $accessType = null,
        ?array $extra = null,
    ): string {
        [, $path] = $this->http->route(Routes::OAUTH_AUTHORIZE);
        $params = ['response_type' => $responseType, 'client_id' => $clientId, 'redirect_uri' => $redirectUri, 'scope' => $scope];
        if ($state !== null) {
            $params['state'] = $state;
        }
        if ($codeChallenge !== null && $codeChallenge !== '') {
            $params['code_challenge'] = $codeChallenge;
            $params['code_challenge_method'] = $codeChallengeMethod ?? 'S256';
        }
        if ($prompt) {
            $params['prompt'] = $prompt;
        }
        if ($accessType) {
            $params['access_type'] = $accessType;
        }
        if ($extra) {
            $params = array_merge($params, $extra);
        }

        return $this->http->baseUrl() . $path . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /** @return array<string, mixed> */
    public function exchangeCode(string $code, string $redirectUri, string $clientId, ?string $clientSecret = null, ?string $codeVerifier = null): array
    {
        $data = ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => $redirectUri, 'client_id' => $clientId];
        if ($clientSecret) {
            $data['client_secret'] = $clientSecret;
        }
        if ($codeVerifier) {
            $data['code_verifier'] = $codeVerifier;
        }

        return $this->tokenRequest($data);
    }

    /** @param list<string>|null $scopes @return array<string, mixed> */
    public function refreshToken(string $refreshToken, string $clientId, ?string $clientSecret = null, ?array $scopes = null): array
    {
        $data = ['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken, 'client_id' => $clientId];
        if ($clientSecret) {
            $data['client_secret'] = $clientSecret;
        }
        if ($scopes) {
            $data['scope'] = implode(' ', $scopes);
        }

        return $this->tokenRequest($data);
    }

    /** @param list<string>|null $scopes @return array<string, mixed> */
    public function clientCredentials(string $clientId, string $clientSecret, ?array $scopes = null): array
    {
        $data = ['grant_type' => 'client_credentials', 'client_id' => $clientId, 'client_secret' => $clientSecret];
        if ($scopes) {
            $data['scope'] = implode(' ', $scopes);
        }

        return $this->tokenRequest($data);
    }

    /**
     * RFC 8693 token exchange. $subjectTokenType / $actorTokenType declare what kind of
     * token is being exchanged (one of the *_TOKEN_TYPE constants, default ACCESS_TOKEN_TYPE).
     *
     * @param list<string>|null $scopes @return array<string, mixed>
     */
    public function tokenExchange(
        string $subjectToken,
        ?string $actorToken = null,
        ?string $audience = null,
        ?array $scopes = null,
        string $subjectTokenType = self::ACCESS_TOKEN_TYPE,
        string $actorTokenType = self::ACCESS_TOKEN_TYPE,
    ): array {
        $data = ['grant_type' => self::TOKEN_EXCHANGE_GRANT, 'subject_token' => $subjectToken, 'subject_token_type' => $subjectTokenType];
        if ($actorToken) {
            $data['actor_token'] = $actorToken;
            $data['actor_token_type'] = $actorTokenType;
        }
        if ($audience) {
            $data['audience'] = $audience;
        }
        if ($scopes) {
            $data['scope'] = implode(' ', $scopes);
        }

        return $this->tokenRequest($data);
    }

    public function revoke(string $token, ?string $tokenTypeHint = null, ?string $clientId = null, ?string $clientSecret = null): mixed
    {
        $data = ['token' => $token];
        if ($tokenTypeHint) {
            $data['token_type_hint'] = $tokenTypeHint;
        }
        if ($clientId) {
            $data['client_id'] = $clientId;
        }
        if ($clientSecret) {
            $data['client_secret'] = $clientSecret;
        }

        return $this->http->call(Routes::OAUTH_REVOKE, form: $data, auth: false);
    }

    /** Uses the client's default credential unless `$accessToken` is given. @return array<string, mixed> */
    public function userinfo(?string $accessToken = null): array
    {
        $headers = $accessToken ? ['Authorization' => 'Bearer ' . $accessToken] : [];

        return (array) $this->http->call(Routes::OAUTH_USERINFO, headers: $headers);
    }

    /** @param array<string, string> $data @return array<string, mixed> */
    private function tokenRequest(array $data): array
    {
        // Token endpoints authenticate via the form body — never inject the client's default credential.
        return (array) $this->http->call(Routes::OAUTH_TOKEN, form: $data, auth: false);
    }
}
