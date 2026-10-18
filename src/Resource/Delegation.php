<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Http\HttpClient;

/** Chain of agency: consent flow helpers, RFC 8693 token exchange, `act` chain introspection. */
final class Delegation
{
    /** Maximum delegation depth enforced by LumoAuth. */
    public const MAX_DELEGATION_DEPTH = 3;

    private readonly Auth $auth;

    public function __construct(private readonly HttpClient $http)
    {
        $this->auth = new Auth($http);
    }

    /** @param list<string>|null $scopes */
    public function consentUrl(string $clientId, string $redirectUri, ?array $scopes = null, ?string $state = null): string
    {
        return $this->auth->authorizationUrl($clientId, $redirectUri, implode(' ', $scopes ?: ['read:documents']), $state, prompt: 'consent', accessType: 'offline');
    }

    /** @return array<string, mixed> */
    public function exchangeCode(string $code, string $redirectUri, string $clientId, ?string $clientSecret = null): array
    {
        return $this->auth->exchangeCode($code, $redirectUri, $clientId, $clientSecret);
    }

    /** @return array<string, mixed> */
    public function refreshUserToken(string $refreshToken, string $clientId, ?string $clientSecret = null): array
    {
        return $this->auth->refreshToken($refreshToken, $clientId, $clientSecret);
    }

    /**
     * The delegated JWT carries an `act` claim recording the chain. $resource (RFC 8707 https
     * URL) becomes its `aud`; without it the token is bound to the acting agent.
     *
     * @param list<string>|null $scopes @return array<string, mixed>
     */
    public function exchange(string $subjectToken, string $actorToken, ?array $scopes = null, ?string $resource = null): array
    {
        return $this->auth->tokenExchange($subjectToken, actorToken: $actorToken, scopes: $scopes, resource: $resource);
    }

    public function revoke(string $token, string $tokenTypeHint = 'refresh_token', ?string $clientId = null, ?string $clientSecret = null): mixed
    {
        return $this->auth->revoke($token, $tokenTypeHint, $clientId, $clientSecret);
    }

    /** Actor subjects from the `act` chain, outermost first (no signature verification). @return list<string> */
    public static function parseActorChain(string $token): array
    {
        $payload = self::decodeJwtPayload($token);
        $actors = [];
        $act = $payload['act'] ?? null;
        while (is_array($act)) {
            if (isset($act['sub']) && is_string($act['sub'])) {
                $actors[] = $act['sub'];
            }
            $act = $act['act'] ?? null;
        }

        return $actors;
    }

    public static function subject(string $token): ?string
    {
        $sub = self::decodeJwtPayload($token)['sub'] ?? null;

        return is_string($sub) ? $sub : null;
    }

    /** @return array<string, mixed>|null */
    private static function decodeJwtPayload(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) < 2) {
            return null;
        }
        $decoded = base64_decode(strtr($parts[1], '-_', '+/') . str_repeat('=', (4 - strlen($parts[1]) % 4) % 4), true);
        if ($decoded === false) {
            return null;
        }
        $payload = json_decode($decoded, true);

        return is_array($payload) ? $payload : null;
    }
}
