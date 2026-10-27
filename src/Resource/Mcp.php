<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Error\LumoAuthConfigError;
use LumoAuth\Error\LumoAuthValidationError;
use LumoAuth\Http\HttpClient;

/** Tokens bound to one MCP server, via RFC 8693 token exchange with an RFC 8707 `resource`. */
final class Mcp
{
    private readonly Auth $auth;

    public function __construct(private readonly HttpClient $http)
    {
        $this->auth = new Auth($http);
    }

    /**
     * Exchange a token for one that is bound to the MCP server: the issued token's `aud`
     * is $serverId. LumoAuth sets `aud` only from the RFC 8707 `resource` parameter, so
     * the server ID must be the MCP server's URL.
     *
     * @param string $serverId the MCP server's https URL, its RFC 8707 resource identifier
     *                         (e.g. `https://mcp.example.com/mcp`; http only for localhost or private hosts)
     * @param string|null $subjectToken token to exchange; defaults to the client's bearer token
     *
     * @throws LumoAuthValidationError when $serverId is not an absolute http(s) URL without a fragment
     */
    public function getToken(string $serverId, ?string $subjectToken = null): string
    {
        self::assertResourceUrl($serverId);
        $token = $subjectToken ?: $this->http->currentToken();
        if ($token === null) {
            throw new LumoAuthConfigError('MCP token exchange needs a subject token — authenticate first or pass subjectToken explicitly.');
        }

        return (string) ($this->auth->tokenExchange($token, audience: $serverId, resource: $serverId)['access_token'] ?? '');
    }

    private static function assertResourceUrl(string $serverId): void
    {
        $parts = parse_url($serverId);
        $scheme = is_array($parts) ? strtolower((string) ($parts['scheme'] ?? '')) : '';
        if (
            !is_array($parts)
            || !in_array($scheme, ['https', 'http'], true)
            || ($parts['host'] ?? '') === ''
            || str_contains($serverId, '#')
        ) {
            throw new LumoAuthValidationError(sprintf(
                "Invalid MCP server id '%s': it must be the MCP server's https URL (its RFC 8707 resource identifier), e.g. https://mcp.example.com/mcp, with no fragment.",
                $serverId,
            ));
        }
    }
}
