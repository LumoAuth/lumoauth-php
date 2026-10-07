<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Error\LumoAuthConfigError;
use LumoAuth\Http\HttpClient;

/** Audience-scoped tokens for MCP servers via RFC 8693 token exchange. */
final class Mcp
{
    private readonly Auth $auth;

    public function __construct(private readonly HttpClient $http)
    {
        $this->auth = new Auth($http);
    }

    /**
     * @param string $serverId audience identifier of the target MCP server (e.g. `urn:mcp:financial-data`)
     * @param string|null $subjectToken token to exchange; defaults to the client's bearer token
     */
    public function getToken(string $serverId, ?string $subjectToken = null): string
    {
        $token = $subjectToken ?: $this->http->currentToken();
        if ($token === null) {
            throw new LumoAuthConfigError('MCP token exchange needs a subject token — authenticate first or pass subjectToken explicitly.');
        }

        return (string) ($this->auth->tokenExchange($token, audience: $serverId)['access_token'] ?? '');
    }
}
