<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Error\LumoAuthConfigError;
use LumoAuth\Error\LumoAuthValidationError;
use LumoAuth\Http\HttpClient;
use LumoAuth\Routes;

/**
 * MCP helpers: tokens bound to one MCP server (RFC 8693 token exchange with an RFC 8707
 * `resource`), and per-tool checks that an MCP server makes with its own token.
 */
final class Mcp
{
    /** Longest tool name that authorizeTool() and Agents::authorizeMcpTool() accept. */
    public const MAX_TOOL_LENGTH = 80;

    private readonly Auth $auth;

    public function __construct(private readonly HttpClient $http)
    {
        $this->auth = new Auth($http);
    }

    /**
     * Exchange a token for one that is bound to one MCP server. LumoAuth sets the issued
     * token's `aud` only from the RFC 8707 `resource` parameter, so $serverId must be the
     * registered Resource URI of the MCP server. The method sends it as `resource`.
     *
     * The token names exactly one MCP server and works only at that server. LumoAuth's
     * own API rejects it. When the MCP server requires DPoP, use a DPoP-bound exchange
     * instead, because this method does not send a DPoP proof.
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

    /**
     * Ask whether a verified caller may run one tool on this MCP server.
     *
     * Call this from the MCP server with the server's OWN client-credentials token
     * (scope `mcp:authorize`). Never forward the token that the caller sent to you:
     * the MCP specification forbids token passthrough. The server's client must be
     * listed in the MCP server's `tool_authorizer_client_ids`.
     *
     * A 403 whose body has `"allowed": false` is a deny decision: the method returns
     * it with `allowed` false and does not throw. Other errors throw as usual, for
     * example LumoAuthPermissionDeniedError for `insufficient_scope` or `forbidden`,
     * and LumoAuthNotFoundError for an unknown server.
     *
     * @param string $serverId    the registered MCP server ID (`mcp_…`), not the resource URI
     * @param string $subjectType `user` or `agent`
     * @param string $subjectId   the verified MCP token's `sub`; for an agent, the `agt_…` ID also works
     * @param string $tool        the tool name, at most 80 characters, without `/`, `:`, `#` or `*`
     *
     * @throws LumoAuthValidationError before any request when an argument is invalid
     */
    public function authorizeTool(string $serverId, string $subjectType, string $subjectId, string $tool): McpToolDecision
    {
        if (!in_array($subjectType, ['user', 'agent'], true)) {
            throw new LumoAuthValidationError(sprintf("Invalid subject type '%s': it must be 'user' or 'agent'.", $subjectType));
        }
        if ($subjectId === '') {
            throw new LumoAuthValidationError('The subject ID must not be empty.');
        }
        self::assertServerAndTool($serverId, $tool);

        $body = $this->http->callDecision(Routes::MCP_AUTHORIZE_TOOL, ['serverId' => $serverId], [
            'subject' => ['type' => $subjectType, 'id' => $subjectId],
            'tool' => $tool,
        ]);

        return McpToolDecision::fromArray($body, $subjectType, $subjectId, $serverId, $tool);
    }

    /**
     * @internal shared with Agents::authorizeMcpTool()
     *
     * @throws LumoAuthValidationError
     */
    public static function assertServerAndTool(string $serverId, string $tool): void
    {
        foreach (['server ID' => $serverId, 'tool name' => $tool] as $what => $value) {
            if ($value === '') {
                throw new LumoAuthValidationError("The MCP $what must not be empty.");
            }
            if (strpbrk($value, '/:#*') !== false) {
                throw new LumoAuthValidationError(sprintf("Invalid MCP %s '%s': it must not contain '/', ':', '#' or '*'.", $what, $value));
            }
        }
        if (strlen($tool) > self::MAX_TOOL_LENGTH) {
            throw new LumoAuthValidationError(sprintf('The MCP tool name is longer than %d characters.', self::MAX_TOOL_LENGTH));
        }
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
