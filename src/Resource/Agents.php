<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Http\HttpClient;
use LumoAuth\Routes;

/** Agent identity: the Ask API (preflight authorization), self-info, registration. */
final class Agents
{
    public function __construct(private readonly HttpClient $http)
    {
    }

    /**
     * Ask whether the caller may perform $action. In $context, `ip`, `userAgent`,
     * `requestMethod` and `requestPath` always describe the request LumoAuth received;
     * values you pass under those names are kept under `pep` (the same rule as ABAC).
     *
     * @param array<string, mixed>|null $context @return array<string, mixed> `allowed`, `action`, `reason`, `audit_id`, …
     */
    public function ask(string $action, ?array $context = null): array
    {
        $body = ['action' => $action];
        if ($context) {
            $body['context'] = $context;
        }

        return (array) $this->http->call(Routes::AGENTS_ASK, json: $body);
    }

    /** @param array<string, mixed>|null $context */
    public function isAllowed(string $action, ?array $context = null): bool
    {
        return (bool) ($this->ask($action, $context)['allowed'] ?? false);
    }

    /**
     * The caller's identity, capabilities and workspace. For an agent credential,
     * `capabilities` are the agent's capability roles. A user access token without
     * the `authz:read` scope gets an empty `capabilities` list.
     *
     * @return array<string, mixed>
     */
    public function me(): array
    {
        return (array) $this->http->call(Routes::AGENTS_ME);
    }

    /**
     * Ask whether this agent may run one tool on a registered MCP server. Call it with
     * the agent's own credential (an agent access token or an `agk_` key).
     *
     * A 403 whose body has `"allowed": false` is a deny decision: the method returns it
     * with `allowed` false and does not throw. Other errors throw as usual. An unknown
     * or inactive server throws LumoAuthNotFoundError (`unknown_server`).
     *
     * @param string $serverId the registered MCP server ID (`mcp_…`), not the resource URI
     * @param string $tool     the tool name, at most 80 characters, without `/`, `:`, `#` or `*`
     *
     * @throws \LumoAuth\Error\LumoAuthValidationError before any request when an argument is invalid
     */
    public function authorizeMcpTool(string $serverId, string $tool): AgentMcpToolDecision
    {
        Mcp::assertServerAndTool($serverId, $tool);
        $body = $this->http->callDecision(Routes::AGENTS_AUTHORIZE_MCP_TOOL, [], ['server_id' => $serverId, 'tool' => $tool]);

        return AgentMcpToolDecision::fromArray($body, $serverId, $tool);
    }

    /** @param list<string>|null $capabilities @return array<string, mixed> */
    public function register(string $name, string $clientId, ?string $description = null, ?array $capabilities = null, ?string $jwksUri = null): array
    {
        $body = ['client_id' => $clientId, 'name' => $name];
        if ($description) {
            $body['description'] = $description;
        }
        if ($capabilities) {
            $body['capabilities'] = array_values($capabilities);
        }
        if ($jwksUri) {
            $body['jwks_uri'] = $jwksUri;
        }

        return (array) $this->http->call(Routes::AGENTS_REGISTER, json: $body);
    }

    /** UserInfo for the agent credential. @return array<string, mixed> */
    public function info(): array
    {
        return (array) $this->http->call(Routes::OAUTH_USERINFO);
    }

    /** @return list<string> */
    public function capabilities(): array
    {
        $caps = $this->info()['capabilities'] ?? [];

        return is_array($caps) ? array_values(array_filter($caps, 'is_string')) : [];
    }

    /** @return array<string, mixed> */
    public function budget(): array
    {
        $b = $this->info()['budget_policy'] ?? null;

        return is_array($b) ? $b : [];
    }
}
