<?php

declare(strict_types=1);

namespace LumoAuth;

use LumoAuth\Error\LumoAuthConfigError;

/**
 * Central registry of every LumoAuth endpoint this SDK talks to.
 *
 * GENERATED from sdk-contract/routes.json by sdk-contract/scripts/gen-php-routes.py.
 * Do not edit by hand: RoutesTest fails when this file is stale. Paths use
 * OpenAPI {camelCase} placeholders. Add endpoints to the contract, regenerate.
 */
final class Routes
{
    // ── aauth: AAuth cryptographic agent identity: token endpoint, discovery, JWKS
    public const AAUTH_AGENT_AUTH = 'aauth.agentAuth';
    public const AAUTH_AGENT_METADATA = 'aauth.agentMetadata';
    public const AAUTH_AGENT_TOKEN = 'aauth.agentToken';
    public const AAUTH_ISSUER_METADATA = 'aauth.issuerMetadata';
    public const AAUTH_JWKS = 'aauth.jwks';
    public const AAUTH_TOKEN_REVOKE = 'aauth.tokenRevoke';
    public const WELLKNOWN_AAUTH_ISSUER = 'wellknown.aauthIssuer';
    // ── abac: Attribute-based checks and attribute management (org-scoped)
    public const ABAC_ATTRIBUTE_DEFINITIONS = 'abac.attributeDefinitions';
    public const ABAC_CHECK = 'abac.check';
    public const ABAC_CHECK_BULK = 'abac.checkBulk';
    public const ABAC_MY_ATTRIBUTES = 'abac.myAttributes';
    public const ABAC_RESOURCE_ATTRIBUTES = 'abac.resourceAttributes';
    public const ABAC_SET_RESOURCE_ATTRIBUTE = 'abac.setResourceAttribute';
    public const ABAC_SET_USER_ATTRIBUTE = 'abac.setUserAttribute';
    // ── agents: Agent identity: Ask API, self-info, registration
    public const AGENTS_ASK = 'agents.ask';
    public const AGENTS_AUTHORIZE_MCP_TOOL = 'agents.authorizeMcpTool';
    public const AGENTS_ME = 'agents.me';
    public const AGENTS_REGISTER = 'agents.register';
    // ── approvals: Push approval for actions
    public const APPROVALS_CREATE = 'approvals.create';
    public const APPROVALS_STATUS = 'approvals.status';
    // ── auth: OAuth 2.1 / OIDC token-endpoint flows and userinfo
    public const OAUTH_AUTHORIZE = 'oauth.authorize';
    public const OAUTH_LOGIN_JSON = 'oauth.loginJson';
    public const OAUTH_LOGOUT = 'oauth.logout';
    public const OAUTH_REVOKE = 'oauth.revoke';
    public const OAUTH_TOKEN = 'oauth.token';
    public const OAUTH_USERINFO = 'oauth.userinfo';
    // ── jit: Just-in-time permissions: tasks, requests, short-lived tokens
    public const JIT_COMPLETE_TASK = 'jit.completeTask';
    public const JIT_CREATE_TASK = 'jit.createTask';
    public const JIT_EVALUATE_TASK = 'jit.evaluateTask';
    public const JIT_PENDING = 'jit.pending';
    public const JIT_REQUEST = 'jit.request';
    public const JIT_REQUEST_STATUS = 'jit.requestStatus';
    public const JIT_TOKEN = 'jit.token';
    // ── mcp: MCP: token exchange for one MCP server (built on oauth.token) and the per-tool check that an MCP server asks with its own client-credentials token
    public const MCP_AUTHORIZE_TOOL = 'mcp.authorizeTool';
    // ── permissions: RBAC permission checks (bearer-scoped, org inferred from the credential)
    public const PERMISSIONS_CHECK = 'permissions.check';
    public const PERMISSIONS_CHECK_ALL = 'permissions.checkAll';
    public const PERMISSIONS_CHECK_ANY = 'permissions.checkAny';
    public const PERMISSIONS_CHECK_BULK = 'permissions.checkBulk';
    public const PERMISSIONS_LIST = 'permissions.list';
    // ── webauth: Browser sign-in helpers served by the web firewall
    public const WEB_CHECK_EMAIL = 'web.checkEmail';
    public const WEB_MAGIC_LINK = 'web.magicLink';
    // ── zanzibar: Relationship-based checks and expansion
    public const ZANZIBAR_CHECK = 'zanzibar.check';
    public const ZANZIBAR_EXPAND = 'zanzibar.expand';

    /** @var array<string, array{0: string, 1: string}> route name => [method, path template] */
    public const ROUTES = [
        'aauth.agentAuth' => ['GET', '/orgs/{orgId}/api/v1/aauth/agent/auth'],
        'aauth.agentMetadata' => ['GET', '/orgs/{orgId}/api/v1/.well-known/aauth-agent'],
        'aauth.agentToken' => ['POST', '/orgs/{orgId}/api/v1/aauth/agent/token'],
        'aauth.issuerMetadata' => ['GET', '/orgs/{orgId}/api/v1/.well-known/aauth-issuer'],
        'aauth.jwks' => ['GET', '/orgs/{orgId}/api/v1/aauth/jwks.json'],
        'aauth.tokenRevoke' => ['POST', '/orgs/{orgId}/api/v1/aauth/token/revoke'],
        'wellknown.aauthIssuer' => ['GET', '/.well-known/aauth-issuer'],
        'abac.attributeDefinitions' => ['GET', '/orgs/{orgId}/api/v1/abac/attribute-definitions'],
        'abac.check' => ['POST', '/orgs/{orgId}/api/v1/abac/check'],
        'abac.checkBulk' => ['POST', '/orgs/{orgId}/api/v1/abac/check-bulk'],
        'abac.myAttributes' => ['GET', '/orgs/{orgId}/api/v1/abac/my-attributes'],
        'abac.resourceAttributes' => ['GET', '/orgs/{orgId}/api/v1/abac/resources/{resourceType}/{resourceId}/attributes'],
        'abac.setResourceAttribute' => ['PUT', '/orgs/{orgId}/api/v1/abac/resources/{resourceType}/{resourceId}/attributes/{attributeSlug}'],
        'abac.setUserAttribute' => ['PUT', '/orgs/{orgId}/api/v1/abac/users/{userId}/attributes/{attributeSlug}'],
        'agents.ask' => ['POST', '/orgs/{orgId}/api/v1/agents/ask'],
        'agents.authorizeMcpTool' => ['POST', '/orgs/{orgId}/api/v1/agents/me/mcp/authorize'],
        'agents.me' => ['GET', '/orgs/{orgId}/api/v1/agents/me'],
        'agents.register' => ['POST', '/orgs/{orgId}/api/v1/agents/register'],
        'approvals.create' => ['POST', '/orgs/{orgId}/api/v1/agents/me/approvals'],
        'approvals.status' => ['GET', '/orgs/{orgId}/api/v1/agents/me/approvals/{token}/status'],
        'oauth.authorize' => ['GET', '/orgs/{orgId}/api/v1/oauth/authorize'],
        'oauth.loginJson' => ['POST', '/orgs/{orgId}/api/v1/oauth/login/json'],
        'oauth.logout' => ['GET', '/orgs/{orgId}/api/v1/oauth/logout'],
        'oauth.revoke' => ['POST', '/orgs/{orgId}/api/v1/oauth/revoke'],
        'oauth.token' => ['POST', '/orgs/{orgId}/api/v1/oauth/token'],
        'oauth.userinfo' => ['GET', '/orgs/{orgId}/api/v1/oauth/userinfo'],
        'jit.completeTask' => ['POST', '/orgs/{orgId}/api/v1/jit/task/{taskId}/complete'],
        'jit.createTask' => ['POST', '/orgs/{orgId}/api/v1/jit/task'],
        'jit.evaluateTask' => ['POST', '/orgs/{orgId}/api/v1/jit/task/{taskId}/evaluate'],
        'jit.pending' => ['GET', '/orgs/{orgId}/api/v1/jit/pending'],
        'jit.request' => ['POST', '/orgs/{orgId}/api/v1/jit/request'],
        'jit.requestStatus' => ['GET', '/orgs/{orgId}/api/v1/jit/request/{requestId}/status'],
        'jit.token' => ['POST', '/orgs/{orgId}/api/v1/jit/request/{requestId}/token'],
        'mcp.authorizeTool' => ['POST', '/orgs/{orgId}/api/v1/mcp/servers/{serverId}/tools/authorize'],
        'permissions.check' => ['POST', '/api/v1/authz/check'],
        'permissions.checkAll' => ['POST', '/api/v1/authz/check-all'],
        'permissions.checkAny' => ['POST', '/api/v1/authz/check-any'],
        'permissions.checkBulk' => ['POST', '/api/v1/authz/check-bulk'],
        'permissions.list' => ['GET', '/api/v1/authz/permissions'],
        'web.checkEmail' => ['POST', '/orgs/{orgId}/check-email'],
        'web.magicLink' => ['POST', '/orgs/{orgId}/magic-link'],
        'zanzibar.check' => ['POST', '/api/v1/authz/zanzibar/check'],
        'zanzibar.expand' => ['POST', '/api/v1/authz/zanzibar/expand'],
    ];

    /** @return array{0: string, 1: string} [method, path template] */
    public static function get(string $name): array
    {
        if (!isset(self::ROUTES[$name])) {
            throw new LumoAuthConfigError(sprintf('Unknown route "%s"', $name));
        }

        return self::ROUTES[$name];
    }

    /**
     * Fill {param} placeholders; values are URL-encoded. A missing value
     * throws so a missing org ID fails at the call site, not as a 404.
     *
     * @param array<string, string|int> $params
     */
    public static function buildPath(string $template, array $params = []): string
    {
        return (string) preg_replace_callback('/\{([^}]+)\}/', static function (array $m) use ($template, $params): string {
            $value = $params[$m[1]] ?? null;
            if ($value === null || $value === '') {
                throw new LumoAuthConfigError(sprintf('Missing route parameter "%s" for path %s', $m[1], $template));
            }

            return rawurlencode((string) $value);
        }, $template);
    }

    /**
     * @param array<string, string|int> $params
     * @return array{0: string, 1: string} [method, concrete path]
     */
    public static function path(string $name, array $params = []): array
    {
        [$method, $template] = self::get($name);

        return [$method, self::buildPath($template, $params)];
    }
}
