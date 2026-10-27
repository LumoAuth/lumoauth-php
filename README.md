# lumoauth/lumoauth

This is the core of the LumoAuth PHP SDK. It lets a PHP application ask [LumoAuth](https://lumoauth.dev)
who may do what: role-based permissions, relationships (Zanzibar) and attribute-based
policies (ABAC). It also covers OAuth 2.1 sign-in, AI agents, human approvals,
just-in-time (JIT) permissions, token exchange and request signing for AAuth.

This page covers the essentials. The [full guide](https://github.com/lumoauth/sdk-php#readme)
has a section for every feature, the complete API reference and a troubleshooting table.
For Symfony and Laravel, install [`lumoauth/symfony-bundle`](https://packagist.org/packages/lumoauth/symfony-bundle)
or [`lumoauth/laravel`](https://packagist.org/packages/lumoauth/laravel) as well.

## Requirements

- PHP 8.1 or later with `ext-json`.
- A PSR-18 HTTP client with PSR-17 factories, such as Guzzle. The SDK finds an installed
  client on its own.
- `ext-sodium` for AAuth signing.

## Install

```bash
composer require lumoauth/lumoauth guzzlehttp/guzzle
```

## Quick start

```php
use LumoAuth\LumoAuth;

$lumo = new LumoAuth(apiKey: getenv('LUMOAUTH_API_KEY'), orgId: 'acme-corp');

if ($lumo->permissions->check('document.edit')) {
    // allowed
}

$canView  = $lumo->zanzibar->isViewer('document:readme', 'user:bob');
$decision = $lumo->abac->check('document', 'read', 'doc-123');   // needs a user or agent token
```

## Configuration

Every argument is optional. A missing value is read from the environment.

| Argument | Environment variable | Default |
|---|---|---|
| `apiKey` | `LUMOAUTH_API_KEY` | none; sent as `X-API-Key` |
| `baseUrl` | `LUMOAUTH_URL` | `https://app.lumoauth.dev` (EU: `https://eu.app.lumoauth.dev`) |
| `orgId` | `LUMOAUTH_ORG_ID` | none; needed for calls inside an organization |
| `tokenProvider` | none | a callable with no arguments that returns a bearer token; it wins over `apiKey` |
| `httpClient`, `requestFactory`, `streamFactory` | none | discovered |

```php
$lumo = new LumoAuth();                                       // everything from the environment
$lumo = new LumoAuth(apiKey: 'lmk_…', orgId: 'acme-corp');    // explicit
$lumo = new LumoAuth(tokenProvider: fn () => $session->get('access_token'));
```

## Credentials and scopes

| Credential | What it can call |
|---|---|
| Organization API key (`lmk_…`) | Permission checks, Zanzibar checks and the generated admin API. ABAC, agent, approval and JIT calls do not accept API keys. |
| User access token (`tokenProvider`) | Calls made for the signed-in user. Some calls need a scope; see below. |
| Agent token or agent API key `agk_…` (`tokenProvider`) | The agent calls, permission checks and Zanzibar checks, limited by the agent's capabilities |

A user access token needs these scopes. The blanket `admin` scope satisfies all of them.

| Call | Scope |
|---|---|
| `permissions->list()`, `permissions->listSlugs()` | `authz:read` |
| ABAC checks and attribute reads | `abac:read` |
| ABAC attribute writes | `abac:write` |
| `jit->pending()` | `jit:approve` |
| `agents->register()` | `admin:agents:write` |

Asking about a user or agent other than the caller needs the `authz:check` scope or the
`authz.check` permission. An organization API key can hold `authz:check`. When you sign
users in and list their permissions, request `authz:read` together with `openid profile email`.

## Namespaces

| Namespace | Example |
|---|---|
| `permissions` | `check('document.edit')`, `check('document.edit', userId: $sub)`, `checkAny([...])`, `checkAll([...])`, `checkBulk([...])`, `listSlugs()` |
| `zanzibar` | `check('document:1', 'viewer', 'user:bob')`, `isOwner(...)`, `expand('document:1', 'viewer')` |
| `abac` | `isAllowed('document', 'read', 'd1', ['pep' => ['ip' => $ip]])`, `checkBulk([...], $environment)`, `myAttributes()`, `setUserAttribute(...)` |
| `agents` | `ask('send_email', $ctx)`, `isAllowed(...)`, `me()`, `capabilities()`, `budget()`, `register(...)`, `authorizeMcpTool($serverId, $tool)` |
| `approvals` | `require(taskId: …, reason: …, onBehalfOf: …)->isApproved()`, `create()`, `status()`, `wait()` |
| `jit` | `createTask(...)`, `request($taskId, $authorizationDetails)`, `status($id)`, `token($id)`, `completeTask($taskId)` |
| `auth` | `authorizationUrl(...)`, `exchangeCode(...)`, `refreshToken(...)`, `clientCredentials(...)`, `tokenExchange(...)`, `revoke(...)`, `userinfo()` |
| `delegation` | `exchange($subjectToken, $actorToken, resource: 'https://api.example.com')`, `Delegation::parseActorChain($jwt)` |
| `mcp` | `getToken('https://mcp.example.com/mcp')`, `authorizeTool(serverId: 'mcp_…', subjectType: 'user', subjectId: $sub, tool: 'search')` |

**Checks about another subject.** The permission checks take `userId:` (the LumoAuth user
ID, a UUID: the `sub` of the user's tokens) or `agentId:` (an `agt_…` ID). The SDK sends
it as `subject: {"type": "user"|"agent", "id": …}`. Without `authz:check` the server
answers 403 `INSUFFICIENT_PERMISSIONS`. An unknown ID throws `LumoAuthNotFoundError`
(`SUBJECT_NOT_FOUND`).

**ABAC environment.** The SDK sends the ABAC context as the policy `environment`. A bulk
check uses one environment for every entry, so pass it once as the second argument of
`checkBulk()`. Entries with different contexts throw `LumoAuthValidationError`.

In ABAC and `agents->ask()` contexts, the server sets `ip`, `userAgent`, `requestMethod`
and `requestPath` from the request that it received. Values that you pass under those
names are kept under `pep`.

**Token exchange.** `auth->tokenExchange()` declares the type of each token with
`Auth::ACCESS_TOKEN_TYPE` (the default), `Auth::JWT_TOKEN_TYPE`, `Auth::ID_TOKEN_TYPE` or
`Auth::REFRESH_TOKEN_TYPE`. The server answers a type mismatch with `invalid_grant`. A
refresh token cannot be the subject when an agent acts for a user. The `resource`
argument (an RFC 8707 https URL) becomes the token's `aud`; LumoAuth does not set `aud`
from `audience`.

**MCP tokens.** `mcp->getToken($serverId)` sends the server ID as `resource`, so the token's
`aud` names the MCP server. The server ID must be the MCP server's https URL, such as
`https://mcp.example.com/mcp`. Any other value, such as `urn:mcp:finance`, throws
`LumoAuthValidationError` before a request is sent. The token works only at that one MCP
server, and LumoAuth's own API rejects it. A server that requires DPoP needs a DPoP-bound
exchange.

**MCP tool checks.** An MCP server calls `mcp->authorizeTool()` with its own client
credentials token (scope `mcp:authorize`). It never forwards the caller's token. It
passes the `sub` of the verified MCP token as the subject. An agent can ask about itself
with `agents->authorizeMcpTool($serverId, $tool)`. `$serverId` is the registered `mcp_…`
ID. When LumoAuth denies the tool, both methods return a decision with `allowed` set to
`false` and do not throw.

## Agents

There is no separate agent class. Create a client whose `tokenProvider` returns the
agent's token:

```php
$tokens = (new LumoAuth(orgId: 'acme-corp'))->auth->clientCredentials(
    getenv('AGENT_CLIENT_ID'),
    getenv('AGENT_CLIENT_SECRET'),
);
$agent = new LumoAuth(orgId: 'acme-corp', tokenProvider: fn () => $tokens['access_token']);

if ($agent->agents->isAllowed('send_email')) {
    $result = $agent->approvals->require(
        taskId: 'wire-7741',
        reason: 'Wire $4,500 to vendor INV-7741',
        onBehalfOf: 'ada@acme.com',
        impact: 'high',
    );
    if ($result->isApproved()) {
        // act
    }
}
```

`approvals->require()` polls until the person answers or 90 seconds pass. It returns the
status (`approved`, `denied`, `expired`, or `pending` after a timeout) instead of throwing.
`$result->approvedBy` is the approver's LumoAuth user ID, or `null` unless approved.

When the person has no enrolled device, LumoAuth sends no push prompt. It emails a plain
notice and answers 202, or it answers 428 when the email fails. `require()` then throws
`LumoAuthApprovalNotDeliveredError` with `reason` set to `email_fallback_sent` or
`no_enrolled_device`. After a 202, `create()` returns `status` `email_fallback_sent` and
`approval_token` `null`.

## Errors

Every exception extends `LumoAuth\Error\LumoAuthError` and has `errorCode`. API errors
also have `statusCode` and the decoded `body`.

| Class | When |
|---|---|
| `LumoAuthAuthenticationError` | 401: the credential is missing, wrong or expired |
| `LumoAuthPermissionDeniedError` | 403: not allowed. `requiredScopes` lists missing scopes. |
| `LumoAuthNotFoundError` | 404 |
| `LumoAuthRateLimitError` | 429. `retryAfter` is the wait in seconds. |
| `LumoAuthApiError` | any other error status |
| `LumoAuthValidationError` | bad input, caught before the request |
| `LumoAuthConfigError` | a missing `orgId` or a missing `ext-sodium` |
| `LumoAuthNetworkError` | no response (DNS, TLS, timeout) |
| `LumoAuthApprovalNotDeliveredError` | no push prompt was sent. `reason` is `email_fallback_sent` or `no_enrolled_device`. |

```php
use LumoAuth\Error\LumoAuthPermissionDeniedError;

try {
    $slugs = $lumo->permissions->listSlugs();
} catch (LumoAuthPermissionDeniedError $e) {
    $missing = $e->requiredScopes;   // ['authz:read']
}
```

## AAuth (agent identity)

```php
use LumoAuth\AAuth\AAuthClient;
use LumoAuth\AAuth\Signer;

[$pem, $jwks] = Signer::generateKeypair();      // publish $jwks at your agent's JWKS URL
$aauth = new AAuthClient($pem, $lumo->http(), orgId: 'acme-corp');
$grant = $aauth->requestAuthorization($resourceToken, 'read write', agentToken: $agentJwt);
$resp  = $aauth->signedRequest('GET', 'https://rs.example/docs', $grant['access_token']);
```

Signing uses RFC 9421 with Ed25519. Its output matches the test vector that is shared by
every LumoAuth SDK.

## Full REST API

```php
$users = new \LumoAuth\ApiClient\Api\AdminUsersApi(null, $lumo->api());   // needs lumoauth/api-client
```

## Licence

MIT
