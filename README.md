# lumoauth/lumoauth

The core LumoAuth PHP SDK. PHP 8.1+, PSR-18 transport (Guzzle or any other
client is discovered automatically), ext-sodium for AAuth signing.

```bash
composer require lumoauth/lumoauth guzzlehttp/guzzle
```

## Configuration

| Constructor argument | Environment variable | Default |
|---|---|---|
| `baseUrl` | `LUMOAUTH_URL` | `https://app.lumoauth.dev` |
| `orgId` | `LUMOAUTH_ORG_ID` | — (required for org-scoped calls) |
| `apiKey` | `LUMOAUTH_API_KEY` | — (sent as `X-API-Key`) |
| `tokenProvider` | — | a callable returning a bearer token; wins over the API key |

```php
$lumo = new LumoAuth();                                   // everything from the environment
$lumo = new LumoAuth(apiKey: 'lk_…', orgId: 'acme-corp'); // explicit
$lumo = new LumoAuth(tokenProvider: fn () => $session->get('access_token'));
```

## Namespaces

| | Example |
|---|---|
| `permissions` | `$lumo->permissions->check('document.edit')`, `checkAny([...])`, `checkBulk([...])`, `listSlugs()` |
| `zanzibar` | `$lumo->zanzibar->isOwner('document:1', 'user:alice')`, `expand('document:1', 'viewer')` |
| `abac` | `$lumo->abac->isAllowed('document', 'read', 'd1', ['ip' => …])`, `setUserAttribute(...)` |
| `agents` | `$lumo->agents->ask('send_email', $ctx)`, `me()`, `register(...)`, `capabilities()` |
| `approvals` | `$lumo->approvals->require(taskId: …, reason: …, onBehalfOf: …)->isApproved()` |
| `jit` | `$lumo->jit->createTask(...)`, `request($taskId, $authorizationDetails)`, `token($requestId)` |
| `mcp` | `$lumo->mcp->getToken('urn:mcp:finance')` |
| `delegation` | `$lumo->delegation->exchange($subjectToken, $actorToken)`, `Delegation::parseActorChain($jwt)` |
| `auth` | `$lumo->auth->authorizationUrl(...)`, `exchangeCode(...)`, `clientCredentials(...)`, `userinfo()` |

## Errors

Every failure is a `LumoAuth\Error\LumoAuthError` with `errorCode` and, for
API errors, `statusCode` and `body` — the taxonomy shared by all SDKs:
`LumoAuthAuthenticationError` (401), `LumoAuthPermissionDeniedError` (403),
`LumoAuthNotFoundError` (404), `LumoAuthRateLimitError` (429, `retryAfter`),
`LumoAuthValidationError`, `LumoAuthConfigError`, `LumoAuthNetworkError`.

## AAuth (agent identity)

```php
use LumoAuth\AAuth\AAuthClient;
use LumoAuth\AAuth\Signer;

[$pem, $jwks] = Signer::generateKeypair();      // publish $jwks at /.well-known/jwks.json
$aauth = new AAuthClient($pem, $lumo->http(), orgId: 'acme-corp');
$grant = $aauth->requestAuthorization($resourceToken, 'read write', agentToken: $agentJwt);
$resp  = $aauth->signedRequest('GET', 'https://rs.example/docs', $grant['access_token']);
```

Signing is RFC 9421 with Ed25519 and is verified against the vector every
SDK shares (`sdk-contract/vectors/aauth-rfc9421.json`).

## Full REST surface

```php
$config = $lumo->api();                                    // needs lumoauth/api-client
$users  = new \LumoAuth\ApiClient\Api\AdminUsersApi(null, $config);
```
