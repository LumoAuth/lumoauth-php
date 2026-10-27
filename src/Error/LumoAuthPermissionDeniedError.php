<?php

declare(strict_types=1);

namespace LumoAuth\Error;

/**
 * HTTP 403: the caller is authenticated but not allowed.
 *
 * When a route needs a user-delegated OAuth scope that the credential lacks
 * (for example `authz:read` on `permissions->list()`), the server answers
 * `{"error":"forbidden","message":"Insufficient scope: …","status":403,
 * "details":{"required_scopes":["authz:read"],"granted_scopes":[…]}}`.
 * `$requiredScopes` lists the scopes it named; it is empty for any other 403.
 */
class LumoAuthPermissionDeniedError extends LumoAuthApiError
{
    /** @var list<string> */
    public readonly array $requiredScopes;

    public function __construct(string $message = 'Permission denied.', string $errorCode = 'PERMISSION_DENIED', int $statusCode = 403, mixed $body = null)
    {
        parent::__construct($message, $errorCode, $statusCode, $body);
        $this->requiredScopes = self::extractRequiredScopes($body);
    }

    /** @return list<string> */
    private static function extractRequiredScopes(mixed $body): array
    {
        $raw = is_array($body) && is_array($body['details'] ?? null) ? ($body['details']['required_scopes'] ?? null) : null;
        if (!is_array($raw) || !array_is_list($raw)) {
            return [];
        }

        return array_values(array_filter($raw, static fn (mixed $s): bool => is_string($s) && $s !== ''));
    }
}
