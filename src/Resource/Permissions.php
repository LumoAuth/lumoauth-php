<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Error\LumoAuthValidationError;
use LumoAuth\Http\HttpClient;
use LumoAuth\Routes;

/**
 * RBAC permission checks: single, bulk, any/all combinations, listing.
 * Bearer-scoped — the organization is inferred from the credential.
 *
 * Every check is about the caller unless you name another subject:
 * `userId:` (the LumoAuth user ID, a UUID) or `agentId:` (the `agt_…` agent ID).
 * The SDK sends it as `subject: {"type": "user"|"agent", "id": …}`.
 * Asking about another subject needs the `authz:check` scope (an organization
 * API key can hold it) or the `authz.check` permission. Without it the server
 * answers 403 `INSUFFICIENT_PERMISSIONS`. An ID that is not in the organization
 * gives 404 `SUBJECT_NOT_FOUND` (LumoAuthNotFoundError).
 */
final class Permissions
{
    public function __construct(private readonly HttpClient $http)
    {
    }

    /** @param array<string, mixed>|null $context */
    public function check(string $permission, ?array $context = null, ?string $userId = null, ?string $agentId = null): bool
    {
        return (bool) ($this->checkDetailed($permission, $context, $userId, $agentId)['allowed'] ?? false);
    }

    /**
     * @param array<string, mixed>|null $context
     * @return array<string, mixed>
     */
    public function checkDetailed(string $permission, ?array $context = null, ?string $userId = null, ?string $agentId = null): array
    {
        return (array) $this->http->call(Routes::PERMISSIONS_CHECK, json: $this->body(permission: $permission, context: $context, userId: $userId, agentId: $agentId));
    }

    /**
     * @param list<string> $permissions
     * @param array<string, mixed>|null $context
     * @return array<string, mixed>
     */
    public function checkBulk(array $permissions, ?array $context = null, ?string $userId = null, ?string $agentId = null): array
    {
        $this->requirePermissions($permissions);

        return (array) $this->http->call(Routes::PERMISSIONS_CHECK_BULK, json: $this->body(permissions: $permissions, context: $context, userId: $userId, agentId: $agentId));
    }

    /** @param list<string> $permissions @param array<string, mixed>|null $context */
    public function checkAny(array $permissions, ?array $context = null, ?string $userId = null, ?string $agentId = null): bool
    {
        return (bool) ($this->checkAnyDetailed($permissions, $context, $userId, $agentId)['allowed'] ?? false);
    }

    /** @param list<string> $permissions @param array<string, mixed>|null $context */
    public function checkAll(array $permissions, ?array $context = null, ?string $userId = null, ?string $agentId = null): bool
    {
        return (bool) ($this->checkAllDetailed($permissions, $context, $userId, $agentId)['allowed'] ?? false);
    }

    /** @param list<string> $permissions @param array<string, mixed>|null $context @return array<string, mixed> */
    public function checkAnyDetailed(array $permissions, ?array $context = null, ?string $userId = null, ?string $agentId = null): array
    {
        $this->requirePermissions($permissions);

        return (array) $this->http->call(Routes::PERMISSIONS_CHECK_ANY, json: $this->body(permissions: $permissions, context: $context, userId: $userId, agentId: $agentId));
    }

    /** @param list<string> $permissions @param array<string, mixed>|null $context @return array<string, mixed> */
    public function checkAllDetailed(array $permissions, ?array $context = null, ?string $userId = null, ?string $agentId = null): array
    {
        $this->requirePermissions($permissions);

        return (array) $this->http->call(Routes::PERMISSIONS_CHECK_ALL, json: $this->body(permissions: $permissions, context: $context, userId: $userId, agentId: $agentId));
    }

    /**
     * Every permission the caller holds. A user access token needs the `authz:read` scope
     * (or the blanket `admin` scope). Organization API keys cannot hold that scope, so with
     * an API key this throws LumoAuthPermissionDeniedError with `requiredScopes === ['authz:read']`.
     *
     * @return array<string, mixed>
     */
    public function list(): array
    {
        return (array) $this->http->call(Routes::PERMISSIONS_LIST);
    }

    /** The permission slugs from list(); needs the same `authz:read` scope. @return list<string> */
    public function listSlugs(): array
    {
        $slugs = [];
        foreach ($this->list()['permissions'] ?? [] as $p) {
            if (is_array($p) && isset($p['slug']) && is_string($p['slug'])) {
                $slugs[] = $p['slug'];
            }
        }

        return array_values(array_unique($slugs));
    }

    /** @param list<string> $permissions */
    private function requirePermissions(array $permissions): void
    {
        if ($permissions === []) {
            throw new LumoAuthValidationError('At least one permission is required.');
        }
    }

    /**
     * @param list<string>|null $permissions
     * @param array<string, mixed>|null $context
     * @return array<string, mixed>
     */
    private function body(?string $permission = null, ?array $permissions = null, ?array $context = null, ?string $userId = null, ?string $agentId = null): array
    {
        if ($permission !== null && $permission === '') {
            throw new LumoAuthValidationError('Permission slug is required.');
        }
        if ($userId !== null && $agentId !== null) {
            throw new LumoAuthValidationError('Pass userId or agentId, not both.');
        }
        if ($userId === '' || $agentId === '') {
            throw new LumoAuthValidationError('The subject ID must not be empty.');
        }
        $body = [];
        if ($permission !== null) {
            $body['permission'] = $permission;
        }
        if ($permissions !== null) {
            $body['permissions'] = array_values($permissions);
        }
        if ($context) {
            $body['context'] = $context;
        }
        // The server reads the subject from `subject` only. A top-level
        // `user_id` is ignored, and the check would be about the caller.
        if ($userId !== null) {
            $body['subject'] = ['type' => 'user', 'id' => $userId];
        } elseif ($agentId !== null) {
            $body['subject'] = ['type' => 'agent', 'id' => $agentId];
        }

        return $body;
    }
}
