<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Error\LumoAuthValidationError;
use LumoAuth\Http\HttpClient;
use LumoAuth\Routes;

/**
 * RBAC permission checks: single, bulk, any/all combinations, listing.
 * Bearer-scoped — the organization is inferred from the credential.
 */
final class Permissions
{
    public function __construct(private readonly HttpClient $http)
    {
    }

    /** @param array<string, mixed>|null $context */
    public function check(string $permission, ?array $context = null, ?string $userId = null): bool
    {
        return (bool) ($this->checkDetailed($permission, $context, $userId)['allowed'] ?? false);
    }

    /**
     * @param array<string, mixed>|null $context
     * @return array<string, mixed>
     */
    public function checkDetailed(string $permission, ?array $context = null, ?string $userId = null): array
    {
        return (array) $this->http->call(Routes::PERMISSIONS_CHECK, json: $this->body(permission: $permission, context: $context, userId: $userId));
    }

    /**
     * @param list<string> $permissions
     * @param array<string, mixed>|null $context
     * @return array<string, mixed>
     */
    public function checkBulk(array $permissions, ?array $context = null, ?string $userId = null): array
    {
        $this->requirePermissions($permissions);

        return (array) $this->http->call(Routes::PERMISSIONS_CHECK_BULK, json: $this->body(permissions: $permissions, context: $context, userId: $userId));
    }

    /** @param list<string> $permissions @param array<string, mixed>|null $context */
    public function checkAny(array $permissions, ?array $context = null, ?string $userId = null): bool
    {
        return (bool) ($this->checkAnyDetailed($permissions, $context, $userId)['allowed'] ?? false);
    }

    /** @param list<string> $permissions @param array<string, mixed>|null $context */
    public function checkAll(array $permissions, ?array $context = null, ?string $userId = null): bool
    {
        return (bool) ($this->checkAllDetailed($permissions, $context, $userId)['allowed'] ?? false);
    }

    /** @param list<string> $permissions @param array<string, mixed>|null $context @return array<string, mixed> */
    public function checkAnyDetailed(array $permissions, ?array $context = null, ?string $userId = null): array
    {
        $this->requirePermissions($permissions);

        return (array) $this->http->call(Routes::PERMISSIONS_CHECK_ANY, json: $this->body(permissions: $permissions, context: $context, userId: $userId));
    }

    /** @param list<string> $permissions @param array<string, mixed>|null $context @return array<string, mixed> */
    public function checkAllDetailed(array $permissions, ?array $context = null, ?string $userId = null): array
    {
        $this->requirePermissions($permissions);

        return (array) $this->http->call(Routes::PERMISSIONS_CHECK_ALL, json: $this->body(permissions: $permissions, context: $context, userId: $userId));
    }

    /** @return array<string, mixed> */
    public function list(): array
    {
        return (array) $this->http->call(Routes::PERMISSIONS_LIST);
    }

    /** @return list<string> */
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
    private function body(?string $permission = null, ?array $permissions = null, ?array $context = null, ?string $userId = null): array
    {
        if ($permission !== null && $permission === '') {
            throw new LumoAuthValidationError('Permission slug is required.');
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
        if ($userId !== null) {
            $body['user_id'] = $userId;
        }

        return $body;
    }
}
