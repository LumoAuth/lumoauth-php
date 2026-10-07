<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Error\LumoAuthValidationError;
use LumoAuth\Http\HttpClient;
use LumoAuth\Routes;

/**
 * Attribute-based checks and attribute management. Org-scoped: the client
 * needs an orgId. Wire bodies use camelCase keys (`resourceType`,
 * `resourceId`); snake_case keys in bulk requests are translated.
 */
final class Abac
{
    public function __construct(private readonly HttpClient $http)
    {
    }

    /**
     * @param array<string, mixed>|null $context
     * @return array<string, mixed> the full decision (`allowed`, `reason`, `matchedPolicies`, …)
     */
    public function check(string $resourceType, string $action, ?string $resourceId = null, ?array $context = null): array
    {
        if ($resourceType === '') {
            throw new LumoAuthValidationError('resourceType is required.');
        }
        if ($action === '') {
            throw new LumoAuthValidationError('action is required.');
        }
        $body = ['resourceType' => $resourceType, 'action' => $action];
        if ($resourceId !== null) {
            $body['resourceId'] = $resourceId;
        }
        if ($context) {
            $body['context'] = $context;
        }

        return (array) $this->http->call(Routes::ABAC_CHECK, json: $body);
    }

    /** @param array<string, mixed>|null $context */
    public function isAllowed(string $resourceType, string $action, ?string $resourceId = null, ?array $context = null): bool
    {
        return (bool) ($this->check($resourceType, $action, $resourceId, $context)['allowed'] ?? false);
    }

    /**
     * @param list<array<string, mixed>> $requests
     * @return array<string, mixed>
     */
    public function checkBulk(array $requests): array
    {
        if ($requests === []) {
            throw new LumoAuthValidationError('At least one check request is required.');
        }
        $wire = [];
        foreach ($requests as $item) {
            $entry = [];
            foreach ($item as $key => $value) {
                $entry[match ($key) { 'resource_type' => 'resourceType', 'resource_id' => 'resourceId', default => $key }] = $value;
            }
            $wire[] = $entry;
        }

        return (array) $this->http->call(Routes::ABAC_CHECK_BULK, json: ['requests' => $wire]);
    }

    /** @return array<string, mixed> */
    public function myAttributes(): array
    {
        return (array) $this->http->call(Routes::ABAC_MY_ATTRIBUTES);
    }

    public function setUserAttribute(string $userId, string $attributeSlug, mixed $value): mixed
    {
        return $this->http->call(Routes::ABAC_SET_USER_ATTRIBUTE, ['userId' => $userId, 'attributeSlug' => $attributeSlug], json: ['value' => $value]);
    }

    /** @return array<string, mixed> */
    public function resourceAttributes(string $resourceType, string $resourceId): array
    {
        return (array) $this->http->call(Routes::ABAC_RESOURCE_ATTRIBUTES, ['resourceType' => $resourceType, 'resourceId' => $resourceId]);
    }

    public function setResourceAttribute(string $resourceType, string $resourceId, string $attributeSlug, mixed $value): mixed
    {
        return $this->http->call(Routes::ABAC_SET_RESOURCE_ATTRIBUTE, ['resourceType' => $resourceType, 'resourceId' => $resourceId, 'attributeSlug' => $attributeSlug], json: ['value' => $value]);
    }

    /**
     * @param string|null $type `user`, `resource` or `environment`
     * @return list<array<string, mixed>>
     */
    public function attributeDefinitions(?string $type = null): array
    {
        $raw = $this->http->call(Routes::ABAC_ATTRIBUTE_DEFINITIONS, query: ['type' => $type]);
        if (is_array($raw) && array_key_exists('data', $raw)) {
            return is_array($raw['data']) ? array_values($raw['data']) : [];
        }

        return is_array($raw) ? array_values($raw) : [];
    }
}
