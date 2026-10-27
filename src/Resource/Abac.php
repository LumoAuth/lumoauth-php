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
 *
 * The `$context` that you pass is sent as the ABAC `environment`. The keys `ip`,
 * `userAgent`, `requestMethod` and `requestPath` always describe the request that
 * LumoAuth received; values that you pass under those names are kept under `pep`.
 *
 * A user access token needs the `abac:read` scope for checks and attribute reads,
 * and `abac:write` to set attributes. Organization API keys are not accepted on
 * these routes.
 */
final class Abac
{
    public function __construct(private readonly HttpClient $http)
    {
    }

    /**
     * @param array<string, mixed>|null $context sent as the ABAC `environment`
     * @return array<string, mixed> the full decision (`allowed`, `reason`, `matchedPolicies`, `user_id`, …).
     *         A caller without the `policies.view` permission gets only `id` and `name` for each matched policy.
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
            // The server reads `environment`; a `context` key would be ignored.
            $body['environment'] = $context;
        }

        return (array) $this->http->call(Routes::ABAC_CHECK, json: $body);
    }

    /** @param array<string, mixed>|null $context */
    public function isAllowed(string $resourceType, string $action, ?string $resourceId = null, ?array $context = null): bool
    {
        return (bool) ($this->check($resourceType, $action, $resourceId, $context)['allowed'] ?? false);
    }

    /**
     * Evaluate up to 100 checks in one call. Each entry has `resourceType` (or
     * `resource_type`), `action` and an optional `resourceId` (or `resource_id`).
     *
     * The server applies ONE environment to every check in a bulk call. Pass it as
     * `$environment`. Entries may instead carry `context` (or `environment`), but then
     * every entry must carry the same value, and it must match `$environment` when you
     * pass both. Otherwise this throws LumoAuthValidationError.
     *
     * @param list<array<string, mixed>> $requests
     * @param array<string, mixed>|null $environment shared ABAC environment for every check
     * @return array<string, mixed> `results` (each with `index`, `resourceType`, `action`,
     *         `resourceId`, `allowed`, `reason` and an optional `error`) and `user_id`
     */
    public function checkBulk(array $requests, ?array $environment = null): array
    {
        if ($requests === []) {
            throw new LumoAuthValidationError('At least one check request is required.');
        }
        if (count($requests) > 100) {
            throw new LumoAuthValidationError('At most 100 checks are allowed in one bulk call.');
        }
        $wire = [];
        $entryEnvironments = [];
        foreach ($requests as $item) {
            $entry = [];
            $entryEnvironment = null;
            foreach ($item as $key => $value) {
                if ($key === 'context' || $key === 'environment') {
                    $entryEnvironment = ($value === null || $value === []) ? null : $value;
                    continue;
                }
                $entry[match ($key) { 'resource_type' => 'resourceType', 'resource_id' => 'resourceId', default => $key }] = $value;
            }
            $wire[] = $entry;
            $entryEnvironments[] = $entryEnvironment;
        }

        $shared = $environment === [] ? null : $environment;
        $withEnvironment = array_values(array_filter($entryEnvironments, static fn ($e): bool => $e !== null));
        if ($withEnvironment !== []) {
            // Every entry must carry the same environment (and match $environment when given):
            // an entry without one would silently be evaluated with the others' environment.
            $first = $withEnvironment[0];
            foreach ($entryEnvironments as $e) {
                if ($e != $first) {
                    throw new LumoAuthValidationError('The server applies one environment to every check in a bulk call; give every entry the same context, or pass it once as $environment.');
                }
            }
            if ($shared !== null && $shared != $first) {
                throw new LumoAuthValidationError('The server applies one environment to every check in a bulk call; the entry context differs from $environment.');
            }
            $shared = $first;
        }

        $body = ['checks' => $wire];
        if ($shared !== null) {
            $body['environment'] = $shared;
        }

        return (array) $this->http->call(Routes::ABAC_CHECK_BULK, json: $body);
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
