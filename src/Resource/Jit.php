<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Http\HttpClient;
use LumoAuth\Routes;

/** Just-in-time permissions: task lifecycle, RFC 9396 permission requests, short-lived tokens. */
final class Jit
{
    /** Maximum TTL the server honours (15 min). */
    public const MAX_TTL = 900;

    public function __construct(private readonly HttpClient $http)
    {
    }

    /** @return array<string, mixed> */
    public function createTask(?string $name = null, ?string $taskType = null, ?string $onBehalfOf = null): array
    {
        $body = [];
        if ($name) {
            $body['name'] = $name;
        }
        if ($taskType) {
            $body['type'] = $taskType;
        }
        if ($onBehalfOf) {
            $body['on_behalf_of'] = $onBehalfOf;
        }

        return (array) $this->http->call(Routes::JIT_CREATE_TASK, json: $body);
    }

    public function completeTask(string $taskId): mixed
    {
        return $this->http->call(Routes::JIT_COMPLETE_TASK, ['taskId' => $taskId]);
    }

    /** @return array<string, mixed> */
    public function evaluateTask(string $taskId, string $result = 'completed', ?string $notes = null): array
    {
        $body = ['result' => $result];
        if ($notes) {
            $body['notes'] = $notes;
        }

        return (array) $this->http->call(Routes::JIT_EVALUATE_TASK, ['taskId' => $taskId], json: $body);
    }

    /** @param array<string, mixed> $authorizationDetails @return array<string, mixed> */
    public function request(string $taskId, array $authorizationDetails, ?string $justification = null, int $ttl = 300): array
    {
        $body = ['task_id' => $taskId, 'authorization_details' => $authorizationDetails, 'requested_ttl' => min($ttl, self::MAX_TTL)];
        if ($justification) {
            $body['justification'] = $justification;
        }

        return (array) $this->http->call(Routes::JIT_REQUEST, json: $body);
    }

    /** @return array<string, mixed> */
    public function status(string $requestId): array
    {
        return (array) $this->http->call(Routes::JIT_REQUEST_STATUS, ['requestId' => $requestId]);
    }

    /** @return array<string, mixed> */
    public function token(string $requestId): array
    {
        return (array) $this->http->call(Routes::JIT_TOKEN, ['requestId' => $requestId]);
    }

    /** Requests waiting for a human reviewer. Needs a browser session or a user access token with the `jit:approve` scope. @return list<array<string, mixed>> */
    public function pending(): array
    {
        // Reply: {"pending_requests": [...], "count": n, "data": [...], "pagination": {...}}
        $reply = $this->http->call(Routes::JIT_PENDING);
        if (!is_array($reply)) {
            return [];
        }
        foreach (['data', 'pending_requests'] as $key) {
            if (isset($reply[$key]) && is_array($reply[$key])) {
                return array_values($reply[$key]);
            }
        }

        return [];
    }
}
