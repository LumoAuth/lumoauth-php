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

    /** @param array<string, mixed>|null $context @return array<string, mixed> `allowed`, `action`, `reason`, `audit_id`, … */
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

    /** @return array<string, mixed> */
    public function me(): array
    {
        return (array) $this->http->call(Routes::AGENTS_ME);
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
