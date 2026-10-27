<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

/**
 * Outcome of Agents::authorizeMcpTool(). A deny is a result with $allowed false, not an
 * exception. $resourceId has the form `<serverId>/<tool>`.
 */
final class AgentMcpToolDecision
{
    public function __construct(
        public readonly bool $allowed,
        /** The calling agent's `agt_…` ID, or null when the response omits it. */
        public readonly ?string $agentId,
        /** Always `mcp_tool`. */
        public readonly string $resourceType,
        public readonly string $resourceId,
    ) {
    }

    /** @param array<string, mixed> $body */
    public static function fromArray(array $body, string $serverId, string $tool): self
    {
        $resource = is_array($body['resource'] ?? null) ? $body['resource'] : [];

        return new self(
            ($body['allowed'] ?? false) === true,
            is_string($body['agent_id'] ?? null) ? $body['agent_id'] : null,
            is_string($resource['type'] ?? null) ? $resource['type'] : 'mcp_tool',
            is_string($resource['id'] ?? null) ? $resource['id'] : $serverId . '/' . $tool,
        );
    }
}
