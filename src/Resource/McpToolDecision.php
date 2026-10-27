<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

/**
 * Outcome of Mcp::authorizeTool(). A deny is a result with $allowed false, not an
 * exception. $resourceId has the form `<serverId>/<tool>`.
 */
final class McpToolDecision
{
    public function __construct(
        public readonly bool $allowed,
        /** `user` or `agent`. */
        public readonly string $subjectType,
        /** The subject ID that LumoAuth evaluated. For an agent, the `agt_…` ID. */
        public readonly string $subjectId,
        /** Always `mcp_tool`. */
        public readonly string $resourceType,
        public readonly string $resourceId,
    ) {
    }

    /** @param array<string, mixed> $body */
    public static function fromArray(array $body, string $subjectType, string $subjectId, string $serverId, string $tool): self
    {
        $subject = is_array($body['subject'] ?? null) ? $body['subject'] : [];
        $resource = is_array($body['resource'] ?? null) ? $body['resource'] : [];

        return new self(
            ($body['allowed'] ?? false) === true,
            is_string($subject['type'] ?? null) ? $subject['type'] : $subjectType,
            is_string($subject['id'] ?? null) ? $subject['id'] : $subjectId,
            is_string($resource['type'] ?? null) ? $resource['type'] : 'mcp_tool',
            is_string($resource['id'] ?? null) ? $resource['id'] : $serverId . '/' . $tool,
        );
    }
}
