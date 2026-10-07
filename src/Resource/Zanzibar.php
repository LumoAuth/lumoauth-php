<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Error\LumoAuthValidationError;
use LumoAuth\Http\HttpClient;
use LumoAuth\Routes;

/** Relationship-based checks: does `subject` have `relation` to `object` (`namespace:id` tuples). */
final class Zanzibar
{
    public function __construct(private readonly HttpClient $http)
    {
    }

    public function check(string $object, string $relation, string $subject): bool
    {
        return (bool) ($this->checkDetailed($object, $relation, $subject)['allowed'] ?? false);
    }

    /** @return array<string, mixed> */
    public function checkDetailed(string $object, string $relation, string $subject): array
    {
        self::validate($object, $relation, $subject);

        return (array) $this->http->call(Routes::ZANZIBAR_CHECK, json: ['object' => $object, 'relation' => $relation, 'subject' => $subject]);
    }

    /**
     * Who has `relation` on `object`, including subjects reached through
     * namespace rewrites. Needs the oracle privilege (`authz.check`).
     *
     * @return array<string, mixed> the root tree node
     */
    public function expand(string $object, string $relation): array
    {
        self::validateObjectRelation($object, $relation);
        $response = $this->http->call(Routes::ZANZIBAR_EXPAND, json: ['object' => $object, 'relation' => $relation]);
        $tree = is_array($response) ? ($response['tree'] ?? null) : null;
        if (!is_array($tree)) {
            throw new LumoAuthValidationError("Unexpected response from LumoAuth API: expected a 'tree' object.");
        }

        return $tree;
    }

    public function isViewer(string $object, string $subject): bool
    {
        return $this->check($object, 'viewer', $subject);
    }

    public function isEditor(string $object, string $subject): bool
    {
        return $this->check($object, 'editor', $subject);
    }

    public function isOwner(string $object, string $subject): bool
    {
        return $this->check($object, 'owner', $subject);
    }

    public function isMember(string $object, string $subject): bool
    {
        return $this->check($object, 'member', $subject);
    }

    public function isAdmin(string $object, string $subject): bool
    {
        return $this->check($object, 'admin', $subject);
    }

    private static function validate(string $object, string $relation, string $subject): void
    {
        self::validateObjectRelation($object, $relation);
        if ($subject === '' || !str_contains($subject, ':')) {
            throw new LumoAuthValidationError('Subject must be in "namespace:id" or "namespace:id#relation" format.');
        }
    }

    private static function validateObjectRelation(string $object, string $relation): void
    {
        if ($object === '' || !str_contains($object, ':')) {
            throw new LumoAuthValidationError('Object must be in "namespace:id" format (e.g. "document:123").');
        }
        if ($relation === '') {
            throw new LumoAuthValidationError('Relation is required (e.g. "viewer", "editor", "owner").');
        }
    }
}
