<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Error\LumoAuthValidationError;
use LumoAuth\Http\HttpClient;
use LumoAuth\Routes;

/** Push approval for actions: create, poll, block until answered. */
final class Approvals
{
    private const IMPACTS = ['low', 'medium', 'high', 'critical'];

    /** @var \Closure(float): void */
    private \Closure $sleep;

    public function __construct(private readonly HttpClient $http, ?callable $sleep = null)
    {
        $this->sleep = $sleep === null
            ? static function (float $seconds): void { usleep((int) ($seconds * 1_000_000)); }
            : \Closure::fromCallable($sleep);
    }

    /** @param array<string, mixed>|null $meta @return array<string, mixed> */
    public function create(string $taskId, string $reason, string $onBehalfOf, string $impact = 'medium', ?array $meta = null): array
    {
        if ($taskId === '') {
            throw new LumoAuthValidationError('taskId is required');
        }
        if ($reason === '') {
            throw new LumoAuthValidationError('reason is required');
        }
        if (!in_array($impact, self::IMPACTS, true)) {
            throw new LumoAuthValidationError("invalid impact: '$impact'");
        }

        return (array) $this->http->call(Routes::APPROVALS_CREATE, json: [
            'task_id' => $taskId,
            'reason' => $reason,
            'impact' => $impact,
            'on_behalf_of' => $onBehalfOf,
            'meta' => $meta ?: null,
        ]);
    }

    /** @return array<string, mixed> */
    public function status(string $token): array
    {
        return (array) $this->http->call(Routes::APPROVALS_STATUS, ['token' => $token]);
    }

    /**
     * Poll until the approval leaves `pending` or the timeout elapses.
     *
     * @return array<string, mixed> the last status (`status` stays `pending` on timeout)
     */
    public function wait(string $token, float $pollIntervalS = 1.5, float $timeoutS = 90.0): array
    {
        $deadline = microtime(true) + $timeoutS;
        $last = ['status' => 'pending'];
        while (microtime(true) < $deadline) {
            ($this->sleep)($pollIntervalS);
            $last = $this->status($token);
            if (($last['status'] ?? null) !== 'pending') {
                break;
            }
        }

        return $last;
    }

    /** Create an approval and block until it is answered. @param array<string, mixed>|null $meta */
    public function require(string $taskId, string $reason, string $onBehalfOf, string $impact = 'medium', ?array $meta = null, float $pollIntervalS = 1.5, float $timeoutS = 90.0): ApprovalResult
    {
        $created = $this->create($taskId, $reason, $onBehalfOf, $impact, $meta);
        $token = (string) ($created['approval_token'] ?? '');
        $last = $this->wait($token, $pollIntervalS, $timeoutS);

        return new ApprovalResult(
            status: (string) ($last['status'] ?? 'expired'),
            token: (string) ($last['approval_token'] ?? $token),
            taskId: (string) ($last['task_id'] ?? $taskId),
            impact: isset($last['impact']) ? (string) $last['impact'] : null,
            reason: isset($last['reason']) ? (string) $last['reason'] : null,
            respondedAt: isset($last['responded_at']) ? (string) $last['responded_at'] : null,
            approvedBy: isset($last['approved_by']) ? (string) $last['approved_by'] : null,
        );
    }
}
