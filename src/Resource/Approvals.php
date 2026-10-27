<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

use LumoAuth\Error\LumoAuthApiError;
use LumoAuth\Error\LumoAuthApprovalNotDeliveredError;
use LumoAuth\Error\LumoAuthError;
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

    /**
     * Send an approval request to the user's phone. A portal test token is refused
     * with 403 `test_token_not_accepted`.
     *
     * When the user has no enrolled device, the server emails a plain notice (no
     * approval link) and answers 202. This method then returns
     * `['status' => 'email_fallback_sent', 'approval_token' => null, …]`: there is
     * nothing to poll, so tell the user to enrol a device. The server gives the same
     * answer for an unknown user. When the email cannot be sent either, the server
     * answers 428 and this method throws LumoAuthApprovalNotDeliveredError with
     * reason `no_enrolled_device`.
     *
     * @param array<string, mixed>|null $meta @return array<string, mixed>
     * @throws LumoAuthApprovalNotDeliveredError on 428
     */
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

        try {
            $created = (array) $this->http->call(Routes::APPROVALS_CREATE, json: [
                'task_id' => $taskId,
                'reason' => $reason,
                'impact' => $impact,
                'on_behalf_of' => $onBehalfOf,
                'meta' => $meta ?: null,
            ]);
        } catch (LumoAuthApiError $e) {
            if ($e->statusCode === 428) {
                throw new LumoAuthApprovalNotDeliveredError(
                    $e->getMessage() !== 'HTTP 428' ? $e->getMessage() : 'The user has no enrolled device, and the email notice could not be sent.',
                    LumoAuthApprovalNotDeliveredError::REASON_NO_ENROLLED_DEVICE,
                    $taskId,
                    $e->body,
                    $e,
                );
            }
            throw $e;
        }
        if (($created['status'] ?? null) === LumoAuthApprovalNotDeliveredError::REASON_EMAIL_FALLBACK_SENT) {
            $created['approval_token'] = null;
        }

        return $created;
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

    /**
     * Create an approval and block until it is answered.
     *
     * Throws LumoAuthApprovalNotDeliveredError when no push prompt was sent: reason
     * `email_fallback_sent` (202, nothing to poll) or `no_enrolled_device` (428).
     *
     * @param array<string, mixed>|null $meta
     */
    public function require(string $taskId, string $reason, string $onBehalfOf, string $impact = 'medium', ?array $meta = null, float $pollIntervalS = 1.5, float $timeoutS = 90.0): ApprovalResult
    {
        $created = $this->create($taskId, $reason, $onBehalfOf, $impact, $meta);
        if (($created['status'] ?? null) === LumoAuthApprovalNotDeliveredError::REASON_EMAIL_FALLBACK_SENT) {
            throw new LumoAuthApprovalNotDeliveredError(
                is_string($created['message'] ?? null) && $created['message'] !== ''
                    ? $created['message']
                    : 'No push prompt was sent: the user has no enrolled device. An email notice without an approval link was sent.',
                LumoAuthApprovalNotDeliveredError::REASON_EMAIL_FALLBACK_SENT,
                isset($created['task_id']) ? (string) $created['task_id'] : $taskId,
                $created,
            );
        }
        $token = (string) ($created['approval_token'] ?? '');
        if ($token === '') {
            throw new LumoAuthError('The approval response has no approval_token to poll.');
        }
        $last = $this->wait($token, $pollIntervalS, $timeoutS);

        return new ApprovalResult(
            status: (string) ($last['status'] ?? 'expired'),
            token: (string) ($last['approval_token'] ?? $token),
            taskId: (string) ($last['task_id'] ?? $taskId),
            impact: isset($last['impact']) ? (string) $last['impact'] : null,
            reason: isset($last['reason']) ? (string) $last['reason'] : null,
            respondedAt: isset($last['responded_at']) ? (string) $last['responded_at'] : null,
            approvedBy: self::approverId($last['approved_by'] ?? null),
        );
    }

    /** `approved_by` is `{"user_id": <int>}` (null unless approved); a bare scalar is accepted too. */
    private static function approverId(mixed $approvedBy): ?string
    {
        if (is_array($approvedBy)) {
            $approvedBy = $approvedBy['user_id'] ?? null;
        }

        return is_scalar($approvedBy) && $approvedBy !== '' && !is_bool($approvedBy) ? (string) $approvedBy : null;
    }
}
