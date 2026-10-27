<?php

declare(strict_types=1);

namespace LumoAuth\Error;

/**
 * The approval request reached nobody, so it cannot be approved in this call.
 *
 * `$reason` is one of:
 *  - `email_fallback_sent`: the server answered 202. The user has no enrolled push
 *    device (or does not exist; the server answers both cases the same way). An email
 *    notice was sent. It has no approval link, and there is no token to poll.
 *  - `no_enrolled_device`: the server answered 428. The user has no enrolled device,
 *    and the email notice could not be sent.
 */
class LumoAuthApprovalNotDeliveredError extends LumoAuthError
{
    public const REASON_EMAIL_FALLBACK_SENT = 'email_fallback_sent';
    public const REASON_NO_ENROLLED_DEVICE = 'no_enrolled_device';

    public function __construct(
        string $message = 'The approval request was not delivered to a device.',
        public readonly string $reason = self::REASON_EMAIL_FALLBACK_SENT,
        public readonly ?string $taskId = null,
        public readonly mixed $body = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 'APPROVAL_NOT_DELIVERED', null, $previous);
    }
}
