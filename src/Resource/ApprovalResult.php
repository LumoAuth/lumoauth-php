<?php

declare(strict_types=1);

namespace LumoAuth\Resource;

/** Outcome of Approvals::require(): the same fields as Python's ApprovalResult. */
final class ApprovalResult
{
    public function __construct(
        public readonly string $status,
        public readonly string $token,
        public readonly string $taskId,
        public readonly ?string $impact = null,
        public readonly ?string $reason = null,
        public readonly ?string $respondedAt = null,
        /** LumoAuth user ID of the approver (`approved_by.user_id`), null unless approved. */
        public readonly ?string $approvedBy = null,
    ) {
    }

    public function isApproved(): bool
    {
        return $this->status === 'approved';
    }
}
