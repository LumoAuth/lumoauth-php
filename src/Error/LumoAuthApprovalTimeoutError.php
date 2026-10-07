<?php

declare(strict_types=1);

namespace LumoAuth\Error;

class LumoAuthApprovalTimeoutError extends LumoAuthError
{
    public function __construct(string $message = 'Approval timed out.', public readonly mixed $approval = null)
    {
        parent::__construct($message, 'APPROVAL_TIMEOUT');
    }
}
