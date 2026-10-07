<?php

declare(strict_types=1);

namespace LumoAuth\Error;

class LumoAuthApprovalDeniedError extends LumoAuthError
{
    public function __construct(string $message = 'Approval denied.', public readonly mixed $approval = null)
    {
        parent::__construct($message, 'APPROVAL_DENIED');
    }
}
