<?php

declare(strict_types=1);

namespace LumoAuth\Error;

class LumoAuthBudgetExceededError extends LumoAuthError
{
    public function __construct(string $message = 'Budget exceeded.', public readonly mixed $budget = null)
    {
        parent::__construct($message, 'BUDGET_EXCEEDED');
    }
}
