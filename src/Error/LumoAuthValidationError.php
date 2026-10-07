<?php

declare(strict_types=1);

namespace LumoAuth\Error;

class LumoAuthValidationError extends LumoAuthError
{
    /** @param list<mixed> $issues */
    public function __construct(string $message, public readonly array $issues = [])
    {
        parent::__construct($message, 'VALIDATION_ERROR');
    }
}
