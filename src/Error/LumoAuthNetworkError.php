<?php

declare(strict_types=1);

namespace LumoAuth\Error;

class LumoAuthNetworkError extends LumoAuthError
{
    public function __construct(string $message, ?\Throwable $cause = null)
    {
        parent::__construct($message, 'NETWORK_ERROR', null, $cause);
    }
}
