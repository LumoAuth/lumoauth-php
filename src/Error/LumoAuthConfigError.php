<?php

declare(strict_types=1);

namespace LumoAuth\Error;

class LumoAuthConfigError extends LumoAuthError
{
    public function __construct(string $message)
    {
        parent::__construct($message, 'CONFIG_ERROR');
    }
}
