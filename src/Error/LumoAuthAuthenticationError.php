<?php

declare(strict_types=1);

namespace LumoAuth\Error;

class LumoAuthAuthenticationError extends LumoAuthApiError
{
    public function __construct(string $message = 'Authentication failed — check your credentials.', string $errorCode = 'AUTHENTICATION_ERROR', int $statusCode = 401, mixed $body = null)
    {
        parent::__construct($message, $errorCode, $statusCode, $body);
    }
}
