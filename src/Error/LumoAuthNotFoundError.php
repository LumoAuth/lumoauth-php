<?php

declare(strict_types=1);

namespace LumoAuth\Error;

class LumoAuthNotFoundError extends LumoAuthApiError
{
    public function __construct(string $message = 'Resource not found.', string $errorCode = 'NOT_FOUND', int $statusCode = 404, mixed $body = null)
    {
        parent::__construct($message, $errorCode, $statusCode, $body);
    }
}
