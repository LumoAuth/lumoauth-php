<?php

declare(strict_types=1);

namespace LumoAuth\Error;

class LumoAuthPermissionDeniedError extends LumoAuthApiError
{
    public function __construct(string $message = 'Permission denied.', string $errorCode = 'PERMISSION_DENIED', int $statusCode = 403, mixed $body = null)
    {
        parent::__construct($message, $errorCode, $statusCode, $body);
    }
}
