<?php

declare(strict_types=1);

namespace LumoAuth\Error;

/** Any non-2xx HTTP response. `$body` is the decoded JSON body (or raw text). */
class LumoAuthApiError extends LumoAuthError
{
    public function __construct(
        string $message,
        string $errorCode = 'API_ERROR',
        ?int $statusCode = null,
        public readonly mixed $body = null,
    ) {
        parent::__construct($message, $errorCode, $statusCode);
    }
}
