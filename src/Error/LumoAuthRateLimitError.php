<?php

declare(strict_types=1);

namespace LumoAuth\Error;

class LumoAuthRateLimitError extends LumoAuthApiError
{
    public function __construct(
        string $message = 'Rate limited — retry later.',
        string $errorCode = 'RATE_LIMITED',
        int $statusCode = 429,
        mixed $body = null,
        public readonly ?float $retryAfter = null,
    ) {
        parent::__construct($message, $errorCode, $statusCode, $body);
    }
}
