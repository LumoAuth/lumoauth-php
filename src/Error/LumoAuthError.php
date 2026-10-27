<?php

declare(strict_types=1);

namespace LumoAuth\Error;

/**
 * Root of the LumoAuth error taxonomy (sdk-contract/errors.json), mirrored
 * 1:1 by the JS, Python and Go SDKs:
 *
 *   LumoAuthError                              LUMOAUTH_ERROR
 *   ├── LumoAuthApiError                       API_ERROR (any 4xx/5xx)
 *   │   ├── LumoAuthAuthenticationError        AUTHENTICATION_ERROR (401)
 *   │   ├── LumoAuthPermissionDeniedError      PERMISSION_DENIED (403, requiredScopes)
 *   │   ├── LumoAuthNotFoundError              NOT_FOUND (404)
 *   │   └── LumoAuthRateLimitError             RATE_LIMITED (429)
 *   ├── LumoAuthValidationError                VALIDATION_ERROR
 *   ├── LumoAuthConfigError                    CONFIG_ERROR
 *   ├── LumoAuthNetworkError                   NETWORK_ERROR
 *   ├── LumoAuthApprovalDeniedError            APPROVAL_DENIED
 *   ├── LumoAuthApprovalTimeoutError           APPROVAL_TIMEOUT
 *   ├── LumoAuthApprovalNotDeliveredError      APPROVAL_NOT_DELIVERED (202 email fallback / 428; $reason)
 *   └── LumoAuthBudgetExceededError            BUDGET_EXCEEDED
 */
class LumoAuthError extends \RuntimeException
{
    public function __construct(
        string $message,
        public readonly string $errorCode = 'LUMOAUTH_ERROR',
        public readonly ?int $statusCode = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $statusCode ?? 0, $previous);
    }
}
