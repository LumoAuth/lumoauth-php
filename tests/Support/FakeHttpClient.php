<?php

declare(strict_types=1);

namespace LumoAuth\Tests\Support;

use Nyholm\Psr7\Response;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/** In-memory PSR-18 client: queue responses, inspect the requests that were sent. */
final class FakeHttpClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];
    /** @var list<array{0: int, 1: mixed, 2: array<string, string>}|\Throwable> */
    private array $queue = [];

    /** @param array<string, string> $headers */
    public function queue(int $status, mixed $body = null, array $headers = []): self
    {
        $this->queue[] = [$status, $body, $headers];

        return $this;
    }

    public function fail(\Throwable $e): self
    {
        $this->queue[] = $e;

        return $this;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;
        $next = array_shift($this->queue) ?? [200, null, []];
        if ($next instanceof \Throwable) {
            throw $next;
        }
        [$status, $body, $headers] = $next;
        if ($body === null) {
            return new Response($status, $headers, '');
        }
        if (is_string($body)) {
            return new Response($status, $headers, $body);
        }

        return new Response($status, ['Content-Type' => 'application/json'] + $headers, json_encode($body, JSON_THROW_ON_ERROR));
    }

    public function last(): RequestInterface
    {
        return $this->requests[array_key_last($this->requests)];
    }

    /** @return array<string, mixed> */
    public function lastJson(): array
    {
        return (array) json_decode((string) $this->last()->getBody(), true, 512, JSON_THROW_ON_ERROR);
    }
}

final class FakeTransportException extends \RuntimeException implements ClientExceptionInterface
{
}
