<?php

declare(strict_types=1);

namespace LumoAuth\Tests;

use LumoAuth\Error\LumoAuthApiError;
use LumoAuth\Error\LumoAuthAuthenticationError;
use LumoAuth\Error\LumoAuthNotFoundError;
use LumoAuth\Error\LumoAuthPermissionDeniedError;
use LumoAuth\Error\LumoAuthRateLimitError;
use LumoAuth\Error\LumoAuthValidationError;
use LumoAuth\LumoAuth;
use LumoAuth\Resource\AgentMcpToolDecision;
use LumoAuth\Resource\McpToolDecision;

final class McpToolAuthorizationTest extends TestCase
{
    private const SERVER = 'mcp_0123456789abcdef01234567';

    private function server(): LumoAuth
    {
        return $this->client(apiKey: null, tokenProvider: static fn (): string => 'mcp-server-cc-token');
    }

    public function testAuthorizeToolAllowSendsTheContractRequest(): void
    {
        $this->fake->queue(200, ['allowed' => true, 'subject' => ['type' => 'agent', 'id' => 'agt_1'], 'resource' => ['type' => 'mcp_tool', 'id' => self::SERVER . '/search']]);
        $d = $this->server()->mcp->authorizeTool(serverId: self::SERVER, subjectType: 'agent', subjectId: 'agent_agt_1', tool: 'search');

        self::assertInstanceOf(McpToolDecision::class, $d);
        self::assertTrue($d->allowed);
        self::assertSame('agent', $d->subjectType);
        self::assertSame('agt_1', $d->subjectId);
        self::assertSame('mcp_tool', $d->resourceType);
        self::assertSame(self::SERVER . '/search', $d->resourceId);

        $req = $this->fake->last();
        self::assertSame('POST', $req->getMethod());
        self::assertSame('https://auth.acme.test/orgs/acme-corp/api/v1/mcp/servers/' . self::SERVER . '/tools/authorize', (string) $req->getUri());
        self::assertSame('Bearer mcp-server-cc-token', $req->getHeaderLine('Authorization'));
        self::assertSame('application/json', $req->getHeaderLine('Content-Type'));
        self::assertSame(['subject' => ['type' => 'agent', 'id' => 'agent_agt_1'], 'tool' => 'search'], $this->fake->lastJson());
    }

    public function testAuthorizeToolUrlEncodesTheServerId(): void
    {
        $this->fake->queue(200, ['allowed' => true]);
        $d = $this->server()->mcp->authorizeTool('mcp a?b', 'user', 'u-1', 'read_file');
        self::assertSame('/orgs/acme-corp/api/v1/mcp/servers/mcp%20a%3Fb/tools/authorize', $this->fake->last()->getUri()->getPath());
        // Missing fields fall back to the request values.
        self::assertSame(['user', 'u-1', 'mcp a?b/read_file'], [$d->subjectType, $d->subjectId, $d->resourceId]);
    }

    public function testAuthorizeToolDenyIsADecisionNotAnError(): void
    {
        $this->fake->queue(403, ['allowed' => false, 'subject' => ['type' => 'user', 'id' => 'u-1'], 'resource' => ['type' => 'mcp_tool', 'id' => self::SERVER . '/delete']]);
        $d = $this->server()->mcp->authorizeTool(self::SERVER, 'user', 'u-1', 'delete');
        self::assertFalse($d->allowed);
        self::assertSame('u-1', $d->subjectId);
        self::assertSame(self::SERVER . '/delete', $d->resourceId);
    }

    public function testAuthorizeToolErrorsMapToTheErrorClasses(): void
    {
        $cases = [
            [403, ['error' => 'insufficient_scope', 'error_description' => 'mcp:authorize required'], [], LumoAuthPermissionDeniedError::class, 'insufficient_scope'],
            [403, ['error' => 'forbidden'], [], LumoAuthPermissionDeniedError::class, 'forbidden'],
            [401, ['error' => 'invalid_token'], [], LumoAuthAuthenticationError::class, 'invalid_token'],
            [404, ['error' => 'not_found'], [], LumoAuthNotFoundError::class, 'not_found'],
            [400, ['error' => 'invalid_request'], [], LumoAuthApiError::class, 'invalid_request'],
            [429, ['error' => 'too_many_requests'], ['Retry-After' => '7'], LumoAuthRateLimitError::class, 'too_many_requests'],
            [403, ['allowed' => 'false'], [], LumoAuthPermissionDeniedError::class, null],
        ];
        $lumo = $this->server();
        foreach ($cases as [$status, $body, $headers, $class, $code]) {
            $this->fake->queue($status, $body, $headers);
            try {
                $lumo->mcp->authorizeTool(self::SERVER, 'user', 'u-1', 'search');
                self::fail("no exception for $status");
            } catch (LumoAuthApiError $e) {
                self::assertSame($class, $e::class, (string) $status);
                self::assertSame($status, $e->statusCode);
                if ($code !== null) {
                    self::assertSame($code, $e->errorCode);
                }
                if ($e instanceof LumoAuthRateLimitError) {
                    self::assertSame(7.0, $e->retryAfter);
                }
            }
        }
    }

    public function testAuthorizeToolValidatesBeforeSending(): void
    {
        $lumo = $this->server();
        $bad = [
            [self::SERVER, 'service', 'u-1', 'search'],
            [self::SERVER, 'user', '', 'search'],
            ['', 'user', 'u-1', 'search'],
            [self::SERVER, 'user', 'u-1', ''],
            ['https://mcp.example.com/mcp', 'user', 'u-1', 'search'],
            [self::SERVER, 'user', 'u-1', 'files/read'],
            [self::SERVER, 'user', 'u-1', 'files:read'],
            [self::SERVER, 'user', 'u-1', 'read#1'],
            [self::SERVER, 'user', 'u-1', '*'],
            [self::SERVER, 'user', 'u-1', str_repeat('t', 81)],
        ];
        foreach ($bad as $args) {
            try {
                $lumo->mcp->authorizeTool(...$args);
                self::fail('accepted ' . json_encode($args));
            } catch (LumoAuthValidationError) {
            }
        }
        self::assertSame([], $this->fake->requests, 'nothing is sent');

        $this->fake->queue(200, ['allowed' => true]);
        self::assertTrue($lumo->mcp->authorizeTool(self::SERVER, 'user', 'u-1', str_repeat('t', 80))->allowed);
    }

    public function testAgentAuthorizeMcpToolAllow(): void
    {
        $agent = $this->client(apiKey: null, tokenProvider: static fn (): string => 'agk_secret');
        $this->fake->queue(200, ['allowed' => true, 'agent_id' => 'agt_9', 'resource' => ['type' => 'mcp_tool', 'id' => self::SERVER . '/search']]);
        $d = $agent->agents->authorizeMcpTool(serverId: self::SERVER, tool: 'search');

        self::assertInstanceOf(AgentMcpToolDecision::class, $d);
        self::assertTrue($d->allowed);
        self::assertSame('agt_9', $d->agentId);
        self::assertSame('mcp_tool', $d->resourceType);
        self::assertSame(self::SERVER . '/search', $d->resourceId);

        $req = $this->fake->last();
        self::assertSame('POST', $req->getMethod());
        self::assertSame('https://auth.acme.test/orgs/acme-corp/api/v1/agents/me/mcp/authorize', (string) $req->getUri());
        self::assertSame('Bearer agk_secret', $req->getHeaderLine('Authorization'));
        self::assertSame(['server_id' => self::SERVER, 'tool' => 'search'], $this->fake->lastJson());
    }

    public function testAgentAuthorizeMcpToolDenyAndErrors(): void
    {
        $agent = $this->client(apiKey: null, tokenProvider: static fn (): string => 'agent-token');
        $this->fake->queue(403, ['allowed' => false, 'agent_id' => 'agt_9', 'resource' => ['type' => 'mcp_tool', 'id' => self::SERVER . '/drop']]);
        $d = $agent->agents->authorizeMcpTool(self::SERVER, 'drop');
        self::assertFalse($d->allowed);
        self::assertSame('agt_9', $d->agentId);

        $cases = [
            [404, ['error' => 'unknown_server'], LumoAuthNotFoundError::class, 'unknown_server'],
            [403, ['error' => 'agent_required'], LumoAuthPermissionDeniedError::class, 'agent_required'],
            [400, ['error' => 'invalid_request'], LumoAuthApiError::class, 'invalid_request'],
        ];
        foreach ($cases as [$status, $body, $class, $code]) {
            $this->fake->queue($status, $body);
            try {
                $agent->agents->authorizeMcpTool(self::SERVER, 'search');
                self::fail("no exception for $status");
            } catch (LumoAuthApiError $e) {
                self::assertSame($class, $e::class);
                self::assertSame($code, $e->errorCode);
            }
        }
    }

    public function testAgentAuthorizeMcpToolValidatesBeforeSending(): void
    {
        $agent = $this->client(apiKey: null, tokenProvider: static fn (): string => 'agent-token');
        foreach ([['', 'search'], [self::SERVER, ''], ['mcp/x', 'search'], [self::SERVER, 'a*'], [self::SERVER, str_repeat('t', 81)]] as [$server, $tool]) {
            try {
                $agent->agents->authorizeMcpTool($server, $tool);
                self::fail("accepted '$server' '$tool'");
            } catch (LumoAuthValidationError) {
            }
        }
        self::assertSame([], $this->fake->requests);
    }
}
