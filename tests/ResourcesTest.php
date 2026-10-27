<?php

declare(strict_types=1);

namespace LumoAuth\Tests;

use LumoAuth\Error\LumoAuthApprovalNotDeliveredError;
use LumoAuth\Error\LumoAuthConfigError;
use LumoAuth\Error\LumoAuthValidationError;
use LumoAuth\Resource\Approvals;
use LumoAuth\Resource\Delegation;

final class ResourcesTest extends TestCase
{
    public function testPermissionsCheckAndBulk(): void
    {
        $lumo = $this->client();
        $this->fake->queue(200, ['allowed' => true])->queue(200, ['results' => []]);
        self::assertTrue($lumo->permissions->check('document.edit', ['ip' => '1.2.3.4'], userId: 'u1'));
        self::assertSame('https://auth.acme.test/api/v1/authz/check', (string) $this->fake->last()->getUri());
        self::assertSame(['permission' => 'document.edit', 'context' => ['ip' => '1.2.3.4'], 'subject' => ['type' => 'user', 'id' => 'u1']], $this->fake->lastJson());

        $lumo->permissions->checkBulk(['a', 'b']);
        self::assertSame(['permissions' => ['a', 'b']], $this->fake->lastJson());
        self::assertStringEndsWith('/authz/check-bulk', (string) $this->fake->last()->getUri());

        $this->expectException(LumoAuthValidationError::class);
        $lumo->permissions->checkAny([]);
    }

    public function testPermissionChecksSendTheSubjectObjectAndNeverUserId(): void
    {
        $lumo = $this->client();
        $uuid = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b';
        $this->fake->queue(200, ['results' => []])->queue(200, ['allowed' => true])->queue(200, ['allowed' => false])->queue(200, ['allowed' => true]);

        $lumo->permissions->checkBulk(['a', 'b'], userId: $uuid);
        self::assertSame(['permissions' => ['a', 'b'], 'subject' => ['type' => 'user', 'id' => $uuid]], $this->fake->lastJson());

        self::assertTrue($lumo->permissions->checkAny(['a'], userId: $uuid));
        self::assertSame(['type' => 'user', 'id' => $uuid], $this->fake->lastJson()['subject']);
        self::assertArrayNotHasKey('user_id', $this->fake->lastJson());
        self::assertStringEndsWith('/authz/check-any', (string) $this->fake->last()->getUri());

        self::assertFalse($lumo->permissions->checkAll(['a', 'b'], userId: $uuid));
        self::assertSame(['permissions' => ['a', 'b'], 'subject' => ['type' => 'user', 'id' => $uuid]], $this->fake->lastJson());
        self::assertStringEndsWith('/authz/check-all', (string) $this->fake->last()->getUri());

        self::assertTrue($lumo->permissions->check('a', agentId: 'agt_123'));
        self::assertSame(['permission' => 'a', 'subject' => ['type' => 'agent', 'id' => 'agt_123']], $this->fake->lastJson());

        $this->expectException(LumoAuthValidationError::class);
        $lumo->permissions->check('a', userId: $uuid, agentId: 'agt_123');
    }

    public function testPermissionsListSlugs(): void
    {
        $this->fake->queue(200, ['permissions' => [['slug' => 'a'], ['slug' => 'b'], ['nope' => 1]]]);
        self::assertSame(['a', 'b'], $this->client()->permissions->listSlugs());
    }

    public function testZanzibarValidatesTuplesAndExpandsTree(): void
    {
        $lumo = $this->client();
        $this->fake->queue(200, ['allowed' => true])->queue(200, ['tree' => ['type' => 'leaf']]);
        self::assertTrue($lumo->zanzibar->isViewer('document:1', 'user:bob'));
        self::assertSame(['object' => 'document:1', 'relation' => 'viewer', 'subject' => 'user:bob'], $this->fake->lastJson());
        self::assertSame(['type' => 'leaf'], $lumo->zanzibar->expand('document:1', 'viewer'));

        $this->expectException(LumoAuthValidationError::class);
        $lumo->zanzibar->check('document', 'viewer', 'user:bob');
    }

    public function testAbacUsesCamelCaseOnTheWire(): void
    {
        $lumo = $this->client();
        $this->fake->queue(200, ['allowed' => false, 'reason' => 'no'])->queue(200, ['results' => []])->queue(200, ['data' => [['slug' => 'dept']]]);
        self::assertFalse($lumo->abac->isAllowed('document', 'read', 'd1', ['time' => 'night']));
        self::assertSame(['resourceType' => 'document', 'action' => 'read', 'resourceId' => 'd1', 'environment' => ['time' => 'night']], $this->fake->lastJson());

        $lumo->abac->checkBulk([['resource_type' => 'doc', 'resource_id' => '1', 'action' => 'read']]);
        self::assertSame(['checks' => [['resourceType' => 'doc', 'resourceId' => '1', 'action' => 'read']]], $this->fake->lastJson());

        self::assertSame([['slug' => 'dept']], $lumo->abac->attributeDefinitions('user'));
        self::assertStringEndsWith('/abac/attribute-definitions?type=user', (string) $this->fake->last()->getUri());
    }

    public function testAbacBulkSendsOneSharedEnvironment(): void
    {
        $lumo = $this->client();
        $this->fake->queue(200, ['results' => []])->queue(200, ['results' => []]);

        $lumo->abac->checkBulk([['resourceType' => 'doc', 'action' => 'read'], ['resourceType' => 'doc', 'action' => 'edit']], ['pep' => ['ip' => '10.0.0.8']]);
        self::assertSame([
            'checks' => [['resourceType' => 'doc', 'action' => 'read'], ['resourceType' => 'doc', 'action' => 'edit']],
            'environment' => ['pep' => ['ip' => '10.0.0.8']],
        ], $this->fake->lastJson());

        $lumo->abac->checkBulk([
            ['resourceType' => 'doc', 'action' => 'read', 'context' => ['time' => 'night']],
            ['resourceType' => 'doc', 'action' => 'edit', 'context' => ['time' => 'night']],
        ]);
        self::assertSame([
            'checks' => [['resourceType' => 'doc', 'action' => 'read'], ['resourceType' => 'doc', 'action' => 'edit']],
            'environment' => ['time' => 'night'],
        ], $this->fake->lastJson());
    }

    public function testAbacBulkRefusesDifferentContexts(): void
    {
        $lumo = $this->client();
        foreach ([
            [[['resourceType' => 'd', 'action' => 'r', 'context' => ['a' => 1]], ['resourceType' => 'd', 'action' => 'r', 'context' => ['a' => 2]]], null],
            [[['resourceType' => 'd', 'action' => 'r', 'context' => ['a' => 1]], ['resourceType' => 'd', 'action' => 'r']], null],
            [[['resourceType' => 'd', 'action' => 'r', 'context' => ['a' => 1]]], ['a' => 2]],
        ] as [$checks, $environment]) {
            try {
                $lumo->abac->checkBulk($checks, $environment);
                self::fail('expected LumoAuthValidationError');
            } catch (LumoAuthValidationError $e) {
                self::assertStringContainsString('one environment to every check', $e->getMessage());
            }
        }
        self::assertSame([], $this->fake->requests, 'nothing is sent when the contexts differ');
    }

    public function testJitRequestClampsTtlAndBuildsPaths(): void
    {
        $lumo = $this->client();
        $this->fake->queue(200, ['request_id' => 'r1'])->queue(200, ['status' => 'approved'])->queue(200, ['pending_requests' => [['id' => 1]], 'count' => 1, 'data' => [['id' => 1]], 'pagination' => ['page' => 1, 'limit' => 20, 'total' => 1]])
            ->queue(200, ['pending_requests' => [['id' => 2]], 'count' => 1])
            ->queue(200, ['count' => 0, 'pagination' => []]);
        $lumo->jit->request('t1', ['type' => 'file_access', 'actions' => ['read']], 'because', ttl: 5000);
        self::assertSame(['task_id' => 't1', 'authorization_details' => ['type' => 'file_access', 'actions' => ['read']], 'requested_ttl' => 900, 'justification' => 'because'], $this->fake->lastJson());
        $lumo->jit->status('r1');
        self::assertStringEndsWith('/orgs/acme-corp/api/v1/jit/request/r1/status', (string) $this->fake->last()->getUri());
        self::assertSame([['id' => 1]], $lumo->jit->pending(), 'reads data, not the reply values');
        self::assertSame([['id' => 2]], $lumo->jit->pending(), 'falls back to pending_requests');
        self::assertSame([], $lumo->jit->pending());
    }

    public function testApprovalsRequireBlocksUntilAnswered(): void
    {
        $lumo = $this->client();
        $sleeps = [];
        $approvals = new Approvals($lumo->http(), static function (float $s) use (&$sleeps): void { $sleeps[] = $s; });
        $this->fake->queue(201, ['approval_token' => 'tok1'])
            ->queue(200, ['status' => 'pending'])
            ->queue(200, ['status' => 'approved', 'approval_token' => 'tok1', 'task_id' => 't1', 'approved_by' => ['user_id' => 42]]);

        $result = $approvals->require('t1', 'Deploy to prod', 'alice@acme.test', 'high', pollIntervalS: 0.01);
        self::assertTrue($result->isApproved());
        self::assertSame('42', $result->approvedBy, 'approved_by.user_id as a string');
        self::assertSame([0.01, 0.01], $sleeps);
        self::assertSame(['task_id' => 't1', 'reason' => 'Deploy to prod', 'impact' => 'high', 'on_behalf_of' => 'alice@acme.test', 'meta' => null], json_decode((string) $this->fake->requests[0]->getBody(), true));

        $this->expectException(LumoAuthValidationError::class);
        $approvals->create('t', 'r', 'u', 'extreme');
    }

    public function testApprovedByAcceptsAScalarAndNull(): void
    {
        $lumo = $this->client();
        $approvals = new Approvals($lumo->http(), static function (float $s): void {});
        $this->fake->queue(201, ['approval_token' => 'tok1'])->queue(200, ['status' => 'approved', 'approved_by' => 7])
            ->queue(201, ['approval_token' => 'tok2'])->queue(200, ['status' => 'denied', 'approved_by' => null]);
        self::assertSame('7', $approvals->require('t1', 'r', 'u')->approvedBy);
        self::assertNull($approvals->require('t2', 'r', 'u')->approvedBy);
    }

    public function testApprovalCreateReturnsEmailFallbackWithoutToken(): void
    {
        $lumo = $this->client();
        $this->fake->queue(202, ['status' => 'email_fallback_sent', 'message' => 'Check your email', 'task_id' => 't1', 'impact' => 'high']);
        $created = $lumo->approvals->create('t1', 'Deploy', 'alice@acme.test', 'high');
        self::assertSame('email_fallback_sent', $created['status']);
        self::assertArrayHasKey('approval_token', $created);
        self::assertNull($created['approval_token']);
        self::assertSame('t1', $created['task_id']);
    }

    public function testApprovalRequireRaisesOnEmailFallbackWithoutPolling(): void
    {
        $lumo = $this->client();
        $approvals = new Approvals($lumo->http(), static function (float $s): void { self::fail('must not sleep/poll'); });
        $this->fake->queue(202, ['status' => 'email_fallback_sent', 'message' => 'Check your email', 'task_id' => 't1', 'impact' => 'high']);
        try {
            $approvals->require('t1', 'Deploy', 'alice@acme.test', 'high');
            self::fail('expected LumoAuthApprovalNotDeliveredError');
        } catch (LumoAuthApprovalNotDeliveredError $e) {
            self::assertSame('email_fallback_sent', $e->reason);
            self::assertSame('t1', $e->taskId);
            self::assertSame('APPROVAL_NOT_DELIVERED', $e->errorCode);
            self::assertSame('Check your email', $e->getMessage());
        }
        self::assertCount(1, $this->fake->requests, 'no status request');
    }

    public function testApprovalNoEnrolledDeviceRaisesFromCreateAndRequire(): void
    {
        $lumo = $this->client();
        $approvals = new Approvals($lumo->http(), static function (float $s): void { self::fail('must not poll'); });
        $body = ['error' => 'no_enrolled_device', 'message' => 'No device and the email failed'];
        $this->fake->queue(428, $body)->queue(428, $body);
        foreach (['create', 'require'] as $method) {
            try {
                $approvals->{$method}('t1', 'Deploy', 'alice@acme.test');
                self::fail("$method: expected LumoAuthApprovalNotDeliveredError");
            } catch (LumoAuthApprovalNotDeliveredError $e) {
                self::assertSame('no_enrolled_device', $e->reason, $method);
                self::assertSame('t1', $e->taskId);
                self::assertSame($body, $e->body);
                self::assertSame('No device and the email failed', $e->getMessage());
            }
        }
        self::assertCount(2, $this->fake->requests);
    }

    public function testMcpTokenIsBoundToTheServerUrl(): void
    {
        $lumo = $this->client(tokenProvider: static fn (): string => 'subject-jwt');
        $this->fake->queue(200, ['access_token' => 'mcp-token']);
        self::assertSame('mcp-token', $lumo->mcp->getToken('https://mcp.example.com/mcp'));
        parse_str((string) $this->fake->last()->getBody(), $form);
        self::assertSame('urn:ietf:params:oauth:grant-type:token-exchange', $form['grant_type']);
        self::assertSame('subject-jwt', $form['subject_token']);
        self::assertSame('https://mcp.example.com/mcp', $form['resource'], 'resource sets aud');
        self::assertSame('https://mcp.example.com/mcp', $form['audience']);
        self::assertFalse($this->fake->last()->hasHeader('Authorization'), 'token endpoints authenticate via the body');

        $this->expectException(LumoAuthConfigError::class);
        $this->client()->mcp->getToken('https://mcp.example.com/mcp');
    }

    public function testMcpRejectsServerIdsThatAreNotUrls(): void
    {
        $lumo = $this->client(tokenProvider: static fn (): string => 'subject-jwt');
        foreach (['urn:mcp:finance', 'mcp.example.com/mcp', 'ftp://mcp.example.com', 'https://mcp.example.com/mcp#x', ''] as $bad) {
            try {
                $lumo->mcp->getToken($bad);
                self::fail("accepted '$bad'");
            } catch (LumoAuthValidationError $e) {
                self::assertStringContainsString('https://mcp.example.com/mcp', $e->getMessage());
            }
        }
        self::assertSame([], $this->fake->requests, 'nothing is sent');
    }

    public function testAuthUrlsAndGrants(): void
    {
        $lumo = $this->client();
        $url = $lumo->auth->authorizationUrl('cid', 'https://app/cb', state: 's1', codeChallenge: 'abc');
        self::assertSame('https://auth.acme.test/orgs/acme-corp/api/v1/oauth/authorize?response_type=code&client_id=cid&redirect_uri=https%3A%2F%2Fapp%2Fcb&scope=openid%20profile%20email&state=s1&code_challenge=abc&code_challenge_method=S256', $url);

        $this->fake->queue(200, ['access_token' => 'at'])->queue(200, ['sub' => 'u1']);
        $lumo->auth->clientCredentials('cid', 'sec', ['read']);
        parse_str((string) $this->fake->last()->getBody(), $form);
        self::assertSame(['grant_type' => 'client_credentials', 'client_id' => 'cid', 'client_secret' => 'sec', 'scope' => 'read'], $form);
        self::assertSame(['sub' => 'u1'], $lumo->auth->userinfo('explicit'));
        self::assertSame('Bearer explicit', $this->fake->last()->getHeaderLine('Authorization'));
    }

    public function testTokenExchangeDeclaresTheTokenTypes(): void
    {
        $lumo = $this->client();
        $this->fake->queue(200, ['access_token' => 'x'])->queue(200, ['access_token' => 'y']);

        $lumo->auth->tokenExchange('subject', 'actor', 'https://mcp.example.com/mcp', ['read']);
        parse_str((string) $this->fake->last()->getBody(), $form);
        self::assertSame(\LumoAuth\Resource\Auth::ACCESS_TOKEN_TYPE, $form['subject_token_type'], 'access_token is the default');
        self::assertSame(\LumoAuth\Resource\Auth::ACCESS_TOKEN_TYPE, $form['actor_token_type']);

        // An ID token (or workload JWT) is declared as such; the actor default stays access_token.
        $lumo->auth->tokenExchange('id-token', 'actor', subjectTokenType: \LumoAuth\Resource\Auth::ID_TOKEN_TYPE);
        parse_str((string) $this->fake->last()->getBody(), $form);
        self::assertSame('urn:ietf:params:oauth:token-type:id_token', $form['subject_token_type']);
        self::assertSame('urn:ietf:params:oauth:token-type:access_token', $form['actor_token_type']);
        self::assertArrayNotHasKey('resource', $form, 'no resource unless asked');
    }

    public function testDelegationExchangeSendsTheResourceIndicator(): void
    {
        $lumo = $this->client();
        $this->fake->queue(200, ['access_token' => 'delegated']);

        $lumo->delegation->exchange('user-token', 'agent-token', ['read'], resource: 'https://api.example.com');
        parse_str((string) $this->fake->last()->getBody(), $form);
        self::assertSame('https://api.example.com', $form['resource']);
        self::assertSame('agent-token', $form['actor_token']);
        self::assertSame('read', $form['scope']);
    }

    public function testAgentsRegisterAndCapabilities(): void
    {
        $lumo = $this->client();
        $this->fake->queue(201, ['id' => 'a1'])->queue(200, ['capabilities' => ['read:docs', 7], 'budget_policy' => ['max' => 1]]);
        $lumo->agents->register('Bot', 'cid', capabilities: ['read:docs']);
        self::assertSame(['client_id' => 'cid', 'name' => 'Bot', 'capabilities' => ['read:docs']], $this->fake->lastJson());
        self::assertSame(['read:docs'], $lumo->agents->capabilities());
    }

    public function testDelegationChainParsing(): void
    {
        $payload = static fn (array $claims): string => 'h.' . rtrim(strtr(base64_encode(json_encode($claims)), '+/', '-_'), '=') . '.s';
        $jwt = $payload(['sub' => 'user:alice', 'act' => ['sub' => 'agent:a', 'act' => ['sub' => 'agent:b']]]);
        self::assertSame(['agent:a', 'agent:b'], Delegation::parseActorChain($jwt));
        self::assertSame('user:alice', Delegation::subject($jwt));
        self::assertSame([], Delegation::parseActorChain('garbage'));

        $lumo = $this->client();
        self::assertStringContainsString('prompt=consent&access_type=offline', $lumo->delegation->consentUrl('cid', 'https://app/cb', ['read:documents']));
    }
}
