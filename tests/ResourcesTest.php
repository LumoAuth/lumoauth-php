<?php

declare(strict_types=1);

namespace LumoAuth\Tests;

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
        self::assertSame(['permission' => 'document.edit', 'context' => ['ip' => '1.2.3.4'], 'user_id' => 'u1'], $this->fake->lastJson());

        $lumo->permissions->checkBulk(['a', 'b']);
        self::assertSame(['permissions' => ['a', 'b']], $this->fake->lastJson());
        self::assertStringEndsWith('/authz/check-bulk', (string) $this->fake->last()->getUri());

        $this->expectException(LumoAuthValidationError::class);
        $lumo->permissions->checkAny([]);
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
        self::assertSame(['resourceType' => 'document', 'action' => 'read', 'resourceId' => 'd1', 'context' => ['time' => 'night']], $this->fake->lastJson());

        $lumo->abac->checkBulk([['resource_type' => 'doc', 'resource_id' => '1', 'action' => 'read']]);
        self::assertSame(['requests' => [['resourceType' => 'doc', 'resourceId' => '1', 'action' => 'read']]], $this->fake->lastJson());

        self::assertSame([['slug' => 'dept']], $lumo->abac->attributeDefinitions('user'));
        self::assertStringEndsWith('/abac/attribute-definitions?type=user', (string) $this->fake->last()->getUri());
    }

    public function testJitRequestClampsTtlAndBuildsPaths(): void
    {
        $lumo = $this->client();
        $this->fake->queue(200, ['request_id' => 'r1'])->queue(200, ['status' => 'approved'])->queue(200, ['requests' => [['id' => 1]]]);
        $lumo->jit->request('t1', ['type' => 'file_access', 'actions' => ['read']], 'because', ttl: 5000);
        self::assertSame(['task_id' => 't1', 'authorization_details' => ['type' => 'file_access', 'actions' => ['read']], 'requested_ttl' => 900, 'justification' => 'because'], $this->fake->lastJson());
        $lumo->jit->status('r1');
        self::assertStringEndsWith('/orgs/acme-corp/api/v1/jit/request/r1/status', (string) $this->fake->last()->getUri());
        self::assertSame([['id' => 1]], $lumo->jit->pending());
    }

    public function testApprovalsRequireBlocksUntilAnswered(): void
    {
        $lumo = $this->client();
        $sleeps = [];
        $approvals = new Approvals($lumo->http(), static function (float $s) use (&$sleeps): void { $sleeps[] = $s; });
        $this->fake->queue(201, ['approval_token' => 'tok1'])
            ->queue(200, ['status' => 'pending'])
            ->queue(200, ['status' => 'approved', 'approval_token' => 'tok1', 'task_id' => 't1', 'approved_by' => 'alice']);

        $result = $approvals->require('t1', 'Deploy to prod', 'alice@acme.test', 'high', pollIntervalS: 0.01);
        self::assertTrue($result->isApproved());
        self::assertSame('alice', $result->approvedBy);
        self::assertSame([0.01, 0.01], $sleeps);
        self::assertSame(['task_id' => 't1', 'reason' => 'Deploy to prod', 'impact' => 'high', 'on_behalf_of' => 'alice@acme.test', 'meta' => null], json_decode((string) $this->fake->requests[0]->getBody(), true));

        $this->expectException(LumoAuthValidationError::class);
        $approvals->create('t', 'r', 'u', 'extreme');
    }

    public function testMcpTokenExchangesTheCurrentBearerToken(): void
    {
        $lumo = $this->client(tokenProvider: static fn (): string => 'subject-jwt');
        $this->fake->queue(200, ['access_token' => 'mcp-token']);
        self::assertSame('mcp-token', $lumo->mcp->getToken('urn:mcp:finance'));
        parse_str((string) $this->fake->last()->getBody(), $form);
        self::assertSame('urn:ietf:params:oauth:grant-type:token-exchange', $form['grant_type']);
        self::assertSame('subject-jwt', $form['subject_token']);
        self::assertSame('urn:mcp:finance', $form['audience']);
        self::assertFalse($this->fake->last()->hasHeader('Authorization'), 'token endpoints authenticate via the body');

        $this->expectException(LumoAuthConfigError::class);
        $this->client()->mcp->getToken('urn:mcp:finance');
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
