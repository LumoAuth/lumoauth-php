<?php

declare(strict_types=1);

namespace LumoAuth\Tests;

use LumoAuth\AAuth\AAuthClient;
use LumoAuth\AAuth\Signer;
use LumoAuth\Tests\Support\ContractFiles;

/**
 * RFC 9421 conformance against the shared vector (sdk-contract/vectors/
 * aauth-rfc9421.json, produced by the Python SDK). Ed25519 is deterministic,
 * so the signature must match byte for byte. The vector is embedded so the
 * suite is meaningful in a standalone checkout; when the contract is present
 * the embedded copy is asserted equal to it.
 */
final class SignerTest extends TestCase
{
    private const VECTOR = [
        'private_key_pem' => "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n-----END PRIVATE KEY-----\n",
        'public_jwk_x' => 'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg',
        'url' => 'https://auth.acme.test/orgs/acme-corp/api/v1/aauth/agent/token',
        'body' => '{"request_type": "auth", "resource_token": "RESOURCE_TOKEN_FIXED", "scope": "read write"}',
        'created' => 1750000000,
        'nonce' => 'AAECAwQFBgcICQoLDA0ODw',
        'agent_token' => 'AGENT_TOKEN_FIXED',
        'content_digest' => 'sha-256=:maoKTEBGVoe/uXlHmt4EeWj7K7xo71Ag/qIPObi3vPw=:',
        'signature_input' => 'sig1=("@method" "@authority" "@path" "signature-key" "content-digest" "content-type" "authorization");created=1750000000;nonce="AAECAwQFBgcICQoLDA0ODw"',
        'signature' => 'sig1=:sr5ZGEA2-LkKN4RvFrpYxhaGPB-tf1STvf1W0bl_UAFt1Rjn_wKKCouOHsFamkDAf85UpwF_HOJXLs07-bynCw:',
    ];

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        if (!function_exists('sodium_crypto_sign_detached')) {
            self::markTestSkipped('ext-sodium missing');
        }
    }

    public function testEmbeddedVectorMatchesTheContract(): void
    {
        if (ContractFiles::dir() === null) {
            self::markTestSkipped('sdk-contract not found');
        }
        $v = ContractFiles::load('vectors/aauth-rfc9421.json');
        self::assertSame(self::VECTOR['private_key_pem'], $v['private_key_pem']);
        self::assertSame(self::VECTOR['body'], $v['request']['body']);
        self::assertSame(self::VECTOR['signature'], $v['expected']['signature']);
        self::assertSame(self::VECTOR['signature_input'], $v['expected']['signature_input']);
        self::assertSame(Signer::COVERED, $v['covered_components']);
    }

    public function testSignReproducesThePythonSignatureByteForByte(): void
    {
        $signer = new Signer(self::VECTOR['private_key_pem']);
        $headers = $signer->sign('POST', self::VECTOR['url'], self::VECTOR['body'], agentToken: self::VECTOR['agent_token'], created: self::VECTOR['created'], nonce: self::VECTOR['nonce']);

        self::assertSame(self::VECTOR['content_digest'], $headers['Content-Digest']);
        self::assertSame('application/json', $headers['Content-Type']);
        self::assertSame(self::VECTOR['signature_input'], $headers['Signature-Input']);
        self::assertSame(self::VECTOR['signature'], $headers['Signature']);
        self::assertSame('agent_token=AGENT_TOKEN_FIXED', $headers['Agent-Auth']);
        self::assertSame(self::VECTOR['public_jwk_x'], $signer->publicJwk()['x']);
    }

    public function testSeedAndPemAreInterchangeableAndGeneratedKeysRoundTrip(): void
    {
        $seed = hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
        self::assertSame((new Signer(self::VECTOR['private_key_pem']))->publicJwk(), (new Signer((string) $seed))->publicJwk());

        [$pem, $jwks] = Signer::generateKeypair('k2');
        $signer = new Signer($pem);
        self::assertSame($jwks['keys'][0], $signer->publicJwk('k2'));
        self::assertSame('Ed25519', $jwks['keys'][0]['crv']);
        $headers = $signer->sign('GET', 'https://rs.test/x');
        self::assertStringStartsWith('sig1=:', $headers['Signature']);
        self::assertMatchesRegularExpression('/;created=\d+;nonce="[A-Za-z0-9_-]{22}"$/', $headers['Signature-Input']);
    }

    public function testAAuthClientSignsTheExactBytesItSends(): void
    {
        $lumo = $this->client(apiKey: null);
        $aauth = new AAuthClient(self::VECTOR['private_key_pem'], $lumo->http(), 'acme-corp');
        $this->fake->queue(401, ['auth_url' => 'https://auth/consent', 'request_token' => 'rt'])->queue(200, ['access_token' => 'at']);

        $consent = $aauth->requestAuthorization('RESOURCE_TOKEN', 'read', agentToken: 'AGENT');
        self::assertSame(['authorization_required' => true, 'auth_url' => 'https://auth/consent', 'request_token' => 'rt'], $consent);
        $req = $this->fake->last();
        self::assertSame('https://auth.acme.test/orgs/acme-corp/api/v1/aauth/agent/token', (string) $req->getUri());
        self::assertSame('agent_token=AGENT', $req->getHeaderLine('Agent-Auth'));
        self::assertSame(Signer::contentDigest((string) $req->getBody()), $req->getHeaderLine('Content-Digest'), 'digest covers the bytes on the wire');
        self::assertFalse($req->hasHeader('X-API-Key'));

        self::assertSame(['access_token' => 'at'], $aauth->refresh('rt', 'RESOURCE_TOKEN', 'AGENT'));
        self::assertSame(['request_type' => 'refresh', 'refresh_token' => 'rt', 'resource_token' => 'RESOURCE_TOKEN'], $this->fake->lastJson());
    }

    public function testSignedRequestCoversTheBearerToken(): void
    {
        $aauth = new AAuthClient(self::VECTOR['private_key_pem'], $this->client(apiKey: null)->http());
        $this->fake->queue(200, ['ok' => true]);
        $response = $aauth->signedRequest('POST', 'https://rs.test/orgs/acme/api/v1/documents', 'ACCESS', ['a' => 1]);
        self::assertSame(200, $response->getStatusCode());
        $req = $this->fake->last();
        self::assertSame('Bearer ACCESS', $req->getHeaderLine('Authorization'));
        self::assertSame('{"a":1}', (string) $req->getBody());
        self::assertStringContainsString('"authorization"', $req->getHeaderLine('Signature-Input'));
    }
}
