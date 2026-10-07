<?php

declare(strict_types=1);

namespace LumoAuth\AAuth;

use LumoAuth\Error\LumoAuthConfigError;
use LumoAuth\Error\LumoAuthValidationError;

/**
 * RFC 9421 HTTP Message Signatures for the AAuth profile, with Ed25519 via
 * ext-sodium. Byte-compatible with the JS, Python and Go SDKs
 * (sdk-contract/vectors/aauth-rfc9421.json).
 *
 * Covered components, in order: @method @authority @path signature-key
 * content-digest content-type authorization. `@signature-params` carries
 * only `created` and `nonce`. Content-Digest uses standard base64 (the
 * server base64-decodes it); the signature is base64url without padding.
 */
final class Signer
{
    public const COVERED = ['@method', '@authority', '@path', 'signature-key', 'content-digest', 'content-type', 'authorization'];

    /** PKCS#8 DER prefix for an Ed25519 private key (RFC 8410): the 32-byte seed follows. */
    private const PKCS8_ED25519_PREFIX = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20";

    /** @var non-empty-string 64-byte libsodium secret key */
    private readonly string $secretKey;
    /** @var non-empty-string 32-byte public key */
    private readonly string $publicKey;

    /** @param string $privateKey a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) or the raw 32-byte seed */
    public function __construct(string $privateKey)
    {
        if (!function_exists('sodium_crypto_sign_detached')) {
            throw new LumoAuthConfigError('AAuth signing needs ext-sodium.');
        }
        $seed = self::seedFrom($privateKey);
        $pair = sodium_crypto_sign_seed_keypair($seed);
        $this->secretKey = sodium_crypto_sign_secretkey($pair);
        $this->publicKey = sodium_crypto_sign_publickey($pair);
    }

    /**
     * Generate an Ed25519 key pair: [PKCS#8 PEM, JWKS document ready to publish].
     *
     * @return array{0: string, 1: array{keys: list<array<string, string>>}}
     */
    public static function generateKeypair(string $kid = 'key-1'): array
    {
        if (!function_exists('sodium_crypto_sign_keypair')) {
            throw new LumoAuthConfigError('AAuth key generation needs ext-sodium.');
        }
        $pair = sodium_crypto_sign_keypair();
        $seed = substr(sodium_crypto_sign_secretkey($pair), 0, 32);
        $pem = "-----BEGIN PRIVATE KEY-----\n" . chunk_split(base64_encode(self::PKCS8_ED25519_PREFIX . $seed), 64, "\n") . "-----END PRIVATE KEY-----\n";

        return [$pem, ['keys' => [self::jwk(sodium_crypto_sign_publickey($pair), $kid)]]];
    }

    /** @return array<string, string> public JWK (`kty` OKP, `crv` Ed25519) */
    public function publicJwk(string $kid = 'key-1'): array
    {
        return self::jwk($this->publicKey, $kid);
    }

    public static function contentDigest(string $body): string
    {
        return 'sha-256=:' . base64_encode(hash('sha256', $body, true)) . ':';
    }

    /**
     * Signature headers for a request: Content-Digest, Content-Type,
     * Signature-Input, Signature and (when given) Agent-Auth.
     *
     * @return array<string, string>
     */
    public function sign(
        string $method,
        string $url,
        string $body = '',
        string $contentType = 'application/json',
        ?string $agentToken = null,
        string $authorization = '',
        string $signatureKey = '',
        ?int $created = null,
        ?string $nonce = null,
    ): array {
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['host'])) {
            throw new LumoAuthValidationError("Cannot sign request: invalid URL '$url'.");
        }
        $authority = $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        $path = ($parts['path'] ?? '') !== '' ? $parts['path'] : '/';
        $created ??= time();
        $nonce ??= self::base64url(random_bytes(16)); // ≥ 12 bytes of entropy
        $digest = self::contentDigest($body);

        $values = [
            '@method' => strtoupper($method),
            '@authority' => $authority,
            '@path' => $path,
            'signature-key' => $signatureKey,
            'content-digest' => $digest,
            'content-type' => $contentType,
            'authorization' => $authorization,
        ];
        $params = self::signatureParams($created, $nonce);
        $base = self::signatureBase($values, $params);
        $signature = sodium_crypto_sign_detached($base, $this->secretKey);

        $headers = [
            'Content-Digest' => $digest,
            'Content-Type' => $contentType,
            'Signature-Input' => 'sig1=' . $params,
            'Signature' => 'sig1=:' . self::base64url($signature) . ':',
        ];
        if ($agentToken !== null && $agentToken !== '') {
            $headers['Agent-Auth'] = 'agent_token=' . $agentToken;
        }

        return $headers;
    }

    /** The `(…);created=…;nonce="…"` parameter string shared by Signature-Input and the base. */
    public static function signatureParams(int $created, string $nonce): string
    {
        $list = implode(' ', array_map(static fn (string $c): string => '"' . $c . '"', self::COVERED));

        return '(' . $list . ');created=' . $created . ';nonce="' . $nonce . '"';
    }

    /** @param array<string, string> $values component values keyed by component name */
    public static function signatureBase(array $values, string $params): string
    {
        $lines = [];
        foreach (self::COVERED as $component) {
            $lines[] = '"' . $component . '": ' . ($values[$component] ?? '');
        }
        $lines[] = '"@signature-params": ' . $params;

        return implode("\n", $lines);
    }

    public static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function seedFrom(string $privateKey): string
    {
        if (strlen($privateKey) === 32) {
            return $privateKey;
        }
        if (str_contains($privateKey, 'BEGIN PRIVATE KEY')) {
            $der = base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $privateKey), true);
            if ($der !== false && str_starts_with($der, self::PKCS8_ED25519_PREFIX) && strlen($der) === 48) {
                return substr($der, 16, 32);
            }
            throw new LumoAuthValidationError('Private key must be a PKCS#8 Ed25519 key.');
        }
        throw new LumoAuthValidationError('Private key must be a PKCS#8 PEM or a 32-byte Ed25519 seed.');
    }

    /** @return array<string, string> */
    private static function jwk(string $publicKey, string $kid): array
    {
        return ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => self::base64url($publicKey), 'use' => 'sig', 'kid' => $kid];
    }
}
