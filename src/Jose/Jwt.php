<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Jose;

use OpenSSLAsymmetricKey;

/**
 * A signed JSON Web Token (RFC 7519, JWS compact form), read and checked
 * with OpenSSL. Only asymmetric signatures are taken — RS256/384/512 and
 * ES256/384/512 —, never `none` and never HMAC: a shared secret would let
 * anyone who knows it, the client included, mint tokens.
 */
final readonly class Jwt
{
    /** The longest compact token read, in bytes. */
    public const int MAX_LENGTH = 16384;

    /** The curve each ECDSA algorithm is defined on (RFC 7518, 3.4). */
    private const array CURVES = ['ES256' => 'P-256', 'ES384' => 'P-384', 'ES512' => 'P-521'];

    private const array ALGORITHMS = [
        'RS256' => ['RSA', OPENSSL_ALGO_SHA256],
        'RS384' => ['RSA', OPENSSL_ALGO_SHA384],
        'RS512' => ['RSA', OPENSSL_ALGO_SHA512],
        'ES256' => ['EC', OPENSSL_ALGO_SHA256],
        'ES384' => ['EC', OPENSSL_ALGO_SHA384],
        'ES512' => ['EC', OPENSSL_ALGO_SHA512],
    ];

    /**
     * @param  array<string, mixed>  $header
     * @param  array<string, mixed>  $claims
     */
    private function __construct(
        public array $header,
        public array $claims,
        private string $signed,
        private string $signature,
    ) {}

    /** The token's parts, or null when it is not a well-formed JWS. */
    public static function parse(string $token): ?self
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3 || strlen($token) > self::MAX_LENGTH) {
            return null;
        }
        $header = self::json($parts[0]);
        $claims = self::json($parts[1]);
        $signature = self::decode($parts[2]);
        if ($header === null || $claims === null || $signature === null || $signature === '') {
            return null;
        }

        return new self($header, $claims, $parts[0].'.'.$parts[1], $signature);
    }

    /** Whether a compact token looks like a JWT at all: three base64url parts. */
    public static function looksLikeOne(string $token): bool
    {
        return preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $token) === 1;
    }

    /** The header's algorithm when it is one taken; null for `none`, HMAC and the unknown. */
    public function algorithm(): ?string
    {
        $alg = $this->header['alg'] ?? null;

        return is_string($alg) && isset(self::ALGORITHMS[$alg]) ? $alg : null;
    }

    public function keyId(): ?string
    {
        $kid = $this->header['kid'] ?? null;

        return is_string($kid) && $kid !== '' ? $kid : null;
    }

    /**
     * Whether the signature is the key's, by the token's algorithm. The key
     * must be of the kind the algorithm names, must not name another
     * algorithm or a use other than `sig`, and an EC key must be on the
     * algorithm's own curve.
     *
     * @param  array<string, mixed>  $jwk
     */
    public function signedBy(array $jwk): bool
    {
        $algorithm = $this->algorithm();
        if ($algorithm === null) {
            return false;
        }
        [$kind, $hash] = self::ALGORITHMS[$algorithm];
        if (($jwk['kty'] ?? null) !== $kind || (isset($jwk['alg']) && $jwk['alg'] !== $algorithm) || (isset($jwk['use']) && $jwk['use'] !== 'sig')) {
            return false;
        }
        $key = Jwk::publicKey($jwk);
        if (! $key instanceof OpenSSLAsymmetricKey) {
            return false;
        }
        $signature = $this->signature;
        if ($kind === 'EC') {
            // ES256 is P-256 with SHA-256, never another pair: OpenSSL alone would verify a P-256 key with SHA-384.
            if (($jwk['crv'] ?? null) !== self::CURVES[$algorithm]) {
                return false;
            }
            $size = Jwk::coordinateSize(self::CURVES[$algorithm]);
            $der = $size === null ? null : self::ecdsaDer($signature, $size);
            if ($der === null) {
                return false;
            }
            $signature = $der;
        }

        return openssl_verify($this->signed, $signature, $key, $hash) === 1;
    }

    /** Base64url without padding, as JOSE writes it; null when it is not. */
    public static function decode(string $text): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]*$/', $text) !== 1) {
            return null;
        }
        $decoded = base64_decode(strtr($text, '-_', '+/').str_repeat('=', (4 - strlen($text) % 4) % 4), true);

        return $decoded === false ? null : $decoded;
    }

    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function json(string $part): ?array
    {
        $text = self::decode($part);
        $data = $text === null ? null : json_decode($text, true);
        if (! is_array($data) || array_is_list($data)) {
            return null;
        }
        $object = [];
        foreach ($data as $key => $value) {
            $object[(string) $key] = $value;
        }

        return $object;
    }

    /** A JOSE ECDSA signature (r || s) as OpenSSL wants it: a DER sequence of two integers. */
    private static function ecdsaDer(string $signature, int $size): ?string
    {
        if (strlen($signature) !== 2 * $size) {
            return null;
        }
        $integer = static function (string $bytes): string {
            $bytes = ltrim($bytes, "\0");
            if ($bytes === '' || ord($bytes[0]) > 0x7F) {
                $bytes = "\0".$bytes;
            }

            return "\x02".pack('C', strlen($bytes)).$bytes;
        };
        $body = $integer(substr($signature, 0, $size)).$integer(substr($signature, $size));
        $length = strlen($body);

        return "\x30".($length < 0x80 ? pack('C', $length) : "\x81".pack('C', $length)).$body;
    }
}
