<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Jose;

use OpenSSLAsymmetricKey;

/**
 * A public key of a JWKS (RFC 7517) as OpenSSL takes it: an RSA key from
 * its modulus and exponent, an EC key (P-256, P-384, P-521) from its point.
 * The SubjectPublicKeyInfo is written in DER here, so no library is needed.
 */
final class Jwk
{
    /** Curves by JWK name: their object identifier and the size of a coordinate. */
    private const array CURVES = [
        'P-256' => ['1.2.840.10045.3.1.7', 32],
        'P-384' => ['1.3.132.0.34', 48],
        'P-521' => ['1.3.132.0.35', 66],
    ];

    /**
     * The key, or null when the JWK is not a usable public key. An RSA
     * modulus under 2048 bits is not accepted.
     *
     * @param  array<string, mixed>  $jwk
     */
    public static function publicKey(array $jwk): ?OpenSSLAsymmetricKey
    {
        $der = match ($jwk['kty'] ?? null) {
            'RSA' => self::rsa($jwk),
            'EC' => self::ec($jwk),
            default => null,
        };
        if ($der === null) {
            return null;
        }
        $pem = "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem);

        return $key === false ? null : $key;
    }

    /** The size of a coordinate on the named curve, for the size of a signature. */
    public static function coordinateSize(string $curve): ?int
    {
        return self::CURVES[$curve][1] ?? null;
    }

    /**
     * @param  array<string, mixed>  $jwk
     */
    private static function rsa(array $jwk): ?string
    {
        $n = is_string($jwk['n'] ?? null) ? Jwt::decode($jwk['n']) : null;
        $e = is_string($jwk['e'] ?? null) ? Jwt::decode($jwk['e']) : null;
        // A modulus under 2048 bits is not accepted.
        if ($n === null || $e === null || strlen(ltrim($n, "\0")) < 256) {
            return null;
        }
        $key = self::sequence(self::integer($n).self::integer($e));
        $algorithm = self::sequence(self::oid('1.2.840.113549.1.1.1')."\x05\x00");

        return self::sequence($algorithm.self::bitString($key));
    }

    /**
     * @param  array<string, mixed>  $jwk
     */
    private static function ec(array $jwk): ?string
    {
        $curve = is_string($jwk['crv'] ?? null) ? self::CURVES[$jwk['crv']] ?? null : null;
        $x = is_string($jwk['x'] ?? null) ? Jwt::decode($jwk['x']) : null;
        $y = is_string($jwk['y'] ?? null) ? Jwt::decode($jwk['y']) : null;
        if ($curve === null || $x === null || $y === null || strlen($x) !== $curve[1] || strlen($y) !== $curve[1]) {
            return null;
        }
        $algorithm = self::sequence(self::oid('1.2.840.10045.2.1').self::oid($curve[0]));

        return self::sequence($algorithm.self::bitString("\x04".$x.$y));
    }

    private static function sequence(string $content): string
    {
        return "\x30".self::length(strlen($content)).$content;
    }

    /** A positive integer: a leading zero byte when the high bit is set. */
    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\0");
        if ($bytes === '' || ord($bytes[0]) > 0x7F) {
            $bytes = "\0".$bytes;
        }

        return "\x02".self::length(strlen($bytes)).$bytes;
    }

    private static function bitString(string $bytes): string
    {
        return "\x03".self::length(strlen($bytes) + 1)."\0".$bytes;
    }

    private static function oid(string $dotted): string
    {
        $parts = array_map(intval(...), explode('.', $dotted));
        $body = pack('C', 40 * $parts[0] + $parts[1]);
        foreach (array_slice($parts, 2) as $part) {
            $chunk = pack('C', $part & 0x7F);
            $part >>= 7;
            while ($part > 0) {
                $chunk = pack('C', ($part & 0x7F) | 0x80).$chunk;
                $part >>= 7;
            }
            $body .= $chunk;
        }

        return "\x06".self::length(strlen($body)).$body;
    }

    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return pack('C', $length);
        }
        $bytes = ltrim(pack('N', $length), "\0");

        return pack('C', 0x80 | strlen($bytes)).$bytes;
    }
}
