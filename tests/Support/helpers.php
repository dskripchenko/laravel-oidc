<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Jose\Jwt;
use Illuminate\Support\Facades\Http;

const TEST_ISSUER = 'https://sso.example.test';

/**
 * A key pair and its public half as a JWK: RSA 2048, or EC on the named
 * OpenSSL curve (prime256v1, secp384r1, secp521r1).
 *
 * @return array{OpenSSLAsymmetricKey, array<string, mixed>}
 */
function testKey(string $kid, string $curve = '', int $bits = 2048): array
{
    $key = openssl_pkey_new($curve === ''
        ? ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits]
        : ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
    if (! $key instanceof OpenSSLAsymmetricKey) {
        throw new LogicException('No key');
    }
    $details = openssl_pkey_get_details($key);
    if (! is_array($details)) {
        throw new LogicException('No details');
    }
    if ($curve === '') {
        return [$key, ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'n' => Jwt::encode($details['rsa']['n']), 'e' => Jwt::encode($details['rsa']['e'])]];
    }
    [$name, $size] = ['prime256v1' => ['P-256', 32], 'secp384r1' => ['P-384', 48], 'secp521r1' => ['P-521', 66]][$curve];

    return [$key, [
        'kty' => 'EC', 'kid' => $kid, 'crv' => $name,
        'x' => Jwt::encode(str_pad($details['ec']['x'], $size, "\0", STR_PAD_LEFT)),
        'y' => Jwt::encode(str_pad($details['ec']['y'], $size, "\0", STR_PAD_LEFT)),
    ]];
}

/** A DER ECDSA signature as JOSE's r || s. */
function joseSignature(string $der, int $size): string
{
    $offset = 2;
    if ((ord($der[1]) & 0x80) !== 0) {
        $offset += ord($der[1]) & 0x7F;
    }
    $r = substr($der, $offset + 2, ord($der[$offset + 1]));
    $offset += 2 + ord($der[$offset + 1]);
    $s = substr($der, $offset + 2, ord($der[$offset + 1]));

    return str_pad(ltrim($r, "\0"), $size, "\0", STR_PAD_LEFT).str_pad(ltrim($s, "\0"), $size, "\0", STR_PAD_LEFT);
}

/**
 * A token signed with the key: by default an access token (RFC 9068) of
 * TEST_ISSUER for the API's audience, held by the client `chat`.
 *
 * @param  array<string, mixed>  $claims
 * @param  array<string, mixed>  $header
 */
function testJwt(OpenSSLAsymmetricKey $key, string $kid, array $claims = [], array $header = [], ?int $hash = null, int $size = 32): string
{
    $header = ['alg' => 'RS256', 'typ' => 'at+jwt', 'kid' => $kid, ...$header];
    $alg = is_string($header['alg']) ? $header['alg'] : 'RS256';
    $hash ??= match (substr($alg, 2)) {
        '384' => OPENSSL_ALGO_SHA384,
        '512' => OPENSSL_ALGO_SHA512,
        default => OPENSSL_ALGO_SHA256,
    };
    $head = Jwt::encode((string) json_encode($header));
    $body = Jwt::encode((string) json_encode(['iss' => TEST_ISSUER, 'aud' => ['api'], 'sub' => 'u-ada', 'exp' => time() + 300, 'azp' => 'chat', ...$claims]));
    $signature = '';
    openssl_sign("{$head}.{$body}", $signature, $key, $hash);
    if (! is_string($signature)) {
        throw new LogicException('Not signed');
    }
    if (str_starts_with($alg, 'ES')) {
        $signature = joseSignature($signature, $size);
    }

    return "{$head}.{$body}.".Jwt::encode($signature);
}

/**
 * The provider publishes the keys in the container's `test.jwks` (or is
 * down while `test.down` is true); the API takes its tokens for `chat`.
 *
 * @param  list<array<string, mixed>>  $keys
 * @param  array<string, mixed>  $userinfo
 * @param  array<string, mixed>  $overrides  Other answers by URL
 */
function fakeProvider(array $keys = [], array $userinfo = ['sub' => 'u-ada'], string $issuerInDocument = TEST_ISSUER, array $overrides = []): void
{
    config([
        'oidc.issuer' => TEST_ISSUER, 'oidc.client_id' => 'app', 'oidc.client_secret' => 'secret', 'oidc.api_tokens' => true,
        'oidc.api_audience' => 'api', 'oidc.api_clients' => 'chat',
    ]);
    app()->instance('test.jwks', $keys);
    app()->instance('test.down', false);
    Http::fake([
        TEST_ISSUER.'/.well-known/openid-configuration' => Http::response([
            'issuer' => $issuerInDocument,
            'authorization_endpoint' => TEST_ISSUER.'/authorize',
            'token_endpoint' => TEST_ISSUER.'/token',
            'userinfo_endpoint' => TEST_ISSUER.'/userinfo',
            'jwks_uri' => TEST_ISSUER.'/jwks',
        ]),
        // The ID token the test put in `test.id_token`, if any.
        TEST_ISSUER.'/token' => static fn () => Http::response(array_filter([
            'access_token' => 'at-1', 'token_type' => 'Bearer', 'id_token' => app()->bound('test.id_token') ? app('test.id_token') : null,
        ])),
        TEST_ISSUER.'/userinfo' => Http::response($userinfo),
        TEST_ISSUER.'/jwks' => static fn () => app('test.down') === true ? Http::response('down', 503) : Http::response(['keys' => app('test.jwks')]),
        ...$overrides,
    ]);
}

/**
 * An ID token of TEST_ISSUER for the client `app`, as a provider signs it.
 *
 * @param  array<string, mixed>  $claims
 * @param  array<string, mixed>  $header
 */
function idToken(OpenSSLAsymmetricKey $key, string $nonce, array $claims = [], array $header = []): string
{
    return testJwt($key, 'sign', [
        'aud' => 'app', 'azp' => null, 'sub' => 'u-ada', 'iat' => time(), 'exp' => time() + 300, 'nonce' => $nonce, ...$claims,
    ], ['typ' => 'JWT', ...$header]);
}
