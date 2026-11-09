<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Jose\Jwk;
use Dskripchenko\Oidc\Jose\Jwt;

it('reads a token and checks an RSA signature', function (): void {
    [$key, $jwk] = testKey('k1');
    $jwt = Jwt::parse(testJwt($key, 'k1', ['sub' => 'u-1']));

    expect($jwt)->not->toBeNull()
        ->and($jwt?->algorithm())->toBe('RS256')
        ->and($jwt?->keyId())->toBe('k1')
        ->and($jwt?->claims['sub'])->toBe('u-1')
        ->and($jwt?->signedBy($jwk))->toBeTrue();
});

it('checks RS384 and RS512', function (string $alg): void {
    [$key, $jwk] = testKey('k1');

    expect(Jwt::parse(testJwt($key, 'k1', [], ['alg' => $alg]))?->signedBy($jwk))->toBeTrue();
})->with(['RS384', 'RS512']);

it('checks EC signatures on each curve', function (string $curve, string $alg, int $size): void {
    [$key, $jwk] = testKey('k1', $curve);

    expect(Jwt::parse(testJwt($key, 'k1', [], ['alg' => $alg], size: $size))?->signedBy($jwk))->toBeTrue();
})->with([
    ['prime256v1', 'ES256', 32],
    ['secp384r1', 'ES384', 48],
    ['secp521r1', 'ES512', 66],
]);

it('refuses a signature of another key', function (): void {
    [$key] = testKey('k1');
    [, $other] = testKey('k1');

    expect(Jwt::parse(testJwt($key, 'k1'))?->signedBy($other))->toBeFalse();
});

it('takes neither none nor HMAC', function (): void {
    [$key, $jwk] = testKey('k1');
    $body = explode('.', testJwt($key, 'k1'))[1];
    $none = Jwt::encode((string) json_encode(['alg' => 'none'])).".{$body}.".Jwt::encode('x');
    $hs = Jwt::encode((string) json_encode(['alg' => 'HS256']));
    $hmac = "{$hs}.{$body}.".Jwt::encode(hash_hmac('sha256', "{$hs}.{$body}", 'secret', true));

    expect(Jwt::parse($none)?->algorithm())->toBeNull()
        ->and(Jwt::parse($none)?->signedBy($jwk))->toBeFalse()
        ->and(Jwt::parse($hmac)?->algorithm())->toBeNull()
        ->and(Jwt::parse($hmac)?->signedBy(['kty' => 'oct', 'k' => Jwt::encode('secret')]))->toBeFalse();
});

it('wants the key of the algorithm\'s kind, alg and use', function (): void {
    [$key, $jwk] = testKey('k1');
    $jwt = Jwt::parse(testJwt($key, 'k1'));

    expect($jwt?->signedBy([...$jwk, 'alg' => 'RS512']))->toBeFalse()
        ->and($jwt?->signedBy([...$jwk, 'use' => 'enc']))->toBeFalse()
        ->and($jwt?->signedBy([...$jwk, 'kty' => 'EC']))->toBeFalse()
        ->and($jwt?->signedBy([...$jwk, 'alg' => 'RS256', 'use' => 'sig']))->toBeTrue();
});

it('wants the EC key on the algorithm\'s own curve', function (): void {
    [$key, $jwk] = testKey('k1', 'prime256v1');

    // A P-256 key with SHA-384 named ES384: OpenSSL alone would verify it.
    $jwt = Jwt::parse(testJwt($key, 'k1', [], ['alg' => 'ES384'], OPENSSL_ALGO_SHA384, 32));
    expect($jwt?->signedBy($jwk))->toBeFalse();
});

it('does not take an RSA key under 2048 bits', function (): void {
    [$key, $jwk] = testKey('k1', '', 1024);

    expect(Jwk::publicKey($jwk))->toBeNull()
        ->and(Jwt::parse(testJwt($key, 'k1'))?->signedBy($jwk))->toBeFalse();
});

it('does not take an EC point of the wrong size or an unknown curve', function (): void {
    [, $jwk] = testKey('k1', 'prime256v1');

    expect(Jwk::publicKey($jwk))->not->toBeNull()
        ->and(Jwk::publicKey([...$jwk, 'x' => Jwt::encode(str_repeat("\1", 31))]))->toBeNull()
        ->and(Jwk::publicKey([...$jwk, 'crv' => 'P-192']))->toBeNull()
        ->and(Jwk::publicKey(['kty' => 'oct']))->toBeNull()
        ->and(Jwk::coordinateSize('P-521'))->toBe(66);
});

it('reads only well-formed compact tokens', function (string $token): void {
    expect(Jwt::parse($token))->toBeNull();
})->with([
    'two parts' => 'a.b',
    'not base64url' => 'a+b.c.d',
    'a list for a header' => Jwt::encode('[1]').'.'.Jwt::encode('{}').'.'.Jwt::encode('x'),
    'no signature' => Jwt::encode('{"alg":"RS256"}').'.'.Jwt::encode('{}').'.',
    'too long' => Jwt::encode('{"alg":"RS256"}').'.'.str_repeat('a', 16400).'.'.Jwt::encode('x'),
]);

it('tells a JWT from another bearer', function (): void {
    expect(Jwt::looksLikeOne('aaa.bbb.ccc'))->toBeTrue()
        ->and(Jwt::looksLikeOne('12|personal-token'))->toBeFalse()
        ->and(Jwt::looksLikeOne('aaa.bbb'))->toBeFalse();
});

it('encodes and decodes base64url without padding', function (): void {
    $bytes = random_bytes(33);

    expect(Jwt::decode(Jwt::encode($bytes)))->toBe($bytes)
        ->and(Jwt::encode("\xfb\xff"))->toBe('-_8')
        ->and(Jwt::decode('a=b'))->toBeNull();
});
