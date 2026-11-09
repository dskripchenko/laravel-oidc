<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Exceptions\ProviderError;
use Dskripchenko\Oidc\Exceptions\StateMismatch;
use Dskripchenko\Oidc\Jose\Jwt;
use Dskripchenko\Oidc\SignIn\IdTokens;
use Dskripchenko\Oidc\SignIn\SignInFlow;
use Illuminate\Http\Request;
use Illuminate\Session\Store;

/**
 * A callback request on the session.
 *
 * @param  array<string, string>  $query
 */
function callback(Store $session, array $query): Request
{
    $request = Request::create('/auth/oidc/callback', 'GET', $query);
    $request->setLaravelSession($session);

    return $request;
}

/**
 * A sign-in started at a provider that signs with a key of its JWKS.
 *
 * @param  array<string, mixed>  $userinfo
 * @param  array<string, mixed>  $context
 * @return array{session: Store, state: string, nonce: string, key: OpenSSLAsymmetricKey}
 */
function started(array $userinfo = ['sub' => 'u-ada', 'email' => 'a@b.test', 'email_verified' => true], array $context = []): array
{
    [$key, $jwk] = testKey('sign');
    fakeProvider([$jwk], $userinfo);
    $session = app('session')->driver();
    parse_str((string) parse_url(app(SignInFlow::class)->start($session, $context), PHP_URL_QUERY), $query);

    return [
        'session' => $session, 'key' => $key,
        'state' => is_string($query['state'] ?? null) ? $query['state'] : '',
        'nonce' => is_string($query['nonce'] ?? null) ? $query['nonce'] : '',
    ];
}

/**
 * The callback of the started sign-in, the provider answering with this ID token.
 *
 * @param  array{session: Store, state: string, nonce: string, key: OpenSSLAsymmetricKey}  $started
 */
function finish(array $started, ?string $idToken): mixed
{
    app()->instance('test.id_token', $idToken);

    return app(SignInFlow::class)->finish(callback($started['session'], ['code' => 'c', 'state' => $started['state']]));
}

it('starts with a fresh state, verifier and nonce, and finishes once with the context', function (): void {
    $started = started(context: ['link' => 7]);
    $kept = $started['session']->get(SignInFlow::SESSION_KEY);
    expect(is_array($kept) ? $kept['state'] : null)->toBe($started['state'])
        ->and(is_array($kept) ? $kept['nonce'] : null)->toBe($started['nonce'])
        ->and(is_array($kept) && is_string($kept['verifier']) ? strlen($kept['verifier']) : 0)->toBe(64);

    $result = finish($started, idToken($started['key'], $started['nonce']));
    expect($result->user->subject)->toBe('u-ada')
        ->and($result->user->verifiedEmail())->toBe('a@b.test')
        ->and($result->context)->toBe(['link' => 7])
        ->and($result->idToken['nonce'])->toBe($started['nonce']);

    // The state and the nonce were taken out: the same callback again is refused.
    expect(fn () => finish($started, idToken($started['key'], $started['nonce'])))->toThrow(StateMismatch::class);
});

it('takes an ES256 ID token, several audiences with azp, and clocks within the leeway', function (): void {
    [$ec, $ecJwk] = testKey('ec', 'prime256v1');
    $started = started();
    app()->instance('test.jwks', [...app('test.jwks'), $ecJwk]);

    expect(finish($started, testJwt($ec, 'ec', [
        'aud' => ['app', 'other'], 'azp' => 'app', 'iat' => time() + 30, 'exp' => time() - 30, 'nonce' => $started['nonce'],
    ], ['alg' => 'ES256', 'typ' => 'JWT']))->user->subject)->toBe('u-ada');
});

it('refuses an ID token that does not pass', function (string $reason, Closure $token): void {
    [$stranger] = testKey('sign');
    $started = started();

    expect(fn () => finish($started, $token($started['key'], $started['nonce'], $stranger)))->toThrow(ProviderError::class, "({$reason})");
})->with([
    'missing' => ['id_token_missing', fn (): ?string => null],
    'bad signature' => ['id_token_invalid', fn ($key, string $nonce, $stranger): string => idToken($stranger, $nonce)],
    'alg none' => ['id_token_invalid', fn ($key, string $nonce): string => Jwt::encode('{"alg":"none","kid":"sign"}').'.'.explode('.', idToken($key, $nonce))[1].'.'.Jwt::encode('x')],
    'RS512, not taken' => ['id_token_invalid', fn ($key, string $nonce): string => idToken($key, $nonce, [], ['alg' => 'RS512'])],
    'not a JWT' => ['id_token_invalid', fn (): string => 'opaque'],
    'wrong iss' => ['id_token_invalid', fn ($key, string $nonce): string => idToken($key, $nonce, ['iss' => 'https://elsewhere.example.test'])],
    'wrong aud' => ['id_token_invalid', fn ($key, string $nonce): string => idToken($key, $nonce, ['aud' => 'other'])],
    'several aud, no azp' => ['id_token_invalid', fn ($key, string $nonce): string => idToken($key, $nonce, ['aud' => ['app', 'other']])],
    'azp of another client' => ['id_token_invalid', fn ($key, string $nonce): string => idToken($key, $nonce, ['azp' => 'other'])],
    'expired' => ['id_token_invalid', fn ($key, string $nonce): string => idToken($key, $nonce, ['exp' => time() - 61])],
    'issued in the future' => ['id_token_invalid', fn ($key, string $nonce): string => idToken($key, $nonce, ['iat' => time() + 120])],
    'no iat' => ['id_token_invalid', fn ($key, string $nonce): string => idToken($key, $nonce, ['iat' => null])],
    'no sub' => ['id_token_invalid', fn ($key, string $nonce): string => idToken($key, $nonce, ['sub' => ''])],
    'nonce mismatch' => ['nonce_mismatch', fn ($key, string $nonce): string => idToken($key, $nonce, ['nonce' => 'another'])],
    'no nonce' => ['nonce_mismatch', fn ($key, string $nonce): string => idToken($key, $nonce, ['nonce' => null])],
]);

it('refuses userinfo of another subject than the ID token\'s', function (): void {
    $started = started(['sub' => 'u-eve']);

    expect(fn () => finish($started, idToken($started['key'], $started['nonce'])))->toThrow(ProviderError::class, '(sub_mismatch)');
});

it('takes the leeway from the configuration', function (): void {
    $started = started();
    config(['oidc.id_token_leeway' => 5]);

    expect(IdTokens::leeway())->toBe(5)
        ->and(fn () => finish($started, idToken($started['key'], $started['nonce'], ['exp' => time() - 30])))->toThrow(ProviderError::class, '(id_token_invalid)');
});

it('refuses a callback with another state or none started', function (): void {
    fakeProvider();
    $session = app('session')->driver();
    $flow = app(SignInFlow::class);

    expect(fn () => $flow->finish(callback($session, ['code' => 'c', 'state' => 'forged'])))->toThrow(StateMismatch::class);
    $flow->start($session);
    expect(fn () => $flow->finish(callback($session, ['code' => 'c', 'state' => 'forged'])))->toThrow(StateMismatch::class);
});

it('fails on an error from the provider or a missing code', function (array $query): void {
    $started = started();

    expect(fn () => app(SignInFlow::class)->finish(callback($started['session'], [...$query, 'state' => $started['state']])))
        ->toThrow(ProviderError::class, '(callback)');
})->with([
    'error' => [['error' => 'access_denied', 'code' => 'c']],
    'no code' => [[]],
]);
