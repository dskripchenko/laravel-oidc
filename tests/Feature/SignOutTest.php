<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Exceptions\ProviderError;
use Dskripchenko\Oidc\Exceptions\SilentSignInRefused;
use Dskripchenko\Oidc\Exceptions\StateMismatch;
use Dskripchenko\Oidc\IssuerKeys;
use Dskripchenko\Oidc\Jose\Jwt;
use Dskripchenko\Oidc\OidcClient;
use Dskripchenko\Oidc\SignIn\SignInFlow;
use Dskripchenko\Oidc\SignOut\LogoutToken;
use Dskripchenko\Oidc\SignOut\LogoutTokens;
use Illuminate\Http\Request;
use Illuminate\Session\Store;

/**
 * The query of a URL as an array.
 *
 * @return array<string, mixed>
 */
function queryOf(string $url): array
{
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    /** @var array<string, mixed> $query */
    return $query;
}

/**
 * A callback of the sign-in started on the session, with this query.
 *
 * @param  array<string, string>  $query
 */
function backFrom(Store $session, string $url, array $query): Request
{
    $request = Request::create('/auth/oidc/callback', 'GET', [...$query, 'state' => queryOf($url)['state'] ?? '']);
    $request->setLaravelSession($session);

    return $request;
}

describe('silent sign-in', function (): void {
    it('asks the provider for no page only when silent', function (): void {
        fakeProvider();
        $flow = app(SignInFlow::class);
        $session = app('session')->driver();

        expect(queryOf($flow->start($session, silent: true)))->toHaveKey('prompt', 'none')
            ->and(queryOf($flow->start($session)))->not->toHaveKey('prompt');
    });

    it('turns the provider\'s refusal into SilentSignInRefused, with the context', function (string $error): void {
        fakeProvider();
        $flow = app(SignInFlow::class);
        $session = app('session')->driver();
        $url = $flow->start($session, ['back' => '/tasks'], silent: true);

        try {
            $flow->finish(backFrom($session, $url, ['error' => $error]));
            $this->fail('No refusal');
        } catch (SilentSignInRefused $e) {
            expect($e->error)->toBe($error)
                ->and($e->context)->toBe(['back' => '/tasks'])
                ->and($e->reason())->toBe('silent_refused');
        }
        // Taken out of the session like any other callback.
        expect(fn () => $flow->finish(backFrom($session, $url, ['error' => $error])))->toThrow(StateMismatch::class);
    })->with(SignInFlow::SILENT_REFUSALS);

    it('keeps any other error, and a refusal of a sign-in that was not silent, a provider error', function (bool $silent, string $error): void {
        fakeProvider();
        $flow = app(SignInFlow::class);
        $session = app('session')->driver();
        $url = $flow->start($session, silent: $silent);

        expect(fn () => $flow->finish(backFrom($session, $url, ['error' => $error])))->toThrow(ProviderError::class, '(callback)');
    })->with([
        'silent, access denied' => [true, 'access_denied'],
        'silent, server error' => [true, 'server_error'],
        'not silent, login required' => [false, 'login_required'],
    ]);

    it('signs the person in when the provider has their session', function (): void {
        [$key, $jwk] = testKey('sign');
        fakeProvider([$jwk]);
        $flow = app(SignInFlow::class);
        $session = app('session')->driver();
        $url = $flow->start($session, silent: true);
        app()->instance('test.id_token', idToken($key, (string) (queryOf($url)['nonce'] ?? '')));

        expect($flow->finish(backFrom($session, $url, ['code' => 'c']))->user->subject)->toBe('u-ada');
    });
});

describe('the provider\'s logout page', function (): void {
    it('ends the session with the client, the hint, the way back and the state', function (): void {
        fakeProvider();
        $url = (string) app(OidcClient::class)->logoutUrl('id-token', 'https://app.test/login?out=1', 'st');

        expect(strtok($url, '?'))->toBe(TEST_ISSUER.'/logout')
            ->and(queryOf($url))->toBe(['client_id' => 'app', 'id_token_hint' => 'id-token', 'post_logout_redirect_uri' => 'https://app.test/login?out=1', 'state' => 'st']);
    });

    it('leaves out what is not given, and names the named client', function (): void {
        fakeProvider();
        config(['oidc.clients.mobile' => ['client_id' => 'mobile']]);

        expect(queryOf((string) app(OidcClient::class)->as('mobile')->logoutUrl()))->toBe(['client_id' => 'mobile']);
    });

    it('is null when the provider has no logout endpoint', function (): void {
        app()->instance('test.no_end_session', true);
        fakeProvider();

        expect(app(OidcClient::class)->logoutUrl('id-token'))->toBeNull();
    });
});

describe('back-channel logout', function (): void {
    it('takes a logout token once, with its subject and session', function (): void {
        [$key, $jwk] = testKey('sign');
        fakeProvider([$jwk]);
        $tokens = app(LogoutTokens::class);
        $token = logoutToken($key);

        $logout = $tokens->validate($token);
        expect($logout->issuer)->toBe(TEST_ISSUER)
            ->and($logout->subject)->toBe('u-ada')
            ->and($logout->sessionId)->toBe('s-1');
        expect(fn () => $tokens->validate($token))->toThrow(ProviderError::class, '(logout_token_replayed)');
    });

    it('takes a token with only a sid or only a sub, without exp while fresh, and ES256', function (Closure $token): void {
        [$key, $jwk] = testKey('sign');
        [$ec, $ecJwk] = testKey('ec', 'prime256v1');
        fakeProvider([$jwk, $ecJwk]);

        expect(app(LogoutTokens::class)->validate($token($key, $ec)))->toBeInstanceOf(LogoutToken::class);
    })->with([
        'only sid' => [fn ($key): string => logoutToken($key, ['sub' => null])],
        'only sub' => [fn ($key): string => logoutToken($key, ['sid' => null])],
        'no exp, fresh' => [fn ($key): string => logoutToken($key, ['exp' => null, 'iat' => time() - 60])],
        'several aud with azp' => [fn ($key): string => logoutToken($key, ['aud' => ['app', 'other'], 'azp' => 'app'])],
        'ES256' => [fn ($key, $ec): string => testJwt($ec, 'ec', [
            'aud' => 'app', 'azp' => null, 'sid' => 's-1', 'iat' => time(), 'exp' => time() + 120, 'jti' => 'j-ec',
            'events' => [LogoutTokens::EVENT => new stdClass],
        ], ['alg' => 'ES256', 'typ' => 'logout+jwt'])],
    ]);

    it('refuses a logout token that does not pass', function (Closure $token): void {
        [$key, $jwk] = testKey('sign');
        [$stranger] = testKey('sign');
        fakeProvider([$jwk]);

        expect(fn () => app(LogoutTokens::class)->validate($token($key, $stranger)))->toThrow(ProviderError::class, '(logout_token_invalid)');
    })->with([
        'not a JWT' => [fn (): string => 'opaque'],
        'bad signature' => [fn ($key, $stranger): string => logoutToken($stranger)],
        'alg none' => [fn ($key): string => Jwt::encode('{"alg":"none","kid":"sign"}').'.'.explode('.', logoutToken($key))[1].'.'],
        'wrong iss' => [fn ($key): string => logoutToken($key, ['iss' => 'https://elsewhere.example.test'])],
        'wrong aud' => [fn ($key): string => logoutToken($key, ['aud' => 'other'])],
        'several aud, no azp' => [fn ($key): string => logoutToken($key, ['aud' => ['app', 'other']])],
        'azp of another client' => [fn ($key): string => logoutToken($key, ['azp' => 'other'])],
        'no iat' => [fn ($key): string => logoutToken($key, ['iat' => null])],
        'issued in the future' => [fn ($key): string => logoutToken($key, ['iat' => time() + 120])],
        'expired' => [fn ($key): string => logoutToken($key, ['exp' => time() - 61])],
        'no exp, stale' => [fn ($key): string => logoutToken($key, ['exp' => null, 'iat' => time() - LogoutTokens::MAX_AGE - 61])],
        'no jti' => [fn ($key): string => logoutToken($key, ['jti' => null])],
        'neither sub nor sid' => [fn ($key): string => logoutToken($key, ['sub' => null, 'sid' => null])],
        'no events' => [fn ($key): string => logoutToken($key, ['events' => null])],
        'another event' => [fn ($key): string => logoutToken($key, ['events' => ['http://example.test/other' => new stdClass]])],
        'event not an object' => [fn ($key): string => logoutToken($key, ['events' => [LogoutTokens::EVENT => 'yes']])],
        'a nonce: an ID token' => [fn ($key): string => logoutToken($key, ['nonce' => 'n'])],
    ]);

    it('takes the token of a named client only when built with that client', function (): void {
        [$key, $jwk] = testKey('sign');
        fakeProvider([$jwk]);
        config(['oidc.clients.mobile' => ['client_id' => 'mobile']]);
        $token = logoutToken($key, ['aud' => 'mobile']);

        expect(fn () => app(LogoutTokens::class)->validate($token))->toThrow(ProviderError::class, '(logout_token_invalid)');
        $mobile = new LogoutTokens(app(OidcClient::class)->as('mobile'), app(IssuerKeys::class), app('cache.store'));
        expect($mobile->validate($token)->sessionId)->toBe('s-1');
    });
});
