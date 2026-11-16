<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Exceptions\ProviderError;
use Dskripchenko\Oidc\IssuerKeys;
use Dskripchenko\Oidc\OidcClient;
use Dskripchenko\Oidc\SignIn\IdTokens;
use Dskripchenko\Oidc\SignIn\SignInFlow;
use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

/*
 * One application, two clients of the same provider: the default one of
 * config/oidc.php and a named one (oidc.clients.<name>) — a mobile gateway
 * next to a web interface, say.
 */

beforeEach(function (): void {
    config(['oidc.clients.mobile' => [
        'client_id' => 'mobile', 'client_secret' => 'm-secret', 'callback_path' => '/mobile/auth/callback', 'scopes' => 'openid profile',
    ]]);
});

it('sends the person to the provider as the named client, with its way back and scopes', function (): void {
    fakeProvider();
    $mobile = app(OidcClient::class)->as('mobile');
    parse_str((string) parse_url($mobile->authorizeUrl('st', 'verifier-1', 'nonce-1'), PHP_URL_QUERY), $query);

    expect($mobile->clientId())->toBe('mobile')
        ->and($mobile->issuer())->toBe(TEST_ISSUER)
        ->and($query)->toMatchArray(['client_id' => 'mobile', 'scope' => 'openid profile', 'redirect_uri' => url('/mobile/auth/callback')])
        // The default client stays as it was.
        ->and(app(OidcClient::class)->clientId())->toBe('app');
});

it('trades the code and refreshes with the named client\'s own secret', function (): void {
    fakeProvider();
    $mobile = app(OidcClient::class)->as('mobile');
    $mobile->exchange('code-1', 'verifier-1');

    Http::assertSent(fn (HttpRequest $r): bool => $r->url() === TEST_ISSUER.'/token' && $r->hasHeader('Authorization', 'Basic '.base64_encode('mobile:m-secret')));
});

it('refuses a client that is not configured', function (array $named): void {
    config(['oidc.clients.broken' => $named]);

    expect(fn () => app(OidcClient::class)->as('broken'))->toThrow(ProviderError::class, '(client)')
        ->and(fn () => app(OidcClient::class)->as('nobody'))->toThrow(ProviderError::class, '(client)');
})->with([
    'no client ID' => [['client_secret' => 'x']],
    'an empty one' => [['client_id' => '']],
]);

it('signs in through the named client and takes only an ID token issued to it', function (): void {
    [$key, $jwk] = testKey('sign');
    fakeProvider([$jwk], ['sub' => 'u-ada']);
    $mobile = app(OidcClient::class)->as('mobile');
    $flow = new SignInFlow($mobile, new IdTokens($mobile, app(IssuerKeys::class)));
    $session = app('session')->driver();
    parse_str((string) parse_url($flow->start($session), PHP_URL_QUERY), $query);
    $nonce = is_string($query['nonce'] ?? null) ? $query['nonce'] : '';
    $state = is_string($query['state'] ?? null) ? $query['state'] : '';
    $back = function (string $idToken) use ($flow, $session, $state): mixed {
        app()->instance('test.id_token', $idToken);
        $request = Request::create('/mobile/auth/callback', 'GET', ['code' => 'c', 'state' => $state]);
        $request->setLaravelSession($session);

        return $flow->finish($request);
    };

    // An ID token of the default client is not this client's.
    expect(fn () => $back(idToken($key, $nonce)))->toThrow(ProviderError::class, '(id_token_invalid)');

    $session->put(SignInFlow::SESSION_KEY, ['state' => $state, 'verifier' => str_repeat('v', 64), 'nonce' => $nonce, 'context' => []]);
    expect($back(idToken($key, $nonce, ['aud' => 'mobile']))->user->subject)->toBe('u-ada');
});
