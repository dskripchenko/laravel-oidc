<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Exceptions\ProviderError;
use Dskripchenko\Oidc\Groups\GroupClaims;
use Dskripchenko\Oidc\OidcClient;
use Dskripchenko\Oidc\Tokens\TokenSet;
use Dskripchenko\Oidc\UserInfo;
use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Support\Facades\Http;

it('is on with an issuer and a client ID', function (): void {
    expect(OidcClient::enabled())->toBeFalse()->and(OidcClient::name())->toBe('SSO');

    config(['oidc.issuer' => TEST_ISSUER.'/', 'oidc.client_id' => 'app', 'oidc.name' => 'Keycloak']);
    expect(OidcClient::enabled())->toBeTrue()
        ->and(OidcClient::name())->toBe('Keycloak')
        ->and(app(OidcClient::class)->issuer())->toBe(TEST_ISSUER);
});

it('sends the person to the provider with PKCE S256, the state and the nonce', function (): void {
    fakeProvider();
    $url = app(OidcClient::class)->authorizeUrl('st', 'verifier-1', 'nonce-1');
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    expect($url)->toStartWith(TEST_ISSUER.'/authorize?')
        ->and($query)->toMatchArray([
            'response_type' => 'code', 'client_id' => 'app', 'scope' => 'openid profile email', 'state' => 'st', 'nonce' => 'nonce-1',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', 'verifier-1', true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256', 'redirect_uri' => url('/auth/oidc/callback'),
        ]);

    config(['oidc.redirect' => 'https://app.example.test/back']);
    expect(app(OidcClient::class)->redirectUri())->toBe('https://app.example.test/back');
});

it('trades the code for tokens, and reads the userinfo with the access token', function (): void {
    fakeProvider([], ['sub' => 'u-1', 'email' => ' Ada@Example.TEST ', 'email_verified' => true, 'preferred_username' => 'ada', 'groups' => ['core', 7]]);
    app()->instance('test.id_token', 'id-1');

    $tokens = app(OidcClient::class)->tokens('code-1', 'verifier-1');
    $info = app(OidcClient::class)->userInfo($tokens['access_token']);

    expect($tokens)->toBe(['access_token' => 'at-1', 'id_token' => 'id-1', 'refresh_token' => null, 'expires_in' => null]);

    expect($info->toArray())->toBe(['sub' => 'u-1', 'email' => 'ada@example.test', 'email_verified' => true, 'name' => 'ada', 'groups' => ['core']])
        ->and($info->verifiedEmail())->toBe('ada@example.test');
    Http::assertSent(fn (HttpRequest $r): bool => $r->url() === TEST_ISSUER.'/token'
        && $r['code'] === 'code-1' && $r['code_verifier'] === 'verifier-1' && $r['grant_type'] === 'authorization_code'
        && $r->hasHeader('Authorization', 'Basic '.base64_encode('app:secret')));
    Http::assertSent(fn (HttpRequest $r): bool => $r->url() === TEST_ISSUER.'/userinfo' && $r->hasHeader('Authorization', 'Bearer at-1'));
});

it('takes the email as verified only when the provider says so outright', function (): void {
    expect(UserInfo::fromClaims(['sub' => 'x', 'email' => 'a@b.test'])->verifiedEmail())->toBeNull()
        ->and(UserInfo::fromClaims(['sub' => 'x', 'email' => 'a@b.test', 'email_verified' => 'true'])->verifiedEmail())->toBeNull()
        ->and(UserInfo::fromClaims(['sub' => 'x', 'email' => 'a@b.test', 'email_verified' => false])->verifiedEmail())->toBeNull()
        ->and(UserInfo::fromClaims(['sub' => 'x', 'email' => 'a@b.test', 'email_verified' => true])->verifiedEmail())->toBe('a@b.test');
});

it('fails when the provider does not answer as expected', function (string $url, array $body, int $status, string $reason): void {
    fakeProvider(overrides: [TEST_ISSUER.$url => Http::response($body, $status)]);

    expect(fn () => app(OidcClient::class)->userInfo(app(OidcClient::class)->tokens('c', 'v')['access_token']))->toThrow(ProviderError::class, "({$reason})");
})->with([
    'no access token' => ['/token', ['token_type' => 'Bearer'], 200, 'token'],
    'token refused' => ['/token', ['error' => 'invalid_grant'], 400, 'token'],
    'userinfo without sub' => ['/userinfo', ['email' => 'a@b.test'], 200, 'userinfo'],
    'userinfo refused' => ['/userinfo', ['error' => 'invalid_token'], 401, 'userinfo'],
]);

it('takes the discovery document only for the configured issuer', function (): void {
    fakeProvider([], [], 'https://elsewhere.example.test');
    expect(fn () => app(OidcClient::class)->endpoint('authorization_endpoint'))->toThrow(ProviderError::class, '(discovery)');
});

it('keeps the discovery document an hour', function (): void {
    fakeProvider();
    app(OidcClient::class)->endpoint('token_endpoint');
    app(OidcClient::class)->endpoint('userinfo_endpoint');
    Http::assertSentCount(1);
    expect(fn () => app(OidcClient::class)->endpoint('end_session_endpoint'))->toThrow(ProviderError::class, '(endpoint)');
});

it('reads the groups from the configured claim', function (): void {
    expect(GroupClaims::of(['groups' => ['a', 1, 'b']]))->toBe(['a', 'b'])
        ->and(GroupClaims::of(['sub' => 'x']))->toBeNull();

    config(['oidc.groups_claim' => 'roles', 'oidc.blocked_group' => 'left']);
    expect(GroupClaims::of(['roles' => ['left']]))->toBe(['left'])
        ->and(GroupClaims::blocks(['x', 'left']))->toBeTrue()
        ->and(GroupClaims::blocks(['x']))->toBeFalse();

    config(['oidc.blocked_group' => '']);
    expect(GroupClaims::blockedGroup())->toBeNull()->and(GroupClaims::blocks(['']))->toBeFalse();
});

it('keeps the refresh token and the lifetimes the provider gives with the access token', function (): void {
    fakeProvider(overrides: [TEST_ISSUER.'/token' => Http::response([
        'access_token' => 'at-1', 'id_token' => 'id-1', 'refresh_token' => 'rt-1', 'expires_in' => 300, 'refresh_expires_in' => '1800',
    ])]);

    $set = app(OidcClient::class)->exchange('code-1', 'verifier-1');

    expect($set)->toEqual(new TokenSet('at-1', 'id-1', 'rt-1', 300, 1800))
        ->and(app(OidcClient::class)->tokens('code-1', 'verifier-1'))->toBe(['access_token' => 'at-1', 'id_token' => 'id-1', 'refresh_token' => 'rt-1', 'expires_in' => 300]);
});

it('reads a token answer leniently but never without an access token', function (): void {
    expect(TokenSet::fromResponse(['access_token' => '']))->toBeNull()
        ->and(TokenSet::fromResponse(['refresh_token' => 'rt']))->toBeNull()
        ->and(TokenSet::fromResponse(['access_token' => 'at', 'id_token' => '', 'refresh_token' => 5, 'expires_in' => 0, 'refresh_expires_in' => 'soon']))
        ->toEqual(new TokenSet('at'));
});

it('refreshes the tokens with the client authenticated', function (): void {
    fakeProvider(overrides: [TEST_ISSUER.'/token' => Http::response(['access_token' => 'at-2', 'refresh_token' => 'rt-2', 'expires_in' => 300])]);

    $set = app(OidcClient::class)->refresh('rt-1');

    expect($set)->toEqual(new TokenSet('at-2', null, 'rt-2', 300));
    Http::assertSent(fn (HttpRequest $r): bool => $r->url() === TEST_ISSUER.'/token'
        && $r['grant_type'] === 'refresh_token' && $r['refresh_token'] === 'rt-1'
        && $r->hasHeader('Authorization', 'Basic '.base64_encode('app:secret')));
});

it('tells a refused refresh token from a provider that cannot answer', function (mixed $answer, string $reason): void {
    fakeProvider(overrides: [TEST_ISSUER.'/token' => $answer]);

    expect(fn () => app(OidcClient::class)->refresh('rt-1'))->toThrow(ProviderError::class, "({$reason})");
})->with([
    'session ended or person blocked' => [fn () => Http::response(['error' => 'invalid_grant'], 400), 'refresh_rejected'],
    'client not allowed' => [fn () => Http::response(['error' => 'unauthorized_client'], 401), 'refresh_rejected'],
    'server error' => [fn () => Http::response('down', 503), 'refresh'],
    'no access token' => [fn () => Http::response(['token_type' => 'Bearer']), 'refresh'],
    'unreachable' => [fn () => Http::failedConnection(), 'refresh'],
]);
