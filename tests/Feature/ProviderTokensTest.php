<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Contracts\GroupSync;
use Dskripchenko\Oidc\Contracts\SubjectUsers;
use Dskripchenko\Oidc\Exceptions\TokenRejected;
use Dskripchenko\Oidc\Jose\Jwt;
use Dskripchenko\Oidc\Tests\Support\FakeGroups;
use Dskripchenko\Oidc\Tests\Support\FakeUsers;
use Dskripchenko\Oidc\Tokens\ProviderTokens;
use Illuminate\Support\Facades\Http;

/**
 * Ada of TEST_ISSUER, and groups that nothing follows unless said.
 *
 * @return array{FakeUsers, FakeGroups}
 */
function people(bool $follows = false): array
{
    $users = new FakeUsers;
    $users->add(TEST_ISSUER, 'u-ada', 1);
    $groups = new FakeGroups($users);
    $groups->follows = $follows;
    app()->instance(SubjectUsers::class, $users);
    app()->instance(GroupSync::class, $groups);

    return [$users, $groups];
}

/** Why the token is rejected; null when it is taken. */
function rejection(string $jwt): ?string
{
    try {
        app(ProviderTokens::class)->verify($jwt);

        return null;
    } catch (TokenRejected $e) {
        expect($e->getStatusCode())->toBe(401);

        return $e->reason();
    }
}

it('takes a token for the person it was issued for, and keeps the keys', function (): void {
    [$key, $jwk] = testKey('k1');
    fakeProvider([$jwk]);
    people();

    $verified = app(ProviderTokens::class)->verify(testJwt($key, 'k1', ['azp' => 'chat', 'exp' => time() + 120]));
    app(ProviderTokens::class)->verify(testJwt($key, 'k1'));

    expect($verified->user->getAuthIdentifier())->toBe(1)
        ->and($verified->token->client)->toBe('chat')
        ->and($verified->token->subject)->toBe('u-ada')
        ->and($verified->token->issuer)->toBe(TEST_ISSUER)
        ->and($verified->token->expiresAt)->toBeGreaterThan(time());
    // The discovery document and the keys, once each.
    Http::assertSentCount(2);
});

it('names the client by client_id when there is no azp, and cuts it to 100 characters', function (): void {
    [$key, $jwk] = testKey('k1');
    fakeProvider([$jwk]);
    people();
    $long = str_repeat('c', 120);
    config(['oidc.api_clients' => "chat,{$long}"]);

    expect(app(ProviderTokens::class)->verify(testJwt($key, 'k1', ['azp' => null, 'client_id' => 'chat']))->token->client)->toBe('chat')
        ->and(app(ProviderTokens::class)->verify(testJwt($key, 'k1', ['azp' => $long]))->token->client)->toBe(str_repeat('c', 100));
});

it('picks up a rotated key once, and does not call out again for another unknown key within the minute', function (): void {
    [$old, $oldJwk] = testKey('old');
    [$new, $newJwk] = testKey('new', 'prime256v1');
    fakeProvider([$oldJwk]);
    people();

    expect(rejection(testJwt($old, 'old')))->toBeNull();
    app()->instance('test.jwks', [$oldJwk, $newJwk]);
    expect(rejection(testJwt($new, 'new', [], ['alg' => 'ES256'])))->toBeNull();
    $calls = count(Http::recorded());
    expect(rejection(testJwt($new, 'unknown', [], ['alg' => 'ES256'])))->toBe('signature')
        ->and(count(Http::recorded()))->toBe($calls);
});

it('rejects each token that is not one to take, with its reason', function (): void {
    [$key, $jwk] = testKey('k1');
    [$stranger] = testKey('k1');
    fakeProvider([$jwk]);
    [$users] = people();
    $users->add(TEST_ISSUER, 'u-gone', 2);
    $users->blocked[TEST_ISSUER.' u-gone'] = true;
    $body = explode('.', testJwt($key, 'k1'))[1];

    expect(rejection('not-a-jwt'))->toBe('format')
        ->and(rejection(Jwt::encode('{"alg":"none","typ":"at+jwt"}').".{$body}.".Jwt::encode('x')))->toBe('algorithm')
        ->and(rejection(Jwt::encode('{"alg":"HS256","typ":"at+jwt"}').".{$body}.".Jwt::encode('x')))->toBe('algorithm')
        ->and(rejection(testJwt($key, 'k1', [], ['typ' => 'JWT'])))->toBe('type')
        ->and(rejection(testJwt($key, 'k1', [], ['typ' => null])))->toBe('type')
        ->and(rejection(testJwt($key, 'k1', ['typ' => 'ID'])))->toBe('type')
        ->and(rejection(testJwt($key, 'k1', ['token_use' => 'id'])))->toBe('type')
        ->and(rejection(testJwt($stranger, 'k1')))->toBe('signature')
        ->and(rejection(testJwt($key, 'k1', ['iss' => 'https://elsewhere.example.test'])))->toBe('issuer')
        ->and(rejection(testJwt($key, 'k1', ['aud' => 'another-app'])))->toBe('audience')
        ->and(rejection(testJwt($key, 'k1', ['azp' => 'stranger'])))->toBe('client')
        ->and(rejection(testJwt($key, 'k1', ['azp' => null])))->toBe('client')
        ->and(rejection(testJwt($key, 'k1', ['exp' => time() - 61])))->toBe('expired')
        ->and(rejection(testJwt($key, 'k1', ['exp' => null])))->toBe('expired')
        ->and(rejection(testJwt($key, 'k1', ['nbf' => time() + 3600])))->toBe('not_yet')
        ->and(rejection(testJwt($key, 'k1', ['sub' => ''])))->toBe('subject')
        ->and(rejection(testJwt($key, 'k1', ['sub' => 'u-nobody'])))->toBe('subject')
        ->and(rejection(testJwt($key, 'k1', ['sub' => 'u-gone'])))->toBe('subject')
        // A minute of clock difference is forgiven.
        ->and(rejection(testJwt($key, 'k1', ['exp' => time() - 30, 'nbf' => time() + 30])))->toBeNull()
        // The issuer with a trailing slash is the issuer.
        ->and(rejection(testJwt($key, 'k1', ['iss' => TEST_ISSUER.'/'])))->toBeNull();
});

it('wants an audience that is not the sign-in client unless allowed, and the types it is told', function (): void {
    [$key, $jwk] = testKey('k1');
    fakeProvider([$jwk]);
    people();

    config(['oidc.api_audience' => '']);
    expect(rejection(testJwt($key, 'k1', ['aud' => ''])))->toBe('audience');
    // The application's own sign-in client is no audience for the API ...
    config(['oidc.api_audience' => 'app']);
    expect(rejection(testJwt($key, 'k1', ['aud' => 'app'])))->toBe('audience');
    // ... unless the application says so.
    config(['oidc.api_audience_same_as_client' => true]);
    expect(rejection(testJwt($key, 'k1', ['aud' => 'app'])))->toBeNull();
    // A provider that types its access tokens "JWT" is allowed by name.
    config(['oidc.api_token_types' => 'at+jwt, JWT']);
    expect(rejection(testJwt($key, 'k1', ['aud' => 'app'], ['typ' => 'JWT'])))->toBeNull()
        ->and(ProviderTokens::types())->toBe(['at+jwt', 'jwt']);
});

it('does not remember a failed fetch of the keys for long', function (): void {
    [$key, $jwk] = testKey('k1');
    fakeProvider([$jwk]);
    people();
    app()->instance('test.down', true);

    expect(rejection(testJwt($key, 'k1')))->toBe('signature');
    app()->instance('test.down', false);
    // Within half a minute the failure is not asked again ...
    $calls = count(Http::recorded());
    expect(rejection(testJwt($key, 'k1')))->toBe('signature')
        ->and(count(Http::recorded()))->toBe($calls);
    // ... after it, the provider is asked again.
    $this->travel(31)->seconds();
    expect(rejection(testJwt($key, 'k1')))->toBeNull();
});

it('follows the groups the token carries, once a minute for the same groups', function (): void {
    [$key, $jwk] = testKey('k1');
    fakeProvider([$jwk]);
    [, $groups] = people(true);

    expect(rejection(testJwt($key, 'k1', ['groups' => ['ops']])))->toBeNull();
    expect(rejection(testJwt($key, 'k1', ['groups' => ['ops', 'ops']])))->toBeNull();
    expect($groups->calls)->toBe([[1, ['ops']]]);
    expect(rejection(testJwt($key, 'k1', ['groups' => ['dev']])))->toBeNull();
    expect($groups->calls)->toHaveCount(2);
    $this->travel(61)->seconds();
    expect(rejection(testJwt($key, 'k1', ['groups' => ['dev']])))->toBeNull();
    expect($groups->calls)->toHaveCount(3);
});

it('rejects a token without groups once the provider\'s last word is old, if anything follows groups', function (): void {
    [$key, $jwk] = testKey('k1');
    fakeProvider([$jwk]);
    [, $groups] = people(true);

    expect(rejection(testJwt($key, 'k1')))->toBe('groups_stale');
    $groups->synced[1] = now()->subHours(23);
    expect(rejection(testJwt($key, 'k1')))->toBeNull();
    config(['oidc.api_sync_max_age' => 1]);
    expect(rejection(testJwt($key, 'k1')))->toBe('groups_stale');

    // Nothing follows groups: they cannot go stale.
    $groups->follows = false;
    expect(rejection(testJwt($key, 'k1')))->toBeNull();
});

it('rejects the token of a person the groups block', function (): void {
    [$key, $jwk] = testKey('k1');
    fakeProvider([$jwk]);
    config(['oidc.blocked_group' => 'left']);
    [$users] = people(true);

    expect(rejection(testJwt($key, 'k1', ['groups' => ['left']])))->toBe('subject')
        ->and($users->find(TEST_ISSUER, 'u-ada'))->toBeNull();
});

it('is off unless the application takes provider tokens', function (): void {
    fakeProvider();
    expect(ProviderTokens::enabled())->toBeTrue();

    config(['oidc.api_tokens' => false]);
    expect(ProviderTokens::enabled())->toBeFalse();
    config(['oidc.api_tokens' => true, 'oidc.issuer' => null]);
    expect(ProviderTokens::enabled())->toBeFalse();
});
