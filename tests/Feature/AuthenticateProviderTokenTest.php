<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Contracts\SubjectUsers;
use Dskripchenko\Oidc\Events\ProviderTokenRejected;
use Dskripchenko\Oidc\Http\Middleware\AuthenticateProviderToken;
use Dskripchenko\Oidc\Tests\Support\FakeUsers;
use Dskripchenko\Oidc\Tokens\ProviderAccessToken;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;

beforeEach(function (): void {
    $users = new FakeUsers;
    $users->add(TEST_ISSUER, 'u-ada', 1);
    app()->instance(SubjectUsers::class, $users);
    Route::middleware(AuthenticateProviderToken::class)->get('/who', static fn (Request $request): array => [
        'user' => $request->user()?->getAuthIdentifier(),
        'client' => ProviderAccessToken::of($request)?->client,
    ]);
});

it('signs the request in as the person of the token', function (): void {
    [$key, $jwk] = testKey('k1');
    fakeProvider([$jwk]);

    $this->getJson('/who', ['Authorization' => 'Bearer '.testJwt($key, 'k1')])
        ->assertOk()->assertExactJson(['user' => 1, 'client' => 'chat']);
});

it('leaves other bearers, and every bearer while it is off, to the application', function (): void {
    [$key, $jwk] = testKey('k1');
    fakeProvider([$jwk]);

    $this->getJson('/who', ['Authorization' => 'Bearer 12|personal'])->assertOk()->assertExactJson(['user' => null, 'client' => null]);
    config(['oidc.api_tokens' => false]);
    $this->getJson('/who', ['Authorization' => 'Bearer '.testJwt($key, 'k1')])->assertOk()->assertExactJson(['user' => null, 'client' => null]);
});

it('rejects a token that does not pass, without trying it as anything else', function (): void {
    [$key, $jwk] = testKey('k1');
    fakeProvider([$jwk]);

    $this->getJson('/who', ['Authorization' => 'Bearer '.testJwt($key, 'k1', ['aud' => 'other'])])
        ->assertStatus(401)->assertJsonPath('message', "The provider's access token was not accepted (audience).");
});

it('reports the first rejections of a minute and slows down an address that keeps sending them', function (): void {
    Event::fake([ProviderTokenRejected::class]);
    [, $jwk] = testKey('k1');
    [$stranger] = testKey('k1');
    fakeProvider([$jwk]);
    $forged = testJwt($stranger, 'k1');

    for ($i = 0; $i < AuthenticateProviderToken::FAILURES_PER_MINUTE; $i++) {
        $this->getJson('/who', ['Authorization' => "Bearer {$forged}"])->assertStatus(401);
    }
    $this->getJson('/who', ['Authorization' => "Bearer {$forged}"])->assertStatus(429)->assertHeader('Retry-After');

    Event::assertDispatchedTimes(ProviderTokenRejected::class, AuthenticateProviderToken::REPORTED_PER_MINUTE);
    Event::assertDispatched(ProviderTokenRejected::class, static fn (ProviderTokenRejected $e): bool => $e->reason === 'signature' && $e->ip === '127.0.0.1');

    $this->travel(61)->seconds();
    $this->getJson('/who', ['Authorization' => "Bearer {$forged}"])->assertStatus(401);
});

it('signs in on the configured guard', function (): void {
    [$key, $jwk] = testKey('k1');
    fakeProvider([$jwk]);
    config(['auth.guards.api' => ['driver' => 'session', 'provider' => 'users'], 'oidc.api_guard' => 'api']);

    $this->getJson('/who', ['Authorization' => 'Bearer '.testJwt($key, 'k1')])->assertOk()->assertJsonPath('user', 1);
    expect(auth()->getDefaultDriver())->toBe('api')
        ->and(auth()->guard('api')->id())->toBe(1);
});
