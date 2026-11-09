<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Exceptions\ProviderError;
use Dskripchenko\Oidc\Exceptions\StateMismatch;
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

it('starts with a fresh state and verifier, and finishes once with the context', function (): void {
    fakeProvider([], ['sub' => 'u-1', 'email' => 'a@b.test', 'email_verified' => true]);
    $session = app('session')->driver();
    $flow = app(SignInFlow::class);

    $url = $flow->start($session, ['link' => 7]);
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
    $kept = $session->get(SignInFlow::SESSION_KEY);
    expect(is_array($kept) ? $kept['state'] : null)->toBe($query['state'])
        ->and(is_array($kept) && is_string($kept['verifier']) ? strlen($kept['verifier']) : 0)->toBe(64);

    $state = is_string($query['state'] ?? null) ? $query['state'] : '';
    $result = $flow->finish(callback($session, ['code' => 'c', 'state' => $state]));
    expect($result->user->subject)->toBe('u-1')
        ->and($result->user->verifiedEmail())->toBe('a@b.test')
        ->and($result->context)->toBe(['link' => 7]);

    // The state was taken out: the same callback again is refused.
    expect(fn () => $flow->finish(callback($session, ['code' => 'c', 'state' => $state])))->toThrow(StateMismatch::class);
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
    fakeProvider();
    $session = app('session')->driver();
    $flow = app(SignInFlow::class);
    parse_str((string) parse_url($flow->start($session), PHP_URL_QUERY), $sent);

    expect(fn () => $flow->finish(callback($session, [...$query, 'state' => is_string($sent['state'] ?? null) ? $sent['state'] : ''])))
        ->toThrow(ProviderError::class, '(callback)');
})->with([
    'error' => [['error' => 'access_denied', 'code' => 'c']],
    'no code' => [[]],
]);
