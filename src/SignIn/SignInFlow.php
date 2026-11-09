<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\SignIn;

use Dskripchenko\Oidc\Exceptions\ProviderError;
use Dskripchenko\Oidc\Exceptions\StateMismatch;
use Dskripchenko\Oidc\OidcClient;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

/**
 * The two ends of a sign-in: off to the provider with a fresh state, PKCE
 * verifier and nonce kept in the session, and back with a code that is
 * traded for the person's userinfo. The state is taken out of the session
 * on the way back, so a callback works once.
 *
 * The application decides who the person is (an account by subject, by a
 * verified email, a new one) and opens its session.
 */
final readonly class SignInFlow
{
    /** The session key of a sign-in in progress. */
    public const string SESSION_KEY = 'oidc';

    public function __construct(private OidcClient $client) {}

    /**
     * The provider's sign-in page; the context comes back with the result.
     *
     * @param  array<string, mixed>  $context  Plain data the application needs at the callback
     *
     * @throws ProviderError
     */
    public function start(Session $session, array $context = []): string
    {
        $state = Str::random(40);
        $verifier = Str::random(64);
        $nonce = Str::random(32);
        $session->put(self::SESSION_KEY, ['state' => $state, 'verifier' => $verifier, 'context' => $context]);

        return $this->client->authorizeUrl($state, $verifier, $nonce);
    }

    /**
     * The callback: the state checked, the code traded.
     *
     * @throws StateMismatch the state is not the one the session started with
     * @throws ProviderError the provider sent an error, no code, or did not answer as expected
     */
    public function finish(Request $request): SignInResult
    {
        $expected = $request->session()->pull(self::SESSION_KEY);
        $state = is_array($expected) ? ($expected['state'] ?? null) : null;
        $verifier = is_array($expected) ? ($expected['verifier'] ?? null) : null;
        if (! is_string($state) || ! is_string($verifier) || ! hash_equals($state, $request->string('state')->toString())) {
            throw new StateMismatch;
        }
        if ($request->filled('error') || ! $request->filled('code')) {
            throw new ProviderError('callback');
        }
        $context = is_array($expected['context'] ?? null) ? $expected['context'] : [];
        $user = $this->client->exchange($request->string('code')->toString(), $verifier);

        /** @var array<string, mixed> $context */
        return new SignInResult($user, $context);
    }
}
