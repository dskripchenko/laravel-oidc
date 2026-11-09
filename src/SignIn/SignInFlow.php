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
 * traded for tokens. The ID token is validated (IdTokens, its nonce the
 * session's), then the userinfo is read and must name the same `sub`. The
 * state and nonce are taken out of the session on the way back, so a
 * callback works once.
 *
 * The application decides who the person is (an account by subject, by a
 * verified email, a new one) and opens its session.
 */
final readonly class SignInFlow
{
    /** The session key of a sign-in in progress. */
    public const string SESSION_KEY = 'oidc';

    public function __construct(
        private OidcClient $client,
        private IdTokens $idTokens,
    ) {}

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
        $session->put(self::SESSION_KEY, ['state' => $state, 'verifier' => $verifier, 'nonce' => $nonce, 'context' => $context]);

        return $this->client->authorizeUrl($state, $verifier, $nonce);
    }

    /**
     * The callback: the state checked, the code traded.
     *
     * @throws StateMismatch the state is not the one the session started with
     * @throws ProviderError the provider sent an error or no code (`callback`), no ID token
     *                       (`id_token_missing`), one that does not pass (`id_token_invalid`,
     *                       `nonce_mismatch`), userinfo of another subject (`sub_mismatch`),
     *                       or did not answer as expected
     */
    public function finish(Request $request): SignInResult
    {
        $expected = $request->session()->pull(self::SESSION_KEY);
        $state = is_array($expected) ? ($expected['state'] ?? null) : null;
        $verifier = is_array($expected) ? ($expected['verifier'] ?? null) : null;
        $nonce = is_array($expected) ? ($expected['nonce'] ?? null) : null;
        if (! is_string($state) || ! is_string($verifier) || ! is_string($nonce) || ! hash_equals($state, $request->string('state')->toString())) {
            throw new StateMismatch;
        }
        if ($request->filled('error') || ! $request->filled('code')) {
            throw new ProviderError('callback');
        }
        $context = is_array($expected['context'] ?? null) ? $expected['context'] : [];
        $tokens = $this->client->exchange($request->string('code')->toString(), $verifier);
        if ($tokens->idToken === null) {
            throw new ProviderError('id_token_missing');
        }
        $claims = $this->idTokens->validate($tokens->idToken, $nonce);
        $user = $this->client->userInfo($tokens->accessToken);
        // The userinfo speaks for the person the ID token names, or for nobody.
        if ($claims['sub'] !== $user->subject) {
            throw new ProviderError('sub_mismatch');
        }

        /** @var array<string, mixed> $context */
        return new SignInResult($user, $context, $claims, $tokens);
    }
}
