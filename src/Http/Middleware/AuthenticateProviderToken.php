<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Http\Middleware;

use Closure;
use Dskripchenko\Oidc\Events\ProviderTokenRejected;
use Dskripchenko\Oidc\Exceptions\TokenRejected;
use Dskripchenko\Oidc\Exceptions\TooManyAttempts;
use Dskripchenko\Oidc\Jose\Jwt;
use Dskripchenko\Oidc\Tokens\ProviderAccessToken;
use Dskripchenko\Oidc\Tokens\ProviderTokens;
use Dskripchenko\Oidc\Tokens\VerifiedToken;
use Illuminate\Auth\AuthManager;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * A bearer that is a JWT is the provider's access token: when the
 * application takes them (`oidc.api_tokens`), it is checked by
 * ProviderTokens and the request goes on as the person it was issued for,
 * on the `oidc.api_guard` guard, with the token in the request
 * (ProviderAccessToken::of()). A JWT that does not pass is rejected (401,
 * TokenRejected), not tried as anything else; any other bearer passes
 * through untouched, for the application's own tokens.
 *
 * Rejections are counted per address: after 30 in a minute the address
 * gets 429 (TooManyAttempts) until the minute is over, and only the first
 * 5 of a minute dispatch ProviderTokenRejected. A genuine token of a known
 * client that is refused (expired, an unknown person…) is counted for its
 * holder — the client and the person — instead: a service that calls on
 * behalf of many people from one address is not slowed down for all of
 * them by a few.
 */
final readonly class AuthenticateProviderToken
{
    /** Rejected tokens from one address (or one holder) a minute before it is slowed down. */
    public const int FAILURES_PER_MINUTE = 30;

    /** Rejected tokens from one address a minute that dispatch an event. */
    public const int REPORTED_PER_MINUTE = 5;

    public function __construct(
        private AuthManager $auth,
        private ProviderTokens $tokens,
        private RateLimiter $limiter,
        private Dispatcher $events,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $bearer = $request->bearerToken();
        if ($bearer !== null && Jwt::looksLikeOne($bearer) && ProviderTokens::enabled()) {
            $verified = $this->verify($request, $bearer);
            $request->attributes->set(ProviderAccessToken::ATTRIBUTE, $verified->token);
            $guard = config('oidc.api_guard');
            $guard = is_string($guard) && $guard !== '' ? $guard : null;
            $this->auth->guard($guard)->setUser($verified->user);
            $this->auth->shouldUse($guard ?? $this->auth->getDefaultDriver());
        }

        /** @var Response */
        return $next($request);
    }

    /**
     * @throws TokenRejected
     * @throws TooManyAttempts
     */
    private function verify(Request $request, string $bearer): VerifiedToken
    {
        $key = 'oidc-provider-token-failed:'.$request->ip();
        if ($this->limiter->tooManyAttempts($key, self::FAILURES_PER_MINUTE)) {
            throw new TooManyAttempts($this->limiter->availableIn($key));
        }
        try {
            return $this->tokens->verify($bearer);
        } catch (TokenRejected $e) {
            $holder = $e->holder();
            if ($holder !== null) {
                $key = 'oidc-provider-token-failed:holder:'.$holder;
                if ($this->limiter->tooManyAttempts($key, self::FAILURES_PER_MINUTE)) {
                    throw new TooManyAttempts($this->limiter->availableIn($key));
                }
            }
            $this->limiter->hit($key, 60);
            // The first few of a minute are enough to see what happens.
            if ($this->limiter->attempts($key) <= self::REPORTED_PER_MINUTE) {
                $this->events->dispatch(new ProviderTokenRejected($e->reason(), $request->ip()));
            }

            throw $e;
        }
    }
}
