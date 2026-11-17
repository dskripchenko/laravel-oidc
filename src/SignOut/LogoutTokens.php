<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\SignOut;

use Dskripchenko\Oidc\Exceptions\ProviderError;
use Dskripchenko\Oidc\IssuerKeys;
use Dskripchenko\Oidc\Jose\Jwt;
use Dskripchenko\Oidc\OidcClient;
use Dskripchenko\Oidc\SignIn\IdTokens;
use Illuminate\Contracts\Cache\Repository as Cache;

/**
 * The logout token of a back-channel logout (OpenID Connect Back-Channel
 * Logout 1.0, 2.6): the provider POSTs it to the application when a session
 * there ended — the person signed out in another application, an
 * administrator ended the session, it expired.
 *
 * It is taken when it is signed with RS256 or ES256 by a key of the
 * issuer's JWKS (never `none`); `iss` is the configured issuer; `aud` holds
 * the client ID, and with several audiences — or any `azp` — `azp` is the
 * client ID; `iat` is not in the future and, without an `exp`, not older
 * than MAX_AGE seconds, and an `exp` has not passed, give or take the
 * leeway; it has a `jti` not seen before, a `sub` or a `sid`, the
 * back-channel logout event in `events`, and no `nonce` (which would make it
 * an ID token).
 *
 * For a named client (`OidcClient::as()`), build it with that client: the
 * token's audience is the client the session was opened with.
 */
final readonly class LogoutTokens
{
    /** The event a logout token carries in its `events` claim. */
    public const string EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    /** Seconds a logout token without an `exp` is taken after its `iat`. */
    public const int MAX_AGE = 300;

    public function __construct(
        private OidcClient $client,
        private IssuerKeys $keys,
        private Cache $cache,
    ) {}

    /**
     * The token once it passed; its `jti` is not taken again.
     *
     * @throws ProviderError logout_token_invalid, logout_token_replayed
     */
    public function validate(string $token): LogoutToken
    {
        $jwt = Jwt::parse($token);
        if ($jwt === null || ! in_array($jwt->algorithm(), IdTokens::ALGORITHMS, true) || ! $this->keys->signed($jwt)) {
            throw new ProviderError('logout_token_invalid');
        }
        $claims = $jwt->claims;
        $clientId = $this->client->clientId();
        $now = time();
        $leeway = IdTokens::leeway();
        $audience = $claims['aud'] ?? null;
        $audiences = is_string($audience) ? [$audience] : (is_array($audience) ? array_values($audience) : []);
        $azp = $claims['azp'] ?? null;
        $iat = $claims['iat'] ?? null;
        $exp = $claims['exp'] ?? null;
        $jti = $claims['jti'] ?? null;
        $sub = is_string($claims['sub'] ?? null) && $claims['sub'] !== '' ? $claims['sub'] : null;
        $sid = is_string($claims['sid'] ?? null) && $claims['sid'] !== '' ? $claims['sid'] : null;
        $events = $claims['events'] ?? null;
        $valid = is_string($claims['iss'] ?? null) && rtrim($claims['iss'], '/') === $this->client->issuer()
            && $clientId !== '' && in_array($clientId, $audiences, true)
            && ((count($audiences) === 1 && $azp === null) || $azp === $clientId)
            && is_int($iat) && $iat <= $now + $leeway
            && ($exp === null ? $iat >= $now - self::MAX_AGE - $leeway : is_int($exp) && $now <= $exp + $leeway)
            && is_string($jti) && $jti !== ''
            && ($sub !== null || $sid !== null)
            && is_array($events) && array_key_exists(self::EVENT, $events) && is_array($events[self::EVENT])
            && ! array_key_exists('nonce', $claims);
        if (! $valid) {
            throw new ProviderError('logout_token_invalid');
        }
        // Kept until the token could no longer be taken anyway.
        $until = (is_int($exp) ? $exp : $iat + self::MAX_AGE) + $leeway - $now;
        if (! $this->cache->add('oidc.logout_jti:'.hash('sha256', $this->client->issuer().'|'.$jti), true, max(1, $until))) {
            throw new ProviderError('logout_token_replayed');
        }

        return new LogoutToken($this->client->issuer(), $sub, $sid, $claims);
    }
}
