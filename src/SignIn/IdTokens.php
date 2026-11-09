<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\SignIn;

use Dskripchenko\Oidc\Exceptions\ProviderError;
use Dskripchenko\Oidc\IssuerKeys;
use Dskripchenko\Oidc\Jose\Jwt;
use Dskripchenko\Oidc\OidcClient;

/**
 * The ID token of a sign-in (OpenID Connect Core, 3.1.3.7): signed with
 * RS256 or ES256 by a key of the issuer's JWKS, never `none`; `iss` the
 * configured issuer; `aud` holding the client ID, and with several
 * audiences — or any `azp` at all — `azp` the client ID; `exp` not passed
 * and `iat` not in the future, give or take `oidc.id_token_leeway` seconds;
 * a `sub`; and the `nonce` the sign-in started with.
 */
final readonly class IdTokens
{
    /** The signature algorithms taken. */
    public const array ALGORITHMS = ['RS256', 'ES256'];

    public function __construct(
        private OidcClient $client,
        private IssuerKeys $keys,
    ) {}

    /** Seconds of clock difference forgiven (`oidc.id_token_leeway`, 60 by default). */
    public static function leeway(): int
    {
        $leeway = config('oidc.id_token_leeway', 60);

        return is_numeric($leeway) ? max(0, (int) $leeway) : 60;
    }

    /**
     * The token's claims once it passed.
     *
     * @return array<string, mixed> With a non-empty string `sub`
     *
     * @throws ProviderError id_token_invalid, nonce_mismatch
     */
    public function validate(string $token, string $nonce): array
    {
        $jwt = Jwt::parse($token);
        if ($jwt === null || ! in_array($jwt->algorithm(), self::ALGORITHMS, true) || ! $this->keys->signed($jwt)) {
            throw new ProviderError('id_token_invalid');
        }
        $claims = $jwt->claims;
        $clientId = config('oidc.client_id');
        $now = time();
        $leeway = self::leeway();
        $audience = $claims['aud'] ?? null;
        $audiences = is_string($audience) ? [$audience] : (is_array($audience) ? array_values($audience) : []);
        $azp = $claims['azp'] ?? null;
        $valid = is_string($claims['iss'] ?? null) && rtrim($claims['iss'], '/') === $this->client->issuer()
            && is_string($clientId) && $clientId !== '' && in_array($clientId, $audiences, true)
            && ((count($audiences) === 1 && $azp === null) || $azp === $clientId)
            && is_int($claims['exp'] ?? null) && $now <= $claims['exp'] + $leeway
            && is_int($claims['iat'] ?? null) && $claims['iat'] <= $now + $leeway
            && is_string($claims['sub'] ?? null) && $claims['sub'] !== '';
        if (! $valid) {
            throw new ProviderError('id_token_invalid');
        }
        if (! is_string($claims['nonce'] ?? null) || $nonce === '' || ! hash_equals($nonce, $claims['nonce'])) {
            throw new ProviderError('nonce_mismatch');
        }

        return $claims;
    }
}
