<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Tokens;

use Dskripchenko\Oidc\Contracts\GroupSync;
use Dskripchenko\Oidc\Contracts\SubjectUsers;
use Dskripchenko\Oidc\Exceptions\TokenRejected;
use Dskripchenko\Oidc\Groups\GroupClaims;
use Dskripchenko\Oidc\IssuerKeys;
use Dskripchenko\Oidc\Jose\Jwt;
use Dskripchenko\Oidc\OidcClient;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Repository as Cache;

/**
 * Access tokens of the provider taken by an API: an outside client signed
 * in through the same provider acts on behalf of the person. The token is a
 * JWT signed with a key of the issuer's JWKS; its header `typ` is one of
 * `oidc.api_token_types` and its claims do not call it an ID token, its
 * `iss` is the issuer, its `aud` holds `oidc.api_audience` — never the
 * application's own sign-in client unless allowed —, its client (`azp`,
 * else `client_id`) is on `oidc.api_clients`, it has not expired (`exp`,
 * `nbf`, a minute of leeway), and its `sub` names a person SubjectUsers
 * knows. Off unless `oidc.api_tokens` is set.
 *
 * The person's groups follow the token: a groups claim in it is applied
 * through GroupSync (once a minute per person and set of groups); a token
 * without one is taken only while the person's last sync through the
 * provider is fresh (`oidc.api_sync_max_age` hours) — if the application
 * follows groups at all.
 *
 * The keys are the issuer's JWKS (IssuerKeys): kept an hour, refetched at
 * most once a minute for an unknown key ID, a failed fetch remembered for
 * half a minute.
 */
final readonly class ProviderTokens
{
    /** Seconds of clock difference forgiven. */
    private const int LEEWAY = 60;

    /** Seconds the same groups of the same person are not synced again. */
    private const int GROUPS_FOR = 60;

    public function __construct(
        private OidcClient $client,
        private IssuerKeys $keys,
        private Cache $cache,
        private SubjectUsers $users,
        private GroupSync $groups,
    ) {}

    public static function enabled(): bool
    {
        return OidcClient::enabled() && (bool) config('oidc.api_tokens', false);
    }

    /**
     * The audience a token must hold: `oidc.api_audience`. It is not the
     * sign-in client's ID unless `oidc.api_audience_same_as_client` says
     * so: a token for the application's own sign-in — an ID token — is not
     * one for the API. Empty: no token is taken.
     */
    public static function audience(): string
    {
        $audience = config('oidc.api_audience');
        $audience = is_string($audience) ? trim($audience) : '';
        if ($audience === config('oidc.client_id') && ! config('oidc.api_audience_same_as_client', false)) {
            return '';
        }

        return $audience;
    }

    /**
     * The clients whose tokens are taken (`oidc.api_clients`).
     *
     * @return list<string>
     */
    public static function clients(): array
    {
        return self::list(config('oidc.api_clients'));
    }

    /**
     * The header types of an access token taken (`oidc.api_token_types`,
     * by default only RFC 9068's `at+jwt`), lower case.
     *
     * @return list<string>
     */
    public static function types(): array
    {
        return array_map(mb_strtolower(...), self::list(config('oidc.api_token_types', 'at+jwt')));
    }

    /**
     * The person the token speaks for, and the client that holds it.
     *
     * @throws TokenRejected the token is not one to take; the reason says why
     */
    public function verify(string $token): VerifiedToken
    {
        $jwt = Jwt::parse($token) ?? throw new TokenRejected('format');
        if ($jwt->algorithm() === null) {
            throw new TokenRejected('algorithm');
        }
        // An ID token is not an access token, whoever signed it.
        $type = $jwt->header['typ'] ?? null;
        if (! is_string($type) || ! in_array(mb_strtolower($type), self::types(), true)
            || ($jwt->claims['typ'] ?? null) === 'ID' || ($jwt->claims['token_use'] ?? null) === 'id') {
            throw new TokenRejected('type');
        }
        if (! $this->keys->signed($jwt)) {
            throw new TokenRejected('signature');
        }
        $claims = $jwt->claims;
        $now = time();
        $issuer = rtrim($this->client->issuer(), '/');
        if (! is_string($claims['iss'] ?? null) || rtrim($claims['iss'], '/') !== $issuer) {
            throw new TokenRejected('issuer');
        }
        $audience = $claims['aud'] ?? null;
        $audiences = is_string($audience) ? [$audience] : (is_array($audience) ? $audience : []);
        if (self::audience() === '' || ! in_array(self::audience(), $audiences, true)) {
            throw new TokenRejected('audience');
        }
        $client = $claims['azp'] ?? $claims['client_id'] ?? null;
        if (! is_string($client) || ! in_array($client, self::clients(), true)) {
            throw new TokenRejected('client');
        }
        // Signed by the provider for a known client: refusals from here on are the holder's.
        $sub = is_string($claims['sub'] ?? null) ? $claims['sub'] : '';
        $holder = hash('sha256', $issuer."\n".$client."\n".$sub);
        if (! is_int($claims['exp'] ?? null) || $now > $claims['exp'] + self::LEEWAY) {
            throw new TokenRejected('expired', $holder);
        }
        if (is_int($claims['nbf'] ?? null) && $now < $claims['nbf'] - self::LEEWAY) {
            throw new TokenRejected('not_yet', $holder);
        }
        if ($sub === '') {
            throw new TokenRejected('subject', $holder);
        }
        $user = $this->users->find($issuer, $sub) ?? throw new TokenRejected('subject', $holder);
        $user = $this->followGroups($user, $issuer, $sub, GroupClaims::of($claims), $holder);

        return new VerifiedToken($user, new ProviderAccessToken($issuer, $sub, mb_substr($client, 0, 100), $claims['exp']), $claims);
    }

    /**
     * The person's groups as the token says, or a check that the last word
     * of the provider is fresh enough. The person as they are afterwards.
     *
     * @param  list<string>|null  $groups
     */
    private function followGroups(Authenticatable $user, string $issuer, string $sub, ?array $groups, string $holder): Authenticatable
    {
        if ($groups === null) {
            $maxAge = config('oidc.api_sync_max_age', 24);
            $hours = is_numeric($maxAge) ? max(1, (int) $maxAge) : 24;
            if ($this->groups->followsGroups()) {
                $synced = $this->groups->syncedAt($user);
                if ($synced === null || $synced->getTimestamp() < now()->subHours($hours)->getTimestamp()) {
                    throw new TokenRejected('groups_stale', $holder);
                }
            }

            return $user;
        }
        $key = 'oidc.api_groups:'.hash('sha256', $issuer."\n".$sub);
        $seen = hash('sha256', (string) json_encode(array_values(array_unique($groups))));
        if ($this->cache->get($key) === $seen) {
            return $user;
        }
        // The provider's "blocked" group: the token is not taken.
        if (! $this->groups->sync($user, $groups)) {
            throw new TokenRejected('subject', $holder);
        }
        $this->cache->put($key, $seen, self::GROUPS_FOR);

        // The groups may have blocked the person.
        return $this->users->find($issuer, $sub) ?? throw new TokenRejected('subject', $holder);
    }

    /**
     * @return list<string>
     */
    private static function list(mixed $setting): array
    {
        $items = array_map(trim(...), explode(',', is_string($setting) ? $setting : ''));

        return array_values(array_filter($items, static fn (string $item): bool => $item !== ''));
    }
}
