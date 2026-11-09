<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc;

use Dskripchenko\Oidc\Contracts\OutboundHttp;
use Dskripchenko\Oidc\Jose\Jwt;
use Illuminate\Contracts\Cache\Repository as Cache;
use Throwable;

/**
 * The issuer's signing keys (the discovery document's `jwks_uri`), for ID
 * tokens and access tokens alike. Fetched through OutboundHttp and kept an
 * hour; a key ID not in the set makes one refetch at most every minute, so
 * a rotated key is picked up and an unknown one cannot make the server call
 * out each time. A failed fetch is remembered for half a minute, not for
 * the hour.
 */
final readonly class IssuerKeys
{
    /** Seconds the keys are kept. */
    private const int KEYS_FOR = 3600;

    /** Seconds between two fetches for an unknown key ID. */
    private const int REFETCH_EVERY = 60;

    /** Seconds a failed fetch of the keys is not repeated. */
    private const int FAILED_FOR = 30;

    public function __construct(
        private OidcClient $client,
        private OutboundHttp $outbound,
        private Cache $cache,
    ) {}

    /** Whether a key of the issuer signed the token: by its `kid`, or any key when it names none. */
    public function signed(Jwt $jwt): bool
    {
        foreach ([false, true] as $fresh) {
            $keys = $this->keys($fresh);
            if ($keys === null) {
                return false;
            }
            $kid = $jwt->keyId();
            $candidates = array_values(array_filter($keys, static fn (array $k): bool => $kid === null || ($k['kid'] ?? null) === $kid));
            foreach ($candidates as $jwk) {
                if ($jwt->signedBy($jwk)) {
                    return true;
                }
            }
            // A key ID the set does not know may be a rotated key: look again, once.
            if ($candidates !== [] || $kid === null) {
                return false;
            }
        }

        return false;
    }

    /**
     * The issuer's keys; a fresh look at most once a minute, and none for
     * half a minute after a failed one.
     *
     * @return list<array<string, mixed>>|null
     */
    private function keys(bool $fresh): ?array
    {
        $key = 'oidc.jwks:'.$this->client->issuer();
        if ($fresh) {
            if (! $this->cache->add($key.':refetch', true, self::REFETCH_EVERY)) {
                return null;
            }
            $this->cache->forget($key);
        }
        $stored = $this->cache->get($key);
        if (! is_array($stored)) {
            if ($this->cache->has($key.':failed')) {
                return null;
            }
            $stored = $this->fetch();
            if ($stored === null) {
                $this->cache->put($key.':failed', true, self::FAILED_FOR);

                return null;
            }
            $this->cache->put($key, $stored, self::KEYS_FOR);
        }
        $keys = [];
        foreach ($stored as $jwk) {
            if (is_array($jwk) && ! array_is_list($jwk)) {
                $keys[] = array_combine(array_map(strval(...), array_keys($jwk)), array_values($jwk));
            }
        }

        return $keys === [] ? null : $keys;
    }

    /**
     * @return list<mixed>|null The set, or null when it could not be had
     */
    private function fetch(): ?array
    {
        try {
            $url = $this->client->endpoint('jwks_uri');
            $set = $this->outbound->request($url)->acceptJson()->get($url)->throw()->json('keys');
        } catch (Throwable) {
            return null;
        }

        return is_array($set) && $set !== [] ? array_values($set) : null;
    }
}
