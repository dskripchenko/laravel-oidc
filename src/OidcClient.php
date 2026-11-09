<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc;

use Dskripchenko\Oidc\Exceptions\ProviderError;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Http\Client\RequestException;

/**
 * An OpenID Connect provider through the authorization code flow with PKCE
 * (S256): its endpoints, the code traded for tokens, and the userinfo. The
 * whole sign-in, with the ID token validated, is SignIn\SignInFlow.
 *
 * The discovery document is kept an hour, and is taken only when its
 * `issuer` is the configured one: a document of another issuer speaks for
 * nobody.
 */
final readonly class OidcClient
{
    /** Seconds the discovery document is kept. */
    private const int DISCOVERY_FOR = 3600;

    public function __construct(
        private Http $http,
        private Cache $cache,
    ) {}

    /** On when an issuer and a client ID are set. */
    public static function enabled(): bool
    {
        return self::setting('issuer') !== '' && self::setting('client_id') !== '';
    }

    /** The provider's name for a "Sign in with ..." button. */
    public static function name(): string
    {
        $name = self::setting('name');

        return $name !== '' ? $name : 'SSO';
    }

    /** The configured issuer, without a trailing slash. */
    public function issuer(): string
    {
        return rtrim(self::setting('issuer'), '/');
    }

    /** Where the provider sends the person back. */
    public function redirectUri(): string
    {
        $configured = self::setting('redirect');
        $path = self::setting('callback_path');

        return $configured !== '' ? $configured : url($path !== '' ? $path : '/auth/oidc/callback');
    }

    /**
     * The provider's sign-in page for this state, PKCE verifier and nonce.
     *
     * @throws ProviderError
     */
    public function authorizeUrl(string $state, string $verifier, string $nonce): string
    {
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => self::setting('client_id'),
            'redirect_uri' => $this->redirectUri(),
            'scope' => self::setting('scopes'),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::challenge($verifier),
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);

        return $this->endpoint('authorization_endpoint').'?'.$query;
    }

    /**
     * Trades the code for the provider's tokens. The ID token is to be
     * validated (SignIn\IdTokens) before the access token is used.
     *
     * @return array{access_token: string, id_token: string|null}
     *
     * @throws ProviderError
     */
    public function tokens(string $code, string $verifier): array
    {
        try {
            $response = $this->http->asForm()->acceptJson()->timeout(15)
                ->withBasicAuth(self::setting('client_id'), self::setting('client_secret'))
                ->post($this->endpoint('token_endpoint'), [
                    'grant_type' => 'authorization_code',
                    'code' => $code,
                    'redirect_uri' => $this->redirectUri(),
                    'code_verifier' => $verifier,
                ])->throw();
        } catch (RequestException) {
            throw new ProviderError('token');
        }
        $access = $response->json('access_token');
        $id = $response->json('id_token');
        if (! is_string($access) || $access === '') {
            throw new ProviderError('token');
        }

        return ['access_token' => $access, 'id_token' => is_string($id) && $id !== '' ? $id : null];
    }

    /**
     * The person's claims from the userinfo endpoint.
     *
     * @throws ProviderError
     */
    public function userInfo(string $accessToken): UserInfo
    {
        try {
            $info = $this->http->acceptJson()->timeout(15)->withToken($accessToken)
                ->get($this->endpoint('userinfo_endpoint'))->throw()->json();
        } catch (RequestException) {
            throw new ProviderError('userinfo');
        }
        if (! is_array($info) || ! is_string($info['sub'] ?? null) || $info['sub'] === '') {
            throw new ProviderError('userinfo');
        }

        return UserInfo::fromClaims($info);
    }

    /**
     * An endpoint of the provider by its name in the discovery document.
     *
     * @throws ProviderError
     */
    public function endpoint(string $name): string
    {
        $url = $this->discovery()[$name] ?? null;
        if (! is_string($url) || $url === '') {
            throw new ProviderError('endpoint');
        }

        return $url;
    }

    /**
     * @return array<string, mixed>
     */
    private function discovery(): array
    {
        $issuer = $this->issuer();
        /** @var array<string, mixed> $document */
        $document = $this->cache->remember("oidc.discovery:{$issuer}", self::DISCOVERY_FOR, function () use ($issuer): array {
            try {
                $document = $this->http->acceptJson()->timeout(10)->get("{$issuer}/.well-known/openid-configuration")->throw()->json();
            } catch (RequestException) {
                throw new ProviderError('discovery');
            }

            // The document speaks for the configured issuer, or for nobody.
            if (! is_array($document) || ! is_string($document['issuer'] ?? null) || rtrim($document['issuer'], '/') !== $issuer) {
                throw new ProviderError('discovery');
            }

            return $document;
        });

        return $document;
    }

    /** A string setting of config/oidc.php; empty when unset. */
    private static function setting(string $key): string
    {
        $value = config("oidc.{$key}");

        return is_string($value) ? $value : '';
    }

    private static function challenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }
}
