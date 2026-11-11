<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Tokens;

use Illuminate\Http\Request;

/**
 * The provider's access token a request came with, once it was accepted:
 * kept as a request attribute by AuthenticateProviderToken. It names the
 * client that holds it and when it ends; it grants nothing by itself — the
 * application decides what such a token may do.
 */
final readonly class ProviderAccessToken
{
    /** The request attribute that holds the token. */
    public const string ATTRIBUTE = 'oidc.provider_access_token';

    /**
     * @param  string  $client  The client that holds it (`azp`, else `client_id`), at most 100 characters
     * @param  int  $expiresAt  When it ends (its `exp`, Unix seconds)
     * @param  list<string>  $scopes  The scopes it was issued with (its `scope`, space-separated in the token)
     */
    public function __construct(
        public string $issuer,
        public string $subject,
        public string $client,
        public int $expiresAt,
        public array $scopes = [],
    ) {}

    /** Whether the token was issued with the scope, named exactly. */
    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /** The accepted provider's token the request came with, if any. */
    public static function of(Request $request): ?self
    {
        $token = $request->attributes->get(self::ATTRIBUTE);

        return $token instanceof self ? $token : null;
    }
}
