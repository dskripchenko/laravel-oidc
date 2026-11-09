<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Tokens;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * An accepted provider's access token and the person it speaks for.
 */
final readonly class VerifiedToken
{
    /**
     * @param  array<string, mixed>  $claims
     */
    public function __construct(
        public Authenticatable $user,
        public ProviderAccessToken $token,
        public array $claims,
    ) {}
}
