<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\SignIn;

use Dskripchenko\Oidc\UserInfo;

/**
 * A finished sign-in: who the provider says signed in, and what the
 * application kept with the start of it.
 */
final readonly class SignInResult
{
    /**
     * @param  array<string, mixed>  $context
     * @param  array<string, mixed>  $idToken  The validated ID token's claims
     */
    public function __construct(
        public UserInfo $user,
        public array $context,
        public array $idToken = [],
    ) {}
}
