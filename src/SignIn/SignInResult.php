<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\SignIn;

use Dskripchenko\Oidc\Tokens\TokenSet;
use Dskripchenko\Oidc\UserInfo;

/**
 * A finished sign-in: who the provider says signed in, what the
 * application kept with the start of it, and the provider's tokens — for
 * an application that calls APIs on behalf of the person (keep them on the
 * server, never in the browser).
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
        public ?TokenSet $tokens = null,
    ) {}
}
