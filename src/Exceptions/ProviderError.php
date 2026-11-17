<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Exceptions;

use RuntimeException;

/**
 * The provider did not answer as expected: discovery, the code exchange,
 * userinfo, a missing endpoint, an error sent back to the callback, or a
 * logout token that does not pass.
 *
 * Reasons: `discovery`, `endpoint`, `token`, `userinfo`, `callback`,
 * `id_token_missing`, `id_token_invalid`, `nonce_mismatch`, `sub_mismatch`,
 * `logout_token_invalid`, `logout_token_replayed`.
 */
final class ProviderError extends RuntimeException implements OidcException
{
    public function __construct(private readonly string $reason)
    {
        parent::__construct("The OpenID Connect provider did not answer as expected ({$reason}).");
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
