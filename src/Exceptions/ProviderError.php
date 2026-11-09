<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Exceptions;

use RuntimeException;

/**
 * The provider did not answer as expected: discovery, the code exchange,
 * userinfo, a missing endpoint, or an error sent back to the callback.
 *
 * Reasons: `discovery`, `endpoint`, `token`, `userinfo`, `callback`.
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
