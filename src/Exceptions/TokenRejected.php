<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * A provider's access token was not accepted (401).
 *
 * Reasons, in the order they are checked: `format`, `algorithm`, `type`,
 * `signature`, `issuer`, `audience`, `client`, `expired`, `not_yet`,
 * `subject`, `groups_stale`.
 *
 * From `expired` on, the token is the provider's own, issued for a known
 * client: `holder()` names the client and the person it speaks for (a hash,
 * never the claims), so its refusals are counted per holder, not per address.
 */
final class TokenRejected extends HttpException implements OidcException
{
    public function __construct(
        private readonly string $reason,
        private readonly ?string $holder = null,
    ) {
        parent::__construct(401, "The provider's access token was not accepted ({$reason}).");
    }

    public function reason(): string
    {
        return $this->reason;
    }

    /** The client and the person of a genuine token (a hash), or null when the token could not be trusted. */
    public function holder(): ?string
    {
        return $this->holder;
    }
}
