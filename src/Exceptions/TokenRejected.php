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
 */
final class TokenRejected extends HttpException implements OidcException
{
    public function __construct(private readonly string $reason)
    {
        parent::__construct(401, "The provider's access token was not accepted ({$reason}).");
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
