<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * An address sent too many rejected provider tokens in a minute (429).
 */
final class TooManyAttempts extends HttpException implements OidcException
{
    public function __construct(public readonly int $seconds)
    {
        parent::__construct(429, 'Too many rejected tokens.', null, ['Retry-After' => (string) $seconds]);
    }

    public function reason(): string
    {
        return 'too_many_attempts';
    }
}
