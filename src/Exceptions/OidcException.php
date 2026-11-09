<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Exceptions;

use Throwable;

/**
 * Every exception of the package. `reason()` is a short machine word, safe
 * to log and show: never a token or its claims.
 */
interface OidcException extends Throwable
{
    public function reason(): string;
}
