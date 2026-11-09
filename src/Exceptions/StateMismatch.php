<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Exceptions;

use RuntimeException;

/**
 * The callback came without the state its sign-in started with: started in
 * another session, opened twice, or forged.
 */
final class StateMismatch extends RuntimeException implements OidcException
{
    public function __construct()
    {
        parent::__construct('The sign-in state does not match.');
    }

    public function reason(): string
    {
        return 'state';
    }
}
