<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Exceptions;

use RuntimeException;

/**
 * A silent sign-in (`prompt=none`) the provider could not finish without
 * showing the person a page: not signed in to the provider (`login_required`),
 * or it needs them to act (`interaction_required`, `consent_required`,
 * `account_selection_required`). Not a failure: show the application's own
 * sign-in page, and do not start a silent sign-in again in this session.
 */
final class SilentSignInRefused extends RuntimeException implements OidcException
{
    /**
     * @param  string  $error  The provider's error code
     * @param  array<string, mixed>  $context  What the application kept with the start of the sign-in
     */
    public function __construct(
        public readonly string $error,
        public readonly array $context = [],
    ) {
        parent::__construct("The provider refused a silent sign-in ({$error}).");
    }

    public function reason(): string
    {
        return 'silent_refused';
    }
}
