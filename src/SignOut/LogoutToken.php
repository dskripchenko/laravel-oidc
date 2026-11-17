<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\SignOut;

/**
 * A logout token that passed (LogoutTokens): the provider ended the
 * session `sessionId` (its `sid`), or every session of `subject`, when only
 * that is given. At least one of the two is set.
 */
final readonly class LogoutToken
{
    /**
     * @param  array<string, mixed>  $claims  The validated token's claims
     */
    public function __construct(
        public string $issuer,
        public ?string $subject,
        public ?string $sessionId,
        public array $claims,
    ) {}
}
