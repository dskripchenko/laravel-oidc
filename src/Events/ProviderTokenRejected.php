<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Events;

/**
 * A provider's access token was rejected by AuthenticateProviderToken.
 * Dispatched for the first few rejections of an address in a minute — enough
 * to see what happens, never a flood. It carries the reason only, never the
 * token or its claims.
 */
final readonly class ProviderTokenRejected
{
    public function __construct(
        public string $reason,
        public ?string $ip,
    ) {}
}
