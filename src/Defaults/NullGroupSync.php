<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Defaults;

use DateTimeInterface;
use Dskripchenko\Oidc\Contracts\GroupSync;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Nothing follows the provider's groups.
 */
final readonly class NullGroupSync implements GroupSync
{
    public function followsGroups(): bool
    {
        return false;
    }

    public function syncedAt(Authenticatable $user): ?DateTimeInterface
    {
        return null;
    }

    public function sync(Authenticatable $user, array $groups): bool
    {
        return true;
    }
}
