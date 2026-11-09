<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Contracts;

use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * What the application does with the groups a provider's access token
 * carries — teams, roles, a block — and how fresh its last word is.
 */
interface GroupSync
{
    /**
     * Whether anything in the application follows the provider's groups.
     * If nothing does, the groups cannot go stale and a token without them
     * is always taken.
     */
    public function followsGroups(): bool;

    /** When the person's groups were last read through the provider; null: never. */
    public function syncedAt(Authenticatable $user): ?DateTimeInterface;

    /**
     * Applies the groups to the person, as a sign-in would.
     *
     * @param  list<string>  $groups
     * @return bool False when the groups refuse the person (a blocked group)
     */
    public function sync(Authenticatable $user, array $groups): bool;
}
