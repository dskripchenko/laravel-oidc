<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Groups;

/**
 * The person's groups as the provider sends them, and the provider's
 * "blocked" group.
 */
final class GroupClaims
{
    /**
     * The groups from the configured claim (`oidc.groups_claim`) of a
     * userinfo response or a token; null when the claim is not there.
     * Entries that are not strings are dropped.
     *
     * @param  array<array-key, mixed>  $claims
     * @return list<string>|null
     */
    public static function of(array $claims): ?array
    {
        $claim = config('oidc.groups_claim');
        $groups = is_string($claim) ? ($claims[$claim] ?? null) : null;

        return is_array($groups) ? array_values(array_filter($groups, is_string(...))) : null;
    }

    /** The group whose members are blocked (`oidc.blocked_group`); null when none is set. */
    public static function blockedGroup(): ?string
    {
        $blocked = config('oidc.blocked_group');

        return is_string($blocked) && $blocked !== '' ? $blocked : null;
    }

    /**
     * Whether these groups include the blocked group.
     *
     * @param  list<string>  $groups
     */
    public static function blocks(array $groups): bool
    {
        $blocked = self::blockedGroup();

        return $blocked !== null && in_array($blocked, $groups, true);
    }
}
