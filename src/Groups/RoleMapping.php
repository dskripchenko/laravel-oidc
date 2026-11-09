<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Groups;

/**
 * Roles from the provider's groups: `oidc.role_groups` maps a group to a
 * role — `admins=admin,auditors=auditor` —, the role named as the
 * application likes (a key, a name). Several groups may give one role.
 *
 * A role on the list is the provider's: given to whoever is in one of its
 * groups, taken back from whoever is not — but only when the provider gave
 * it. A role the person holds by hand stays until they join one of its
 * groups (then the provider takes it over), and is never taken back by the
 * groups. The application stores where a role came from and applies the
 * changes; this class only decides them.
 */
final class RoleMapping
{
    /**
     * The pairs of the setting in their order; a pair without a group or a
     * role is left out.
     *
     * @param  string|null  $setting  By default `oidc.role_groups`
     * @return list<array{group: string, role: string}>
     */
    public static function pairs(?string $setting = null): array
    {
        $setting ??= config('oidc.role_groups');
        $pairs = [];
        foreach (explode(',', is_string($setting) ? $setting : '') as $pair) {
            [$group, $role] = array_pad(array_map(trim(...), explode('=', $pair, 2)), 2, '');
            if ($group !== '' && $role !== '') {
                $pairs[] = ['group' => $group, 'role' => $role];
            }
        }

        return $pairs;
    }

    /**
     * What to do with one role.
     *
     * @param  non-empty-list<string>  $giving  The groups that give the role
     * @param  list<string>  $groups  The person's groups
     * @param  bool|null  $heldFromProvider  Null: not held; true: held from the provider; false: held by hand
     * @return RoleChange|null Null: nothing to change
     */
    public static function decide(array $giving, array $groups, ?bool $heldFromProvider): ?RoleChange
    {
        $in = array_values(array_intersect($giving, $groups));
        if ($in !== [] && $heldFromProvider !== true) {
            return new RoleChange(true, $heldFromProvider === false, $in[0]);
        }
        if ($in === [] && $heldFromProvider === true) {
            return new RoleChange(false, false, $giving[0]);
        }

        return null;
    }
}
