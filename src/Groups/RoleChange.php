<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Groups;

/**
 * What the groups say about one role the provider gives.
 */
final readonly class RoleChange
{
    /**
     * @param  bool  $give  Give the role (true) or take it back (false)
     * @param  bool  $takeOver  Giving a role the person already holds by hand: from now on it is the provider's
     * @param  string  $group  The group that gives it, or the first one that would have
     */
    public function __construct(
        public bool $give,
        public bool $takeOver,
        public string $group,
    ) {}
}
