<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Tests\Support;

use DateTimeInterface;
use Dskripchenko\Oidc\Contracts\GroupSync;
use Dskripchenko\Oidc\Groups\GroupClaims;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Remembers the syncs; the blocked group blocks the person in FakeUsers.
 */
final class FakeGroups implements GroupSync
{
    public bool $follows = true;

    /** @var array<int|string, DateTimeInterface> */
    public array $synced = [];

    /** @var list<array{int|string, list<string>}> */
    public array $calls = [];

    public function __construct(private FakeUsers $users) {}

    public function followsGroups(): bool
    {
        return $this->follows;
    }

    public function syncedAt(Authenticatable $user): ?DateTimeInterface
    {
        $id = $user->getAuthIdentifier();

        return is_int($id) || is_string($id) ? $this->synced[$id] ?? null : null;
    }

    public function sync(Authenticatable $user, array $groups): bool
    {
        $id = $user->getAuthIdentifier();
        if (! is_int($id) && ! is_string($id)) {
            return false;
        }
        $this->calls[] = [$id, $groups];
        $this->synced[$id] = now();
        if (GroupClaims::blocks($groups)) {
            foreach ($this->users->people as $key => $person) {
                if ($person->getAuthIdentifier() === $id) {
                    $this->users->blocked[$key] = true;
                }
            }

            return false;
        }

        return true;
    }
}
