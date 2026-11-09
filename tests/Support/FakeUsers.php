<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Tests\Support;

use Dskripchenko\Oidc\Contracts\SubjectUsers;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * People by "issuer subject"; a blocked one is not found.
 */
final class FakeUsers implements SubjectUsers
{
    /** @var array<string, GenericUser> */
    public array $people = [];

    /** @var array<string, true> */
    public array $blocked = [];

    public function add(string $issuer, string $subject, int $id): GenericUser
    {
        return $this->people["{$issuer} {$subject}"] = new GenericUser(['id' => $id, 'name' => $subject, 'remember_token' => null, 'password' => '']);
    }

    public function find(string $issuer, string $subject): ?Authenticatable
    {
        $key = "{$issuer} {$subject}";

        return isset($this->blocked[$key]) ? null : $this->people[$key] ?? null;
    }
}
