<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Who a provider's subject is in the application. Return null for anyone
 * who may not act through a provider's token: unknown, blocked, a service
 * account — the token is then rejected (`subject`).
 */
interface SubjectUsers
{
    public function find(string $issuer, string $subject): ?Authenticatable;
}
