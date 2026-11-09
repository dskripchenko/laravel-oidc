<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Defaults;

use Dskripchenko\Oidc\Contracts\SubjectUsers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Database\Eloquent\Model;
use LogicException;

/**
 * The person by the issuer and subject columns of a model:
 * `oidc.users.model` (by default the `users` auth provider's model),
 * `oidc.users.issuer_column`, `oidc.users.subject_column`. It knows no more
 * rules — bind your own SubjectUsers to leave out blocked accounts.
 */
final readonly class EloquentSubjectUsers implements SubjectUsers
{
    public function __construct(private Config $config) {}

    public function find(string $issuer, string $subject): ?Authenticatable
    {
        $model = $this->config->get('oidc.users.model') ?? $this->config->get('auth.providers.users.model');
        if (! is_string($model) || ! is_a($model, Model::class, true) || ! is_a($model, Authenticatable::class, true)) {
            throw new LogicException('oidc.users.model must name an Eloquent model that is Authenticatable.');
        }
        $issuerColumn = $this->config->get('oidc.users.issuer_column', 'oidc_issuer');
        $subjectColumn = $this->config->get('oidc.users.subject_column', 'oidc_subject');
        if (! is_string($issuerColumn) || ! is_string($subjectColumn)) {
            throw new LogicException('oidc.users.issuer_column and oidc.users.subject_column must be strings.');
        }
        $user = $model::query()->where($issuerColumn, $issuer)->where($subjectColumn, $subject)->first();

        return $user instanceof Authenticatable ? $user : null;
    }
}
