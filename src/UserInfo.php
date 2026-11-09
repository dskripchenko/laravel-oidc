<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc;

use Dskripchenko\Oidc\Groups\GroupClaims;

/**
 * Who signed in, as the provider's userinfo endpoint says.
 */
final readonly class UserInfo
{
    /**
     * @param  string|null  $email  Lower case, trimmed
     * @param  bool|null  $emailVerified  Null when the provider does not say
     * @param  list<string>|null  $groups  Null when the provider does not send the claim
     * @param  array<array-key, mixed>  $claims  Everything the provider sent
     */
    public function __construct(
        public string $subject,
        public ?string $email,
        public ?bool $emailVerified,
        public ?string $name,
        public ?array $groups,
        public array $claims = [],
    ) {}

    /**
     * @param  array<array-key, mixed>  $claims  The userinfo response, with a non-empty `sub`
     */
    public static function fromClaims(array $claims): self
    {
        $sub = $claims['sub'] ?? null;

        return new self(
            subject: is_string($sub) ? $sub : '',
            email: is_string($claims['email'] ?? null) ? mb_strtolower(trim($claims['email'])) : null,
            emailVerified: is_bool($claims['email_verified'] ?? null) ? $claims['email_verified'] : null,
            name: is_string($claims['name'] ?? null) ? $claims['name'] : (is_string($claims['preferred_username'] ?? null) ? $claims['preferred_username'] : null),
            groups: GroupClaims::of($claims),
            claims: $claims,
        );
    }

    /**
     * The email only when the provider says outright that it is verified
     * (`email_verified: true`): an address it does not vouch for may be
     * anyone's typing and must not match an account.
     */
    public function verifiedEmail(): ?string
    {
        return $this->emailVerified === true ? $this->email : null;
    }

    /**
     * @return array{sub: string, email: string|null, email_verified: bool|null, name: string|null, groups: list<string>|null}
     */
    public function toArray(): array
    {
        return [
            'sub' => $this->subject,
            'email' => $this->email,
            'email_verified' => $this->emailVerified,
            'name' => $this->name,
            'groups' => $this->groups,
        ];
    }
}
