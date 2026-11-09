<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Tokens;

/**
 * The tokens of one answer of the provider's token endpoint: the access
 * token, and what came with it — an ID token, a refresh token, the access
 * token's lifetime in seconds. Keep it on the server: none of it is for
 * the browser.
 */
final readonly class TokenSet
{
    public function __construct(
        public string $accessToken,
        public ?string $idToken = null,
        public ?string $refreshToken = null,
        public ?int $expiresIn = null,
        // The refresh token's lifetime in seconds, when the provider says it
        // (`refresh_expires_in`, Keycloak).
        public ?int $refreshExpiresIn = null,
    ) {}

    /**
     * From a token endpoint's JSON answer; null without an access token.
     *
     * @param  array<mixed>  $answer
     */
    public static function fromResponse(array $answer): ?self
    {
        $access = $answer['access_token'] ?? null;
        if (! is_string($access) || $access === '') {
            return null;
        }

        return new self(
            $access,
            self::text($answer['id_token'] ?? null),
            self::text($answer['refresh_token'] ?? null),
            self::seconds($answer['expires_in'] ?? null),
            self::seconds($answer['refresh_expires_in'] ?? null),
        );
    }

    private static function text(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    private static function seconds(mixed $value): ?int
    {
        // Some providers send the number as a string; zero means "not said" (Keycloak's offline tokens).
        return is_numeric($value) && (int) $value > 0 ? (int) $value : null;
    }
}
