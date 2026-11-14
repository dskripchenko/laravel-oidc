<?php

declare(strict_types=1);

// OpenID Connect provider (Authelia, Keycloak, Zitadel, ...): on when an
// issuer and a client ID are set. The provider's endpoints come from its
// discovery document (<issuer>/.well-known/openid-configuration).
return [
    'issuer' => env('OIDC_ISSUER'),
    // The provider's name for a "Sign in with ..." button.
    'name' => env('OIDC_NAME', 'SSO'),
    'client_id' => env('OIDC_CLIENT_ID'),
    'client_secret' => env('OIDC_CLIENT_SECRET'),
    // Registered with the provider; by default the application's URL of
    // `callback_path`.
    'redirect' => env('OIDC_REDIRECT_URI'),
    'callback_path' => '/auth/oidc/callback',
    'scopes' => env('OIDC_SCOPES', 'openid profile email'),
    // Seconds of clock difference forgiven when the ID token's `exp` and
    // `iat` are checked.
    'id_token_leeway' => env('OIDC_ID_TOKEN_LEEWAY', 60),

    // The claim with the person's groups (userinfo and access tokens). Ask
    // the provider for it in the scopes ("groups" for Authelia, Keycloak
    // with a group mapper).
    'groups_claim' => env('OIDC_GROUPS_CLAIM', 'groups'),
    // A group whose members the application blocks (GroupClaims::blocks()).
    'blocked_group' => env('OIDC_BLOCKED_GROUP'),
    // Roles from groups: "group=role,group=role" (RoleMapping::pairs()).
    'role_groups' => env('OIDC_ROLE_GROUPS'),

    // Access tokens of the provider taken by the API on behalf of the
    // person (ProviderTokens, AuthenticateProviderToken). Off by default.
    'api_tokens' => (bool) env('OIDC_API_TOKENS', false),
    // The audience a token must hold (the API's identifier at the
    // provider). Required: empty takes no token. It may not be the
    // sign-in client's ID — a token for the application's own sign-in is
    // not one for the API — unless the next setting says so.
    'api_audience' => env('OIDC_API_AUDIENCE'),
    'api_audience_same_as_client' => (bool) env('OIDC_API_AUDIENCE_SAME_AS_CLIENT', false),
    // The clients whose tokens are taken: their client IDs (`azp`, else
    // `client_id` of the token), comma-separated. Required. An entry ending
    // in `*` takes every client with that prefix (`agent-*`); a lone `*` none.
    'api_clients' => env('OIDC_API_CLIENTS'),
    // The header types (`typ`) of an access token, comma-separated; RFC
    // 9068's `at+jwt` by default. Add `JWT` for a provider that marks its
    // access tokens so (Keycloak) — the audience and the clients above
    // still keep its ID tokens out.
    'api_token_types' => env('OIDC_API_TOKEN_TYPES', 'at+jwt'),
    // A token without the groups claim is taken while the person's groups
    // were read through the provider within these hours; only when the
    // application follows groups at all (GroupSync::followsGroups()).
    'api_sync_max_age' => env('OIDC_API_SYNC_MAX_AGE', 24),
    // The guard the person of an accepted token is set on; null: the
    // default guard.
    'api_guard' => env('OIDC_API_GUARD'),

    // The default SubjectUsers: the model with the issuer and subject
    // columns. Bind your own SubjectUsers for more rules (active only, ...).
    'users' => [
        'model' => null,
        'issuer_column' => 'oidc_issuer',
        'subject_column' => 'oidc_subject',
    ],
];
