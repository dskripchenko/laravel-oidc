# dskripchenko/laravel-oidc

OpenID Connect for Laravel, without a JOSE library:

- **Sign-in** through the authorization code flow with PKCE (S256), a state
  and a nonce kept in the session, the ID token validated against the
  issuer's JWKS, then the person's userinfo.
- **Provider access tokens for an API**: an outside client signed in through
  the same provider calls the API with the provider's token (a JWT), checked
  against the issuer's JWKS — RS256/384/512 and ES256/384/512 only, never
  `none` or HMAC.
- **Groups** from the provider: the claim read, a "blocked" group, roles from
  `group=role` pairs, and a freshness rule for tokens without groups.

The package does not decide who the person is in your application: who a
subject is, what groups do and what a provider's token may do are yours,
through two small contracts.

PHP 8.3+, Laravel 11–13, ext-openssl.

## Install

```bash
composer require dskripchenko/laravel-oidc
php artisan vendor:publish --tag=oidc-config   # optional
```

```dotenv
OIDC_ISSUER=https://sso.example.com
OIDC_CLIENT_ID=my-app
OIDC_CLIENT_SECRET=...
OIDC_SCOPES="openid profile email groups"
```

The provider's endpoints come from `<issuer>/.well-known/openid-configuration`.
The document is kept an hour and taken only when its `issuer` is the
configured one.

## Sign-in

The routes and the session are yours; `SignInFlow` does the protocol.

```php
use Dskripchenko\Oidc\Exceptions\OidcException;
use Dskripchenko\Oidc\OidcClient;
use Dskripchenko\Oidc\SignIn\SignInFlow;

Route::get('/auth/oidc/redirect', function (Request $request, SignInFlow $flow) {
    abort_unless(OidcClient::enabled(), 404);

    return redirect()->away($flow->start($request->session(), ['back' => '/']));
});

Route::get('/auth/oidc/callback', function (Request $request, SignInFlow $flow) {
    try {
        $result = $flow->finish($request);         // state, ID token, userinfo checked
    } catch (OidcException $e) {
        return redirect('/login?sso='.$e->reason()); // state, nonce_mismatch, ...
    }
    $info = $result->user;                          // Dskripchenko\Oidc\UserInfo
    $user = User::firstWhere('oidc_subject', $info->subject)
        ?? User::firstWhere('email', $info->verifiedEmail()); // null unless email_verified === true
    // ... your rules, then:
    Auth::login($user);
    $request->session()->regenerate();

    return redirect($result->context['back']);
});
```

`UserInfo` has `subject`, `email` (lower case), `emailVerified`, `name`
(`name`, else `preferred_username`), `groups` (the `OIDC_GROUPS_CLAIM` claim,
null when absent) and the raw `claims`. `verifiedEmail()` returns the email
only when the provider says `email_verified: true` — an address it does not
vouch for may be anyone's typing and must not match an account.

The state and the nonce are taken out of the session, so a callback works
once. `finish()` requires an ID token in the token response and validates it
(OpenID Connect Core, 3.1.3.7) before the userinfo is read:

| Check | Reason of the `ProviderError` |
|---|---|
| the token response has an `id_token` | `id_token_missing` |
| signed with RS256 or ES256 by a key of the issuer's JWKS (by `kid`); never `none`, HMAC or another algorithm | `id_token_invalid` |
| `iss` is the configured issuer | `id_token_invalid` |
| `aud` holds `OIDC_CLIENT_ID`; with several audiences, or any `azp`, `azp` is `OIDC_CLIENT_ID` | `id_token_invalid` |
| `exp` not passed and `iat` not in the future, give or take the leeway | `id_token_invalid` |
| a non-empty `sub` | `id_token_invalid` |
| `nonce` is the one this sign-in started with | `nonce_mismatch` |
| the userinfo's `sub` is the ID token's | `sub_mismatch` |

The leeway is `OIDC_ID_TOKEN_LEEWAY` seconds (`oidc.id_token_leeway`, 60 by
default): the clock difference forgiven between this server and the
provider. The validated claims are in `$result->idToken`.

## Calling APIs on behalf of the person

An application that calls another API with the person's access token (a
backend for its own frontend) keeps the tokens of the sign-in on the server:

```php
$result = $flow->finish($request);
$tokens = $result->tokens;            // Dskripchenko\Oidc\Tokens\TokenSet
// $tokens->accessToken, ->refreshToken, ->expiresIn, ->refreshExpiresIn, ->idToken
```

Store them encrypted, next to the session, and never send them to the
browser. When the access token expires, trade the refresh token:

```php
use Dskripchenko\Oidc\Exceptions\ProviderError;

try {
    $fresh = app(OidcClient::class)->refresh($stored->refreshToken);
    // keep $fresh->refreshToken ?? $stored->refreshToken
} catch (ProviderError $e) {
    if ($e->reason() === 'refresh_rejected') {
        // blocked, signed out or the session ended at the provider: end the session here too
    }
    // 'refresh': the provider could not answer; try again later
}
```

The provider refuses the refresh token (`refresh_rejected`, any 4xx
answer) of a person it blocked or signed out, or of a session it ended — so
an application that refreshes on its own schedule follows a block within the
access token's lifetime. `OidcClient::tokens()` returns the same refresh
token and lifetime in its array; `exchange()` gives the `TokenSet`.

## Provider access tokens in an API

```dotenv
OIDC_API_TOKENS=true
OIDC_API_AUDIENCE=my-api          # required; not OIDC_CLIENT_ID (see below)
OIDC_API_CLIENTS=chat,mobile      # required: azp / client_id of the token; agent-* — a prefix
OIDC_API_GUARD=sanctum            # optional; the default guard otherwise
```

```php
use Dskripchenko\Oidc\Http\Middleware\AuthenticateProviderToken;
use Dskripchenko\Oidc\Tokens\ProviderAccessToken;

Route::middleware([AuthenticateProviderToken::class, 'auth:sanctum'])->get('/api/me', function (Request $request) {
    $token = ProviderAccessToken::of($request); // null for any other credential

    return ['user' => $request->user()->id, 'client' => $token?->client];
});
```

The token also names its scopes (`$token->scopes`, `$token->hasScope('manage')`)
from its `scope` claim — a scope matched by its exact name, never by a prefix —
so an action can ask for one the provider grants only to some clients.

A bearer that looks like a JWT is checked; any other bearer passes through to
your own tokens. A JWT that does not pass gets 401 (`TokenRejected`), never a
second try as something else. A token is taken when:

| Check | Rejection reason |
|---|---|
| a well-formed JWS, at most 16 KiB | `format` |
| `alg` is RS256/384/512 or ES256/384/512 | `algorithm` |
| header `typ` is in `OIDC_API_TOKEN_TYPES` (default `at+jwt`, RFC 9068), and the claims do not say ID token (`typ: ID`, `token_use: id`) | `type` |
| signed by a key of the issuer's JWKS, by `kid`; the key's `kty`, `alg`, `use` and EC curve match the algorithm | `signature` |
| `iss` is the issuer | `issuer` |
| `aud` holds `OIDC_API_AUDIENCE` | `audience` |
| `azp` (else `client_id`) is in `OIDC_API_CLIENTS` — by name, or by a prefix ending in `*` | `client` |
| `exp` not passed, `nbf` reached (60 s leeway) | `expired`, `not_yet` |
| `sub` names a person `SubjectUsers` returns | `subject` |
| groups fresh enough (below) | `groups_stale` |

Clients made on the fly (service accounts of agents, one per agent) are
taken by a prefix: `OIDC_API_CLIENTS=chat,agent-*` takes `agent-reviewer`
and `agent-writer`, not `agent-` itself; a lone `*` takes no client. Keep the
prefix to clients only your provider's administrators can make.

`OIDC_API_AUDIENCE` equal to `OIDC_CLIENT_ID` is ignored — a token for your
own sign-in is not one for the API — unless
`OIDC_API_AUDIENCE_SAME_AS_CLIENT=true`. Providers that type access tokens
`JWT` (Keycloak) need `OIDC_API_TOKEN_TYPES=at+jwt,JWT`; the audience and the
client list still keep their ID tokens out.

**JWKS.** The same keys as for ID tokens (`IssuerKeys`). Fetched from the discovery document's `jwks_uri` through the
`OutboundHttp` contract and kept an hour. An unknown `kid` refetches at most
once a minute: a rotated key is picked up, a stream of made-up key IDs does
not make the server call out. A failed fetch is remembered for 30 seconds.

**Rate limit.** After 30 rejected tokens from one address in a minute the
address gets 429 (`TooManyAttempts`, `Retry-After`). A genuine token — signed
by the provider, for your audience and a known client — that is still refused
(`expired`, `not_yet`, `subject`, `groups_stale`) is counted for its holder,
the client and the person, not for the address: a service calling on behalf
of many people from one address is not slowed down for all of them because
of a few. Claims of a token that did not pass the signature, issuer, audience
and client checks are never trusted for this. The first 5 rejections of a
minute (per address or holder) dispatch `ProviderTokenRejected` with the
reason and the IP — never the token or its claims — for your audit log.

The token grants nothing by itself: decide what a request with
`ProviderAccessToken::of($request) !== null` may do. Do not mint your own
long-lived tokens from it: they would outlive the provider's token and its
block.

## Groups

```php
use Dskripchenko\Oidc\Groups\GroupClaims;
use Dskripchenko\Oidc\Groups\RoleMapping;

GroupClaims::of($claims);          // list<string>|null from OIDC_GROUPS_CLAIM
GroupClaims::blocks($groups);      // in OIDC_BLOCKED_GROUP?

RoleMapping::pairs();              // OIDC_ROLE_GROUPS="admins=admin,auditors=auditor"
RoleMapping::decide($givingGroups, $groups, $heldFromProvider); // RoleChange|null
```

`decide()` gives a role to a member of one of its groups, takes over a role
held by hand when the person joins its group, and takes back only a role the
provider gave — never one given by hand. You store where a role came from and
apply the change.

With a groups claim in an access token, `GroupSync::sync()` runs as at a
sign-in (once a minute per person and set of groups); returning false — a
blocked person — rejects the token. A token without the claim is taken only
while `GroupSync::syncedAt()` is within `OIDC_API_SYNC_MAX_AGE` hours (24),
and only if `GroupSync::followsGroups()`.

## Contracts

| Contract | Default | Bind your own to |
|---|---|---|
| `Contracts\SubjectUsers` | `EloquentSubjectUsers`: the `users` provider's model (or `oidc.users.model`) by `oidc_issuer` and `oidc_subject` | leave out blocked accounts and service accounts |
| `Contracts\GroupSync` | `NullGroupSync`: nothing follows groups | apply teams, roles, the block |
| `Contracts\OutboundHttp` | `PlainOutboundHttp`: timeout, no redirects | guard the JWKS request against SSRF |

## Exceptions

All implement `Exceptions\OidcException` with a short `reason()`:
`ProviderError` (`discovery`, `endpoint`, `token`, `refresh`, `refresh_rejected`,
`userinfo`, `callback`),
`StateMismatch` (`state`), `TokenRejected` (401, reasons above),
`TooManyAttempts` (429).

## Testing

```bash
composer test      # pest
composer analyse   # phpstan, level max
composer format    # pint
```

## License

MIT. See [LICENSE](LICENSE).
